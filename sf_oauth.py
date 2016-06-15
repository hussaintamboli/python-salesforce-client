#!/usr/bin/python

"""
## Python interface to Salesforce APIs ##
1. REST
2. Bulk
"""

import hmac
import hashlib
import binascii
import json
import logging

import requests

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


__author__ = 'hussain'

# http://stackoverflow.com/questions/13897205/create-an-anonymous-class-instance-in-python
STATUS = type('Status', (object,), { "SUCCESS": True, "ERROR": False })

log = getLogger()


# NOTE - Decorator
# http://www.saltycrane.com/blog/2009/11/trying-out-retry-decorator-python/
# retry decorator (modified)
def retry(ExceptionToCheck, tries=4, delay=30, logger=None):
    """Retry calling the decorated function.

    By default, will try for 4 times with 30 sec delay. So we try for total 2 mins.

    http://www.saltycrane.com/blog/2009/11/trying-out-retry-decorator-python/
    original from: http://wiki.python.org/moin/PythonDecoratorLibrary#Retry

    :param ExceptionToCheck: the exception to check. may be a tuple of
        exceptions to check
    :type ExceptionToCheck: Exception or tuple
    :param tries: number of times to try (not retry) before giving up
    :type tries: int
    :param delay: initial delay between retries in seconds
    :type delay: int
    """
    def deco_retry(f):

        @wraps(f)
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 1:
                try:
                    return f(*args, **kwargs)
                except ExceptionToCheck, e:
                    if logger:
                        logger.info("{exc}, Retrying {f} in {mdelay} seconds..."
                                    .format(exc=str(e), mdelay=mdelay, f=f))
                    time.sleep(mdelay)
                    mtries -= 1
            return f(*args, **kwargs)

        return f_retry  # true decorator

    return deco_retry



class DictObj(object):
    def __getattr__(self, attr):
        return self.__dict__.get(attr)


class SFBatchNotCompletedError(Exception):
    pass


class SFBatchFailure(Exception):
    pass


class SFOperationFailure(Exception):
    pass


class AccessTokenError(Exception):
    pass


class SFRest:

    API_STATUS__RECORD_CREATED, API_STATUS__RECORD_UPDATED = 201, 204

    def __init__(self, credentials):
        self.read_config(credentials)
        self.SUCCESS, self.FAILED = 1, 0

    def authenticate(self):
        try:
            self.pre_process_oauth_request()
            return STATUS.SUCCESS
        except AccessTokenError:
            return STATUS.ERROR

    def read_config(self, credentials):
        credentials = json.loads(credentials)
        # overwrite attribs that were defined in readConfig of base class
        self.consumer_key = credentials.get('consumer_key').encode('utf-8')
        self.consumer_secret = credentials.get('consumer_secret').encode('utf-8')
        self.redirect_uri = credentials.get('redirect_uri').encode('utf-8')
        self.login_base_url = credentials.get('login_base_url').encode('utf-8')
        self.refresh_token = credentials.get('refresh_token').encode('utf-8')
        # new attrib for this child class
        # OFFSET is available in API version 24.0 and later
        # https://developer.salesforce.com/docs/atlas.en-us.soql_sosl.meta/soql_sosl/sforce_api_calls_soql_select_offset.htm
        self.api_version = credentials.get('api_version').encode('utf-8')

    def pre_process_oauth_request(self):
        token_request_data = self.get_new_access_token_by_refresh_token(
            self.refresh_token, self.login_base_url,
            self.consumer_key, self.consumer_secret, self.redirect_uri
        )
        if not token_request_data.get('access_token'):
            raise AccessTokenError("Access token request failed")
        if not self.verify_signature_for_oauth(token_request_data, self.consumer_secret):
            raise AccessTokenError("Local and generated signatures don't match!")
        access_token = token_request_data['access_token']
        instance_url = token_request_data['instance_url']
        return {
            'instanceUrl': instance_url,
            'accessToken': access_token
        }

    def execute_soql_query(self, query="SELECT Id, SMSMagic_AccountId__c FROM Account"):
        temp_oauth_response = self.pre_process_oauth_request()
        instance_url, access_token = temp_oauth_response['instanceUrl'], temp_oauth_response['accessToken']
        url_GET = instance_url + "/services/data/v%s/query/" % self.api_version
        data = {'q': query}
        headers = {
            "Authorization": "OAuth %s" % str(access_token),
            "Content-Type": "application/json"
        }
        try:
            # You may not have requests module of python by default. Install it first
            query_result = requests.get(url_GET, headers=headers, params=data)
        except requests.exceptions.RequestException as err:
            log.error("execute_soql_query failed. Exception : %s", err)
            raise SFOperationFailure(err)
        except Exception as err:
            log.error("execute_soql_query failed. Exception : %s", err)
            raise SFOperationFailure(err)
        return query_result.text

    def get_new_access_token_by_refresh_token(self, refresh_token, login_base_url, consumer_key, consumer_secret, redirect_uri):
        token_url = login_base_url + '/services/oauth2/token'
        post_fields = {
            'grant_type': 'refresh_token',
            'client_id': consumer_key,
            'client_secret': consumer_secret,
            'refresh_token': refresh_token,
            'redirect_uri': redirect_uri,
            'format': 'json'
        }
        log.info("Before making request for access token. url=%s and POST params=%s", token_url, post_fields)
        try:
            api_response = requests.post(token_url, data=post_fields)
            log.debug("URL used for access token = %s", api_response.url)
            return api_response.json()
        except Exception as err:
            log.error("get_new_access_token_by_refresh_token failed. Exception : %s", err)
            raise AccessTokenError("Error in getting access_token. %s" % str(err))

    def verify_signature_for_oauth(self, token_request_data, consumer_secret):
        if token_request_data or not token_request_data == '':
            if not token_request_data['signature'] == '':
                received_signature = token_request_data['signature']
        if not token_request_data['id'] == '':
            received_id = token_request_data['id']
        if not token_request_data['issued_at'] == '':
            issued_at = token_request_data['issued_at']
        query_string = received_id + issued_at
        hash_signature = hmac.new(consumer_secret, query_string, hashlib.sha256)
        generated_signature = binascii.b2a_base64(hash_signature.digest())[:-1]
        if generated_signature != received_signature:
            log.error("Local and generated signatures don't match!")
            raise AccessTokenError("Local and generated signatures don't match!")
        return True

    def upsert_record_using_oauth(self, custom_object_name_to_be_upserted, external_field_name, external_id, data):
        temp_oauth_response = self.pre_process_oauth_request()
        instance_url, access_token = temp_oauth_response['instanceUrl'], temp_oauth_response['accessToken']
        push_url = "%s/services/data/v%s/sobjects/%s/%s/%s" % \
                  (instance_url, self.api_version, custom_object_name_to_be_upserted, external_field_name, external_id)
        data = json.dumps(data)
        headers = {
            "Authorization": "OAuth %s" % str(access_token),
            "Content-Type": "application/json"
        }
        try:
            # You may not have requests module of python by default. Install it first
            patch_response = requests.patch(push_url, data, headers=headers)
            response = {'status': patch_response.status_code, 'data': patch_response.text}
        except Exception as err:
            log.error("upsert_record_using_oauth failed. Exception=%s", err)
            response = {'status': self.FAILED, 'error': err}
        log.info("Upsert response = %s", response)
        return response

    def insert_records_using_composite_resource(self, object_name_to_be_inserted, newrecords):
        # NOTE : Only available from Summer 15 release i.e. Above API V34.0
        # Also remember that the API operation is of Atomic type
        # i.e. It either succeeds or fails altogether
        temp_oauth_response = self.pre_process_oauth_request()
        instance_url, access_token = temp_oauth_response['instanceUrl'], temp_oauth_response['accessToken']
        url = "%s/services/data/v%s/composite/tree/%s" % \
                  (instance_url, self.api_version, object_name_to_be_inserted)
        data = json.dumps(newrecords)
        headers = {
            "Authorization": "OAuth %s" % str(access_token),
            "Content-Type": "application/json"
        }
        try:
            # You may not have requests module of python by default. Install it first
            post_response = requests.post(url, data, headers=headers)
            response = {'status': post_response.status_code, 'data': post_response.text}
        except Exception as err:
            log.error("upsert_record_using_oauth failed. Exception=%s", err)
            response = {'status': self.FAILED, 'error': err}
        log.info("Upsert response = %s", response)
        return response

    def get_one_object_using_oauth(self, object_name_to_be_fetched, external_id,
                                   external_field_name=None, fields=[], is_custom_object=False):
        temp_oauth_response = self.pre_process_oauth_request()
        instance_url, access_token = temp_oauth_response['instanceUrl'], temp_oauth_response['accessToken']
        if is_custom_object:
            url = "%s/services/data/v%s/sobjects/%s/%s/%s" % \
                  (instance_url, self.api_version, object_name_to_be_fetched,
                   external_field_name, external_id)
        else:
            url = "%s/services/data/v%s/sobjects/%s/%s" % \
                  (instance_url, self.api_version, object_name_to_be_fetched, external_id)
        if isinstance(fields, list) and fields:
            url = "%s?fields=%s" % (url, ",".join(fields))

        log.info("GET url = %s", url)
        headers = {
            "Authorization": "OAuth %s" % str(access_token),
            "Content-Type": "application/json"
        }
        try:
            # You may not have requests module of python by default. Install it first
            get_response = requests.get(url, headers=headers)
            response = {'status': get_response.status_code, 'data': get_response.content}
        except Exception as err:
            log.error("get_one_object_using_oauth failed. Exception=%s", err)
            response = {'status': self.FAILED, 'error': err}
        return response


class BulkSFRest(SFRest):

    def __init__(self, credentials):
        SFRest.__init__(self, credentials)
        self.xmlns = "http://www.force.com/2009/06/asyncapi/dataload"

    def create_job(self, sf_object='Account', operation='query',
                   content_type='CSV', concurrency_mode='Parallel'):

        sf_access_response = self.pre_process_oauth_request()
        instance_url, access_token = sf_access_response['instanceUrl'], sf_access_response['accessToken']
        log.info('create_job :: instance_url=%s and access_token=%s' % (instance_url, access_token))

        xml = """<?xml version="1.0" encoding="UTF-8"?>
                <jobInfo xmlns="{4}">
                <operation>{0}</operation>
                <object>{1}</object>
                <concurrencyMode>{2}</concurrencyMode>
                <contentType>{3}</contentType>
                </jobInfo>""".format(operation, sf_object, concurrency_mode,
                                     content_type, self.xmlns)
        url = "{instance_url}/services/async/{api_version}/job".format(
            instance_url=instance_url, api_version=self.api_version)
        headers = {
            'X-SFDC-Session': access_token,
            'Content-Type': 'application/xml; charset=UTF-8'
        }
        log.debug('create_job :: post request data : url=%s, xml=%s and headers=%s'
                  % (url, xml, headers))
        response = requests.post(url, data=xml, headers=headers)
        xml_response = response.content
        log.debug('create_job :: API response=%s', xml_response)

        # return job_id
        tree = ET.fromstring(xml_response)
        job_id = tree.find('.//{%s}id' % self.xmlns)
        # Element objects are considered a False value if they have no children
        # So we need to use specific test instead viz. 'elem is not None' test instead
        # http://stackoverflow.com/questions/20129996/why-does-boolxml-etree-elementtree-element-evaluate-to-false
        if job_id is not None:
            return job_id.text
        raise SFOperationFailure("create_job :: id not found in xml response")

    def add_batch_to_the_job(self, data, job_id, upload_csv=False):
        sf_access_response = self.pre_process_oauth_request()
        instance_url, access_token = sf_access_response['instanceUrl'], sf_access_response['accessToken']
        log.info('add_batch_to_the_job :: instance_url=%s and access_token=%s' % (instance_url, access_token))

        url = "{instance_url}/services/async/{api_version}/job/{job_id}/batch".format(
            instance_url=instance_url, api_version=self.api_version, job_id=job_id)
        headers = {
            'X-SFDC-Session': access_token,
            'Content-Type': 'text/csv; charset=UTF-8'
        }
        log.debug('add_batch_to_the_job :: post request data : url=%s, data=%s and headers=%s'
                  % (url, data, headers))
        if upload_csv:
            response = requests.post(url, data=open(data, 'rb').read(), headers=headers)
        else:
            response = requests.post(url, data=data, headers=headers)

        xml_response = response.content
        log.debug('add_batch_to_the_job :: API response=%s', xml_response)

        # return batch_id
        tree = ET.fromstring(xml_response)
        batch_id = tree.find('.//{%s}id' % self.xmlns)
        if batch_id is not None:
            return batch_id.text
        raise SFOperationFailure("add_batch_to_the_job :: id not found in xml response")

    # FYI - Getting Information for All Batches in a Job
    # https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/asynch_api_batches_get_info_all.htm

    @retry(SFBatchNotCompletedError, logger=log, tries=20)
    def check_batch_completion_status(self, job_id, batch_id):
        sf_access_response = self.pre_process_oauth_request()
        instance_url, access_token = sf_access_response['instanceUrl'], sf_access_response['accessToken']
        log.info('check_batch_completion_status :: instance_url=%s and access_token=%s' % (instance_url, access_token))

        url = "{instance_url}/services/async/{api_version}/job/{job_id}/batch/{batch_id}".format(
            instance_url=instance_url, api_version=self.api_version, job_id=job_id, batch_id=batch_id)
        headers = {
            'X-SFDC-Session': access_token
        }
        log.debug('check_batch_completion_status :: get request data : url=%s and headers=%s'
                  % (url, headers))
        response = requests.get(url, headers=headers)
        xml_response = response.content
        log.debug('check_batch_completion_status :: API response=%s', xml_response)

        # return result_id
        tree = ET.fromstring(xml_response)
        batch_state = tree.find('.//{%s}state' % self.xmlns)
        if batch_state is not None:
            if batch_state.text == 'Completed':
                return True
            elif batch_state.text == 'Failed' or batch_state.text == 'Not Processed':
                # exception when batch failed
                batch_state_message = tree.find('.//{%s}stateMessage' % self.xmlns)
                batch_state_message = batch_state_message.text if (batch_state_message is not None) else ''
                raise SFBatchFailure("Batch failed. %s" % batch_state_message)
            # exception when batch not yet completed
            raise SFBatchNotCompletedError("Batch not yet completed")
        # same exception with different error message, when batch response doesn't have 'state'
        raise SFBatchNotCompletedError("'state' not found in Batch xml response")

    def create_batch_result(self, job_id, batch_id):
        batch_completed = self.check_batch_completion_status(job_id, batch_id)
        if batch_completed:
            sf_access_response = self.pre_process_oauth_request()
            instance_url, access_token = sf_access_response['instanceUrl'], sf_access_response['accessToken']
            log.info('create_batch_result :: instance_url=%s and access_token=%s' % (instance_url, access_token))

            url = "{instance_url}/services/async/{api_version}/job/{job_id}/batch/{batch_id}/result".format(
                instance_url=instance_url, api_version=self.api_version, job_id=job_id, batch_id=batch_id)
            headers = {
                'X-SFDC-Session': access_token
            }
            log.debug('create_batch_result :: get request data : url=%s and headers=%s'
                      % (url, headers))
            response = requests.get(url, headers=headers)
            api_response = response.content
            log.debug('create_batch_result :: API response=%s', api_response)

            if response.headers.get('content-type') == 'text/csv':
                # In case of bulk insert, Salesforce will give CSV in response
                return api_response

            # return result_id
            tree = ET.fromstring(api_response)
            batch_result = tree.find('.//{%s}result' % self.xmlns)
            if batch_result is not None:
                return batch_result.text
            raise SFOperationFailure("create_batch_result :: result not found in xml response")

    def get_batch_result(self, job_id, batch_id, result_id):
        sf_access_response = self.pre_process_oauth_request()
        instance_url, access_token = sf_access_response['instanceUrl'], sf_access_response['accessToken']
        log.info('get_batch_result :: instance_url=%s and access_token=%s' % (instance_url, access_token))

        url = "{instance_url}/services/async/{api_version}/job/{job_id}/batch/{batch_id}/result/{result_id}".format(
            instance_url=instance_url, api_version=self.api_version, job_id=job_id, batch_id=batch_id, result_id=result_id)
        headers = {
            'X-SFDC-Session': access_token,
            'Content-Encoding': 'gzip',
            'Content-Type': 'text/csv; charset=UTF-8'
        }
        log.debug('get_batch_result :: get request data : url=%s and headers=%s'
                  % (url, headers))
        response = requests.get(url, headers=headers)
        csv_response = response.content

        return csv_response

    def close_the_job(self, job_id):
        log.info("close_the_job :: job id = %s" % job_id)
        sf_access_response = self.pre_process_oauth_request()
        instance_url, access_token = sf_access_response['instanceUrl'], sf_access_response['accessToken']
        log.info('close_the_job :: instance_url=%s and access_token=%s' % (instance_url, access_token))

        xml = """<?xml version="1.0" encoding="UTF-8"?>
            <jobInfo xmlns="{0}">
            <state>Closed</state>
            </jobInfo>""".format(self.xmlns)
        url = "{instance_url}/services/async/{api_version}/job/{job_id}".format(
            instance_url=instance_url, api_version=self.api_version, job_id=job_id)
        headers = {
            'X-SFDC-Session': access_token,
            'Content-Type': 'application/xml; charset=UTF-8'
        }
        log.debug('close_the_job :: post request data : url=%s, xml=%s and headers=%s'
                  % (url, xml, headers))
        response = requests.post(url, data=xml, headers=headers)
        xml_response = response.content
        log.debug('close_the_job :: API response=%s', xml_response)

        # return job_id
        tree = ET.fromstring(xml_response)
        job_id = tree.find('.//{%s}id' % self.xmlns)
        # Element objects are considered a False value if they have no children
        # So we need to use specific test instead viz. 'elem is not None' test instead
        # http://stackoverflow.com/questions/20129996/why-does-boolxml-etree-elementtree-element-evaluate-to-false
        if job_id is not None:
            return job_id.text
        raise SFOperationFailure("job was not closed properly")


