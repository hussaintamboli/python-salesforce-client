#!/usr/bin/python

### CRUD Salesforce Objects Using OAuth ###

import urllib, urllib2
import ConfigParser
import Logger
import json
import requests # sudo easy_install requests

class PushToSF:
	
	def __init__(self,configFile=None):
		self.configFile=configFile;
		self.config = ConfigParser.ConfigParser()
		self.config.read(self.configFile)
		self.log = Logger.Logger(self.config)
		self.partnerWSDL = self.config.get('wsdl','partnerWSDL')
	        self.partnersandboxWSDL = self.config.get('wsdl','partnersandboxWSDL')
		self.SUCCESS, self.FAILED = 1, 0
		self.log.info("in Constructor of PushToSF")

	def pushToSFUsingOAuth(self):
		self.log.info("In pushToSFUsingOAuth method")
		self.loginBaseUrl = "https://login.salesforce.com"
		self.consumerKey = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		self.consumerSecret = "XXXXXXXXXXXXX"
		self.redirectURI = "https://redirect-sf.com/redirect/smagicoauth"
		self.refreshToken = "<Put Refresh token here, maybe after fetching from Db.>"		

		# For standard object
		name = "Lead" # You can also put custom object name here
		leadId = "XXXXXXXXXXXXXXXXXXXX" # External Id
		fieldValue = "sucessfulSFPush@screen-magic.com"

		response = self.getNewAccessTokenByRefreshToken(self.refreshToken, self.loginBaseUrl, self.consumerKey, self.consumerSecret, self.redirectURI)
		if response == self.FAILED:
			return response
		tokenRequestData = json.load(response)	
		self.log.info("tokenRequestData : %s"%tokenRequestData)
		if not self.verifySignatureForOAuth(tokenRequestData, self.consumerSecret):
	        	return self.FAILED
		accessToken = tokenRequestData['access_token']
		self.log.info("accessToken : %s"%accessToken)
		instanceUrl = tokenRequestData['instance_url']
		self.log.info("instanceUrl : %s"%instanceUrl)
		packagePrefix = "" # "Your package prefix in case of custom object push"
		externalFieldName = "Id" # "name of the externalId field"
		externalField = leadId
		fieldName = "Email" # "Attribute of that object"
		pushUrl = instanceUrl + "/services/data/v20.0/sobjects/" + packagePrefix + name + "/" + packagePrefix + externalFieldName + "/" + externalField
		self.log.info("Final Url : %s"%pushUrl)
		data = json.dumps({packagePrefix + fieldName : fieldValue})
		self.log.info("Json data to be added to header: %s"%data)
		status = self.pushToSFRequestForOAuth(pushUrl, data, accessToken)
	        if (status == self.FAILED):
        		self.log.info('push to Sf UsingOAuth failed!')
	        else:
            		self.log.info('Record pushed successfully')
        	return status


	def getNewAccessTokenByRefreshToken(self, refreshToken, loginBaseUrl, consumerKey, consumerSecret, redirectURI):
		self.log.info("In getNewAccessTokenByRefreshToken method")
		self.log.info("refreshToken : %s"%refreshToken)
		self.log.info("loginBaseUrl : %s"%loginBaseUrl)
		self.log.info("consumerKey: %s"%consumerKey)
		self.log.info("consumerSecret : %s"%consumerSecret)
		self.log.info("redirectURI : %s"%redirectURI)		

		tokenUrl = loginBaseUrl + '/services/oauth2/token'
		self.log.info("tokenUrl : %s"%tokenUrl)
		postFields = {
                    'grant_type' : 'refresh_token',
                    'client_id' : consumerKey,
                    'client_secret' : consumerSecret,
                    'refresh_token' : refreshToken,
                    'redirect_uri' : redirectURI,
                    'format' : 'json'
                    }
		data = urllib.urlencode(postFields)
	        self.log.info('data :%s'%data)
	        request = urllib2.Request(tokenUrl, data)
		try:
	        	response = urllib2.urlopen(request)	
		except Exception, e:
			self.log.info("Couldn't get the response containing access_token! Exception : %s"%str(e))
			return self.FAILED
		return response

	def verifySignatureForOAuth(self, tokenRequestData, consumerSecret):
		self.log.info('In verifySignatureForOAuth method.')
		if tokenRequestData or not tokenRequestData == '':
		    if not tokenRequestData['signature'] == '':
			receivedSignature = tokenRequestData['signature']
		    if not tokenRequestData['id'] == '':
			receivedId = tokenRequestData['id']
			self.log.info('id :%s'%receivedId)
		    if not tokenRequestData['issued_at'] == '':
			issuedAt = tokenRequestData['issued_at']
			self.log.info('issuedAt :%s'%issuedAt)
		    queryString = receivedId + issuedAt
		    self.log.info('queryString : %s'%queryString)
		    self.log.info('COnsumerSecret : %s'%consumerSecret)
		    hashSignature = hmac.new(consumerSecret,queryString , hashlib.sha256)
		    self.log.info('Hash : %s'%hashSignature)
		    generatedSignature = binascii.b2a_base64(hashSignature.digest())[:-1]
		    self.log.info('generatedSignature : %s'%generatedSignature)
		    self.log.info('receivedSignature : %s'%receivedSignature)
		    if generatedSignature == receivedSignature:
			self.log.info('Generated and received Signature matched')
			return self.SUCCESS
		    else:
			self.log.info('Generated and received Signature did not match')
			return self.FAILED


	def pushToSFRequestForOAuth(self, url, data, accessToken):
		self.log.info("In pushToSFRequestForOAuth")
		headers = {"Authorization" : "OAuth %s"%str(accessToken), "Content-Type" : "application/json"}
		try:
			# You may not have requests module of python by default. Install it first
			patchResponse = requests.patch(url, data, headers=headers)
		except Exception, e:
			self.log.info("Exception in new method pushToSFRequestForOAuth %s"%str(e))
			return self.FAILED
		self.log.info("Patch response : %s"%patchResponse)
		return self.SUCCESS


if __name__ == "__main__":

	configFile = './conf/sfconfig.cnf'
	push = PushToSF(configFile)	

	# For SF Push using OAuth
	response = push.pushToSFUsingOAuth()
	# print response # 0 : SF push failed and 1 : SF push successful
