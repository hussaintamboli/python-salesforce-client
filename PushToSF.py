#!/usr/bin/python

########PushToSF########
# 1. Using WebService
# 2. Using OAuth
########################

import urllib, urllib2
import ConfigParser
import Logger
from base64 import encode
import hmac, hashlib
import json
from encodings.base64_codec import base64_encode
import binascii
import requests # sudo easy_install requests
from Decrypt import Decrypt

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

	def pushToSFUsingWS(self):
		self.log.info("In pushToSFUsingWS method")
		from sforce.partner import SforcePartnerClient	
	
		self.login = "sf@salesfoce.com"
		self.password = "sf-123"
		self.securityToken = "XXXXXXXXXXX"
		safety = self.config.get('security', 'safety').strip()
                self.log.info("Safety field : %s When safety = on use Decrypt to decode the credentials"%safety)
                if safety == "on":
                        self.login = self.config.get('credentials', 'login')
                        self.password = self.config.get('credentials', 'password')
                        self.securityToken = self.config.get('credentials', 'securityToken')
                        self.log.info("Encrypted -> login : %s, password: %s, securityToken: %s"%(self.login, self.password, self.securityToken))
                        self.dec = Decrypt(self.configFile)
                        self.login = self.dec.decode(self.login)
                        self.password = self.dec.decode(self.password)
                        self.securityToken = self.dec.decode(self.securityToken)
                        self.log.info("Decrypted -> login : %s, password: %s, securityToken: %s"%(self.login, self.password, self.securityToken))

                self.log.info("Actual Credentials -> login : %s, password: %s, securityToken: %s"%(self.login, self.password, self.securityToken))		
		self.client = SforcePartnerClient(self.partnerWSDL)
		loginResponse = self.logIn(self.login, self.password, self.securityToken)
		if loginResponse == self.FAILED:
			return self.FAILED
		response = self.createLeadUsingWS()
		if response == self.FAILED:
			return self.FAILED
		else:
			self.log.info("Operation on lead successful!. %s"%response)		
		leadId = response.id
		response = self.upsertLeadUsingWS(leadId)
		if response == self.FAILED:
			return self.FAILED
		else:
			self.log.info("Operation on lead successful!. %s"%response)		
		logoutResponse = self.logOut()
		if logoutResponse == self.FAILED:
			return self.FAILED

		
	def logIn(self, login, password, securityToken):
		self.log.info("Logging in with credentials, login : %s , password : %s , securityToken : %s"%(login, password, securityToken))
		try:
			loginResult = self.client.login(login, password, securityToken)
		except Exception, e:
			self.log.info("Login Failed! Exception : %s"%str(e))
			return self.FAILED
		self.log.info("Log in successful")
		return self.SUCCESS

	def logOut(self):
		self.log.info("Logging out..")
		try:
			logoutResult = self.client.logout()
		except Exception, e:
			self.log.info("Log out failed! Exception : %s"%str(e))
			return self.FAILED
		self.log.info("Log out successful")
		return self.SUCCESS		

	def createLeadUsingWS(self):
		# Creating new lead
		self.log.info("In createLeadUsingWS method.")
		name = 'Lead'
		try:
			self.lead = self.client.generateObject(name)
			self.lead.FirstName = 'Hussain'
			self.lead.LastName = 'Tamboli'
			self.lead.Company = "Screen-Magic Inc."
			self.lead.Email = 'hussaintamboli@screen-magic.com'
			self.log.info("Creating new %s ..."%name)
			result = self.client.create(self.lead)	
		except Exception, e:
			self.log.info("Lead creation failed! Exception : %s"%str(e))
			return self.FAILED
		return result
	
	def deleteLeadUsingWS(self, leadId):
		self.log.info("In deleteLeadUsingWS method.")
		try:
			self.log.info("Deleting lead with id %s"%leadId)
			result = self.client.delete(leadId)
		except Exception, e:
			self.log.info("Lead deletion failed! Exception : %s"%str(e))
			return self.FAILED
		return result

	def upsertLeadUsingWS(self, leadId):
		# If lead with id present, update
		# else insert
		self.log.info("In upsertLeadUsingWS method")
		try:
			self.lead.Id = leadId
			self.lead.Email = "hussain@screen-magic.com"
			response = self.client.upsert('Id', self.lead)
		except Exception, e:
			self.log.info("Upsert failed! Exception : %s"%str(e))
			return self.FAILED
		return response

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

	# For SF Push using WebService
	response = push.pushToSFUsingWS()
	# For SF Push using OAuth
	#response = push.pushToSFUsingOAuth()
	# print response # 0 : SF push failed and 1 : SF push successful
