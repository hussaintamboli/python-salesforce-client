#!/usr/bin/python

### CRUD Salesforce Objects Using SOAP API ###

import ConfigParser
import Logger
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
	
		self.login = self.config.get('credentials', 'login')
		self.password = self.config.get('credentials', 'password')
		self.securityToken = self.config.get('credentials', 'securityToken')
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


if __name__ == "__main__":

	configFile = './conf/sfconfig.cnf'
	push = PushToSF(configFile)	

	# For SF Push using WebService
	response = push.pushToSFUsingWS()
	# For SF Push using OAuth
	#response = push.pushToSFUsingOAuth()
	# print response # 0 : SF push failed and 1 : SF push successful
