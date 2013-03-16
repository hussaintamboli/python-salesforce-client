import hashlib
import base64
import Logger
import ConfigParser
import mcrypt # Downloaded from https://pypi.python.org/pypi/python-mcrypt 
# or http://labix.org/python-mcrypt.
# If the installation gives error - "mycrypt.h file not found" then
# Install libmcrypt or  libmcrypt-dev . See the document in python help(mcrypt)

class Decrypt:

	def __init__(self, configFile = None):
                self.configFile = configFile
                if self.configFile != None:
                        self.config = ConfigParser.ConfigParser()
                        self.config.read(self.configFile)
                        self.log = Logger.Logger(self.config)
                else:
                        self.log = Logger.Logger()
		self.SUCCESS, self.FAILED = True, False
		self.KEY_SIZE = 32
		self.BLOCK_SIZE = 32
		self.log.info("In Constructor of Decrypt")

	def getKey(self, key):
		self.log.info("In getKey method with key : %s"%key)
		md5Key = hashlib.md5()
		md5Key.update(key)
		return md5Key.hexdigest()

	def getBase64Decode(self, encString):
		self.log.info("In getBase64Decode.")
		b64DecString = base64.b64decode(encString)
		return b64DecString

	def xorDecode(self, string, key):
		self.log.info("In xorDecode method with string : %s and key : %s"%(string, key))
		mString = self.xorMerge(string, key)
		if mString == self.FAILED:
			self.log.info("xorMerge Failed!")
			return self.FAILED
		self.log.info("xor Merge returned %s"%mString)
		dec = ''
		i = 0
		while i < len(mString):
			try:
				dec += chr(ord(mString[i+1:i+2]) ^ ord(mString[i:i+1]))
				i += 2
			except Exception, e:
				self.log.info("exception %s"%str(e))
				return self.FAILED
		return dec

	def xorMerge(self, string, key):
		self.log.info("In xorMerge method. with string : %s and key : %s"%(string, key))
		hashString = self.hashMethod(key)
		if hashString == self.FAILED:
			self.log.info("hasMethod failed!")
			return self.FAILED
		self.log.info("hash method retured : %s"%hashString)
		xored = ''
		i = 0
		while i < len(string):
			j = i % len(hashString)
			xored += chr(ord(string[i:i+1]) ^ ord(hashString[j:j+1]))
			i += 1
		return xored

	def hashMethod(self, key):
		self.log.info("In hash method with key : %s"%key)
		hashStr = ''
		try:
			hashStr = hashlib.sha1(key).hexdigest()
		except Exception, e:
			self.log.info("Exception in sha1 %s"%str(e))
			return self.FAILED
		return hashStr

	def removeCipherNoise(self, string, key):
		self.log.info("In removeCipherNoise. with string : %s and key : %s"%(string, key))
		keyHash = self.hashMethod(key)
		keylen = len(keyHash)
		stri = ''
		i, j = 0, 0
		length = len(string)
		while i < length:
			if j >= keylen:
				j = 0
			temp = ord(string[i]) - ord(keyHash[j])
			if temp < 0:
				temp = temp + 256
			stri += chr(temp)
			i += 1
			j += 1
		return stri

	def mcryptDecode(self, string, key):
		self.log.info("In mcryptDecode with key : %s and string : %s"%(key, string))
		string = self.removeCipherNoise(string, key)
		self.log.info("Returned after removing cipher noise : %s"%string)
		initSize = 32
		initVect = string[0:initSize]
		string = string[initSize:]
		decoded = self.mcryptDecryption(key, initVect, string)
		if decoded == self.FAILED:
			return self.FAILED	
		return decoded
		
	def decode(self, string):
		self.log.info("In decode method. Decoding string : %s"%string)
		securitySection = "security"
		keyItem = "key"
		key = self.config.get(securitySection, keyItem)		
		if not key:
			self.log.info("Key Invalid")
			return 	self.FAILED
		key = self.getKey(key)
		self.log.info("Encrypted key : %s"%key)
		dec = self.getBase64Decode(string)
		self.log.info("b64decoded string : %s"%dec)
		if True:
			decoded = self.mcryptDecode(dec, key)
			if decoded == self.FAILED:
				self.log.info("Decoding failed!")
				return self.FAILED
			self.log.info("mcryptDecode returned %s"%decoded)
		else:
			xorDec = self.xorDecode(dec, key)
			if xorDec == self.FAILED:
				self.log.info("Decoding failed!")
				return self.FAILED
			self.log.info("Decoded string: %s"%xorDec)
			decoded = xorDec
		# Just make sure you remove the trailing \x00
		decoded = decoded.rstrip('\x00')
		return decoded

	def mcryptDecryption(self, key, iv, data):
		self.log.info("In mcryptDecryption.")
		try:
			m = mcrypt.MCRYPT('rijndael-256', 'cbc')	
			m.init(key, iv)
			decrypted = m.decrypt(data)
		except Exception, e:
			self.log.info("Exception in mcryptDecryption : %s"%str(e))
			return self.FAILED
		return decrypted



if __name__ == "__main__":
	configFile = "./conf/sfconfig.cnf"
	string = "PASTE YOUR ENCRYPTED CREDENTIAL HERE"
	dec = Decrypt(configFile)
	print repr(dec.decode(string))
