
Python Code to CRUD Salesforce Objects
--------------------------------------

Looking for a way to CRUD Salesforce Standard and Custom objects using Python?
I'll show you how it's done.

There are two ways to achieve this -  

 1. **Using WebService:**
		For WS, we chose - [salesforce-python-toolkit][1]. This toolkit uses SOAP API to make various operations like create, delete, update, upsert, etc. using WSDL files provided by Salesforce. You can see for all the possible operations on SF objects in those wsdl files. Calling a webservice with SOAP will need the actual credentials.  
		You will need username, password and security token in plaintext to login to the API. But we didn't have them in plaintext format. They were encrypted using CI's Encrypt library. We wrote a module - Decrypt for doing that.
		

 2. **Using OAuth:**
                 They had explained things really well [here][2]. But the API was in Java. We started searching for a python API for for Salesforce objects. There was none. In fact I think nobody had written it using python. So instead of searching more, we wrote a module of our own. 

**OAuth** : For a Salesforce's client application to access user information, the user has to authorize that application to use its information. When user authorizes the application a refreshToken is sent to the application. This application then can access and modify user's information using this refreshToken, it doesn't need user's login and password. 

  [1]: http://code.google.com/p/salesforce-python-toolkit/ 
  [2]: http://www.salesforce.com/us/developer/docs/api_rest/api_rest.pdf 
