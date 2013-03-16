
PushToSF
========

When we were writing our DeliveryReports engine, we specifically chose python because it was suitable for our need to run background jobs. Our goal was to perform vario
us operations on Salesforce's standard and custom objects.

There are two ways to achieve this -> i. Using WebService and ii. Using OAuth.
For WS, we chose - salesforce-python-toolkit (http://code.google.com/p/salesforce-python-toolkit/) .

Unfortunately the same API didn't support OAuth access. So we started searching for a python API for Salesforce's OAuth access. There was none. In fact I think nobody had written it using python. They had explained things really well in - http://www.salesforce.com/us/developer/docs/api_rest/api_rest.pdf . So instead of searching more, we wrote a module of our own.
