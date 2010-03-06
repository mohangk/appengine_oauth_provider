# Overview

This code is based on the [django-oauth](http://code.welldev.org/django-oauth) plugin. I have tried to maintain most of the code structure, replacing the django specific code with the equivalent in GAE.  

# Usage 

1. Copy the oauth_provider dir into your GAE application folder.
2. Modify the configuration values within the config.py file that is in the oauth_provider folder.
3. Add the oauth_request.RequestTokenHandler, oauth_request.AccessTokenHandler and oauth_request.AuthorizeHandler to your apllications url mappings.

For e.g.:

    import oauth_request

    url_mappings = [
        ('/request_token',oauth_request.RequestTokenHandler),
	('/access_token', oauth_request.AccessTokenHandler),
	('/authorize', oauth_request.AuthorizeHandler),    
	('/api/test/?', ApiHandler)
    ]
  
4. Protect the relevant webapp.RequestHandler methods by applying the oauth_required decorator

For e.g: 

    from oauth_provider.decorators import oauth_required

    class ApiHandler(webapp.RequestHandler):
        @oauth_required  
	def get(self,user):
	    self.response.out.write("hello world!")
	    return
 
Checkout the example GAE application in the example folder for a clearer explanation.

# Tests

The tests are within the tests.py module in the root folder and have the following dependencies - nosetests, nose-gae and webtest installed
To run the tests, from within the root folder do the following

<code>nosetests --with-gae --gae-application=./example/ tests.py 
</code>

Please note that these tests don't seem to run on the 1.3.1 SDK as of yet, it runs fine on SDK 1.3.0. From what I can tell SDK 1.3.1 breaks compatibility with nose-gae. It is possible to make nose-gae run with an older version by using the --gae-lib-root flag.

