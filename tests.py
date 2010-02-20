import os
from nose.tools import with_setup
from webtest import TestApp

from oauth_provider.models import Resource, Consumer, Token, Nonce
from oauth_provider.oauth_request import application 

from oauth_provider.oauth import OAuthRequest, OAuthSignatureMethod_HMAC_SHA1, OAuthToken, OAuthConsumer


app = TestApp(application())
   
CONSUMER_KEY = 'dpf43f3p2l4k3l03'
CONSUMER_SECRET = 'kd94hf93k423kf44'

def setup_func():
    
    #from http://code.google.com/p/nose-gae/issues/detail?id=13
    os.environ['SERVER_NAME'] = 'localhost'
    os.environ['SERVER_PORT'] = '8080'
    os.environ['AUTH_DOMAIN'] = 'example.org'
    os.environ['USER_EMAIL'] = ''
    os.environ['USER_ID'] = ''
    
    
    resource = Resource(name='default', url='/oauth/photo/')
    resource.put()
    
    consumer = Consumer(key_=CONSUMER_KEY, secret=CONSUMER_SECRET, name='printer.example.com')
    consumer.put()
    
def teardown_func():
    [[obj.delete() for obj in class_name.all().fetch(1000)] for class_name in (Token,Resource,Consumer,Nonce)]

    
@with_setup(setup_func, teardown_func)
def test_oauth1_0():
    """
    Test to veriy OAuth 1.0 flow
    """

    """
    After Jane informs printer.example.com that she would like to print her 
    vacation photo stored at photos.example.net, the printer website tries to 
    access the photo and receives HTTP 401 Unauthorized indicating it is private. 
    The Service Provider includes the following header with the response::
    """
    
    #TODO - not able to handle /request_token/ - returns 404
    #TODO - add test for reuse of nonce for the request token stage?
    #TODO - add test for oauth params in Authorization, GET and POST
    response = app.get('/request_token',status=401)
    assert response.status == '401 Invalid request parameters.'
    assert response.headers['WWW-Authenticate'] == 'OAuth realm="http://events.example.net/"'
    assert response.body == 'Invalid request parameters.'
    
    """
    The Consumer sends the following HTTP POST request to the Service Provider::
    """
    import time
    parameters = {
        'oauth_consumer_key': CONSUMER_KEY,
        'oauth_signature_method': 'PLAINTEXT',
        'oauth_signature': '%s&' % CONSUMER_SECRET,
        'oauth_timestamp': str(int(time.time())),
        'oauth_nonce': 'requestnonce',
        'oauth_version': '1.0',
        #'scope': 'default', # custom argument to specify Protected Resource
    }
    
    response = app.post('/request_token',parameters) 
    
    """
    The Service Provider checks the signature and replies with an unauthorized 
    Request Token in the body of the HTTP response::
    """
    assert response.status == '200 OK'
    
    tokens = Token.all().fetch(1000)
    #double checking the sanity of the test - there should only be one token in 
    #the store at this stage
    
    assert len(tokens) == 1
    token = tokens[0]
    assert 'oauth_token_secret=%s&oauth_token=%s'%(token.secret,token.key_) == response.body
    
    #Ensure that the token returned is unauthorized request token
    assert token.is_approved == False
    assert token.token_type == Token.REQUEST
    
    """
    If you try to access a resource with a wrong scope, it will return an error::
    """

    #the scope related tests are not here as they the scope
    #function has not been implemented yet
    #>> parameters['scope'] = 'videos'
    #>>> response = c.get("/oauth/request_token/", parameters)
    #>>> response.status_code
    #401
    #>>> response.content
    #'Resource videos does not exist.'
    
    
    """
    Requesting User Authorization
    -----------------------------
    
    The Consumer redirects Jane's browser to the Service Provider User 
    Authorization URL to obtain Jane's approval for accessing her private photos.
    
    The Service Provider asks Jane to sign-in using her username and password::
    
    """
    parameters = {
        'oauth_token' : token.key_,
        'oauth_callback' : 'http://test.com/request_token_ready'
    }
    
    response = app.post('/authorize', parameters)
    assert response.status == '302 Moved Temporarily'
    assert response.location ==\
'http://localhost/_ah/login?continue=http%%3A//localhost/authorize%%3Foauth_token%%3D%s%%26oauth_callback%%3Dhttp%%3A//test.com/request_token_ready'%(token.key_)

    #the token details should not be altered by this call
    tokens = Token.all().fetch(1000)
    assert len(tokens) == 1
    token = tokens[0]
    
    assert token.is_approved == False
    assert token.token_type == Token.REQUEST
    
    #In reality the user would of been redirected to the Google login page and 
    #then redirected to the authorization url. We simulate the user being logged
    #in and redirect manually to the authorization page
    
    #simulate logged in 
    os.environ['USER_EMAIL'] = 'mohan@test.com'
    
    response = app.post('/authorize', parameters)
    
    #verify that the request token is now approved
    tokens = Token.all().fetch(1000)
    assert len(tokens) == 1
    token = tokens[0]
    
    assert token.is_approved == True
    assert token.token_type == Token.REQUEST
    
    #verify the response - now that we are approved we should get 
    assert response.status == '302 Moved Temporarily'
    assert response.location == 'http://test.com/request_token_ready?oauth_token=%s'%(token.key_)
    
    #TODO add test for case where the user rejects the approval, 
    #now the flow assumes that it will always be approved upon logging in
    
    """
    Obtaining an Access Token
    -------------------------
    
    Now that the Consumer knows Jane approved the Request Token, it asks the 
    Service Provider to exchange it for an Access Token::
    """
    
    parameters = {
         'oauth_consumer_key': CONSUMER_KEY,
         'oauth_token': token.key_,
         'oauth_signature_method': 'PLAINTEXT',
         'oauth_signature': '%s&%s' % (CONSUMER_SECRET, token.secret),
         'oauth_timestamp': str(int(time.time())),
         'oauth_nonce': 'accessnonce',
         'oauth_version': '1.0',
    }
    response = app.post("/access_token", parameters)
    
    """
    The Service Provider checks the signature and replies with an Access Token in 
    the body of the HTTP response::
    """
    
    response.status == '200 OK'
    #verify the access token now 
    
    access_tokens = Token.all()\
        .filter('token_type =',Token.ACCESS).fetch(1000)
    #double checking the sanity of the test - there should only be one token in 
    #the store at this stage
    
    assert len(access_tokens) == 1
    access_token = access_tokens[0]
    assert 'oauth_token_secret=%s&oauth_token=%s'%(access_token.secret,access_token.key_) == response.body

    assert str(access_token.user) == 'mohan@test.com'
    
    """
    The Consumer will not be able to request another Access Token with the same
    Nonce::
    """
    
    nonces = Nonce.all().fetch(1000)
    assert nonces[0].key_ == "accessnonce"
    
    response = app.post("/access_token", parameters,status=401)
    
    assert response.status == '401 Nonce already used: accessnonce'
    assert response.body == 'Nonce already used: accessnonce'
    
    """
    The Consumer will not be able to request an Access Token if the token is not
    approved::
    """
    
    token.is_approved = False
    token.put()
    
    parameters['oauth_nonce'] = 'anotheraccessnonce'
    response = app.post("/access_token", parameters,status=401)
    response.status == "401 Consumer key or token key does not match. Make sure your request token is approved. Check your verifier too if you use OAuth 1.0a."
    response.body == 'Consumer key or token key does not match. Make sure your request token is approved. Check your verifier too if you use OAuth 1.0a.'
    
    """
    Accessing Protected Resources
    -----------------------------
    
    The Consumer is now ready to request the private photo. Since the photo URL is 
    not secure (HTTP), it must use HMAC-SHA1.
    
    Generating Signature Base String
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    To generate the signature, it first needs to generate the Signature Base 
    String. The request contains the following parameters (oauth_signature 
    excluded) which are ordered and concatenated into a normalized string::
    """
    
    parameters = {
         'oauth_consumer_key': CONSUMER_KEY,
         'oauth_token': access_token.key_,
         'oauth_signature_method': 'HMAC-SHA1',
         'oauth_timestamp': str(int(time.time())),
         'oauth_nonce': 'accessresourcenonce',
         'oauth_version': '1.0',
    }
    
    """
    Calculating Signature Value
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    HMAC-SHA1 produces the following digest value as a base64-encoded string 
    (using the Signature Base String as text and kd94hf93k423kf44&pfkkdhi9sl3r4s00 
    as key)::
    """
    
    consumer = Consumer.all().fetch(1000)[0]
    
    #we dont use the OAuthRequest.from_token_and_callback function as how the 
    #original method does as it does a token.key instead of token.key_
    
    oauth_request = OAuthRequest('POST','http://localhost/protected',parameters)
    signature_method = OAuthSignatureMethod_HMAC_SHA1()
    signature = signature_method.build_signature(oauth_request, consumer, 
                                                         access_token)
    

    
    """
    Requesting Protected Resource
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    All together, the Consumer request for the photo is::
    """

    parameters['oauth_signature'] = signature
    response = app.post("/protected", parameters)
    
    assert response.status == '200 OK'
    assert response.body == 'Protected Resource access!'
    
    """
    Otherwise, an explicit error will be raised::
    """
    
    parameters['oauth_signature'] = 'wrongsignature'
    parameters['oauth_nonce'] = 'anotheraccessresourcenonce'
    response = app.post("/protected", parameters,status=401)

    assert '401 Invalid signature. Expected signature base string: POST' in response.status 
    assert 'Invalid signature. Expected signature base string: POST' in response.body

    response = app.post("/protected",status=401)

    #TODO - why are we getting "Invalid OAuth parameters instead of Invalid request parameters"
    assert response.status == '401 Invalid OAuth parameters'
    assert response.headers['WWW-Authenticate'] == 'OAuth realm="http://events.example.net/"'
    assert response.body == 'Invalid OAuth parameters'
    
    """
    Revoking Access
    ---------------
    
    If Jane deletes the Access Token of printer.example.com, the Consumer will not 
    be able to access the Protected Resource anymore::
    """
    access_token_key = access_token.key_
    access_token.delete()
    parameters['oauth_nonce'] = 'yetanotheraccessresourcenonce'
    
    oauth_request = OAuthRequest('POST','http://localhost/protected',parameters)
    signature_method = OAuthSignatureMethod_HMAC_SHA1()
    signature = signature_method.build_signature(oauth_request, consumer, 
                                                         access_token)
    
    parameters['oauth_signature'] = signature

    
    response = app.post("/protected", parameters,status=401)

    assert response.status == '401 Invalid access token: %s'%(access_token_key)
    assert response.body == 'Invalid access token: %s'%(access_token_key)

    """
    Clean up
    --------

    Remove created models' instances to be able to launch 1.0a tests just below::
    """
    #handled by teardown_func
   
@with_setup(setup_func, teardown_func)
def test_oauth1_0a():
    """
    Test to veriy OAuth 1.0a flow
    """

    """
    After Jane informs printer.example.com that she would like to print her 
    vacation photo stored at photos.example.net, the printer website tries to 
    access the photo and receives HTTP 401 Unauthorized indicating it is private. 
    The Service Provider includes the following header with the response::
    """
    
    #TODO - not able to handle /request_token/ - returns 404
    #TODO - add test for reuse of nonce for the request token stage?
    #TODO - add test for oauth params in Authorization, GET and POST
    response = app.get('/request_token',status=401)
    assert response.status == '401 Invalid request parameters.'
    assert response.headers['WWW-Authenticate'] == 'OAuth realm="http://events.example.net/"'
    assert response.body == 'Invalid request parameters.'
    
    """
    The Consumer sends the following HTTP POST request to the Service Provider::
    """
    import time
    parameters = {
        'oauth_consumer_key': CONSUMER_KEY,
        'oauth_signature_method': 'PLAINTEXT',
        'oauth_signature': '%s&' % CONSUMER_SECRET,
        'oauth_timestamp': str(int(time.time())),
        'oauth_nonce': 'requestnonce',
        'oauth_version': '1.0',
        'oauth_callback' : 'http://test.com/request_token_ready',
        #'scope': 'default', # custom argument to specify Protected Resource
    }
    
    response = app.post('/request_token',parameters) 
    
    """
    The Service Provider checks the signature and replies with an unauthorized 
    Request Token in the body of the HTTP response::
    """
    assert response.status == '200 OK'
    
    tokens = Token.all().fetch(1000)
    #double checking the sanity of the test - there should only be one token in 
    #the store at this stage
    
    assert len(tokens) == 1
    token = tokens[0]
    assert 'oauth_token_secret=%s&oauth_token=%s&oauth_callback_confirmed=true'%(token.secret,token.key_) == response.body
    
    #Ensure that the token returned is unauthorized request token
    assert token.is_approved == False
    assert token.token_type == Token.REQUEST
    assert token.callback == 'http://test.com/request_token_ready'
    assert token. callback_confirmed == True
    
    """
    If you try to access a resource with a wrong scope, it will return an error::
    """
    #Not implemented yet
    #>>> parameters['scope'] = 'videos'
    #>>> response = c.get("/oauth/request_token/", parameters)
    #>>> response.status_code
    #401
    #>>> response.content
    #'Resource videos does not exist.'
    #>>> parameters['scope'] = 'photos' # restore
    """
    If you try to put a wrong callback, it will return an error::
    """
    parameters['oauth_callback'] = 'wrongcallback'
    response = app.post("/request_token", parameters,status=401)
    assert response.status == '401 Invalid callback URL.'
    assert response.body == 'Invalid callback URL.'
    
      
    """
    Requesting User Authorization
    -----------------------------
    
    The Consumer redirects Jane's browser to the Service Provider User 
    Authorization URL to obtain Jane's approval for accessing her private photos.
    
    The Service Provider asks Jane to sign-in using her username and password::
    
    """
    parameters = {
        'oauth_token' : token.key_,
    }
    
    
    response = app.post('/authorize', parameters)
    assert response.status == '302 Moved Temporarily'
    assert response.location ==\
'http://localhost/_ah/login?continue=http%%3A//localhost/authorize%%3Foauth_token%%3D%s'%(token.key_)

    #the token details should not be altered by this call
    tokens = Token.all().fetch(1000)
    assert len(tokens) == 1
    token = tokens[0]
    
    assert token.is_approved == False
    assert token.token_type == Token.REQUEST
    
    #In reality the user would of been redirected to the Google login page and 
    #then redirected to the authorization url. We simulate the user being logged
    #in and redirect manually to the authorization page
    
    #simulate logged in 
    os.environ['USER_EMAIL'] = 'mohan@test.com'
    
    response = app.post('/authorize', parameters)

    #verify that the request token is now approved
    tokens = Token.all().fetch(1000)
    assert len(tokens) == 1
    token = tokens[0]
    
    assert token.is_approved == True
    assert token.token_type == Token.REQUEST
    
    #verify the response - now that we are approved we should get 
    assert response.status == '302 Moved Temporarily'
    assert response.location == 'http://test.com/request_token_ready?oauth_verifier=%s&oauth_token=%s'%(token.verifier,token.key_)
    
    #TODO add test for case where the user rejects the approval, 
    #now the flow assumes that it will always be approved upon logging in
    
    """
    With OAuth 1.0a, the callback argument can be set to "oob" (out-of-band), 
    you can specify your own default callback view with the
    ``OAUTH_CALLBACK_VIEW`` setting::
    """
    from oauth_provider.consts import OUT_OF_BAND
    token.callback = OUT_OF_BAND
    token.put()

    parameters = {
        'oauth_token': token.key_,
    }
    response = app.post('/authorize', parameters)
    response.status == '200 OK'
    response.body == 'Successfully authorised : oauth_verifier=%s&oauth_token=%s'%(token.verifier,token.key_)

    #reload the token as the last post to /authorize would of generated a new verifer
    tokens = Token.all().fetch(1000)
    assert len(tokens) == 1
    token = tokens[0]
    
    """
    Obtaining an Access Token
    -------------------------
    
    Now that the Consumer knows Jane approved the Request Token, it asks the 
    Service Provider to exchange it for an Access Token::
    """

    parameters = {
         'oauth_consumer_key': CONSUMER_KEY,
         'oauth_token': token.key_,
         'oauth_signature_method': 'PLAINTEXT',
         'oauth_signature': '%s&%s' % (CONSUMER_SECRET, token.secret),
         'oauth_timestamp': str(int(time.time())),
         'oauth_nonce': 'accessnonce',
         'oauth_version': '1.0',
         'oauth_verifier': token.verifier,
    }
    response = app.post("/access_token", parameters)
    
    """
    The Service Provider checks the signature and replies with an Access Token in 
    the body of the HTTP response::
    """
    
    response.status == '200 OK'
    #verify the access token now 
    
    access_tokens = Token.all()\
        .filter('token_type =',Token.ACCESS).fetch(1000)
    #double checking the sanity of the test - there should only be one token in 
    #the store at this stage
    
    assert len(access_tokens) == 1
    access_token = access_tokens[0]
    assert 'oauth_token_secret=%s&oauth_token=%s'%(access_token.secret,access_token.key_) == response.body

    assert str(access_token.user) == 'mohan@test.com'
    
    """
    The Consumer will not be able to request another Access Token with the same
    Nonce::
    """
    
    nonces = Nonce.all().fetch(1000)
    assert nonces[0].key_ == "accessnonce"
    
    response = app.post("/access_token", parameters,status=401)
    
    assert response.status == '401 Nonce already used: accessnonce'
    assert response.body == 'Nonce already used: accessnonce'
    
    """
    Nor with a missing/invalid verifier::
    """
    parameters['oauth_nonce'] = 'yetanotheraccessnonce'
    parameters['oauth_verifier'] = 'invalidverifier'
    
    response = app.post("/access_token", parameters,status=401)
    response.status == '401 Consumer key or token key does not match. Make sure your request token is approved. Check your verifier too if you use OAuth 1.0a.'
    response.body ==\
    'Consumer key or token key does not match. Make sure your request token is approved. Check your verifier too if you use OAuth 1.0a.'
    parameters['oauth_verifier'] = token.verifier 
    
    """
    The Consumer will not be able to request an Access Token if the token is not
    approved::
    """
    
    token.is_approved = False
    token.put()
    
    parameters['oauth_nonce'] = 'anotheraccessnonce'
    response = app.post("/access_token", parameters,status=401)
    response.status == "401 Consumer key or token key does not match. Make sure your request token is approved. Check your verifier too if you use OAuth 1.0a."
    response.body == 'Consumer key or token key does not match. Make sure your request token is approved. Check your verifier too if you use OAuth 1.0a.'
    
    """
    Accessing Protected Resources
    -----------------------------
    
    The Consumer is now ready to request the private photo. Since the photo URL is 
    not secure (HTTP), it must use HMAC-SHA1.
    
    Generating Signature Base String
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    To generate the signature, it first needs to generate the Signature Base 
    String. The request contains the following parameters (oauth_signature 
    excluded) which are ordered and concatenated into a normalized string::
    """
    
    parameters = {
         'oauth_consumer_key': CONSUMER_KEY,
         'oauth_token': access_token.key_,
         'oauth_signature_method': 'HMAC-SHA1',
         'oauth_timestamp': str(int(time.time())),
         'oauth_nonce': 'accessresourcenonce',
         'oauth_version': '1.0',
    }
    
    """
    Calculating Signature Value
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    HMAC-SHA1 produces the following digest value as a base64-encoded string 
    (using the Signature Base String as text and kd94hf93k423kf44&pfkkdhi9sl3r4s00 
    as key)::
    """
    
    consumer = Consumer.all().fetch(1000)[0]
    
    #we dont use the OAuthRequest.from_token_and_callback function as how the 
    #original method does as it does a token.key instead of token.key_
    
    oauth_request = OAuthRequest('POST','http://localhost/protected',parameters)
    signature_method = OAuthSignatureMethod_HMAC_SHA1()
    signature = signature_method.build_signature(oauth_request, consumer, 
                                                         access_token)
    

    
    """
    Requesting Protected Resource
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    All together, the Consumer request for the photo is::
    """

    parameters['oauth_signature'] = signature
    response = app.post("/protected", parameters)
    
    assert response.status == '200 OK'
    assert response.body == 'Protected Resource access!'
    
    """
    Otherwise, an explicit error will be raised::
    """
    
    parameters['oauth_signature'] = 'wrongsignature'
    parameters['oauth_nonce'] = 'anotheraccessresourcenonce'
    response = app.post("/protected", parameters,status=401)

    assert '401 Invalid signature. Expected signature base string: POST' in response.status 
    assert 'Invalid signature. Expected signature base string: POST' in response.body

    response = app.post("/protected",status=401)

    #TODO - why are we getting "Invalid OAuth parameters instead of Invalid request parameters"
    assert response.status == '401 Invalid OAuth parameters'
    assert response.headers['WWW-Authenticate'] == 'OAuth realm="http://events.example.net/"'
    assert response.body == 'Invalid OAuth parameters'
    
    """
    Revoking Access
    ---------------
    
    If Jane deletes the Access Token of printer.example.com, the Consumer will not 
    be able to access the Protected Resource anymore::
    """
    access_token_key = access_token.key_
    access_token.delete()
    parameters['oauth_nonce'] = 'yetanotheraccessresourcenonce'
    
    oauth_request = OAuthRequest('POST','http://localhost/protected',parameters)
    signature_method = OAuthSignatureMethod_HMAC_SHA1()
    signature = signature_method.build_signature(oauth_request, consumer, 
                                                         access_token)
    
    parameters['oauth_signature'] = signature

    
    response = app.post("/protected", parameters,status=401)

    assert response.status == '401 Invalid access token: %s'%(access_token_key)
    assert response.body == 'Invalid access token: %s'%(access_token_key)

    
