import os

from webtest import TestApp

from oauth_provider.models import Resource, Consumer, Token
from oauth_provider.oauth_request import application 


app = TestApp(application())
   
CONSUMER_KEY = 'dpf43f3p2l4k3l03'
CONSUMER_SECRET = 'kd94hf93k423kf44'

def setup():
    
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
    

def test_oauth1_0():
    
    #TODO - not able to handle /request_token/ - returns 404
    response = app.get('/request_token',status=401)
    assert response.status == '401 Invalid request parameters.'
    assert response.headers['WWW-Authenticate'] == 'OAuth realm="http://events.example.net/"'
    assert response.body == 'Invalid request parameters.'
    
    import time
    
    parameters = {
        'oauth_consumer_key': CONSUMER_KEY,
        'oauth_signature_method': 'PLAINTEXT',
        'oauth_signature': '%s&' % CONSUMER_SECRET,
        'oauth_timestamp': str(int(time.time())),
        'oauth_nonce': 'requestnonce',
        'oauth_version': '1.0',
        'scope': 'default', # custom argument to specify Protected Resource
    }
    
    response = app.post('/request_token',parameters)    
    assert response.status == '200 OK'
    
    token = Token.all().fetch(1000)[0]
    assert 'oauth_token_secret=%s&oauth_token=%s'%(token.secret,token.key_) == response.body
        
    #the scope related tests are not here as they the scope
    #function has not been implemented yet
    #>> parameters['scope'] = 'videos'
    #>>> response = c.get("/oauth/request_token/", parameters)
    #>>> response.status_code
    #401
    #>>> response.content
    #'Resource videos does not exist.'
    
    parameters = {
        'oauth_token' : token.key_,
        'oauth_callback' : 'http://test.com/request_token_ready'
    }
    
    response = app.post('/authorize', parameters)
    assert response.status == '302 Moved Temporarily'
    #assert response.location == "http://localhost/_ah/login?continue=http%3A//localhost/authorize%3Fcallback%3Dhttp%3A//test.com/request_token_ready"


