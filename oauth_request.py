#!/usr/bin/env python
#
# The verifier is returned after verifying and is  
# passed back when retrieving the access tokens
#
import logging

from google.appengine.ext.webapp import RequestHandler
from google.appengine.api import users

import oauth

from stores import GAEOAuthDataStore,check_valid_callback

REQUEST_TOKEN_URL = '/request_token'
ACCESS_TOKEN_URL = '/access_token'
AUTHORIZATION_URL = '/authorize'
CALLBACK_URL = '/request_token_ready'
RESOURCE_URL = '/protected_resource'

#to be moved to settings 
OAUTH_BLACKLISTED_HOSTNAMES = []
OAUTH_REALM_KEY_NAME = 'http://events.example.net/'
OAUTH_SIGNATURE_METHODS = ['plaintext', 'hmac-sha1']


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

def set_trace():
  import pdb, sys
  warningger = pdb.Pdb(stdin=sys.__stdin__,
      stdout=sys.__stdout__)
  warningger.set_trace(sys._getframe().f_back)

def initialize_server_request(request):
    """Shortcut for initialization."""
    # Django converts Authorization header in HTTP_AUTHORIZATION
    # Warning: it doesn't happen in tests but it's useful, do not remove!
    auth_header = {}
    if 'Authorization' in request.headers:
        auth_header = {'Authorization': request.headers['Authorization']}
    #no needed for GAE
    #elif 'HTTP_AUTHORIZATION' in request.META:
    #    auth_header =  {'Authorization': request.META['HTTP_AUTHORIZATION']}

    parameters = dict([(argument_name,request.get(argument_name)) for argument_name in request.arguments()])
    #parameters = dict(request.REQUEST.items())
    oauth_request = oauth.OAuthRequest.from_request(request.method, 
                                              request.url, 
                                              headers=request.headers,
                                              parameters=parameters,
                                              query_string=request.query_string)
    if oauth_request:
        oauth_server = oauth.OAuthServer(GAEOAuthDataStore(oauth_request))

        if 'plaintext' in OAUTH_SIGNATURE_METHODS:
            oauth_server.add_signature_method(oauth.OAuthSignatureMethod_PLAINTEXT())
        if 'hmac-sha1' in OAUTH_SIGNATURE_METHODS:
            oauth_server.add_signature_method(oauth.OAuthSignatureMethod_HMAC_SHA1())
    else:
        oauth_server = None
    return oauth_server, oauth_request


def send_oauth_error(err=None):
    """Shortcut for sending an error."""
    # send a 401 error
    response = HttpResponse(err.message.encode('utf-8'), mimetype="text/plain")
    response.status_code = 401
    # return the authenticate header
    header = build_authenticate_header(realm=OAUTH_REALM_KEY_NAME)
    for k, v in header.iteritems():
        response[k] = v
    return response


class OAuthRequestHandler(RequestHandler):
    """HTTP request handler with OAuth support."""
    
    # example way to send an oauth error
    def send_oauth_error(self, err=None):
        # send a 401 error
        self.response.clear()
        self.response.set_status(401, str(err.message))
        # return the authenticate header
        header = oauth.build_authenticate_header(realm=OAUTH_REALM_KEY_NAME)
        for k, v in header.iteritems():
            self.response.headers.add_header(k, v)
        return

    def get(self, *args):
        logger.warning("!!!START REQUEST!!!")
        """Handler method for OAuth GET requests."""   
        logger.warning("!!!Req URL: %s"%self.request.url)
     
        if self.request.path.startswith(REQUEST_TOKEN_URL):
            logger.warning("!!!Entering REQUEST_TOKEN_URL")
            
            oauth_server, oauth_request = initialize_server_request(self.request)
            if oauth_server is None:
                return self.send_oauth_error(oauth.OAuthError(('Invalid request parameters.')))
            else:
                logger.warning("!!!OAuth Params: %s"%oauth_request.parameters)
                
            try:
                # create a request token
                token = oauth_server.fetch_request_token(oauth_request)
                # return the token
                #response = HttpResponse(token.to_string(), mimetype="text/plain")
                self.response.set_status(200, 'OK')
                self.response.out.write(token.to_string())
            except oauth.OAuthError, err:
                logger.exception("Error when trying to do a request_token")
                self.send_oauth_error(err)
            logger.warning("!!!End request")
            return 


        # user authorization
        if self.request.path.startswith(AUTHORIZATION_URL):
            logger.warning("!!!Entering AUTHORIZATION_URL")
            # get the request token
            oauth_server, oauth_request = initialize_server_request(self.request)
            if oauth_server is None:
                return self.send_oauth_error(oauth.OAuthError(('Invalid request parameters.')))
            else:
                logger.warning("!!!OAuth Params: %s"%oauth_request.parameters)
            try:
                # get the request token
                token = oauth_server.fetch_request_token(oauth_request)
            except oauth.OAuthError, err:
                logger.exception("Failed accessing request token")
                return self.send_oauth_error((err))
            try:
                # get the request callback, though there might not be one if this is OAuth 1.0a
                callback = oauth_server.get_callback(oauth_request)
                
                # OAuth 1.0a: this parameter should not be present on this version
                if token.callback_confirmed:
                    return self.send_oauth_error(oauth.OAuthError(("Cannot specify oauth_callback at authorization step for 1.0a protocol")))
                if not check_valid_callback(callback):
                    return self.send_oauth_error(oauth.OAuthError(("Invalid callback URL")))
            except oauth.OAuthError,err:
                callback = None
                
            # OAuth 1.0a: use the token's callback if confirmed
            if token.callback_confirmed:
                callback = token.callback
                if callback == OUT_OF_BAND:
                    callback = None
            logger.warning("!!!Callback : %s"%callback)
            try:
                user = users.get_current_user()
                
                if user:
                    logger.warning("!!!User logged in - authorize token ")
                    #authorize the token
                    token = oauth_server.authorize_token(token, user)
                    # return the token key
                    args = { 'token': token }
                    if callback:
                        if "?" in callback:
                            url_delimiter = "&"
                        else:
                            url_delimiter = "?"
                        if 'token' in args:
                            query_args = args['token'].to_string(only_key=True)
                        else: # access is not authorized i.e. error
                            query_args = 'error=%s' % args['error']
                        
                        logger.warning('Redirecting to: %s%s%s' % (callback, url_delimiter, query_args))
                        self.redirect(('%s%s%s' % (callback, url_delimiter, query_args)))
                    else:
                        self.response.set_status(200, 'OK')
                        self.response.out.write("Successfully authorised : %s"%token.to_string(only_key=True))
                else:
                    logger.warning("!!!User not logged in - fwd to login page ")
                    #should put up some screen explaining what this 
                    #authentication is for before forwarding to login box
                    self.redirect(users.create_login_url(self.request.uri))
            
            except oauth.OAuthError, err:
                logger.exception("Error when trying to do an authorization")
                self.send_oauth_error(err)
            logger.warning("!!!End request")
            return

        # access token
        if self.request.path.startswith(ACCESS_TOKEN_URL):
            logger.warning("!!!Entering ACESS_TOKEN_URL")

            oauth_server, oauth_request = initialize_server_request(self.request)
            if oauth_server is None:
                return self.send_oauth_error(oauth.OAuthError(('Invalid request parameters.')))
            else:
                logger.warning("!!!OAuth Params: %s"%oauth_request.parameters)
            
            try:
                # create an access token
                token = oauth_server.fetch_access_token(oauth_request)
                
                if token == None:
                    logger.warning("!!! oauth_server.fetch_access_token returning None")
                    self.send_oauth_error(oauth.OAuthError("Cannot find corresponding access token."))
                    return
                # send okay response
                self.response.set_status(200, 'OK')
                # return the token
                self.response.out.write(token.to_string())
            except oauth.OAuthError, err:
                self.send_oauth_error(err)
            logger.warning("!!!End request")

            return

    
    def post(self, *args):
      """Handler method for OAuth POST requests."""
      return self.get()
    
    def put(self, *args):
      """Handler method for OAuth PUT requests."""
      self.error(405)
    
    def delete(self, *args):
      """Handler method for OAuth DELETE requests."""
      self.error(405)
