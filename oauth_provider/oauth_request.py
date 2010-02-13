import logging

from google.appengine.ext.webapp import RequestHandler
from google.appengine.api import users

import oauth

from stores import check_valid_callback
from utils import initialize_server_request, send_oauth_error

REQUEST_TOKEN_URL = '/request_token'
ACCESS_TOKEN_URL = '/access_token'
AUTHORIZATION_URL = '/authorize'
CALLBACK_URL = '/request_token_ready'
RESOURCE_URL = '/protected_resource'

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


class OAuthRequestHandler(RequestHandler):
    """HTTP request handler with OAuth support."""
    def get(self, *args):
        logger.warning("!!!START REQUEST!!!")
        """Handler method for OAuth GET requests."""   
        logger.warning("!!!Req URL: %s"%self.request.url)
     
        if self.request.path.startswith(REQUEST_TOKEN_URL):
            logger.warning("!!!Entering REQUEST_TOKEN_URL")
            
            oauth_server, oauth_request = initialize_server_request(self.request)
            if oauth_server is None:
                send_oauth_error(oauth.OAuthError('Invalid request parameters.'), self.response)
                return
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
                send_oauth_error(err, self.response)
                return
            logger.warning("!!!End request")
            return 


        # user authorization
        if self.request.path.startswith(AUTHORIZATION_URL):
            logger.warning("!!!Entering AUTHORIZATION_URL")
            # get the request token
            oauth_server, oauth_request = initialize_server_request(self.request)
            if oauth_server is None:
                return send_oauth_error(oauth.OAuthError('Invalid request parameters.'), self.response)
            else:
                logger.warning("!!!OAuth Params: %s"%oauth_request.parameters)
            try:
                # get the request token
                token = oauth_server.fetch_request_token(oauth_request)
            except oauth.OAuthError, err:
                logger.exception("Failed accessing request token")
                return send_oauth_error(err, self.response)
            try:
                # get the request callback, though there might not be one if this is OAuth 1.0a
                callback = oauth_server.get_callback(oauth_request)
                
                # OAuth 1.0a: this parameter should not be present on this version
                if token.callback_confirmed:
                    return send_oauth_error(oauth.OAuthError("Cannot specify oauth_callback at authorization step for 1.0a protocol"), self.response)
                if not check_valid_callback(callback):
                    return send_oauth_error(oauth.OAuthError("Invalid callback URL"), self.response)
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
                send_oauth_error(err, self.response)
            logger.warning("!!!End request")
            return

        # access token
        if self.request.path.startswith(ACCESS_TOKEN_URL):
            logger.warning("!!!Entering ACESS_TOKEN_URL")

            oauth_server, oauth_request = initialize_server_request(self.request)
            if oauth_server is None:
                return send_oauth_error(oauth.OAuthError('Invalid request parameters.'), self.response)
            else:
                logger.warning("!!!OAuth Params: %s"%oauth_request.parameters)
            
            try:
                # create an access token
                token = oauth_server.fetch_access_token(oauth_request)
                
                if token == None:
                    logger.warning("!!! oauth_server.fetch_access_token returning None")
                    send_oauth_error(oauth.OAuthError("Cannot find corresponding access token."), self.response)
                    return
                # send okay response
                self.response.set_status(200, 'OK')
                # return the token
                self.response.out.write(token.to_string())
            except oauth.OAuthError, err:
                send_oauth_error(err, self.response)
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
