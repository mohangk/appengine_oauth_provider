import logging
import os

from google.appengine.ext import webapp
from google.appengine.api import users
from google.appengine.ext.webapp import template
import oauth

from stores import check_valid_callback
from utils import initialize_server_request, send_oauth_error
from decorators import oauth_required
from consts import OUT_OF_BAND

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

class RequestTokenHandler(webapp.RequestHandler):
    """HTTP request handler with OAuth support."""
    def get(self, *args):
        logger.warning("!!!START REQUEST!!!")
        """Handler method for OAuth GET requests."""   
        logger.warning("!!!Req URL: %s"%self.request.url)
     
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
            self.response.set_status(200, 'OK')
            self.response.out.write(token.to_string())
        except oauth.OAuthError, err:
            logger.exception("Error when trying to do a request_token")
            send_oauth_error(err, self.response)
            return
        logger.warning("!!!End request")
        return

    def post(self, *args):
      """Handler method for OAuth POST requests."""
      return self.get()


class AuthorizeHandler(webapp.RequestHandler):
    """HTTP request handler with OAuth support."""
    def get(self, *args):
        logger.warning("!!!START REQUEST!!!")
        """Handler method for OAuth GET requests."""   
        logger.warning("!!!Req URL: %s"%self.request.url)
     
        # user authorization
        
        #TODO: put up a screen explaining what this authorization is for before
        #approving the request_token, and allowing the user to decide if they 
        #want to proceed- now it just approves right away. If the user rejects
        #the approval , redirect to the callback with an error parameter
        
        
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
            logger.warning("!!!User logged in ")
            if user:
                if self.request.get('authorize_access'):
                    if int(self.request.get('authorize_access'))==1:
                        logger.warning("User has clicked authorize_access")
                        #check if they want to :s`authorize the token
                        token = oauth_server.authorize_token(token, user)
                        # return the token key
                        args = { 'token': token }
                    elif int(self.request.get('authorize_access')) == 0:
                        args = { 'error': _('Access not granted by user.') }
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
                    logger.warning("User has logged in but not authorized_access yet")
                    #display the authorize view
                    path = os.path.join(os.path.dirname(__file__),'templates',
                                        'authorize.html')
                    self.response.out.write(template.render(path,
                                                            {'token':token}))
            
            else:
                logger.warning("!!!User not logged in - fwd to login page ")
                
                #handle the fact that this might be a POST request and the 
                #required oauth_token (and possibly oauth_callback for
                # OAuth 1.0 requests) will not be on the request.uri
                #Hence we add it to it before redirecting to the login page
                
                request_uri = self.request.uri
                
                if 'oauth_token' not in request_uri and '?' not in request_uri:
                    request_uri = '%s?%s' % (request_uri,token.to_string(only_key=True))
                elif 'oauth_token' not in request_uri and '?' in request_uri:
                    request_uri = '%s&%s' % (request_uri,token.to_string(only_key=True))

                if not token.callback_confirmed and 'oauth_callback' not in request_uri and '?' not in request_uri:
                    request_uri = '%s?oauth_callback=%s' % (request_uri,callback)
                elif not token.callback_confirmed and 'oauth_callback' not in request_uri and '?' in request_uri:
                    request_uri = '%s&oauth_callback=%s' % (request_uri,callback)
                    
              
                self.redirect(users.create_login_url(request_uri))
        
        except oauth.OAuthError, err:
            logger.exception("Error when trying to do an authorization")
            send_oauth_error(err, self.response)
        logger.warning("!!!End request")
        return

    
    def post(self, *args):
      """Handler method for OAuth POST requests."""
      return self.get()

class AccessTokenHandler(webapp.RequestHandler):
    """HTTP request handler with OAuth support."""
    def get(self, *args):
        logger.warning("!!!START REQUEST!!!")
        """Handler method for OAuth GET requests."""   
        logger.warning("!!!Req URL: %s"%self.request.url)
        
        # access token
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


class AuthorizationView(webapp.RequestHandler):
    """This class provides a basic authorization view that is served up to the
    user upon logging in, verifying if they indeed do want to authorize the
    consumer"""

    def get(self):
        logger.warning("!!!Start TomboyPublicApi request")
        hostname = self.request.headers.get('host')
        self.response.out.write("""
              <html>
               <form action="" method="post">
               Authorize access to this applications data ?
               <input type="Submit">
               </form>
              </html>
              """%(hostname,hostname,hostname,hostname,hostname))
            
        logger.warning("!!!End TomboyApi request")
    
        return


class ProtectedResource(webapp.RequestHandler):
    @oauth_required  
    def get(self):
        self.response.out.write('Protected Resource access!')
        return
    
    def post(self, *args):
        """Handler method for OAuth POST requests."""
        return self.get()
      
def application():
    """
    This is used for tests
    """
    url_mappings = [
        ('/request_token',RequestTokenHandler),
        ('/access_token', AccessTokenHandler),
        ('/authorize', AuthorizeHandler),
        ('/protected',ProtectedResource)
    ]
    return webapp.WSGIApplication(url_mappings, debug=True)

      

