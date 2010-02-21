import wsgiref.handlers
from google.appengine.ext import webapp

from oauth_provider import oauth_request
from oauth_provider.decorators import oauth_required

import logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

class TomboyApiPublicHandler(webapp.RequestHandler):
    def get(self):
        logger.warning("!!!Start TomboyPublicApi request")
        hostname = self.request.headers.get('host')
        self.response.out.write("""
              {
                  "user-ref": {
                       "api-ref" : "http://%s/api/1.0/sally",
                       "href" : "http://%s/sally"
                  },
                  "oauth_access_token_url": "http://%s/access_token", 
                  "api-version": "1.0", 
                  "oauth_request_token_url": "http://%s/request_token", 
                  "oauth_authorize_url": "http://%s/authorize"
              }"""%(hostname,hostname,hostname,hostname,hostname))
            
        logger.warning("!!!End TomboyApi request")
    
        return

class TomboyApiPrivateHandler(webapp.RequestHandler):
    @oauth_required  
    def get(self,user):
        logger.warning("!!!Start TomboyPrivateApi request %s"%(user))
        hostname = self.request.headers.get('host')
        self.response.out.write("""
              {
                  "user-ref": {
                       "api-ref" : "http://%s/api/1.0/sally",
                       "href" : "http://%s/sally"
                  },
                  "oauth_access_token_url": "http://%s/access_token", 
                  "api-version": "1.0", 
                  "oauth_request_token_url": "http://%s/request_token", 
                  "oauth_authorize_url": "http://%s/authorize"
              }"""%(hostname,hostname,hostname,hostname,hostname))
            
        logger.warning("!!!End TomboyApi request")
    
        return
                

url_mappings = [
    ('/request_token',oauth_request.RequestTokenHandler),
    ('/access_token', oauth_request.AccessTokenHandler),
    ('/authorize', oauth_request.AuthorizeHandler),    
    ('/api/1.0/?', TomboyApiPublicHandler),
    ('/api/1.0/(.*)/?', TomboyApiPrivateHandler)
]

def main():
  application = webapp.WSGIApplication(url_mappings,
                                       debug=True)
  wsgiref.handlers.CGIHandler().run(application)


if __name__ == '__main__':
  main()
