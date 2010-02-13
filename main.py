#!/usr/bin/env python


import wsgiref.handlers
from google.appengine.ext import webapp
import django.utils.simplejson as simplejson
from oauth_provider import oauth_request

from oauth_provider.decorators import oauth_required

import logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


class TomboyApiPublicHandler(webapp.RequestHandler):
    def get(self):
        logger.warning("!!!Start TomboyPublicApi request")
        self.response.out.write("""
              {
                  "user-ref": {
                       "api-ref" : "http://localhost:8080/api/1.0/sally",
                       "href" : "http://localhost:8080/sally"
                  },
                  "oauth_access_token_url": "http://localhost:8080/access_token", 
                  "api-version": "1.0", 
                  "oauth_request_token_url": "http://localhost:8080/request_token", 
                  "oauth_authorize_url": "http://localhost:8080/authorize"
              }""")
            
        logger.warning("!!!End TomboyApi request")
    
        return

class TomboyApiPrivateHandler(webapp.RequestHandler):
    @oauth_required  
    def get(self,user):
        logger.warning("!!!Start TomboyPrivateApi request %s"%(user))
        self.response.out.write("""
              {
                  "user-ref": {
                       "api-ref" : "http://localhost:8080/api/1.0/sally",
                       "href" : "http://localhost:8080/sally"
                  },
                  "oauth_access_token_url": "http://localhost:8080/access_token", 
                  "api-version": "1.0", 
                  "oauth_request_token_url": "http://localhost:8080/request_token", 
                  "oauth_authorize_url": "http://localhost:8080/authorize"
              }""")
            
        logger.warning("!!!End TomboyApi request")
    
        return
                

url_mappings = [
    ('/request_token',oauth_request.OAuthRequestHandler),
    ('/access_token', oauth_request.OAuthRequestHandler),
    ('/authorize', oauth_request.OAuthRequestHandler),    
    ('/api/1.0/?', TomboyApiPublicHandler),
    ('/api/1.0/(.*)/?', TomboyApiPrivateHandler)
]

def main():
  application = webapp.WSGIApplication(url_mappings,
                                       debug=True)
  wsgiref.handlers.CGIHandler().run(application)


if __name__ == '__main__':
  main()
