#!/usr/bin/env python
#
# Copyright 2009 Brian Gershon
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import wsgiref.handlers
from google.appengine.ext import webapp
import django.utils.simplejson as simplejson
import oauth_request

import logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


class TomboyApiHandler(webapp.RequestHandler):
    def get(self):
        logger.warning("!!!Start TomboyApi request")
        self.response.out.write("""
              {
                  "oauth_access_token_url": "http://localhost:8080/access_token", 
                  "api-version": "1.0", 
                  "oauth_request_token_url": "http://localhost:8080/request_token", 
                  "oauth_authorize_url": "http://localhost:8080/authorize"
              }""")
            
        logger.warning("!!!End TomboyApi request")
    
        return
                

url_mappings = [
    # REQUEST_TOKEN_URL = 'https://photos.example.net/request_token'
    ('/request_token',oauth_request.OAuthRequestHandler),

    # ACCESS_TOKEN_URL = 'https://photos.example.net/access_token'
    ('/access_token', oauth_request.OAuthRequestHandler),

    # AUTHORIZATION_URL = 'https://photos.example.net/authorize'
    ('/authorize', oauth_request.OAuthRequestHandler),
    
    # RESOURCE_URL = 'http://photos.example.net/photos'
    # ('/api/events', EventsOAuthHandler),
    ('/protected_resource', oauth_request.OAuthRequestHandler),
    
    ('/api/1.0', TomboyApiHandler),
    
     ('/', TomboyApiHandler),
]

def main():
  application = webapp.WSGIApplication(url_mappings,
                                       debug=True)
  wsgiref.handlers.CGIHandler().run(application)


if __name__ == '__main__':
  main()
