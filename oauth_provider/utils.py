import oauth
from stores import GAEOAuthDataStore
from google.appengine.ext.webapp import Response

#to be moved to settings
OAUTH_SIGNATURE_METHODS = ['plaintext', 'hmac-sha1']

#to be moved to settings 
OAUTH_REALM_KEY_NAME = 'http://events.example.net/'

def initialize_server_request(request):
    """Shortcut for initialization."""
    
    auth_header = {}
    if 'Authorization' in request.headers:
        auth_header = {'Authorization': request.headers['Authorization']}

    parameters = dict([(argument_name,request.get(argument_name)) for argument_name in request.arguments()])
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


def send_oauth_error(err,response):
    """Shortcut for sending an error."""
    response.clear()
    response.set_status(401, str(err.message))
    header = oauth.build_authenticate_header(realm=OAUTH_REALM_KEY_NAME)
    for k, v in header.iteritems():
       response.headers.add_header(k, v)
    response.out.write(err.message.encode('utf-8'))
    
