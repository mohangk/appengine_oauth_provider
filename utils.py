import oauth

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
