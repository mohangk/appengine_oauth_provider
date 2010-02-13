import oauth

from functools import wraps, update_wrapper

from utils import initialize_server_request, send_oauth_error
from consts import OAUTH_PARAMETERS_NAMES

def oauth_required(method):
    def wrapper(self,*args,**kwargs):
        if is_valid_request(self.request):
            try:
                consumer, token, parameters = validate_token(self.request)               
                if consumer and token:
                    return method(self,*args,**kwargs)
            except oauth.OAuthError, e:
                send_oauth_error(e,self.response)
                return       

        send_oauth_error(oauth.OAuthError("Invalid OAuth parameters"),self.response)
        return   
    return wrapper


def is_valid_request(request):
    """
    Checks whether the required parameters are either in
    the http-authorization header sent by some clients,
    which is by the way the preferred method according to
    OAuth spec, but otherwise fall back to `GET` and `POST`.
    """
    is_in = lambda l: all((p in l) for p in OAUTH_PARAMETERS_NAMES)

    try:
        auth_params = request.headers["Authorization"]
    except KeyError,e:
        auth_params = []
        
    parameters = dict([(argument_name,request.get(argument_name)) for argument_name in request.arguments()])

    return is_in(auth_params) or is_in(parameters)


def validate_token(request):
    oauth_server, oauth_request = initialize_server_request(request)
    return oauth_server.verify_request(oauth_request)

