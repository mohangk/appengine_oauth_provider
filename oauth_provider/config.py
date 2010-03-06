
#these are the different signature method available by your provider
#options are plaintext and or hmac-sha1
OAUTH_SIGNATURE_METHODS = ['plaintext', 'hmac-sha1']

#this is the realm that will be used within the Authorization headers sent bto
#the client
OAUTH_REALM_KEY_NAME = 'http://events.example.net/'

#this is a list of sites that should not be allowed to be consumers of this API
OAUTH_BLACKLISTED_HOSTNAMES = []


