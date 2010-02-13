KEY_SIZE = 16
SECRET_SIZE = 16
VERIFIER_SIZE = 10
CONSUMER_KEY_SIZE = 256
MAX_URL_LENGTH = 2083 # http://www.boutell.com/newfaq/misc/urllength.html

PENDING = 1
ACCEPTED = 2
CANCELED = 3
REJECTED = 4

CONSUMER_STATES = (
    (PENDING,  'Pending'),
    (ACCEPTED, 'Accepted'),
    (CANCELED, 'Canceled'),
    (REJECTED, 'Rejected'),
)

PARAMETERS_NAMES = ('consumer_key', 'token', 'signature',
                    'signature_method', 'timestamp', 'nonce')
OAUTH_PARAMETERS_NAMES = ['oauth_'+s for s in PARAMETERS_NAMES]

OUT_OF_BAND = 'oob'
