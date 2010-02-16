import urllib

from google.appengine.ext import db

from consts import KEY_SIZE, SECRET_SIZE, CONSUMER_KEY_SIZE, CONSUMER_STATES,\
                   PENDING, ACCEPTED, VERIFIER_SIZE, MAX_URL_LENGTH

def generate_random(length=10, allowed_chars='abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'):
    "Generates a random password with the given length and given allowed_chars"
    # Note that default value of allowed_chars does not have "I" or letters
    # that look like it -- just to avoid confusion.
    from random import choice
    return ''.join([choice(allowed_chars) for i in range(length)])

class Nonce(db.Model):
    token_key = db.StringProperty()
    consumer_key = db.StringProperty()
    key_ = db.StringProperty()
        
    def __unicode__(self):
        return u"Nonce %s for %s" % (self.key, self.consumer_key)

#need to determine what this is for
class Resource(db.Model):
    name = db.StringProperty( )
    url = db.TextProperty()
    is_readonly = db.BooleanProperty(default=True)
    
    def __unicode__(self):
        return u"Resource %s with url %s" % (self.name, self.url)

class Consumer(db.Model):
    name = db.StringProperty()
    description = db.TextProperty()

    key_ = db.StringProperty()
    secret = db.StringProperty()

    status = db.IntegerProperty(choices=[state[0] for state in CONSUMER_STATES], default=PENDING)
    user = db.UserProperty(required=False)
    #user = models.ForeignKey(User, null=True, blank=True, related_name='consumers')

    #objects = ConsumerManager()
        
    def __unicode__(self):
        return u"Consumer %s with key %s" % (self.name, self.key)

    def generate_random_codes(self):
        
        key = generate_random(length=KEY_SIZE)
        secret = generate_random(length=SECRET_SIZE)

        while Consumer.all().filter('key =',key).filter('secret =',secret).count():
            key = generate_random(length=KEY_SIZE)
            secret = generate_random(length=SECRET_SIZE)

        self.key = key
        self.secret = secret
        self.put()

class Token(db.Model):
    REQUEST = 1
    ACCESS = 2
    TOKEN_TYPES = (REQUEST, ACCESS)
    
    key_ = db.StringProperty()
    secret = db.StringProperty()
    token_type = db.IntegerProperty(choices=TOKEN_TYPES)
    timestamp = db.IntegerProperty()
    is_approved = db.BooleanProperty(default=False)
    
    user = db.UserProperty(required=False)
    consumer = db.ReferenceProperty(Consumer, collection_name="tokens")
    resource = db.ReferenceProperty(Resource, collection_name="resources")
    
    ## OAuth 1.0a stuff
    verifier = db.StringProperty()
    callback = db.StringProperty(required=False)
    callback_confirmed = db.BooleanProperty(default=False)
    
    
    def __unicode__(self):
        return u"%s Token %s for %s" % (self.get_token_type_display(), self.key_, self.consumer)

    def to_string(self, only_key=False):
        token_dict = {
            'oauth_token': self.key_, 
            'oauth_token_secret': self.secret
        }
        
        if self.callback_confirmed:
            token_dict.update({'oauth_callback_confirmed': 'true'})
        
        if self.verifier:
            token_dict.update({ 'oauth_verifier': self.verifier })

        if only_key:
            del token_dict['oauth_token_secret']
            if token_dict.has_key('oauth_callback_confirmed'):
                del token_dict['oauth_callback_confirmed']

        return urllib.urlencode(token_dict)


    def generate_random_codes(self):
        key = generate_random(length=KEY_SIZE)
        secret = generate_random(length=SECRET_SIZE)

        while Token.all().filter('key_ =',key).filter('secret =',secret).count():
            key = generate_random(length=KEY_SIZE)
            secret = generate_random(length=SECRET_SIZE)
            
        self.key_ = key
        self.secret = secret
        self.put()
        
    def get_callback_url(self):
        """
        OAuth 1.0a, append the oauth_verifier.
        """
        if self.callback and self.verifier:
            parts = urlparse.urlparse(self.callback)
            scheme, netloc, path, params, query, fragment = parts[:6]
            if query:
                query = '%s&oauth_verifier=%s' % (query, self.verifier)
            else:
                query = 'oauth_verifier=%s' % self.verifier
            return urlparse.urlunparse((scheme, netloc, path, params,
                query, fragment))
        return self.callback
    
    def create_token(cls, consumer, token_type, timestamp, resource, 
            user=None, callback=None, callback_confirmed=False):
        """Shortcut to create a token with random key/secret."""
        tokens = Token.all()\
            .filter('consumer =',consumer)\
            .filter('token_type =',token_type)\
            .filter('timestamp =',timestamp)\
            .filter('resource =',resource)\
            .filter('user =',user)\
            .filter('callback =',callback)\
            .filter('callback_confirmed =',callback_confirmed).fetch(1000)
        
        if len(tokens) == 1:
            token = tokens[0]
        elif len(tokens) == 0:
            #create a nonce
            token = Token(consumer=consumer, 
                                token_type=token_type, 
                                timestamp=timestamp,
                                resource=resource,
                                user=user,
                                callback=callback,
                                callback_confirmed=callback_confirmed)
            token.generate_random_codes()
            token.put()
        else:
            raise Exception('More then one token matches consumer_key "%s", \
                token_type "%s", timestamp "%s", resource "%s", user "%s" \
                callback "%s", callback_confirmed "%s"'\
                %(consumer.key,token_type, timestamp, resource, user, callback,\
                    callback_confirmed))
            
        return token
    create_token = classmethod(create_token)

        
#admin.site.register(Token)
