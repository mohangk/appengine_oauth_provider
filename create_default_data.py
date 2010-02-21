from oauth_provider.models import Resource,Consumer
from oauth_provider.consts import ACCEPTED



default_consumer = Consumer(name="Tomboy default consumer", 
        description="Tomboy default consumer", 
        key_ = 'anyone',
        secret = 'anyone',
        status = ACCEPTED
        )
default_consumer.put()

default_resource = Resource(name="default")
default_resource.put()
