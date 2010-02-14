# Overview

This code is based on the [django-oauth](http://code.welldev.org/django-oauth) plugin. I have tried to maintain most of the code structure, replacing the django specific code with the equivalent in GAE.  

# Usage 

1. Copy the oauth_provider dir into your GAE application folder. 
2. Protect the relevant webapp.RequestHandler methods by applying the oauth_required decorator.

Checkout the example GAE application in the example folder for a clearer explanation.
