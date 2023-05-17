"""
ASGI config for D10 project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from channels.security.websocket import AllowedHostsOriginValidator, OriginValidator

from code10.authenticationWs import  P2PAuthMiddlewareInstanceStack

import code10.routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'D10.settings')
# os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket":  
        AllowedHostsOriginValidator(
            P2PAuthMiddlewareInstanceStack(  # AuthMiddlewareStack(
                URLRouter( code10.routing.websocket_urlpatterns_p2p)
            )
    ),

    
})
