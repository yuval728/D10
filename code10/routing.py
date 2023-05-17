from django.urls import path

from . import consumer

websocket_urlpatterns_p2p = [
    path('p2pchat/', consumer.P2PChatConsumer.as_asgi()),
    # path('ws/P2PChat/<int:friend_id>/', consumer.P2PChatConsumer.as_asgi()), use token url instead
]


