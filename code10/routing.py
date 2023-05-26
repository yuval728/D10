from django.urls import path

from . import consumer

websocket_urlpatterns = [
    path('p2pchat/', consumer.P2PChatConsumer.as_asgi()),
    path('p2gchat/', consumer.P2GChatConsumer.as_asgi()),
    # path('ws/P2PChat/<int:friend_id>/', consumer.P2PChatConsumer.as_asgi()), use token url instead
]

