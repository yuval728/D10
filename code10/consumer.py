from asgiref.sync import async_to_sync, sync_to_async
from channels.generic.websocket import WebsocketConsumer, AsyncWebsocketConsumer

import json
from .models import *

class P2PChatConsumer(WebsocketConsumer):
    
    def __init__(self, *args, **kwargs):
        super().__init__(args, kwargs)
        self.user = None
        self.friend= None
        self.friend_user= None

    def connect(self):
        
        self.user= self.scope['user']
        self.friend= self.scope['friend']
        self.friend_user= self.scope['friend_user']
        
        self.accept()
        #join the friend channel
        async_to_sync(self.channel_layer.group_add)(
            # self.friend.id,
            str(self.friend.id),
            self.channel_name
        )
    
    def disconnect(self, close_code):
        # Leave room group
        async_to_sync(self.channel_layer.group_discard)(
            str(self.friend.id),
            self.channel_name
        )
    
    def receive(self, text_data):
        print(text_data)
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
         
        if not self.user or not self.friend or not self.friend_user:
            return
        
        async_to_sync(self.channel_layer.group_send)(
            str(self.friend.id),
            {
                'type': 'chat_message',
                'message': message,
                'user1': self.user.id,
                'friend': self.friend.id,
                'user2': self.friend_user.id,
            }
        )
        
        # TODO: change status of the message
        userChat= UserChat.objects.create( user1=self.user, user2=self.friend_user, friend=self.friend, message=message)
        
    
    def chat_message(self, event):
        # Send message to WebSocket
        self.send(text_data=json.dumps(event))
        

# class testConsumer(AsyncWebsocketConsumer):

#     async def connect(self):
#         print("connected")
        
#         await self.connect()
#         #join the friend channel
#         async_to_sync(self.channel_layer.group_add)(
#             "test",
#             self.channel_name
#         )
    
#     async def disconnect(self, close_code):
#         # Leave room group
#         print("disconnected")
        
#         async_to_sync(self.channel_layer.group_discard)(
#             "test",
#             self.channel_name
#         )
    
        
        