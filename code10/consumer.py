from asgiref.sync import async_to_sync, sync_to_async
from channels.generic.websocket import WebsocketConsumer, AsyncWebsocketConsumer

from collections import defaultdict

import json
from .models import *

class P2PChatConsumer(WebsocketConsumer):
    friendOnline= defaultdict(lambda: defaultdict(lambda: False))
    
    def __init__(self, *args, **kwargs):
        super().__init__(args, kwargs)
        self.user = None
        self.friend= None
        self.friend_user= None

    def connect(self):
        
        self.user= self.scope['user']
        self.friend= self.scope['friend']
        self.friend_user= self.scope['friend_user']
        
        if not self.user or not self.friend or not self.friend_user:
            return
        
        
        if self.friendOnline[self.friend.id][self.user.id]:
            print("already connected")
            return 
        self.accept()
        
        # friendChannel= self.channel_layer.
        # print(friendChannel)
        
        async_to_sync(self.channel_layer.group_add)(
            str(self.friend.id),
            self.channel_name
        )
        
        self.friendOnline[self.friend.id][self.user.id]= True
        print(self.friendOnline)
    
    def disconnect(self, close_code):
        # Leave room group
        async_to_sync(self.channel_layer.group_discard)(
            str(self.friend.id),
            self.channel_name
        )
        
        self.friendOnline[self.friend.id][self.user.id]= False
    
    def receive(self, text_data):
        # print(text_data)/
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
         
        if not self.user or not self.friend or not self.friend_user:
            return
        
        status='unread'
        if self.friendOnline[self.friend.id][self.friend_user.id]:
            status='read'

        async_to_sync(self.channel_layer.group_send)(
            str(self.friend.id),
            {
                'type': 'chat_message',
                'message': message,
                'user1': self.user.id,
                'friend': self.friend.id,
                'user2': self.friend_user.id,
                'status': status,
            }
        )
        
        # TODO: change status of the message
        userChat= UserChat.objects.create( user1=self.user, user2=self.friend_user, friend=self.friend, message=message, status=status)
        
    
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
    
        
        