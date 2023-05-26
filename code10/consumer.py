from asgiref.sync import async_to_sync, sync_to_async
from channels.generic.websocket import WebsocketConsumer, AsyncWebsocketConsumer
from django.db.models import Q

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
        
        try:
            self.user= self.scope['user']
            self.friend= self.scope['friend']
            self.friend_user= self.scope['friend_user']
        except:
            return
    
        
        if self.friendOnline[self.friend.id][self.user.id]:
            print("already connected")
            return 
        self.accept()
        

        async_to_sync(self.channel_layer.group_add)(
            str(self.friend.id),
            self.channel_name
        )
        
        self.friendOnline[self.friend.id][self.user.id]= True
        print(self.friendOnline)
    
    def disconnect(self, close_code):
        # Leave room group
        if not self.user or not self.friend or not self.friend_user:
            print(  "not connected")
            return
        
        else:
            async_to_sync(self.channel_layer.group_discard)(
                str(self.friend.id),
                self.channel_name
            )
            
            self.friendOnline[self.friend.id][self.user.id]= False
    
    def receive(self, text_data):
    
        if not self.user or not self.friend or not self.friend_user:
            return
        
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
         
        status='unread'
        if self.friendOnline[self.friend.id][self.friend_user.id]:
            status='read'
            
        # TODO: change status of the message
        userChat= UserChat.objects.create( user1=self.user, user2=self.friend_user, friend=self.friend, message=message, status=status)

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
        
        
    
    def chat_message(self, event):
        # Send message to WebSocket
        self.send(text_data=json.dumps(event))
        

class P2GChatConsumer(WebsocketConsumer):
    groupMembers= defaultdict(lambda: defaultdict(lambda: False))
    
    
    def __init__(self, *args, **kwargs):
        super().__init__(args, kwargs)
        self.user = None
        self.group= None
        self.groupUser= None
        
    def connect(self):
        
        try:
            self.user= self.scope['user']
            self.group= self.scope['group']
            self.groupUser= self.scope['groupUser']
        except:
            return
        

        if self.groupMembers[self.group.id][self.user.id]:
            print("already connected")
            return 
        
        self.accept()
        
        async_to_sync(self.channel_layer.group_add)(
            str(self.group.id),
            self.channel_name
        )
        
        self.groupMembers[self.group.id][self.user.id]= True
        print(self.groupMembers)
        
    def disconnect(self, close_code):
        # Leave room group
        if not self.user or not self.group or not self.groupUser:
            # message= "user or group or groupUser not found"
            # self.send(text_data=json.dumps({'message': message}))
            return
        
        else:
            async_to_sync(self.channel_layer.group_discard)(
                str(self.group.id),
                self.channel_name
            )
            
            # self.groupMembers[self.group.id][self.user.id]= False
            del self.groupMembers[self.group.id][self.user.id]
        
    def receive(self, text_data):
        
        
        if not self.user or not self.group or not self.groupUser:
            return
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
        
        groupChat= GroupChat.objects.create( user=self.user, group=self.group, message=message)
        
        groupusers=UserGroup.objects.select_related('user').filter(group=self.group, status__in=['member', 'admin']).exclude(user=self.user)
        # print(groupusers)
        print(self.groupUser.getStatus())
        
        groupChatStatus=list()
        for  groupuser in groupusers:
            if self.groupMembers[self.group.id][groupuser.user.id]:
                groupChatStatus.append(GroupChatStatus(user=groupuser.user, status=1, groupChat=groupChat))
            else:
                groupChatStatus.append(GroupChatStatus(user=groupuser.user, status=0, groupChat=groupChat))
            
        # print(groupChatStatus)

        GroupChatStatus.objects.bulk_create(groupChatStatus)
    
        async_to_sync(self.channel_layer.group_send)(
            str(self.group.id),
            { 
                'type': 'chat_message',
                'message': message,
                'user': self.user.id,
                'group': self.group.id,
                # status: 'unread',
            }
        )
        
        
        
    def chat_message(self, event):
        # Send message to WebSocket
        self.send(text_data=json.dumps(event))
        
        