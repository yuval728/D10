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
            return  self.close()
    
        
        if  self.friendOnline[self.friend.id][self.user.id]:
            print("already connected")
            return 
        
        self.accept()
        
        try:
            friendChannel= FriendChannel.objects.get(user=self.user, friend=self.friend)
            friendChannel.setChannel(self.channel_name)
        except FriendChannel.DoesNotExist:
            friendChannel= FriendChannel.objects.create(user=self.user, friend=self.friend, channel=self.channel_name)

        async_to_sync(self.channel_layer.group_add)(
            str(self.friend.id),
            self.channel_name
        )
        
        self.friendOnline[self.friend.id][self.user.id]= True
        # print(self.friendOnline)
    
    def disconnect(self, close_code):
        # Leave room group
        try:
            print("disconnecting", close_code)
            if not self.user or not self.friend or not self.friend_user:
                return self.close()
            
            elif close_code == 1000:
                async_to_sync(self.channel_layer.group_discard)(
                    str(self.friend.id),
                    self.channel_name
                )
                FriendChannel.objects.get(user=self.user, friend=self.friend).delete()
                
                self.friendOnline[self.friend.id][self.user.id]= False
        
        except Exception as e:
            print(e)
            return self.close()
         
    
    def receive(self, text_data ):
    
        if not self.user or not self.friend or not self.friend_user:
            return self.close()
        
        text_data_json = json.loads(text_data)
        message = text_data_json['message'] if 'message' in text_data_json else None
        msg_type= text_data_json['type'] if 'type' in text_data_json else None
         
         
        if msg_type == 'typing':
            async_to_sync(self.channel_layer.group_send)(
                str(self.friend.id),
                {
                    'type': 'chat_message',
                    # 'message': 'typing',
                    'user1': self.user.id,
                    'friend': self.friend.id,
                    # 'user2': self.friend_user.id,
                    'msg_type': msg_type,
                }
            )
            return
        
        # * It is not executed
        # if msg_type == 'friendStatus':
        #     print("friendStatus")
        #     return
        
        status='unread'
        if self.friendOnline[self.friend.id][self.friend_user.id]:
            status='read'
        # TODO: change status of the message
        userChat= UserChat.objects.create( user1=self.user, user2=self.friend_user, friend=self.friend, message=message, status=status)
        
        
        file= None
        if 'file' in text_data_json:
            file= text_data_json['file']
            if file.split('/')[2] == str(self.friend.id):
                userChatFile= UserChatFile.objects.create(chat=userChat, file=file, fileType=text_data_json['fileType'])
                

        async_to_sync(self.channel_layer.group_send)(
            str(self.friend.id),
            {
                'type': 'chat_message',
                'message': message,
                'user1': self.user.id,
                'friend': self.friend.id,
                'user2': self.friend_user.id,
                'status': status,
                'file': file,
            }
        )
        
        
    
    def chat_message(self, event):
        # Send message to WebSocket
        self.send(text_data=json.dumps(event))
        
    def websocket_close(self, event):
        self.send(text_data=json.dumps(event), close=True)

# ############################################################################################################
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
            return self.close()
        

        if self.groupMembers[self.group.id][self.user.id]:
            print("already connected")
            return 
        
        self.accept()
        
        async_to_sync(self.channel_layer.group_add)(
            str(self.group.id),
            self.channel_name
        )
        
        try:
            groupChannel= GroupChannel.objects.get(user=self.user, group=self.group)
            groupChannel.setChannel(self.channel_name)
        except GroupChannel.DoesNotExist:
            groupChannel= GroupChannel.objects.create(user=self.user, group=self.group, channel=self.channel_name)
        
        self.groupMembers[self.group.id][self.user.id]= True
        print(self.groupMembers)
        
    def disconnect(self, close_code):
        # Leave room group
        try:
            if not self.user or not self.group or not self.groupUser:
                # message= "user or group or groupUser not found"
                # self.send(text_data=json.dumps({'message': message}))
                return self.close()
            
            else:
                async_to_sync(self.channel_layer.group_discard)(
                    str(self.group.id),
                    self.channel_name
                )
                try:
                    GroupChannel.objects.get(user=self.user, group=self.group).delete()
                except GroupChannel.DoesNotExist:
                    print("GroupChannel.DoesNotExist")
                
                self.groupMembers[self.group.id][self.user.id]= False
                # del self.groupMembers[self.group.id][self.user.id]
        
        except Exception as e:
            print(e)
        
    def receive(self, text_data):
        
        if not self.user or not self.group or not self.groupUser:
            return self.close()
        # self.send(text_data=json.dumps({'message': "user or group or groupUser not found"}))
        
        
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
        
        groupusers=UserGroup.objects.select_related('user').filter(group=self.group, status__in=['member', 'admin']).exclude(user=self.user)
        
        
        groupChat= GroupChat.objects.create( user=self.user, group=self.group, message=message)

        
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
                'msg_type': 'message',
                # status: 'unread',
            }
        )
        
        
        
    def chat_message(self, event):
        # Send message to WebSocket
        self.send(text_data=json.dumps(event))
        
    def websocket_close(self, event):
        self.send(text_data=json.dumps(event), close=True)