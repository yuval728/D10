from channels.db import database_sync_to_async
from asgiref.sync import async_to_sync, sync_to_async

from channels.auth import AuthMiddlewareStack
from django.db import close_old_connections

from rest_framework.authentication import BaseAuthentication
from rest_framework_simplejwt.backends import TokenBackend
from rest_framework import permissions, status, exceptions

from .models import User, UserFriend , UserGroup

class ChatAuthMiddlewareInstance:
    def __init__(self, inner):
        self.inner = inner
        
    @database_sync_to_async
    def get_friend(self, friend_id):
        return UserFriend.objects.select_related('user1', 'user2').get(id=friend_id, status='friends')

    @database_sync_to_async
    def get_group(self, groupUser_id):
        return UserGroup.objects.select_related('group','user').get(id=groupUser_id, status__in=['admin', 'member'])
    
    async def __call__(self, scope, receive, send):
        close_old_connections() # ? check if sysnc_to_async is needed
        
        headers= dict(scope['headers'])
        if b'authorization' not in headers:
            return await self.inner(scope, receive, send)
        
        try:
            token= headers[b'authorization'].decode().split(' ')[1]
            if not token:
                return None
            tokenBackend= TokenBackend(algorithm='HS256')
            valid_data= tokenBackend.decode(token,verify=False)
            
            if valid_data['chat_type'] == 'P2P':
                # print(valid_data)
                scope= await self.p2pAuthInstance(valid_data, scope)
            
            elif valid_data['chat_type'] == 'P2G':
                scope= await self.p2gAuthInstance(valid_data, scope)
            

        except Exception as e:
            print(e)

        return await self.inner(scope, receive, send)
        
        
    async def p2pAuthInstance(self, valid_data, scope):
        try:
            # friend=UserFriend.objects.select_related('user1', 'user2').get(id=valid_data['friend_id'])
            # friend=database_sync_to_async(UserFriend.objects.select_related('user1', 'user2').get, thread_sensitive=True)(id=valid_data['friend_id'])
            # friend=await sync_to_async(UserFriend.objects.select_related('user1', 'user2').get, thread_sensitive=True)(id=valid_data['friend_id'])
            friend= await self.get_friend(valid_data['friend_id'])
        except UserFriend.DoesNotExist:
            raise exceptions.AuthenticationFailed('Friend not found')
        
        scope['friend']= friend
        if valid_data['user_id'] == friend.user1.id:
            scope['user']= friend.user1
            scope['friend_user']= friend.user2
        elif valid_data['user_id'] == friend.user2.id:
            scope['user']= friend.user2
            scope['friend_user']= friend.user1
        else:
            raise exceptions.AuthenticationFailed('User not found')
        
        return scope
    
    async def p2gAuthInstance(self, valid_data, scope):
        try:
            groupUser= await self.get_group(valid_data['groupUser_id'])
        except UserGroup.DoesNotExist:
            raise exceptions.AuthenticationFailed('Group not found')
        
        scope['groupUser']= groupUser
        scope['user']= groupUser.user
        scope['group']= groupUser.group
        
        return scope


ChatAuthMiddlewareInstanceStack = lambda inner: ChatAuthMiddlewareInstance(AuthMiddlewareStack(inner))    
        


