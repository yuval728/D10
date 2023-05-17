from channels.db import database_sync_to_async
from asgiref.sync import async_to_sync, sync_to_async

from channels.auth import AuthMiddlewareStack
from django.db import close_old_connections

from rest_framework.authentication import BaseAuthentication
from rest_framework_simplejwt.backends import TokenBackend
from rest_framework import permissions, status, exceptions

from .models import User, UserFriend

class P2PAuthMiddlewareInstance:
    def __init__(self, inner):
        self.inner = inner
        
    @database_sync_to_async
    def get_friend(self, friend_id):
        return UserFriend.objects.select_related('user1', 'user2').get(id=friend_id)

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
            try:
                # friend=UserFriend.objects.select_related('user1', 'user2').get(id=valid_data['friend_id'])
                # friend=database_sync_to_async(UserFriend.objects.select_related('user1', 'user2').get, thread_sensitive=True)(id=valid_data['friend_id'])
                # friend=await sync_to_async(UserFriend.objects.select_related('user1', 'user2').get, thread_sensitive=True)(id=valid_data['friend_id'])
                friend= await  self.get_friend(valid_data['friend_id'])
            
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

        except Exception as e:
            print(e)

        return await self.inner(scope, receive, send)
        
    
P2PAuthMiddlewareInstanceStack = lambda inner: P2PAuthMiddlewareInstance(AuthMiddlewareStack(inner))
