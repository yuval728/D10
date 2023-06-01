from rest_framework.authentication import BaseAuthentication
from rest_framework_simplejwt.backends import TokenBackend
# from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
# from rest_framework_simplejwt.tokens import UntypedToken

from .models import User, UserFriend
from .serializers import UserSerializer

from rest_framework import permissions, status, exceptions




class CustomAuthentication(BaseAuthentication):
    def authenticate(self, request):
        try:
            # print(request.headers['Authorization'])
            token= request.headers['Authorization'].split(' ')[1]
            if not token:
                return None
            tokenBackend= TokenBackend(algorithm='HS256')
            valid_data= tokenBackend.decode(token,verify=False)
            try:
                instance= User.objects.get(id=valid_data['user_id'], email=valid_data['email'])
            except User.DoesNotExist:
                raise exceptions.AuthenticationFailed('User not found')
            
            user= UserSerializer(instance).data
            user.instance= instance # ? check if this is needed
            user.is_authenticated= True
            return (user, None)
        except Exception as e:
            return None
        
        
class IsAuthenticatedAndVerified(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated and request.user['verified']:
            return True
        return False

# ? Cant be used with channels 
# ? so when getting chats call directly from api
class P2PAuthentication(BaseAuthentication):
    def authenticate(self, request):
        try:
            token= request.headers['Authorization'].split(' ')[1]
            if not token:
                return None
            tokenBackend= TokenBackend(algorithm='HS256')
            valid_data= tokenBackend.decode(token,verify=False)
            # try:
            #     user=User.objects.get(id=valid_data['user_id'])

            # except User.DoesNotExist:
            #     raise exceptions.AuthenticationFailed('User not found')
            
            try:
                friend=UserFriend.objects.select_related('user1', 'user2').get(id=valid_data['friend_id'], status='friends')
                
            except UserFriend.DoesNotExist:
                raise exceptions.AuthenticationFailed('Friend not found')
            
            
            # * reason to keep user instead of p2p is that it is not working with p2p
            user={
                'friend': friend,
            }
            if valid_data['user_id'] == friend.user1.id:
                user['user']= friend.user1
                user['friend_user']= friend.user2
            elif valid_data['user_id'] == friend.user2.id:
                user['user']= friend.user2
                user['friend_user']= friend.user1
            else:
                raise exceptions.AuthenticationFailed('User not found')
                
            
            return (user, None)
        except Exception as e:
            return None
        
