from rest_framework.authentication import BaseAuthentication
from rest_framework_simplejwt.backends import TokenBackend
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
        
# check if user is authenticated and verified
class IsAuthenticatedAndVerified(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated and request.user['verified']:
            return True
        return False

class P2PAuthentication(BaseAuthentication):
    def authenticate(self, request):
        try:
            # print(request.headers['Authorization'])
            token= request.headers['Authorization'].split(' ')[1]
            if not token:
                return None
            tokenBackend= TokenBackend(algorithm='HS256')
            valid_data= tokenBackend.decode(token,verify=False)
            try:
                instance= UserFriend.objects.select_related('user1', 'user2').get(id=valid_data['friend_id'])
                # see if user1 and user2 instance required
            except User.DoesNotExist:
                raise exceptions.AuthenticationFailed('User not found')
            
            # p2p.user1= UserSerializer(instance.user1).data
            # p2p.user2= UserSerializer(instance.user2).data
            return (user, None)
        except Exception as e:
            return None