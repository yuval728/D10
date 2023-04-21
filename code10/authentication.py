from rest_framework.authentication import BaseAuthentication
from rest_framework_simplejwt.backends import TokenBackend
from .models import User
from .serializers import UserSerializer

from rest_framework import permissions, status, exceptions


class CustomAuthentication(BaseAuthentication):
    def authenticate(self, request):
        try:
            token= request.headers['Authorization'].split(' ')[1]
            if not token:
                return None
            tokenBackend= TokenBackend(algorithm='HS256')
            valid_data= tokenBackend.decode(token,verify=False)
            try:
                user= User.objects.get(id=valid_data['user_id'], email=valid_data['email'])
            except User.DoesNotExist:
                raise exceptions.AuthenticationFailed('User not found')
            user= UserSerializer(user).data
            return (user, None)
        except Exception as e:
            return None