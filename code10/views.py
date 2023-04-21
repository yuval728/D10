# from django.shortcuts import render
# from django.http import HttpResponse
# from django.contrib import messages
from django.shortcuts import get_object_or_404
from django.contrib.auth.hashers import make_password, check_password

from .authentication import CustomAuthentication

from .models import User
from .serializers import UserSerializer, TokenObtainPairSerializer

from rest_framework import permissions, status, exceptions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes, authentication_classes



# Create your views here.




@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def register(request):
    try:
        serializer = UserSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def login(request):
    try:
        user= User.objects.get(username=request.data['username'])
        if user:
            if check_password(request.data['password'], user.password):
                serializer=  UserSerializer(user)
                token= TokenObtainPairSerializer.get_token(user)
                return Response({'user': serializer.data, 'access': str(token.access_token), 'refresh': str(token)}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)
            
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@authentication_classes([CustomAuthentication])
@permission_classes([])
def myProfile(request):
    try:
        return Response(request.user, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)



