# from django.shortcuts import render
# from django.http import HttpResponse
# from django.contrib import messages
from django.shortcuts import get_object_or_404
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone

from .authentication import CustomAuthentication, IsAuthenticatedAndVerified
from rest_framework.authtoken.models import Token

from .models import *
from .serializers import *

from rest_framework import permissions, status, exceptions, authentication
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes, authentication_classes

from .utils.otp_generate import generateOTP

# Create your views here.
# Django token
# ?Token is not working properly
@api_view(['POST'])
@authentication_classes([authentication.TokenAuthentication])
@permission_classes([permissions.AllowAny])
def login2(request):
    try:
        user= User.objects.get(username=request.data['username'])
        if user:
            if check_password(request.data['password'], user.password):
                serializer=  UserSerializer(user)
                token= Token.objects.get_or_create(user=serializer.data['username'])
                return Response({'user': serializer.data, 'token': token[0].key}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)
            
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

# ?It retrives the user from django.contrib.auth.models.User 
@api_view(['GET'])
@authentication_classes([authentication.TokenAuthentication])
@permission_classes([permissions.IsAuthenticated])
def myProfile2(request):
    try:
        uss= request.user
        print(type(uss))
        return Response({'user': "hee"}, status=status.HTTP_200_OK)
        
        # return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([])
@permission_classes([permissions.AllowAny])
def register(request):
    try:
        serializer = UserSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            user=serializer.instance
            data= {'user': user, 'password': make_password(request.data['password'])}
            try:
                userstatus=UserStatus.objects.create(user=data['user'])
            except Exception as e:
                print("Error in creating status")
                print(e)
                userpassword=UserOldPassword.objects.create(user=data['user'], password=data['password'])
            except Exception as e:
                print("Error in creating old password")
                print(e)
            
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Jwt token
@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def login(request):
    try:
        user= User.objects.get(username=request.data['username'])
        if user:
            if check_password(request.data['password'], user.password):
                serializer=  UserSerializer(user)
                token= TokenObtainPairSerializer.get_token(user)
                
                userStatus= UserStatus.objects.get(user=serializer.data['id'])
                userStatus.setStatus(True)
                userStatus= UserStatusSerializer(userStatus)
                
                return Response({'user': serializer.data, 'access': str(token.access_token), 'refresh': str(token), 'status': userStatus.data}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)
            
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserProfile(APIView):
    authentication_classes = [CustomAuthentication]
    permission_classes= [permissions.IsAuthenticated]
    
    def get(self, request):
        try:
            if request.user:
                return Response(request.user, status=status.HTTP_200_OK)
            
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
    def put(self, request):
        try:
            if request.user:
                if 'password' in request.data:
                    return Response({'error': 'Unauthorised password updating is not allowed'}, status=status.HTTP_401_UNAUTHORIZED)
                if 'verified' in request.data:
                    return Response({'error': 'Unauthorised verification'}, status=status.HTTP_401_UNAUTHORIZED)
                
                # ? TODO: update email, phone, username
                user= request.user.instance
                serializer = UserSerializer(user, data=request.data, context={'request': request} )
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data,status=status.HTTP_202_ACCEPTED)
                
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(e)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def patch(self, request):
        try:
            if request.user:
                if 'password' in request.data:
                    return Response({'error': 'Unauthorised password updating is not allowed'}, status=status.HTTP_401_UNAUTHORIZED)
                if 'verified' in request.data:
                    return Response({'error': 'Unauthorised verification'}, status=status.HTTP_401_UNAUTHORIZED)
               
                # user= User.objects.get(id=request.user['id'])
                user= request.user.instance
                serializer = UserSerializer(user, data=request.data, context={'request': request}, partial=True )
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data,status=status.HTTP_202_ACCEPTED)
                    
                
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@authentication_classes([CustomAuthentication])
@permission_classes([permissions.IsAuthenticated])
def verfiyUserRequest(request):
    try:
        if request.user:
            if request.user['verified']:
                return Response({'error': 'User is already verified'}, status=status.HTTP_400_BAD_REQUEST)
            
            otp, expiry= generateOTP()
            
            try:
                userotp=UserOTP.objects.get(user=request.user['id'])
                userotp.otp=otp
                userotp.expiry=expiry
                userotp.save()
            except:
                UserOTP.objects.create(user=request.user.instance, otp=otp, expiry=expiry)
            # TODO: send email
            # sendEmail(request.user['email'], otp)
            
            return Response({'otp': otp,'msg':'Verification email has been sent'}, status=status.HTTP_200_OK)
        
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@api_view(['PATCH'])
@authentication_classes([CustomAuthentication])
@permission_classes([permissions.IsAuthenticated])
def verifyUser(request):
    try:
        if request.user:
            if request.user['verified']:
                return Response({'error': 'User is already verified'}, status=status.HTTP_400_BAD_REQUEST)
            try:
                checkOtp= UserOTP.objects.get(user=request.user['id'])
            except:
                return Response({'error': 'OTP not found'}, status=status.HTTP_404_NOT_FOUND)
            if checkOtp.expiry < timezone.now():
                return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
            if checkOtp.otp != request.data['otp']:
                return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
            checkOtp.setExpiry()
            
            # User.objects.filter(id=request.user['id']).update(verified=True)
            request.user.instance.setVerified()
            
            return Response({'msg': 'User verified'}, status=status.HTTP_200_OK)
        
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

