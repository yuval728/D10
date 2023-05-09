# from django.shortcuts import render
# from django.http import HttpResponse
# from django.contrib import messages
from django.shortcuts import get_object_or_404
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
from django.db.models import Q

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
                userpassword=UserOldPassword.objects.create(user=data['user'], password=data['password'])
            except Exception as e:
                print("Error ")
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
        try:
            user= User.objects.get(username=request.data['username'])
        except Exception as e:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        # if user:
        if check_password(request.data['password'], user.password):
            serializer=  UserSerializer(user)
            token= TokenObtainPairSerializer.get_token(user)
            
            userStatus= UserStatus.objects.get(user=serializer.data['id'])
            userStatus.setStatus(True)
            userStatus= UserStatusSerializer(userStatus)
            
            return Response({'user': serializer.data, 'access': str(token.access_token), 'refresh': str(token), 'status': userStatus.data}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)
            
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
    

@api_view(['POST'])
@authentication_classes([CustomAuthentication])
@permission_classes([permissions.IsAuthenticated])
def forgotPassword(request):
    try:
        if request.user:
            otp, expiry= generateOTP()
            
            try:
                userotp=UserOTP.objects.get(user=request.user['id'])
                userotp.otp=otp
                userotp.expiry=expiry
                userotp.save()
            except:
                UserOTP.objects.create(user=request.user.instance, otp=otp, expiry=expiry)
            return Response({'otp': otp,'msg':'OTP has been sent'}, status=status.HTTP_200_OK)    
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['PATCH'])
@authentication_classes([CustomAuthentication])
@permission_classes([permissions.IsAuthenticated])
def resetPassword(request):
    try:
        if request.user:
            try:
                checkOtp= UserOTP.objects.get(user=request.user['id'])
            except:
                return Response({'error': 'OTP not found'}, status=status.HTTP_404_NOT_FOUND)
            if checkOtp.expiry < timezone.now():
                return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
            if checkOtp.otp != request.data['otp']:
                return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
            checkOtp.setExpiry()
            
            useroldpassword=UserOldPassword.objects.filter(user=request.user['id'])
            for oldpassword in useroldpassword:
                if check_password(request.data['password'], oldpassword.password):
                    return Response({'error': 'Password already used'}, status=status.HTTP_400_BAD_REQUEST)
            
            password=make_password(request.data['password'])
            UserOldPassword.objects.create(user=request.user.instance, password=password)
            userserialize=UserSerializer(request.user.instance, data={'password':password}, context={'request': request}, partial=True)
            if userserialize.is_valid():
                userserialize.save()
                return Response({'msg': 'Password reset successfully'}, status=status.HTTP_200_OK)

            return Response(userserialize.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

@api_view(['POST'])
@authentication_classes([CustomAuthentication])
@permission_classes([IsAuthenticatedAndVerified])
def sendFriendRequest(request):
    try:
        if request.user:
           
            if str(request.user['id']) == request.data['friend']:  #? if friend is int or string
                return Response({'error': 'You cannot send friend request to yourself'}, status=status.HTTP_400_BAD_REQUEST)
            try:
                friend= User.objects.get(id=request.data['friend'])
            except:
                return Response({'error': 'Friend not found'}, status=status.HTTP_404_NOT_FOUND)
            try:
                
                alreadyfriend=UserFriend.objects.filter( Q(user1=request.user['id'], user2=request.data['friend']) | Q(user1=request.data['friend'], user2=request.user['id']) )
                if alreadyfriend:
                    return Response({'error': 'You are already friends'}, status=status.HTTP_400_BAD_REQUEST)
                
                
                friendrequest=UserFriendRequest.objects.get(user1=request.user['id'], user2=request.data['friend'])
                if friendrequest.status=='accepted':
                    return Response({'error': 'You are already friends'}, status=status.HTTP_400_BAD_REQUEST)
                elif friendrequest.status=='pending':
                    return Response({'error': 'Friend request already sent'}, status=status.HTTP_400_BAD_REQUEST)
                elif friendrequest.status=='rejected':
                    friendrequest.status='pending'
                    friendrequest.save()
                    return Response({'msg': 'Friend request sent'}, status=status.HTTP_200_OK)
                elif friendrequest.status=='cancelled':
                    friendrequest.status='pending'
                    friendrequest.save()
                    return Response({'msg': 'Friend request sent'}, status=status.HTTP_200_OK)
                elif friendrequest.status=='blocked':
                    return Response({'error': 'You have blocked this user'}, status=status.HTTP_400_BAD_REQUEST) #TODO: change message
            except:
                UserFriendRequest.objects.create(user1=request.user.instance, user2=friend, status='pending')
                return Response({'msg': 'Friend request sent'}, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['PATCH'])
@authentication_classes([CustomAuthentication])
@permission_classes([IsAuthenticatedAndVerified])
def respondFriendRequest(request):
    try:
        if request.user:
            try:
                friendrequest=UserFriendRequest.objects.get(user2=request.user['id'], user1=int(request.data['friend'])) #? do with id or friend and check type 
                # if friendrequest.status!='pending': #? check if friend request is pending and also for accepted
                #     return Response({'error': 'Friend request not found'}, status=status.HTTP_404_NOT_FOUND)
                
                reqStatus=request.data['status']
                if reqStatus!='accepted' and reqStatus!='rejected' and reqStatus!='blocked':
                    return Response({'error': 'Invalid status'}, status=status.HTTP_400_BAD_REQUEST)
                
                friendrequest.status=reqStatus
                friendrequest.save()
                if reqStatus=='accepted':
                    UserFriend.objects.create(user1=request.user.instance, user2=friendrequest.user1)
                
                return Response({'msg': f'Friend request {reqStatus}'}, status=status.HTTP_200_OK)
            except:
                return Response({'error': 'Friend request not found'}, status=status.HTTP_404_NOT_FOUND)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['PATCH'])
@authentication_classes([CustomAuthentication])
@permission_classes([IsAuthenticatedAndVerified])
def cancelFriendRequest(request):
    try:
        if request.user:
            try:
                friendrequest=UserFriendRequest.objects.get(user1=request.user['id'], user2=request.data['friend'])
                if friendrequest.status!='pending':
                    return Response({'error': 'Friend request not found'}, status=status.HTTP_404_NOT_FOUND)
                
                friendrequest.status='cancelled'
                friendrequest.save()
                
                return Response({'msg': 'Friend request cancelled'}, status=status.HTTP_200_OK)
            except:
                return Response({'error': 'Friend request not found'}, status=status.HTTP_404_NOT_FOUND)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['GET'])
@authentication_classes([CustomAuthentication])
@permission_classes([IsAuthenticatedAndVerified])
def getFriendRequest(request):
    try:
        if request.user:
            friendrequests=UserFriendRequest.objects.filter(user2=request.user['id'], status='pending').values('id', 'user1', 'user1__username', 'user1__profilePicture')
            return Response({"friendrequests":friendrequests}, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)   
  
@api_view(['GET'])
@authentication_classes([CustomAuthentication])
@permission_classes([IsAuthenticatedAndVerified])
def sentFriendRequest(request):
    try:
        if request.user:
            # if request.query_params:
            #     try:
            #         friendrequest=UserFriendRequest.objects.get(id=request.query_params['id'], user1=request.user['id'])
            #         return Response({"friendrequest":friendrequest}, status=status.HTTP_200_OK)
            #     except:
            #         return Response({'error': 'Friend request not found'}, status=status.HTTP_404_NOT_FOUND)
                
            friendrequests=UserFriendRequest.objects.filter(user1=request.user['id'], status='pending').values('id', 'user2', 'user2__username', 'user2__profilePicture')
            return Response({"friendrequests":friendrequests}, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)  
    
@api_view(['GET'])
@authentication_classes([CustomAuthentication])
@permission_classes([IsAuthenticatedAndVerified])
def getUserList(request):
    try:
        if request.user:
           
            if request.query_params and request.query_params['user']:
                query=request.query_params['user']
                users=User.objects.filter(username__icontains=query).values( 'id', 'username', 'profilePicture', 'verified')
            else:
                users=User.objects.values( 'id', 'username', 'profilePicture', 'verified')
            return Response({"users":users}, status=status.HTTP_200_OK)
            
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)