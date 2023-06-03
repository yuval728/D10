# from django.shortcuts import render
from django.http import HttpResponse, FileResponse
# from django.contrib import messages
from django.shortcuts import get_object_or_404
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
from django.db.models import Q
from django.utils.text import slugify
# from django.core.mail import send_mail

from .authentication import CustomAuthentication, IsAuthenticatedAndVerified, P2PAuthentication
from rest_framework.authtoken.models import Token

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from .models import *
from .serializers import *

from rest_framework import permissions, status, exceptions, authentication
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes, authentication_classes

from .utils.otp_generate import generateOTP
import time, random, os

# from django.views.decorators.csrf import csrf_exempt


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
            token= TokenObtainPairSerializerAuth.get_token(user)
            
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
            begin=time.time()
            if request.user['verified']:
                return Response({'error': 'User is already verified'}, status=status.HTTP_400_BAD_REQUEST)
            try:
                checkOtp= UserOTP.objects.get(user=request.user['id'])
            except:
                return Response({'error': 'OTP not found'}, status=status.HTTP_404_NOT_FOUND)
            # checkOtp=get_object_or_404(UserOTP, user=request.user['id'])
            
            if checkOtp.expiry < timezone.now():
                return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
            if checkOtp.otp != request.data['otp']:
                return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
            checkOtp.setExpiry()
            
            request.user.instance.setVerified()
            
            end=time.time()
            print('Time taken: ', end-begin)
            return Response({'msg': 'User verified'}, status=status.HTTP_200_OK)
        
        # print('User not found')
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
                
                alreadyfriend=UserFriend.objects.filter( Q(user1=request.user['id'], user2=request.data['friend']) | Q(user1=request.data['friend'], user2=request.user['id']))
                if alreadyfriend:
                    
                    if alreadyfriend[0].status=='accepted':
                        return Response({'error': 'You are already friends'}, status=status.HTTP_400_BAD_REQUEST)
                    
                    if alreadyfriend[0].status=='blocked':
                        if alreadyfriend[0].by==str(request.user['id']):
                            return Response({'error': 'You have blocked this user'}, status=status.HTTP_400_BAD_REQUEST)
                        else:
                            return Response({'error': 'You are blocked by this user'}, status=status.HTTP_400_BAD_REQUEST)
                    
                
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
                    return Response({'error': 'You have blocked this user'}, status=status.HTTP_400_BAD_REQUEST) #TODO: change message to you are blocked by this user
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
            mutable = request.data._mutable
            request.data._mutable = True #? to make request.data mutable
            try:
                
                request.data['friend']=int(request.data['friend'])
                
                friendrequest=UserFriendRequest.objects.get(user2=request.user['id'], user1=request.data['friend'])
            except:
                return Response({'error': 'Friend request not found'}, status=status.HTTP_404_NOT_FOUND)
            #? do with id or friend and check type 
            # if friendrequest.status!='pending': #? check if friend request is pending and also for accepted
            #     return Response({'error': 'Friend request not found'}, status=status.HTTP_404_NOT_FOUND)
                
            reqStatus=request.data['status']
            if reqStatus!='accepted' and reqStatus!='rejected' and reqStatus!='blocked':
                return Response({'error': 'Invalid status'}, status=status.HTTP_400_BAD_REQUEST)
            
            friendrequest.status=reqStatus
            friendrequest.save()
            # Todo: test it again with blocked status
            if reqStatus=='accepted':
                oldFriend=UserFriend.objects.filter( Q(user1=friendrequest.user1, user2=friendrequest.user2) | Q(user1=friendrequest.user2, user2=friendrequest.user1)) # * Filter to get
                if oldFriend:
                    if oldFriend[0].status=='accepted':
                        return Response({'error': 'You are already friends'}, status=status.HTTP_400_BAD_REQUEST)
                    if oldFriend[0].status=='blocked': 
                        if oldFriend[0].by!=str(request.user['id']):
                            return Response({'error': 'You are blocked by this user'}, status=status.HTTP_400_BAD_REQUEST)
                        
                    oldFriend[0].status='friends'
                    oldFriend[0].by=''
                    oldFriend[0].save()
                else:
                    UserFriend.objects.create(user1=friendrequest.user1, user2=friendrequest.user2, status='friend', by='')
            
            request.data._mutable = mutable
            
            return Response({'msg': f'Friend request {reqStatus}'}, status=status.HTTP_200_OK)
        
    
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
    
@api_view(['GET'])
@authentication_classes([CustomAuthentication])
@permission_classes([IsAuthenticatedAndVerified])
def getFriendList(request):
    try:
        if request.user:
            if request.query_params and request.query_params['friend']:
                query=request.query_params['friend']
                friends=UserFriend.objects.filter(Q(user1=request.user['id']) | Q(user2=request.user['id']), Q(user1__username__icontains=query) | Q(user2__username__icontains=query)).values('id', 'user1', 'user1__username', 'user1__profilePicture', 'user2', 'user2__username', 'user2__profilePicture')
            else:
                friends=UserFriend.objects.filter(Q(user1=request.user['id']) | Q(user2=request.user['id'])).values('id', 'user1', 'user1__username', 'user1__profilePicture', 'user2', 'user2__username', 'user2__profilePicture')
            return Response({"friends":friends}, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['PUT'])
@authentication_classes([CustomAuthentication])
@permission_classes([IsAuthenticatedAndVerified])
def updateFriendStatus(request):
    try:
        if request.user:
            try:
                resStatus=request.data['status']
                if  resStatus!='blocked' and resStatus!='removed':
                    return Response({'error': 'Invalid status'}, status=status.HTTP_400_BAD_REQUEST)
                
                friend=UserFriend.objects.select_related('user1', 'user2').get(id=request.data['id'])
                if friend.user1.id!=request.user['id'] and friend.user2.id!=request.user['id']:
                    return Response({'error': 'Friend not found'}, status=status.HTTP_404_NOT_FOUND)
                
                if friend.status=='blocked':
                    if friend.by!=str(request.user['id']):
                        return Response({'error': 'You are not authorized to unblock this friend'}, status=status.HTTP_401_UNAUTHORIZED)
                    else:
                        friend.status='removed'
                        friend.save()
                        return Response({'msg': 'Friend has been unblocked'}, status=status.HTTP_200_OK)
                elif friend.status=='removed':
                    return Response({'error': 'Friend not found'}, status=status.HTTP_404_NOT_FOUND)
                else:
                    friend.status=resStatus
                    friend.by=request.user['id']
                    friend.save()
                    
                        
                    channel_layer = get_channel_layer()
                    
                    async_to_sync(channel_layer.group_send)(
                        str(friend.id),
                        {
                        'type': 'chat_message',
                        'id': friend.id,
                        'status': resStatus,
                        'by': request.user['id']
                        }
                    )

                    async_to_sync(channel_layer.group_send)(
                        str(friend.id),
                        {
                            'type': 'websocket.close',
                            'code': 1000,
                        }
                    )  
                        
                    return Response({'msg': f'Friend has been {resStatus}'}, status=status.HTTP_200_OK)
            
            except:
                return Response({'error': 'Friend not found'}, status=status.HTTP_404_NOT_FOUND)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['GET'])
@authentication_classes([CustomAuthentication])
@permission_classes([IsAuthenticatedAndVerified])
def getFriendToken(request): #? Change this to request, friendId 
    try:
        if request.user:
            if not request.query_params or not request.query_params['friend']:
               return Response({'error': 'query param friend is required'}, status=status.HTTP_400_BAD_REQUEST)
            query=request.query_params['friend']
            try:
                begin=time.time()
                # ? check if this is faster :: select_related is faster 
                userFriend=UserFriend.objects.select_related('user1', 'user2').get(Q(user1=request.user['id'], user2__id=query) | Q(user2=request.user['id'], user1__id=query))
            except:
                return Response({'error': 'Friend not found'}, status=status.HTTP_404_NOT_FOUND)
            
            if userFriend.status=='blocked':
                if userFriend.by!=str(request.user['id']):
                    return Response({'error': 'You are blocked by this user'}, status=status.HTTP_401_UNAUTHORIZED)
            elif userFriend.status=='removed':
                return Response({'error': 'Friend not found'}, status=status.HTTP_404_NOT_FOUND)
            
            token=TokenObtainSerializerP2P.get_token(request.user.instance, userFriend)
            
            # UserChat.objects.create(user1=userFriend.user1, user2=userFriend.user2, friend=userFriend, message='test')
            end=time.time()
            print(end-begin)
            return Response({'token': str(token.access_token)}, status=status.HTTP_200_OK)
            
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

    
class GroupViews(APIView):
    authentication_classes=[CustomAuthentication]
    permission_classes=[IsAuthenticatedAndVerified]
    
    def get(self, request):
        try:
            if not request.user:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            
            
            if request.query_params and request.query_params['group']:
                query=request.query_params['group']
                groups=Group.objects.filter(name__icontains=query).values('id', 'groupName','groupDescription', 'groupPicture', 'groupHash') #? remove groupHash
            else:
                groups=Group.objects.values('id', 'groupName','groupDescription')
            return Response({"groups":groups}, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def post(self, request):
        try:
            if not request.user:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            
            data={
                'groupName': request.data['groupName'],
                'groupDescription': request.data['groupDescription'] if 'groupDescription' in request.data else None,
                'groupPicture': request.data['groupPicture'] if 'groupPicture' in request.data else None,
                'createdBy': request.user['id'],
                'groupPassword': request.data['groupPassword'],
            }
            serializer=GroupSerializer(data=data, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                UserGroup.objects.create(user=request.user.instance, group=serializer.instance, status='admin')
                
                return Response({'msg': 'Group created successfully', 'group': serializer.data}, status=status.HTTP_201_CREATED)
                            
            return Response({'error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            print(e)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    def put(self, request):
        try:
            
            if not request.user:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

            begin=time.time()
            try:
                groupUser=UserGroup.objects.select_related('group').get(user=request.user['id'], group__id=request.data['groupId'], status__in=['admin', 'member'],group__is_deleted=False)
            except Exception as e:
                print(e)
                return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
            
            if groupUser.status=='member':
                end=time.time()
                print(end-begin)
                return Response({'error': 'You are not authorized to edit this group'}, status=status.HTTP_401_UNAUTHORIZED)
            
            if groupUser.status=='admin':
                data={
                    'groupName': request.data['groupName'],
                    'groupDescription': request.data['groupDescription'],
                    'groupPicture': request.data['groupPicture'] if 'groupPicture' in request.data else None,
                }

                if groupUser.group.createdBy==request.user.instance:
                    data['groupPassword']=request.data['groupPassword']
                
                
                serializer=GroupSerializer(groupUser.group, data=data, context={'request': request}, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    
                    end=time.time()
                    print(end-begin)
                    return Response({'msg': 'Group updated successfully', 'group': serializer.data}, status=status.HTTP_200_OK)
                
                end=time.time()
                print(end-begin)
                return Response({'error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            
                
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def delete(self, request):
        try:
            if not request.user:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            
            try:
                group=Group.objects.get(id=request.data['groupId'])
            except:
                return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
            
            if group.createdBy!=request.user.instance:
                return Response({'error': 'You are not authorized to delete this group'}, status=status.HTTP_401_UNAUTHORIZED)
            
            group.soft_delete()
            return Response({'msg': 'Group deleted successfully'}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

@api_view(['POST'])
@authentication_classes([CustomAuthentication])
@permission_classes([IsAuthenticatedAndVerified])
def joinGroup(request):
    try:
        if not request.user:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        try:
            # group=Group.objects.get(is_deleted=False, groupHash=request.data['groupHash'])
            group=Group.objects.get(is_deleted=False, id=request.data['groupId'])
        except:
            return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
        
        begin=time.time()
        try:
            groupUser=group.usergroup_set.get(user=request.user.instance)
            print(time.time()-begin)
            
            # begin=time.time()
            # groupUser=UserGroup.objects.select_related('group').get(user=request.user["id"], group__id=request.data['groupId'], group__is_deleted=False)
            # print(time.time()-begin)
            if groupUser.status=='member' or groupUser.status=='admin':
                return Response({'error': 'You are already a member of this group'}, status=status.HTTP_400_BAD_REQUEST)
            
            
            return Response({'error': 'You have to be invited to join this group'}, status=status.HTTP_401_UNAUTHORIZED)
            
            
        except :
            if not check_password(request.data['groupPassword'], group.groupPassword):
                return Response({'error': 'Invalid password'}, status=status.HTTP_401_UNAUTHORIZED) 
            
            #? Which one is better? 2nd one is faster by few milliseconds
            # UserGroup.objects.create(user=request.user.instance, group=group, status='member')
            group.usergroup_set.create(user=request.user.instance, status='member')
            print(time.time()-begin)
            return Response({'msg': 'You have joined the group successfully'}, status=status.HTTP_200_OK)
            
        
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['PATCH'])
@authentication_classes([CustomAuthentication])
@permission_classes([IsAuthenticatedAndVerified])
def leaveGroup(request):
    try:
        if not request.user:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        try:
            groupUser=UserGroup.objects.select_related('group').get(user=request.user["id"], group__id=request.data['groupId'], group__is_deleted=False, status__in=['admin', 'member'])
        except:
            return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
        
        if groupUser.group.createdBy==request.user.instance:
            return Response({'error': 'You cannot leave the group as you are the creator'}, status=status.HTTP_401_UNAUTHORIZED)
            
        groupUser.status='left'
        groupUser.save()
        
        disconnectGroupUser(request.user["id"], request.data['groupId'], 'left')
        
        return Response({'msg': 'You have left the group successfully'}, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['PUT'])
@authentication_classes([CustomAuthentication])
@permission_classes([IsAuthenticatedAndVerified])
def updateGroupUserStatus(request):
    try:
        
        begin=time.time()
        if not request.user:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        if request.data['userId']==str(request.user["id"]):
            return Response({'error': 'You cannot update your own status'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if request.data['status']!='admin' and request.data['status']!='member' and request.data['status']!='kicked':
            return Response({'error': 'Invalid status'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            groupUser=UserGroup.objects.select_related('group').get(user=request.user["id"], group__id=request.data['groupId'], group__is_deleted=False, status__in=['admin', 'member'])
        except:
            return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
    
        if groupUser.status!='admin':
            return Response({'error': 'You are not authorized to update the status of this user'}, status=status.HTTP_401_UNAUTHORIZED)
            
        try:
            groupUser2=UserGroup.objects.select_related('group','user').get(user=request.data['userId'], group__id=request.data['groupId'], group__is_deleted=False, status__in=['admin', 'member'])
        except:
            return Response({'error': 'User not found in group'}, status=status.HTTP_404_NOT_FOUND)
        
        if groupUser2.user==groupUser.group.createdBy:
            print(time.time()-begin)
            return Response({'error': 'You cannot update the status of the creator'}, status=status.HTTP_401_UNAUTHORIZED)
        
        
        # if groupUser2.status=='admin':  #? check if this is needed
        #     return Response({'error': 'You cannot update the status of another admin'}, status=status.HTTP_401_UNAUTHORIZED)
         
        groupUser2.status=request.data['status']
        groupUser2.save()
        
        
        if request.data['status']=='kicked':
            disconnectGroupUser(request.data["userId"], request.data['groupId'], request.data['status'])
        
        print(time.time()-begin)
         
        return Response({'msg': 'Status updated successfully'}, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

def disconnectGroupUser(user, group, status):
    try:
        channel_layer=get_channel_layer()
        
        async_to_sync(channel_layer.group_send)(
            group,
            {
                'type': 'chat_message',
                'status': status,
                'user': user,
                'group': group,
                'msg_type': 'status',
            }
        )
        # ? need to save the message ?
        try:
            groupChannel= GroupChannel.objects.get(group=group,user=user)
            
            async_to_sync(channel_layer.send)(
                groupChannel.channel,
                {
                    'type': 'websocket.close',
                    'code': 1000,
                }
            )
        except:
            pass
    
    except Exception as e:
        print(e)
        pass



@api_view(['GET'])
@authentication_classes([CustomAuthentication])
@permission_classes([IsAuthenticatedAndVerified])
def getGroupUsers(request, groupId):
    try:
        if not request.user:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        begin=time.time()
        try:
            groupUser=UserGroup.objects.select_related('group').get(user=request.user["id"], group__id=groupId, group__is_deleted=False, status__in=['admin', 'member'])
        except:
            return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
        
       
        users=groupUser.group.usergroup_set.select_related('user').filter(~Q(user__id=request.user["id"]),status__in=['admin', 'member'],).values('user__id', 'user__username',  'user__profilePicture', 'status')
        
        print(time.time()-begin)
        return Response({'users': users}, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['POST'])
@authentication_classes([CustomAuthentication])
@permission_classes([IsAuthenticatedAndVerified])
def createGroupInviteLink(request):
    try:
        if not request.user:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        begin=time.time()
        try:
            groupUser=UserGroup.objects.select_related('group').get(user=request.user["id"], group__id=request.data['groupId'], group__is_deleted=False, status__in=['admin', 'member'])
        except:
            return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
        
        if groupUser.status!='admin':
            return Response({'error': 'You are not authorized to create invite links for this group'}, status=status.HTTP_401_UNAUTHORIZED)
        
        slug=slugify(groupUser.group.groupName+str(timezone.now())+str(random.randint(0, 1000000)))
        expiry=timezone.now()+timezone.timedelta(hours=1)
        try:
            inviteLink=GroupInviteSlug.objects.get(group__id=request.data['groupId'])
            inviteLink.slug=slug
            inviteLink.expiry=expiry
            inviteLink.save()
        except:
            inviteLink=GroupInviteSlug.objects.create(group=groupUser.group, slug=slug, expiry=expiry)

        
        print(time.time()-begin)
        return Response({'msg': 'Invite link created successfully', 'inviteLink': inviteLink.slug}, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['GET'])
@authentication_classes([CustomAuthentication])
@permission_classes([IsAuthenticatedAndVerified])
def joinGroupViaInviteLink(request, slug):
    try:
        if not request.user:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        begin=time.time()
        try:
            inviteLink=GroupInviteSlug.objects.select_related('group').get(slug=slug, expiry__gte=timezone.now())
        except:
            return Response({'error': 'Invite link not found or expired'}, status=status.HTTP_404_NOT_FOUND)
        
        try:
            groupUser=UserGroup.objects.get(user=request.user["id"], group__id=inviteLink.group.id, group__is_deleted=False)
            
            if groupUser.status=='admin' or groupUser.status=='member':
                return Response({'error': 'You are already a member of this group'}, status=status.HTTP_400_BAD_REQUEST)
            
            groupUser.status='member'
            groupUser.save()
            
        except:
            groupUser=UserGroup.objects.create(user=request.user.instance, group=inviteLink.group, status='member')
        
        print(time.time()-begin)
        return Response({'msg': 'You have joined the group successfully'}, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@authentication_classes([CustomAuthentication])
@permission_classes([IsAuthenticatedAndVerified])
def getGroupToken(request,groupId):
    try:
        if not request.user:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        begin=time.time()
        try:
            groupUser=UserGroup.objects.select_related('group').get(user=request.user["id"], group__id=groupId, group__is_deleted=False, status__in=['admin', 'member'])
        except:
            return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
        
        token=TokenObtainSerializerP2G.get_token(request.user.instance, groupUser.id)
        
        end=time.time()
        print(end-begin)
        return Response({'token': str(token.access_token)}, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@api_view(['GET'])
@authentication_classes([P2PAuthentication])
@permission_classes([])
def testGet(request):
    try:
        begin=time.time()
        if request.user:
            user1=UserSerializer(request.user['user']).data
            user2=UserSerializer(request.user['friend_user']).data
            friend=UserFriendSerializer(request.user['friend']).data
            end=time.time()
            print(end-begin)
            return Response({'user1': user1, 'user2': user2, 'friend': friend}, status=status.HTTP_200_OK)
        return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@api_view(['POST'])
@authentication_classes([P2PAuthentication])
@permission_classes([])
def sendMediaP2P(request):
    try:
        begin=time.time()
        if not request.user:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        if not request.FILES['media']:
            return Response({'error': 'Media not found'}, status=status.HTTP_404_NOT_FOUND)
        
        file=request.FILES['media']
        print(file.name, file.size, file.content_type)
        
        # if request.data['mediaType'] not in ['image', 'video', 'audio', 'document']:
        #     return Response({'error': 'Invalid media type'}, status=status.HTTP_400_BAD_REQUEST)
        
        
        fileLocation='media/userChatFiles/'+str(request.user['friend'].id) +'/'+str(timezone.now().strftime("%Y%m%d%H%M%S"))+file.name
        if not os.path.exists('media/userChatFiles/'+str(request.user['friend'].id)):
            os.makedirs('media/userChatFiles/'+str(request.user['friend'].id))
            
        with open(fileLocation, 'wb+') as destination:
            for chunk in file.chunks():
                destination.write(chunk)
        
        print(time.time()-begin)
        return Response({'msg': fileLocation}, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
@api_view(['GET'])
@authentication_classes([P2PAuthentication])
@permission_classes([])
def getMediaP2P(request):
    try:
        begin=time.time()
        if not request.user:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        if not request.query_params or 'fileLocation' not in request.query_params:
            return Response({'error': 'File location not found'}, status=status.HTTP_404_NOT_FOUND)
        
        fileLocation=request.query_params['fileLocation']
        
        if not fileLocation.startswith('media/userChatFiles/'+str(request.user['friend'].id)):
            return Response({'error': 'File not found bitch'}, status=status.HTTP_404_NOT_FOUND)
        
        if not os.path.exists(fileLocation):
            return Response({'error': 'File not found'}, status=status.HTTP_404_NOT_FOUND)
        
        file=open(fileLocation, 'rb')
        response=FileResponse(file)
        print(time.time()-begin)
        return response
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)