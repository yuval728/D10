# from django.contrib.auth.models import User, Group
from rest_framework import serializers
from .models import *
from django.db.models import Q
from django.contrib.auth.hashers import make_password, check_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenObtainSerializer


class TokenObtainPairSerializerAuth(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token =  super(TokenObtainPairSerializerAuth, cls).get_token(user)
        # Add custom claims
        # token['username'] = user.username
        token['email'] = user.email
        # token['userId'] = user.id
        # token['phoneNumber'] = user.phoneNumber
        # token['profilePicture'] = user.profilePicture
        # ...
        return token
    
class TokenObtainSerializerP2P(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls,user, friend):
        
        token = super(TokenObtainSerializerP2P, cls).get_token(user)
        # Add custom claims
        token['chat_type']= 'P2P'
        token['friend_id']= friend.id
        if user.id == friend.user1.id:
            token['friend_userId']= friend.user2.id
        else:
            token['friend_userId']= friend.user1.id
        # ...
        # print(token)
        return token
    
class TokenObtainSerializerP2G(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls,user, groupUser):
        
        token = super(TokenObtainSerializerP2G, cls).get_token(user)
        # Add custom claims
        token['groupUser_id']= groupUser
        token['chat_type']= 'P2G'
        # ...
        
        return token
    
class UserSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    username = serializers.CharField(max_length=100)
    email = serializers.EmailField(max_length=100)
    password = serializers.CharField(max_length=128, write_only=True)
    # confirm_password = serializers.CharField(max_length=128, write_only=True)
    phoneNumber = serializers.CharField(max_length=15)
    profilePicture = serializers.ImageField(required=False, allow_null=True, allow_empty_file=True)
    verified = serializers.BooleanField(default=False)
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'phoneNumber', 'profilePicture', 'verified')
        # fields = '__all__'
    
    def create(self, validated_data):
        validated_data['email'] = validated_data['email'].lower()
        validated_data['username']= validated_data['username'].lower()
        user = User.objects.filter(Q(email=validated_data['email']) | Q(username=validated_data['username']) | Q(phoneNumber=validated_data['phoneNumber'])).first()
        if user:
            if user.email == validated_data['email']:
                raise serializers.ValidationError({'error': 'Email already exists'})
            if user.username == validated_data['username']:
                raise serializers.ValidationError({'error': 'Username already exists'})
            if user.phoneNumber == validated_data['phoneNumber']:
                raise serializers.ValidationError({'error': 'Phone No already exists'})
        validated_data['verified'] = False
        validated_data['password'] = make_password(validated_data['password'])
        user=  User.objects.create(**validated_data)
        # print(user)
        return user
    
    # def update(self, instance, validated_data):
    #     instance.username=validated_data.get('username',instance.username)
    #     instance.email=validated_data.get('email',instance.email)
    #     # instance.password=validated_data.get('password',instance.password)
    #     instance.phoneNumber=validated_data.get('phoneNumber',instance.phoneNumber)
    #     instance.profilePicture=validated_data.get('profilePicture',instance.profilePicture)
    #     instance.save()
    #     return instance
    
    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            # if attr == 'password':
            #     instance.set_password(value)
            # else:
                setattr(instance, attr, value)
                # instance[attr] = value
        instance.save()
        return instance
    
# * Not in use 
class UserStatusSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    user = serializers.PrimaryKeyRelatedField(read_only=True)
    status = serializers.BooleanField(default=False)
    lastLogin = serializers.DateTimeField(allow_null=True, required=False)
    show= serializers.BooleanField(default=True)

    class Meta:
        model = UserStatus
        # fields = '__all__'
        fields = ('id', 'user', 'status', 'lastLogin', 'show')
        # extra_kwargs = {'user': {'read_only': True }}
    
# * Not in use
class UserFriendRequestSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    user1 = serializers.PrimaryKeyRelatedField(read_only=True)
    user2 = serializers.PrimaryKeyRelatedField(read_only=True)
    status = serializers.CharField(max_length=10, default='pending')
    # by = serializers.CharField(max_length=10, default='user1')
    
    class Meta:
        model = UserFriendRequest
        fields = '__all__'
        
    def create(self, validated_data):
        # validated_data['status'] = 'pending'
        # validated_data['by'] = 'user1'
        userFriendRequest = UserFriendRequest.objects.create(**validated_data)
        return userFriendRequest
    
    def update(self, instance, validated_data):
        instance.status=validated_data.get('status',instance.status)
        instance.save()
        return instance
    
# * Not in use
class UserFriendSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    user1 = serializers.PrimaryKeyRelatedField(read_only=True)
    user2 = serializers.PrimaryKeyRelatedField(read_only=True)
    status = serializers.CharField(max_length=10)
    
    class Meta:
        model = UserFriend
        fields = '__all__'
        
    def create(self, validated_data):
        # validated_data['status'] = 'friends'
        userFriend = UserFriend.objects.create(**validated_data)
        return userFriend
    
    def update(self, instance, validated_data):
        instance.status=validated_data.get('status',instance.status)
        instance.save()
        return instance
    
    
class GroupSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    groupHash= serializers.UUIDField(read_only=True)
    groupName = serializers.CharField(max_length=100)
    groupDescription = serializers.CharField(allow_blank=True, allow_null=True)
    groupPicture = serializers.ImageField(required=False, allow_null=True, allow_empty_file=True)
    groupPassword = serializers.CharField(max_length=128, write_only=True)
    createdBy = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    class Meta:
        model = Group
        fields = '__all__'
        
    def create(self, validated_data):
        validated_data['groupPassword'] = make_password(validated_data['groupPassword'])
        group = Group.objects.create(**validated_data)
        return group
    
    def update(self, instance, validated_data):
        instance.groupName=validated_data.get('groupName',instance.groupName)
        instance.groupPicture=validated_data.get('groupPicture',instance.groupPicture)
        instance.groupPassword=make_password(validated_data.get('groupPassword',instance.groupPassword))
        instance.groupDescription=validated_data.get('groupDescription',instance.groupDescription)
        instance.save()
        return instance