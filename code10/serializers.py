# from django.contrib.auth.models import User, Group
from rest_framework import serializers
from .models import *
from django.db.models import Q
from django.contrib.auth.hashers import make_password, check_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class TokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token =  super(TokenObtainPairSerializer, cls).get_token(user)
        # Add custom claims
        token['username'] = user.username
        token['email'] = user.email
        # token['userId'] = user.id
        # token['phoneNumber'] = user.phoneNumber
        # token['profilePicture'] = user.profilePicture
        # ...
        return token
    
class UserSerializer(serializers.ModelSerializer): #HyperlinkedModelSerializer
    id = serializers.IntegerField(read_only=True)
    username = serializers.CharField(max_length=100)
    email = serializers.EmailField(max_length=100)
    password = serializers.CharField(max_length=128, write_only=True)
    # confirm_password = serializers.CharField(max_length=128, write_only=True)
    phoneNumber = serializers.CharField(max_length=15)
    profilePicture = serializers.ImageField(required=False, allow_null=True, allow_empty_file=True)
    
    class Meta:
        model = User
        # fields = ('id', 'username', 'email', 'password', 'phoneNumber', 'profilePicture')
        fields = '__all__'
    
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
                
        validated_data['password'] = make_password(validated_data['password'])
        user=  User.objects.create(**validated_data)
        return user
    
    def update(self, instance, validated_data):
        instance.username=validated_data.get('username',instance.username)
        instance.email=validated_data.get('email',instance.email)
        instance.password=validated_data.get('password',instance.password)
        instance.phoneNumber=validated_data.get('phoneNumber',instance.phoneNumber)
        instance.profilePicture=validated_data.get('profilePicture',instance.profilePicture)
        instance.save()
        return instance
    
    # async def partial_update(self, instance, validated_data):
    #     # instance.username=validated_data.get('username',instance.username)
    #     # instance.email=validated_data.get('email',instance.email)
    #     # instance.password=validated_data.get('password',instance.password)
    #     # instance.phoneNumber=validated_data.get('phoneNumber',instance.phoneNumber)
    #     instance.profilePicture=validated_data.get('profilePicture',instance.profilePicture)
    #     await instance.save()
    #     return instance
    
    
    
        

    