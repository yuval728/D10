# from django.contrib.auth.models import User, Group
from rest_framework import serializers
from .models import *
from django.db.models import Q
from django.contrib.auth.hashers import make_password, check_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

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
        self.validate_emailPhoneNum(validated_data['email'], validated_data['phoneNumber'])
        self.validate_username(validated_data['username'])
        # self.validate(validated_data)
        validated_data['password'] = self.hashPassword(validated_data['password'])
        return User.objects.create(**validated_data)
    
    async def update(self, instance, validated_data):
        instance.username=validated_data.get('username',instance.username)
        instance.email=validated_data.get('email',instance.email)
        instance.password=validated_data.get('password',instance.password)
        instance.phoneNumber=validated_data.get('phoneNumber',instance.phoneNumber)
        instance.profilePicture=validated_data.get('profilePicture',instance.profilePicture)
        await instance.save()
        return instance
    
    async def delete(self, instance):
        await instance.delete()
        return 
    
    async def partial_update(self, instance, validated_data):
        # instance.username=validated_data.get('username',instance.username)
        # instance.email=validated_data.get('email',instance.email)
        # instance.password=validated_data.get('password',instance.password)
        # instance.phoneNumber=validated_data.get('phoneNumber',instance.phoneNumber)
        instance.profilePicture=validated_data.get('profilePicture',instance.profilePicture)
        await instance.save()
        return instance
    
    def validate_username(self, username):
        if  User.objects.filter(username=username).exists():
            raise serializers.ValidationError("Username already exists")
        return username
    
    def validate_emailPhoneNum(self, email, phoneNumber):
        if User.objects.filter(Q(email=email) | Q(phoneNumber=phoneNumber)).exists():
            raise serializers.ValidationError("Email or Phone Number already exists")
        return [email, phoneNumber]
    
    def hashPassword(self, password):
        return make_password(password)
    
    # def validate(self, data):
    #     if data['password'] != data['confirm_password']:
    #         raise serializers.ValidationError("Passwords do not match")
    #     return data
    
    
    
        

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
    