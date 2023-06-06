from django.test import TestCase
from .models import *
from rest_framework.test import APIClient, APITestCase
from django.contrib.auth.hashers import make_password, check_password


# Create your tests here.
class UserTestCase(APITestCase):
    def test_signup_proper(self):
        data={
            "username": "test",
            "email": "test@gmail.com",
            "password": "test",
            "phoneNumber": "1234567890"
        }
        response= self.client.post('/register/',data)
        # print(response.json())
        self.assertEqual(response.status_code, 201)
        
    def test_signup_missing_fields(self):
        data={
            "username": "test",
            "email": "test@gmail.com",
            "password":"test",
        }
        response= self.client.post('/register/',data)
        # print(response.json())
        self.assertEqual(response.status_code, 400)
    
    def test_signup_duplicate_email(self):
        
        user=User.objects.create(username="test",email="test@gmail.com",password="test",phoneNumber="1234567890")
        data={
            "username": "test",
            "email": "test@gmail.com",
            "password": "test",
            "phoneNumber": "1234567890"
        }
        response= self.client.post('/register/',data)
        # print(response.json())
        self.assertEqual(response.status_code, 500)
            
        
    def test_login_no_user(self):
        data={
            "username": "test",
            "password":"test",
        }
        response= self.client.post('/login/',data)
        print(response.json())
        self.assertEqual(response.status_code, 404)
        
    def test_login_wrong_password(self):
        # user=User.objects.create(username="test",email="test@gmail.com", password=make_password("test"),phoneNumber="1234567890")
        
        data={
            "username": "test",
            "password":"testx",
        }
        
        response= self.client.post('/login/',data)
        print(response.json())
        self.assertEqual(response.status_code, 401)
        
    def test_login_proper(self):
        
        user=User.objects.create(username="test",email="test@gmail.com", password=make_password("test"),phoneNumber="1234567890")
        
        data={
            "username": "test",
            "password":"test",
        }
        
        response= self.client.post('/login/',data)
        print(response.json())
        self.assertEqual(response.status_code, 200)
    