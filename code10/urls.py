from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('token/refresh/', TokenRefreshView.as_view(),name ='token_refresh'),
    path('myprofile/', views.UserProfile.as_view(), name='myprofile'),
    path('verificationRequest/', views.verfiyUserRequest, name='verificationRequest'),
    path('verifyUser/', views.verifyUser, name='verifyUser'),
    path('forgotPassword/', views.forgotPassword, name='forgotPassword'),
    path('resetPassword/', views.resetPassword, name='resetPassword'),
    # path('login2/', views.login2, name='login2'),
    # path('myprofile2/', views.myProfile2, name='myprofile2'),
]
