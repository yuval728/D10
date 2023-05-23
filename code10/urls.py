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
    path('getUsers/', views.getUserList, name='getUsers'),
    path('sendFriendRequest/', views.sendFriendRequest, name='sendFriendRequest'),
    path('cancelFriendRequest/', views.cancelFriendRequest, name='cancelFriendRequest'),
    path('respondToFriendRequest/', views.respondFriendRequest, name='respondToFriendRequest'),
    path('sentFriendRequests/', views.sentFriendRequest, name='sentFriendRequests'),
    # path('sentFriendRequests/<int:id>/', views.sentFriendRequest, name='sentFriendRequests'),
    path('getFriendRequests/', views.getFriendRequest, name='receivedFriendRequests'),
    # path('getFriendRequests/<int:id>/', views.getFriendRequest, name='receivedFriendRequests'),
    path ('getFriends/', views.getFriendList, name='getFriends'),
    path('updateFriendShip/', views.updateFriendStatus, name='updateFriendShip'),
    path('getFriendToken/', views.getFriendToken, name='getFriendToken'),
    path('groups/',views.GroupViews.as_view(), name='groups'),
    path('joinGroup/', views.joinGroup, name='joinGroup'),
    path('leaveGroup/', views.leaveGroup, name='leaveGroup'),
    path('updateGroupUser/', views.updateGroupUserStatus, name='updateGroupUserStatus'),
    path('getGroupUsers/<int:groupId>/', views.getGroupUsers, name='getGroupUsers'),
    path('sendGroupInvite/', views.createGroupInviteLink, name='sendGroupInvite'),
    path('joinGroup/<str:slug>/', views.joinGroupViaInviteLink, name='joinGroupByInviteLink'),
]
