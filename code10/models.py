from django.db import models
from django_extensions.db.models import TimeStampedModel
from django.utils import timezone
import uuid
from .metaModels import *
# Create your models here.

def user_directory_path(instance, filename):
    # file will be uploaded to MEDIA_ROOT/user_<id>/<filename>
    # print(instance.id)
    # print(instance)
    return 'static/userData/{0}/profilePictures/{1}'.format(instance, filename)
class User(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    username=models.CharField(max_length=100,blank=True)
    email=models.EmailField(max_length=100,unique=True)
    password=models.CharField(max_length=128)
    phoneNumber=models.CharField(max_length=15,unique=True)
    verified=models.BooleanField(default=False)
    profilePicture=models.ImageField(upload_to=user_directory_path,blank=True)
    
    def __uuid__(self):
        return self.id
    
    def __str__(self):
        return str(self.id)
    
    def setVerified(self):
        self.verified=True
        self.save()    
    
class UserStatus(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    status=models.BooleanField(default=False)
    lastLogin=models.DateTimeField(blank=True,null=True)
    show=models.BooleanField(default=True)
    user=models.OneToOneField(User,on_delete=models.CASCADE)
    # readReceipt=models.BooleanField(default=True)
    
    def __str__(self):
        return self.user.username+" "+str(self.status)
    
    def setStatus(self, status):
        self.status=status
        self.save()
    
    def setShow(self):
        self.show=not self.show
        self.save()
        
    def setLastLogin(self):
        self.lastLogin=timezone.now()
        self.save()

class UserOTP(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    otp=models.CharField(max_length=6)
    expiry=models.DateTimeField(blank=True,null=True)
    user=models.OneToOneField(User,on_delete=models.CASCADE)
    
    def __str__(self):
        return self.user.username+" "+self.otp
    
    def setExpiry(self):
        self.expiry=timezone.now()
        self.save()
    
class UserOldPassword(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    password=models.CharField(max_length=128)
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    
    def __str__(self):
        return " ".join([self.user.username,self.password])
    

# ? Learn more about device token
# class UserDevice(TimeStampedModel):
#     id=models.AutoField(primary_key=True)
#     deviceName=models.CharField(max_length=100)
#     deviceToken=models.CharField(max_length=100)
#     user=models.ForeignKey(User,on_delete=models.CASCADE)
    
#     def __str__(self):
#         return self.deviceName+" "+self.deviceToken+" "+self.user.username


class UserFriend(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    user1=models.ForeignKey(User,on_delete=models.CASCADE,related_name='user1')
    user2=models.ForeignKey(User,on_delete=models.CASCADE,related_name='user2')
    status=models.CharField(max_length=100,default='friends')
    by=models.CharField(max_length=100,default='',null=True)
    
    def __str__(self):
        return self.user1.username+" "+self.user2.username+" "+self.status

class UserFriendRequest(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    user1=models.ForeignKey(User,on_delete=models.CASCADE,related_name='requester')
    user2=models.ForeignKey(User,on_delete=models.CASCADE,related_name='accepter')
    status=models.CharField(max_length=100,default='pending')
    # by=models.CharField(max_length=100,default='user1')
    def __str__(self):
        return " ".join([self.user1.username,self.user2.username,self.status])


def group_directory_path(instance, filename): # ? Keep group picture static ?
    print(instance)
    return 'static/groupData/{0}/groupPictures/{1}'.format(instance, filename)
    
class Group(SoftDeleteModel):
    id=models.AutoField(primary_key=True)
    groupHash=models.UUIDField(default=uuid.uuid4,editable=False,unique=True )
    groupName=models.CharField(max_length=100)
    groupDescription=models.TextField(blank=True,null=True)
    groupPassword=models.CharField(max_length=100)
    groupPicture=models.ImageField(upload_to=group_directory_path,blank=True)
    createdBy=models.ForeignKey(User,on_delete=models.CASCADE,related_name='groupCreator')
    
    
    def __uuid__(self):
        return self.id
    
    def __str__(self):
        return " ".join([self.groupName,str(self.groupHash),str(self.id)])

class UserGroup(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    group=models.ForeignKey(Group,on_delete=models.CASCADE)
    status=models.CharField(max_length=100,default='member')
    
    def __str__(self):
        return " ".join([self.user.username,self.group.groupName,self.status])
    
    def getStatus(self):
        return self.status

# ? Try with UserFriend Model rather than using user1 and user2
class UserChat(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    friend=models.ForeignKey(UserFriend,on_delete=models.CASCADE)
    user1=models.ForeignKey(User,on_delete=models.CASCADE,related_name='sender')
    user2=models.ForeignKey(User,on_delete=models.CASCADE,related_name='receiver')
    message=models.TextField(blank=True)
    status=models.CharField(max_length=100,default='unread') # ? boolean field
    
    def __str__(self):
        return str(self.id)
    
    def setStatus(self):
        self.status=not self.status
        self.save()

def userChatFile_directory_path(instance, filename):
    # TODO filename will be year/month/day/time-filename
    return 'media/userChatFiles/{0}/{1}'.format(instance, filename)
    # return 'userChatFiles/{0}/{1}'.format(instance.id, filename)
class UserChatFile(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    chat=models.OneToOneField(UserChat,on_delete=models.CASCADE)
    file=models.FileField(upload_to=userChatFile_directory_path,blank=True)
    fileType=models.CharField(max_length=100,blank=True)
    
    def __uuid__(self):
        return self.id 
    
    def __str__(self):
        # return " ".join([str(self.chat.friend.id)])
        return str(self.chat.friend.id)
    
        
class GroupChat(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    group=models.ForeignKey(Group,on_delete=models.CASCADE)
    user=models.ForeignKey(User,on_delete=models.CASCADE,related_name='groupChatSender')
    message=models.TextField(blank=True)
    def __uuid__(self):
        return self.id 
    
    def __str__(self):
        return str(self.id)
    
def groupChatFile_directory_path(instance, filename):
    return 'groupChatFiles/{0}/{1}'.format(instance.id, filename)

class GroupChatFile(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    groupChat=models.OneToOneField(GroupChat,on_delete=models.CASCADE)
    file=models.FileField(upload_to=groupChatFile_directory_path,blank=True)
    fileType=models.CharField(max_length=100,blank=True)
    
    def __uuid__(self):
        return self.id 
    
    def __str__(self):
        return self.groupChat.id
    
class GroupChatStatus(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    groupChat=models.ForeignKey(GroupChat,on_delete=models.CASCADE)
    user=models.ForeignKey(User,on_delete=models.CASCADE,related_name='groupChatUser')
    status=models.SmallIntegerField(default=0)
    
    def __str__(self):
        return " ".join([str(self.groupChat.id),self.user.username,str(self.status)])

class GroupInviteSlug(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    group=models.OneToOneField(Group,on_delete=models.CASCADE)
    slug=models.SlugField(max_length=250,unique=True)
    expiry=models.DateTimeField()
    def __str__(self):
        return " ".join([self.group.groupName,self.slug])
    
    
class FriendChannel(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    user=models.ForeignKey(User,on_delete=models.CASCADE,related_name='friendChannelUser')
    friend=models.ForeignKey(UserFriend,on_delete=models.CASCADE,related_name='friendChannelFriend')
    channel=models.CharField(max_length=100)
    def __str__(self):
        return " ".join([self.user.username,self.friend.user1.username,self.channel])
    
    def setChannel(self,channel=''):
        self.channel=channel
        self.save()
    
class GroupChannel(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    user=models.ForeignKey(User,on_delete=models.CASCADE,related_name='groupChannelUser')
    group=models.ForeignKey(Group,on_delete=models.CASCADE,related_name='groupChannelGroup')
    channel=models.CharField(max_length=100)
    def __str__(self):
        return " ".join([self.user.username,self.group.groupName,self.channel])
    
    def setChannel(self,channel=''):
        self.channel=channel
        self.save()