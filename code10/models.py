from django.db import models
from django_extensions.db.models import TimeStampedModel

# Create your models here.

def user_directory_path(instance, filename):
    # file will be uploaded to MEDIA_ROOT/user_<id>/<filename>
    print(instance.id)
    print(instance)
    return 'userData/{0}/profilePictures/{1}'.format(instance, filename)
class User(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    username=models.CharField(max_length=100,blank=True)
    email=models.EmailField(max_length=100,unique=True)
    password=models.CharField(max_length=128)
    phoneNumber=models.CharField(max_length=15,unique=True)
    profilePicture=models.ImageField(upload_to=user_directory_path,blank=True)
    
    def __uuid__(self):
        return self.id
    
    def __str__(self):
        return str(self.id)
    
    
    
class UserStatus(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    status=models.BooleanField(default=False)
    lastLogin=models.DateTimeField(blank=True,null=True)
    show=models.BooleanField(default=True)
    user=models.OneToOneField(User,on_delete=models.CASCADE)
    
    def __str__(self):
        return self.user.username+" "+str(self.status)
    
    def setStatus(self):
        self.status=not self.status
        self.save()
    
    def setShow(self):
        self.show=not self.show
        self.save()
        
    def setLastLogin(self):
        self.lastLogin=timezone.now()
        self.save()
    
class UserFriend(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    user1=models.ForeignKey(User,on_delete=models.CASCADE,related_name='user1')
    user2=models.ForeignKey(User,on_delete=models.CASCADE,related_name='user2')
    status=models.CharField(max_length=100,default='friends')
    
    def __str__(self):
        return self.user1.username+" "+self.user2.username+" "+self.status

class UserFriendRequest(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    user1=models.ForeignKey(User,on_delete=models.CASCADE,related_name='requester')
    user2=models.ForeignKey(User,on_delete=models.CASCADE,related_name='accepter')
    status=models.CharField(max_length=100,default='pending')
    
    def __str__(self):
        return self.user1.username+" "+self.user2.username+" "+self.status


def group_directory_path(instance, filename):
    return 'groupData/{0}/groupPictures/{1}'.format(instance.id, filename)
    
class Group(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    groupName=models.CharField(max_length=100)
    groupPassword=models.CharField(max_length=100)
    groupPicture=models.ImageField(upload_to=group_directory_path,blank=True)
    createdBy=models.ForeignKey(User,on_delete=models.CASCADE,related_name='groupCreator')
    
    def __uuid__(self):
        return self.id
    
    def __str__(self):
        return self.groupName

class UserGroup(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    group=models.ForeignKey(Group,on_delete=models.CASCADE)
    status=models.CharField(max_length=100,default='member')
    
    def __str__(self):
        return self.user.username+" "+self.group.groupName+" "+self.status


class UserChat(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    user1=models.ForeignKey(User,on_delete=models.CASCADE,related_name='sender')
    user2=models.ForeignKey(User,on_delete=models.CASCADE,related_name='receiver')
    message=models.TextField(blank=True)
    status=models.CharField(max_length=100,default='unread')
    
    def __str__(self):
        return str(self.id)
    
    # def setStatus(self):
    #     self.status=not self.status
    #     self.save()

def userChatFile_directory_path(instance, filename):
    # TODO filename will be year/month/day/time-filename
    return 'userChatFiles/{0}/{1}'.format(instance.id, filename)
class UserChatFile(TimeStampedModel):
    id=models.AutoField(primary_key=True)
    chat=models.OneToOneField(UserChat,on_delete=models.CASCADE)
    file=models.FileField(upload_to=userChatFile_directory_path,blank=True)
    fileType=models.CharField(max_length=100,blank=True)
    
    def __uuid__(self):
        return self.id 
    
    def __str__(self):
        return self.chat.id
    
        
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
    status=models.CharField(max_length=100,default='unread')
    
    def __str__(self):
        return self.groupChat.id+" "+self.user.username+" "+self.status

