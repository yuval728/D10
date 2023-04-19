from django.contrib import admin
from .models import *

# Register your models here.

admin.site.register(User)
admin.site.register(UserStatus)
admin.site.register(UserFriend)
admin.site.register(UserFriendRequest)
admin.site.register(UserChat)
admin.site.register(UserChatFile)
admin.site.register(Group)
admin.site.register(UserGroup)
admin.site.register(GroupChat)
admin.site.register(GroupChatFile)
admin.site.register(GroupChatStatus)




