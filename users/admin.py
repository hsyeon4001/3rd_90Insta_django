from django.contrib import admin
from .models import *


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    """ User Admin """


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """ UserProfile Admin """
