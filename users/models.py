from django.db import connection
from django.db import models
import os


class User(models.Model):
    user_type = models.CharField(max_length=20)
    email = models.EmailField(max_length=100)
    password = models.BinaryField(max_length=500)
    nickname = models.CharField(max_length=30, unique=True)

    auth = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'users'
        constraints = [
            models.UniqueConstraint(
                fields=['user_type', 'email'], name="UNIQUE OF USER")
        ]

    @classmethod
    def truncate(cls):
        with connection.cursor() as cursor:
            # -- Disable foreign key checkin
            cursor.execute('SET FOREIGN_KEY_CHECKS = 0;')
            cursor.execute(
                f'TRUNCATE TABLE {cls._meta.db_table};')
            # -- Enable foreign key checking
            cursor.execute('SET FOREIGN_KEY_CHECKS = 1;')


def get_upload_path(instance, filename):
    return os.path.join(
        str(instance.user.id),
        filename
    )


class UserProfile(models.Model):
    user = models.OneToOneField(
        "User", on_delete=models.CASCADE, primary_key=True)
    image = models.ImageField(
        max_length=100, upload_to=get_upload_path, default='image/default_profile_image.jpg')
    name = models.CharField(max_length=45, null=True, blank=True)
    intro = models.CharField(max_length=150, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_profiles'

    @classmethod
    def truncate(cls):
        with connection.cursor() as cursor:
            # -- Disable foreign key checkin
            cursor.execute('SET FOREIGN_KEY_CHECKS = 0;')
            cursor.execute(
                f'TRUNCATE TABLE {cls._meta.db_table};')
            # -- Enable foreign key checking
            cursor.execute('SET FOREIGN_KEY_CHECKS = 1;')
