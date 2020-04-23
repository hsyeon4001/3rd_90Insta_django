from django.db import connection
from django.dispatch import receiver
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

    def __str__(self):
        return self.email + "'s info"

    @classmethod
    def truncate(cls):
        with connection.cursor() as cursor:
            # -- Disable foreign key checkin
            cursor.execute('SET FOREIGN_KEY_CHECKS = 0;')
            cursor.execute(
                f'TRUNCATE TABLE {cls._meta.db_table};')
            # -- Enable foreign key checking
            cursor.execute('SET FOREIGN_KEY_CHECKS = 1;')


DEFAULT_IMAGE = '/image/default_profile_image.jpg'


def get_upload_path(instance, filename):
    return os.path.join(
        str(instance.user.id),
        filename
    )


class UserProfile(models.Model):
    user = models.OneToOneField(
        "User", on_delete=models.CASCADE, primary_key=True, related_name="profile")
    image = models.ImageField(
        max_length=100, upload_to=get_upload_path, null=True, blank=True)
    name = models.CharField(max_length=45, null=True, blank=True)
    intro = models.CharField(max_length=150, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.email + "'s profile"

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


# @receiver(models.signals.post_delete, sender=UserProfile)
# def auto_delete_file_on_delete(sender, instance, **kwargs):
#     """
#     Deletes file from filesystem
#     when corresponding `MediaFile` object is deleted.
#     """
#     if instance.image:
#         if os.path.isfile(instance.file.path):
#             os.remove(instance.file.path)


@receiver(models.signals.pre_save, sender=UserProfile)
def auto_delete_file_on_change(sender, instance, **kwargs):
    """
    Deletes old file from filesystem
    when corresponding `MediaFile` object is updated
    with new file.
    """
    print("instance: ", instance)
    if not instance.pk:
        return False

    try:
        old_file = sender.objects.get(pk=instance.pk).image
    except sender.DoesNotExist:
        return False

    new_file = instance.image

    # 추가 내용!
    # default 이미지를 없앴기 때문에 db에는 빈 문자열('')로 저장된다.
    # 이러한 이유로 새로운 이미지로 업데이트할 때 에러가 발생한다.
    # 이전 파일이 존재하지 않기 때문!! (DB에서는 빈 문자열로 존재)
    # 그래서 이전 파일이 존재하지 않는 경우(빈 문자열)에는 삭제할 필요없이 새로운 이미지만 업데이트 된다.
    if old_file == "":
        return False

    if not old_file == new_file:
        if os.path.isfile(old_file.path):
            os.remove(old_file.path)
