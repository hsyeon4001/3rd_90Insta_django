from django.db import models


class Post(models.Model):
    post_author = models.ForeignKey(
        'users.User', on_delete=models.CASCADE)
    text = models.TextField(max_length=2200, null=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'posts'


class Photo(models.Model):
    post = models.ForeignKey(
        'Post', on_delete=models.CASCADE)
    photo = models.ImageField(max_length=100)
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'photos'
