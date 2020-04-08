from django.db import models


class Comment(models.Model):
    comment_author = models.ForeignKey(
        'users.User', on_delete=models.CASCADE)
    post = models.ForeignKey(
        'posts.Post', on_delete=models.CASCADE)
    comment = models.TextField(max_length=2200)
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'comments'
