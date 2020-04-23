from django.urls import path, include
from rest_framework import routers
from users.views import *

app_name = 'users'

urlpatterns = [
    path('sign-up/', SignUpView.as_view()),
    path('sign-in/', SignInView.as_view()),
    path('password-change/', PasswordChangeView.as_view()),
    path('password-search/', PasswordSearchView.as_view()),
    path('profile-edit/', ProfileEditView.as_view()),
    path('auth/<activate_token>', UserActiveView.as_view(), name="auth"),
    path('test/', TestView.as_view()),
]
