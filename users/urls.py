from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework import routers
from users.views import SignUpView, SignInView


urlpatterns = [
    path('sign-up/', SignUpView.as_view()),
    path('sign-in/', SignInView.as_view()),
]


urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
