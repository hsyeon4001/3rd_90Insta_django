import os
import datetime
# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'on1hhvx2zcjvp1)#$^k9d244t)1w*tqt(&_xjcb8jmagdpl(ln'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    "users.apps.UsersConfig",
    "posts.apps.PostsConfig",
    "comments.apps.CommentsConfig",
    "rest_framework",
    "rest_framework.authtoken",
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'


# Database
# https://docs.djangoproject.com/en/3.0/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "insta_db",
        "USER": "root",
        "PASSWORD": "01032645255",
        "HOST": "localhost",
        "PORT": "3306",
    }
}


REST_FRAMEWORK = {

    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",
    ],

    # 'DEFAULT_PERMISSION_CLASSES': [
    #     'rest_framework.permissions.IsAuthenticated',
    # ],

    'DEFAULT_AUTHENTICATION_CLASSES': [
        # 'rest_framework.authentication.BasicAuthentication',
        # 'rest_framework.authentication.SessionAuthentication',
        # 'rest_framework_simplejwt.authentication.JWTAuthentication',
    ]
}

# JWT_AUTH = {
#     'JWT_SECRET_KEY': SECRET_KEY,
#     'JWT_ALGORITHM': 'HS256',
#     'JWT_ALLOW_REFRESH': True,
#     'JWT_EXPIRATION_DELTA': datetime.timedelta(days=7),
#     'JWT_REFRESH_EXPIRATION_DELTA': datetime.timedelta(days=28),
# }

# Password validation
# https://docs.djangoproject.com/en/3.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = "Asia/Seoul"

USE_I18N = True

USE_L10N = True

USE_TZ = False


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.0/howto/static-files/

STATIC_URL = '/static/'


# 유저가 업로드한 모든 이미지 파일에 대한 URL Prefix
MEDIA_URL = '/image/'

# 업로드된 이미지 파일을 저장할 디렉토리 경로
MEDIA_ROOT = os.path.join(BASE_DIR, 'image')
