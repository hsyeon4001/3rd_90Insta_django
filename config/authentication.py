import jwt
import json
import random
# from django.http import JsonResponse
from rest_framework import status
from rest_framework.response import Response
from config.settings import SECRET_KEY
from users.models import User


def login_validate(func):
    def wrapper(self, request, *args, **kwargs):

        print("로그인 상태를 점검합니다.")

        if "Authorization" not in request.headers:
            return Response({"message": "로그인이 필요합니다."}, status=status.HTTP_401_UNAUTHORIZED)

        # {"Authorization" : "Bearer <JWT>"}
#        encode_token = request.headers["Authorization"].split()[1]
        encode_token = request.headers["Authorization"]

        try:
            payload = jwt.decode(encode_token, SECRET_KEY, algorithms='HS256')
            user = User.objects.get(id=payload['id'])

            request.user = user  # request에 로그인 유저의 정보를 저장한다.

        except jwt.exceptions.ExpiredSignatureError:
            return Response({"message": "해당 계정은 로그아웃 됐습니다. 다시 로그인 해 주시기 바랍니다."}, status=status.HTTP_401_UNAUTHORIZED)

        except jwt.DecodeError:
            return Response({"message": "Token이 유효하지 않습니다."}, status=status.HTTP_401_UNAUTHORIZED)

        except User.DoesNotExist:
            return Response({"message": "존재하지 않는 계정입니다."}, status=status.HTTP_401_UNAUTHORIZED)

        return func(self, request, *args, **kwargs)
    return wrapper


def randstr(length):
    rstr = "0123456789abcdefghijklnmopqrstuvwxyzABCDEFGHIJKLNMOPQRSTUVWXYZ"
    rstr_len = len(rstr) - 1
    result = ""
    for i in range(length):
        result += rstr[random.randint(0, rstr_len)]
    return result
