# from rest_framework.authentication import SessionAuthentication, BasicAuthentication
# from rest_framework.authtoken.models import Token
# from rest_framework.decorators import permission_classes, authentication_classes
# from rest_framework.permissions import IsAuthenticated
# from rest_framework import authentication, permissions
import jwt
import json
import bcrypt
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.db import IntegrityError
from users.models import User, UserProfile
from config.settings import SECRET_KEY


class SignUpView(APIView):

    """ 일반 회원 가입 """

    def post(self, request):
        data = json.loads(request.body)

        user_type = "GENERAL"
        email = data['email']
        password = data['password']
        nickname = data['nickname']

        print(email)
        print(password)
        print(nickname)

        try:
            if len(password) >= 6:
                password = bcrypt.hashpw(
                    password.encode('utf-8'), bcrypt.gensalt())
            else:
                return Response({"message": "password는 최소 6글자 이상이어야 합니다."}, status=status.HTTP_400_BAD_REQUEST)

            validate_email(email)

            user_create = User(
                user_type=user_type,
                email=email,
                password=password,
                nickname=nickname
            )
            user_create.save()

        except ValidationError as e:
            print(e)
            return Response({"message": "유효하지 않은 email입니다."}, status=status.HTTP_400_BAD_REQUEST)

        except IntegrityError as e:
            print(e)
            return Response({"message": "이미 존재하는 email입니다."}, status=status.HTTP_400_BAD_REQUEST)

        # 새로운 계정이 생성됨과 동시에 해당 계정의 프로필도 생성한다.
        new_user_id = User.objects.get(nickname=nickname).id
        new_profile = UserProfile(user_id=new_user_id)
        new_profile.save()

        return Response({"message": "회원 가입 완료"}, status=status.HTTP_201_CREATED)


class SignInView(APIView):

    """ 일반 회원 로그인"""

    def post(self, request):
        data = json.loads(request.body)

        input_email = data['email']
        input_password = data['password']

        # 이메일을 통해 회원인지 판단.
        email_check = User.objects.filter(email=input_email).exists()

        if email_check:
            # 로그인을 요청한 회원
            user = User.objects.get(email=input_email)

            # 입력한 패스워드가 일치하는지 확인
            password_check = bcrypt.checkpw(
                input_password.encode('utf-8'),
                user.password
            )

            if password_check:
                print(SECRET_KEY)

                token = jwt.encode(
                    {"user": user.id},
                    SECRET_KEY,
                    algorithm='HS256'
                )

                return Response({"token": token}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "password가 일치하지 않습니다."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"message": "존재하지 않는 email입니다."}, status=status.HTTP_400_BAD_REQUEST)
