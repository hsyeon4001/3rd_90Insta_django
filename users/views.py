# from rest_framework.authentication import SessionAuthentication, BasicAuthentication
# from rest_framework.authtoken.models import Token
# from rest_framework.decorators import permission_classes, authentication_classes
# from rest_framework.permissions import IsAuthenticated
# from rest_framework import authentication, permissions
import jwt
import json
import bcrypt
import datetime
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.db import IntegrityError
from users.models import User, UserProfile
from config.settings import SECRET_KEY
from config.authentication import login_validate, randstr

from django.shortcuts import get_object_or_404
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.core.mail import EmailMessage


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

            if nickname == "":
                return Response({"message": "nickname을 입력하셔야 합니다."}, status=status.HTTP_400_BAD_REQUEST)

            user_create = User(
                user_type=user_type,
                email=email,
                password=password,
                nickname=nickname
            )
            print("여기")
            user_create.save()

        except ValidationError as e:
            print(e)
            return Response({"message": "유효하지 않은 email입니다."}, status=status.HTTP_400_BAD_REQUEST)

        except IntegrityError as e:
            if 'UNIQUE OF USER' in e.args[1]:
                return Response({"message": "이미 존재하는 email입니다."}, status=status.HTTP_400_BAD_REQUEST)
            if 'nickname' in e.args[1]:
                return Response({"message": "이미 존재하는 nickname입니다."}, status=status.HTTP_400_BAD_REQUEST)

        # 새로운 계정이 생성됨과 동시에 해당 계정의 프로필도 생성한다.
        new_user = User.objects.get(nickname=nickname)
        new_user_id = new_user.id
        new_profile = UserProfile(
            user_id=new_user_id, name=randstr(45))  # 추후 이메일 인증을 위해 유저 프로필 이름에 랜덤값 삽입
        new_profile.save()

        # 이메일 인증 준비
        current_site = get_current_site(request)  # localhost:8000
        message = render_to_string(
            'users/user_active_email.html',
            {
                'domain': current_site.domain,
                'activate_token': new_user.profile.name,
            }
        )

        mail_subject = "[90Insta] 회원가입 인증 메일입니다."
        user_email = new_user.email
        email = EmailMessage(mail_subject, message, to=[user_email])
        email.send()

        return Response({"message": "회원 가입 완료"}, status=status.HTTP_201_CREATED)


class UserActiveView(APIView):
    """ Email 인증 View """

    def get(self, request, activate_token):
        new_user_profile = get_object_or_404(UserProfile, name=activate_token)

        new_user = User.objects.get(pk=new_user_profile.pk)

        new_user.auth = True
        new_user_profile.name = None

        new_user.save()
        new_user_profile.save()

        return HttpResponse("이메일 인증이 완료됐습니다!!!")


class SignInView(APIView):

    """ 일반 회원 로그인 View"""
    # ToDo: 추후에 이메일 인증 기능이 완성되면, 본 회원이 인증 완료(auth=True)인지 판단해야함

    def post(self, request):
        data = json.loads(request.body)
        print(request.headers)
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

            user_auth = user.auth  # 인증 여부: 완료(True), 미완료(False)

            if not user_auth:
                return Response({"message": "이메일 인증을 완료해주시기 바랍니다."}, status=status.HTTP_400_BAD_REQUEST)

            if password_check:

                token = jwt.encode(
                    {
                        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=3600),
                        "id": user.id,
                        # "user_type": user.user_type,
                        # "email": user.email,
                        # "nickname": user.nickname,
                    },
                    SECRET_KEY,
                    algorithm='HS256'
                )

                return Response({"token": token}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "password가 일치하지 않습니다."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"message": "존재하지 않는 email입니다."}, status=status.HTTP_400_BAD_REQUEST)


class PasswordChangeView(APIView):

    """ password 변경 View """
    # 비밀번호를 변경했다고해서 토크 만료 시간이 연장되는 것은 아니다.

    @login_validate
    def post(self, request):
        user = request.user
        user_password = user.password  # 현재 로그인한 유저의 암호화된 비밀번호(bytes 타입)

        data = json.loads(request.body)

        # 입력받은 세 가지 password의 길이 검사
        for key, value in data.items():
            if len(value) < 6:
                return Response({"message": "password는 최소 6글자 이상이어야 합니다."}, status=status.HTTP_400_BAD_REQUEST)

        prev_password = data["prev_password"]
        new_password = data["new_password"]
        new_password_check = data["new_password_check"]

        if not bcrypt.checkpw(prev_password.encode('utf-8'), user_password):
            return Response({"message": "현재 password를 다시 확인해 주시기 바랍니다."}, status=status.HTTP_400_BAD_REQUEST)
        if prev_password == new_password:
            return Response({"message": "이전과 다른 새로운 password를 입력해야 합니다."}, status=status.HTTP_400_BAD_REQUEST)
        if new_password != new_password_check:
            return Response({"message": "새로 입력한 password가 일치하지 않습니다."}, status=status.HTTP_400_BAD_REQUEST)

        new_password = bcrypt.hashpw(
            new_password.encode('utf-8'), bcrypt.gensalt())

        user.password = new_password
        user.save()

        return Response({"message": "password를 변경했습니다."}, status=status.HTTP_201_CREATED)


class ProfileEditView(APIView):

    """ 회원 프로필 변집 View """
    @login_validate
    def get(self, request):

        image = request.user.profile.image  # class: ImageField
        print(type(image))
        name = request.user.profile.name
        nickname = request.user.nickname
        intro = request.user.profile.intro

        data = {
            "image": image.name,
            "name": name,
            "nickname": nickname,
            "intro": intro,
        }

        return Response({"data": data}, status=status.HTTP_200_OK)

    @login_validate
    def post(self, request):

        image = request.data['image']  # Inmemory Fiels
        name = request.data['name']
        nickname = request.data['nickname']
        intro = request.data['intro']

        if nickname == "":
            return Response({"message": "nickname을 입력하셔야 합니다."}, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        user_profile = request.user.profile

        try:
            user.nickname = nickname
            user_profile.image = image
            user_profile.name = name
            user_profile.intro = intro

            user.save()
            user_profile.save()

        except IntegrityError as e:
            return Response({"message": "이미 존재하는 nickname입니다."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"messaga": "프로필이 업데이트 됐습니다."}, status=status.HTTP_201_CREATED)


class TestView(APIView):

    """ 테스트 용 View """

    @login_validate
    def post(self, request):

        print(get_current_site(request))

        encode_token = request.headers["Authorization"].split()[1]

        payload = jwt.decode(encode_token, SECRET_KEY, algorithms='HS256')

        encode_token = request.headers["Authorization"].split()[1]
        payload = jwt.decode(encode_token, SECRET_KEY, algorithms='HS256')

        print(request)
        print(request.headers)
        print("로그인 유저 정보: ", request.user)
        print("로그인 유저 프로필 정보: ", request.user.profile)

        result = bcrypt.checkpw('01028404144'.encode(
            "utf-8"), request.user.password)
        print(result)
        print(payload['exp'])
        return Response({"message": payload}, status=status.HTTP_200_OK)
