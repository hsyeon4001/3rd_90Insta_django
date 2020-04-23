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

from django.shortcuts import get_object_or_404, redirect
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.core.mail import EmailMessage


class SignUpView(APIView):

    """ 일반 회원 가입 """

    def post(self, request):
        print(vars(request))
        print(type(request))
        # data = json.load(request.body) # postman에서 raw로 받을 때 사용...
        data = request.data
        print(data)
        user_type = "GENERAL"
        email = data['email']
        password = data['password']
        nickname = data['nickname']

        print(email)
        print(password)
        print(nickname)

        try:

            if email == "" or password == "" or nickname == "":
                return Response({"message": "빈 칸 없이 모두 입력해 주시기 바랍니다."}, status=status.HTTP_400_BAD_REQUEST)

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

        # 가입 인증 이메일 전송
        mail_subject = "[90Insta] 회원가입 인증 E-mail 입니다."
        user_email = new_user.email
        email = EmailMessage(mail_subject, message, to=[user_email])
        email.send()

        return Response({"message": "회원 가입 완료"}, status=status.HTTP_201_CREATED)


class UserActiveView(APIView):
    """ Email 인증 View """

    def get(self, request, activate_token):
        try:
            new_user_profile = get_object_or_404(
                UserProfile, name=activate_token)
        except:
            return HttpResponse("이미 인증 완료된 E-mail 입니다!")

        new_user = User.objects.get(pk=new_user_profile.pk)

        new_user.auth = True
        new_user_profile.name = None

        new_user.save()
        new_user_profile.save()

#        return HttpResponse("이메일 인증이 완료됐습니다!!!")
        return redirect('http://192.168.1.71/join_complete.html')


class SignInView(APIView):

    """ 일반 회원 로그인 View"""
    # ToDo: 추후에 이메일 인증 기능이 완성되면, 본 회원이 인증 완료(auth=True)인지 판단해야함

    def post(self, request):
        # data = json.loads(request.body) # postman에서 raw로 받을 때 사용..
        print("request 헤더입니다: ", request.headers)
        data = request.data
        input_email = data['email']
        input_password = data['password']

        if input_email == "" or input_password == "":
            return Response({"message": "빈 칸 없이 모두 입력해 주시기 바랍니다."}, status=status.HTTP_400_BAD_REQUEST)

        print(input_email)
        print(input_password)

        try:
            validate_email(input_email)

            if len(input_password) < 6:
                return Response({"message": "password는 최소 6글자 이상이어야 합니다."}, status=status.HTTP_400_BAD_REQUEST)

        except ValidationError as e:
            print(e)
            return Response({"message": "유효하지 않은 email입니다."}, status=status.HTTP_400_BAD_REQUEST)

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

                data = {"token": token, "id": user.id}

                return Response(data, status=status.HTTP_200_OK)
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

#        data = json.loads(request.body)
        data = request.data

        # 입력받은 세 가지 password의 길이 검사
        for key, value in data.items():
            if value == '':
                return Response({"message": "빈 칸 없이 모두 입력해 주시기 바랍니다."}, status=status.HTTP_400_BAD_REQUEST)

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


class PasswordSearchView(APIView):

    """ password 찾기 View """

    def post(self, request):
        # byte 타입의 request를 역직렬화 하여 dict로 만들어준다.
        #        data = json.loads(request.body)
        data = request.data
        user_email = data["email"]

        if user_email == "":
            return Response({"message": "빈 칸 없이 모두 입력해 주시기 바랍니다."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_email(user_email)

            user = User.objects.get(email=user_email)

            # 6자리의 임의의 password(숫자, 영문 대소문자) 생성
            new_password = randstr(6)

            # 이메일 전송 준비
            message = render_to_string(
                'users/user_password_search.html',
                {
                    'nickname': user.nickname,
                    'password': new_password,
                }
            )

            # email로 새로 생성한 password 전송
            mail_subject = "[90Insta] 새로 발급한 Password 입니다."
            email = EmailMessage(mail_subject, message, to=[user_email])
            email.send()

            new_password_encode = bcrypt.hashpw(
                new_password.encode('utf-8'), bcrypt.gensalt())

            user.password = new_password_encode
            user.save()

        except ValidationError as e:
            print(e)
            return Response({"message": "유효하지 않은 email입니다."}, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            return Response({"message": "존재하지 않는 E-mail입니다."}, status=status.HTTP_401_UNAUTHORIZED)

        return Response({"message": "이메일로 새로운 password를 발급했습니다."}, status=status.HTTP_201_CREATED)


class ProfileEditView(APIView):

    """ 회원 프로필 변집 View """
    @login_validate
    def get(self, request):

        image = request.user.profile.image  # class: ImageField
        name = request.user.profile.name
        nickname = request.user.nickname
        intro = request.user.profile.intro

        # http://현재도메인:8000/image/{user pk}/이미지이름.jpg
        try:
            print(image)
            print(image.url)
            print(image.path)
            image_url = f"http://{request.get_host()}{image.url}"
        except ValueError:
            image_url = ""
        except Exception as e:
            print("에러 발생: ", e)

        print("image: ", image)
        print("name: ", name)
        print("nickname: ", nickname)
        print("intro: ", intro)

        data = {
            "image": image_url,
            "name": name,
            "nickname": nickname,
            "intro": intro,
        }

        return Response({"data": data}, status=status.HTTP_200_OK)

    @login_validate
    def post(self, request):

        print(request.POST)

        try:
            image = request.FILES['image']
        except:
            image = ''
        name = request.POST.get('name')
        nickname = request.POST.get('nickname')
        intro = request.POST.get('intro')

        # try:
        #     image = request.data['image']  # Inmemory Fiels
        # except:
        #     image = ''
        # name = request.data['name']
        # nickname = request.data['nickname']
        # intro = request.data['intro']

        print("image 타입: ", type(image))
        # print(vars(image))
        print("image: ", image)
        print("name: ", name)
        print("nickname: ", nickname)
        print("intro: ", intro)

        if nickname == "":
            return Response({"message": "nickname을 입력하셔야 합니다."}, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        user_profile = request.user.profile

        # 현재 프로필 이미지를 유지하고자 하는 경우.
        if user_profile.image != "" and image == "":
            image = user_profile.image

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
