# By Default
from django_filters.rest_framework import DjangoFilterBackend
from http.client import INTERNAL_SERVER_ERROR
from msilib.schema import Error
from dateutil import relativedelta
from django.db import InternalError
from django.http import HttpResponseRedirect
from django.db.models.aggregates import Sum, Max, Min
from django.http.response import HttpResponse
from rest_framework import viewsets
from rest_framework.views import APIView
from django.shortcuts import render

# Language Translation
from django.utils.translation import gettext_lazy as _

# Custom Util
from app_admin.util import SendEmail


# Custom Renders
from app_admin.renderers import UserRenderer

# Rest Frame Work
from rest_framework import authentication, generics, serializers
from rest_framework.response import Response
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework import status, views

# URLS
from django.urls import reverse


# Decouple for hide all Credentials
from decouple import config

# Swaggers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

# Permission Class
from rest_framework import permissions
from rest_framework.permissions import IsAdminUser, IsAuthenticated, AllowAny
# Date Time
from datetime import datetime, date, timedelta
from datetime import date as datetoday

# HTTP
from django.http import HttpResponsePermanentRedirect
from django.http import Http404

# JWT
import jwt

# OS
import os

# Filter
from django.db.models import Q

# Import & Export File
import csv


# API

from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage
from rest_framework.decorators import action

# Count
from django.db.models import Count, F, Value, Avg

# Simple Json Web Token
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication

# System Modules
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import (
    smart_str,
    force_str,
    smart_bytes,
    DjangoUnicodeDecodeError,
)
# Export PDF - xhmtl
from io import BytesIO
from django.http import HttpResponse
from django.template.loader import get_template

from django.shortcuts import render, get_object_or_404
import re
from app_admin.models import User
# Serializers
from app_admin.serializers import (

    RegisterUserSerializers,
    CreateAdminUserSerializers,
    EmailVerificationSerializers,
    UserLoginSerializers,
    ResetPasswordEmailRequestSerializer,
    SetNewPasswordSerializer,
    AdminLoginSerializers,
    UserChangePasswordSerilizer,


)


"""
******************************************************************************************************************
                                                        User
******************************************************************************************************************
"""


class CustomRedirect(HttpResponsePermanentRedirect):
    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']


# User Sign-Up or Registration API and Send E-Mail for Verifing Account
class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterUserSerializers
    parser_classes = [MultiPartParser, ]
    permission_classes = [AllowAny]
    # renderer_classes = (UserRenderer)

    # POST Method for User Registertion
    def post(self, request, *args, **kwargs):
        user = request.data
        serializer = self.serializer_class(data=user)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user_data = serializer.data

            # Send Email for verifing
            user = User.objects.get(email=user_data["email"])
            token = RefreshToken.for_user(user).access_token
            current_site = get_current_site(request).domain
            relativeLink = reverse("Email-Verify")
            absurl = ("http://" + current_site + relativeLink + "?token="
                      + str(token))
            email_body = ("Hi \n" + user.username +
                          " Use link below to verify your email \n " + absurl)

            # HTML Tag
            template_path = 'welcome.html'

            context_data = {
                'name': user.username,
                'verfiy_link': absurl

            }
            email_html_template = get_template(
                template_path).render(context_data)

            data = {
                "email_body": email_html_template,
                "to_email": user.email,
                "email_subject": "verify your email",
            }

            # data = {
            #     "email_body": email_body,
            #     "to_email": user.email,
            #     "email_subject": "verify your email",
            # }
            SendEmail.send_email(data)

            return Response({
                "responseCode": 200,
                "responseMessage": _("User is Successfully registered. send Email for Verifing on your registerd Email"),
                "responseData": user_data, },
                status=status.HTTP_201_CREATED)
        else:
            if serializer.errors.get('Password_Length'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Passwords must be bewtween 6  to 25 Characters.")},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('user_tnc'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Please agree to all the term and condition")},
                    status=status.HTTP_400_BAD_REQUEST)
            # Exists
            elif serializer.errors.get('username_exists'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Username already is existed.")},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('email_exists'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Email already is existed.")},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('phone_exists'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Phone Number already is existed.")},
                    status=status.HTTP_400_BAD_REQUEST)
            # Validation
            elif serializer.errors.get('email_validation'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Please, Enter the Company E-Mail.")},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('Phonedigit'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Phone number must be numeric")},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('Phonelength'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _('Phone must be bewtween 8  to 12 Characters')},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('FirstName_validation'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _('First Name must be alphbet.')},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('Last_Name_validation'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _('Last Name must be alphbet.')},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('designation_validation'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _('Designation Name must be alphbet.')},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('department_validation'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _('Department Name must be alphbet.')},
                    status=status.HTTP_400_BAD_REQUEST)
            return Response({"responseCode": 400, "responseMessage": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class AdminRegisterView(generics.GenericAPIView):

    serializer_class = CreateAdminUserSerializers
    parser_classes = [MultiPartParser, ]
    permission_classes = [AllowAny]
    # renderer_classes = (UserRenderer)

    # POST Method for User Registertion
    def post(self, request, *args, **kwargs):
        user = request.data
        serializer = self.serializer_class(data=user)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user_data = serializer.data

            # Send Email for verifing
            user = User.objects.get(email=user_data["email"])
            token = RefreshToken.for_user(user).access_token
            current_site = get_current_site(request).domain
            relativeLink = reverse("Email-Verify")
            absurl = ("http://" + current_site + relativeLink + "?token="
                      + str(token))
            email_body = ("Hi \n" + user.username +
                          " Use link below to verify your email \n " + absurl)

            # HTML Tag

            template_path = 'welcome.html'

            context_data = {
                'name': user.username,
                'verfiy_link': absurl

            }
            email_html_template = get_template(
                template_path).render(context_data)

            data = {
                "email_body": email_html_template,
                "to_email": user.email,
                "email_subject": "verify your email",
            }

            # data = {
            #     "email_body": email_body,
            #     "to_email": user.email,
            #     "email_subject": "verify your email",
            # }
            SendEmail.send_email(data)

            return Response({
                "responseCode": 200,
                "responseMessage": _("User is Successfully registered. send Email for Verifing on your registerd Email"),
                "responseData": user_data, },
                status=status.HTTP_201_CREATED)
            return Response(user_data, status=status.HTTP_201_CREATED)
        else:
            if serializer.errors.get('Password_Length'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Passwords must be bewtween 6  to 25 Characters.")},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('user_tnc'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Please agree to all the term and condition")},
                    status=status.HTTP_400_BAD_REQUEST)
            # Exists
            elif serializer.errors.get('username_exists'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Username already is existed.")},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('email_exists'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Email already is existed.")},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('phone_exists'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Phone Number already is existed.")},
                    status=status.HTTP_400_BAD_REQUEST)
            # Validation
            elif serializer.errors.get('email_validation'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Please, Enter the Company E-Mail.")},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('Phonedigit'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Phone number must be numeric")},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('Phonelength'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _('Phone must be bewtween 8  to 12 Characters')},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('FirstName_validation'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _('First Name must be alphbet.')},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('Last_Name_validation'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _('Last Name must be alphbet.')},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('designation_validation'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _('Designation Name must be alphbet.')},
                    status=status.HTTP_400_BAD_REQUEST)

            return Response({"responseCode": 400, "responseMessage": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


# Verify Account after Singing Up Account with Email
class VerifyEmailViews(views.APIView):

    # Set Serializers
    serializer_class = EmailVerificationSerializers
    permission_classes = [AllowAny]

    # Get Method For Links and Token
    def get(self, request):
        token = request.GET.get("token")  # Get Token

        try:
            # Decode Token
            payload = jwt.decode(token, settings.SECRET_KEY,
                                 algorithms="HS256")

            user = User.objects.get(id=payload["user_id"])

            if user.is_verify:
                return Response({
                    "responseCode": 200,
                    "responseMessage": _("Your Account have been verified through OTP")},
                    status=status.HTTP_200_OK)

            elif not user.is_verify:
                user.is_verify = True
                user.save()

                return Response({
                    "responseCode": 200,
                    "responseMessage": _("Your Account is verified.")},
                    status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError:
            return Response({
                "responseCode": 400,
                "responseMessage": _("Your link is expired.")},
                status=status.HTTP_400_BAD_REQUEST)

        except jwt.exceptions.DecodeError:
            return Response({
                "responseCode": 400,
                "responseMessage": _("Your link is Invalid.")},
                status=status.HTTP_400_BAD_REQUEST)
            return Response({"error": _("Invalid token")}, status=status.HTTP_400_BAD_REQUEST)


class UserLoginViews(generics.GenericAPIView):
    serializer_class = UserLoginSerializers
    authentication_clesses = [JWTAuthentication]
    permission_classes = [AllowAny]

    parser_classes = [MultiPartParser]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        # lang = self.request.headers["Accept-Language"]

        if serializer.is_valid(raise_exception=True):
            # userData = serializer.data

            email = request.data["email"]
            GetUserIDLogin = User.objects.get(email=email).id
            temp = User.objects.filter(id=GetUserIDLogin).update(
                last_login=datetime.now())

            user = User.objects.get(id=GetUserIDLogin)

            user_Data = {"id": user.id,
                         "email": user.email,
                         "username": user.username,
                         "last_login": user.last_login}

            token = {'refresh': user.tokens()['refresh'],
                     'access': user.tokens()['access']}
            return Response({
                "responseCode": 200,
                "responseMessage": _("Login Successfully. {}").format(user.username),
                "responseData": user_Data,
                "token": token
            }, status=status.HTTP_200_OK)

        else:
            if serializer.errors.get("Invalid_Credentials"):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Invalid credentials, try again")},
                    status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get("IsActive"):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Your Account is disable. Please contact Admin")},
                    status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get("Isverify"):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Email is not verified")},
                    status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get("Is_Admin"):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Admin will not allow to login.")},
                    status=status.HTTP_400_BAD_REQUEST)

        return Response({"responseCode": 400, "responseMessage": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


# Admin Login
class AdminLoginViews(generics.GenericAPIView):

    serializer_class = AdminLoginSerializers
    permissions_class = [AllowAny]
    # parser_classes = [MultiPartParser]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        # lang = self.request.headers["Accept-Language"]

        if serializer.is_valid(raise_exception=True):

            email = request.data["email"]
            GetUserIDLogin = User.objects.get(email=email).id
            temp = User.objects.filter(id=GetUserIDLogin).update(
                last_login=datetime.now())

            user = User.objects.get(id=GetUserIDLogin)

            user_Data = {"email": user.email,
                         "username": user.username,
                         "last_login": user.last_login}

            token = {'refresh': user.tokens()['refresh'],
                     'access': user.tokens()['access']}

            return Response({
                "responseCode": 200,
                "responseMessage": _("Login Successfully. {}").format(user.username),
                "responseData": user_Data,
                "token": token
            }, status=status.HTTP_200_OK)

        else:
            if serializer.errors.get("Invalid_Credentials"):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Invalid credentials, try again")},
                    status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get("IsActive"):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Your Account is disable. Please contact Admin")},
                    status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get("Isverify"):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Email is not verified")},
                    status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get("Normal_User"):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Admin will allow to login.")},
                    status=status.HTTP_400_BAD_REQUEST)

        return Response({"responseCode": 400, "responseMessage": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


# Request to Forget Password
# Request Forget Password
class RequestPasswordResetEmailViews(generics.GenericAPIView):

    serializer_class = ResetPasswordEmailRequestSerializer
    authentication_clesses = [JWTAuthentication]
    permission_classes = [AllowAny]

    # Swager Paramters
    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data.get('email', '')
        if not re.match('^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$', email):
            return Response({
                "responseCode": 400,
                "responseMessage": _("You are not company employee. Please Enter Company Email.")},
                status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            if user.is_staff == True or user.is_superuser == True:
                return Response({
                    "responseCode": 401,
                    "responseMessage": _("You can not reset your password. ")},
                    status=status.HTTP_401_UNAUTHORIZED)

            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain

            relativeLink = reverse(
                'passwordResetConfirm', kwargs={'uidb64': uidb64, 'token': token})

            redirect_url = request.data.get('redirect_url', '')

            absurl = 'http://'+current_site + relativeLink

            """
            email_body = 'Hello, \n Use link below to reset your password  \n' + \
                absurl+"?redirect_url="+redirect_url

            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
            """

            # HTML Tag
            email_body = absurl+"?redirect_url="+redirect_url

            template_path = 'forgetPassword.html'

            context_data = {
                'verfiy_link': email_body
            }

            email_html_template = get_template(
                template_path).render(context_data)

            data = {
                "email_body": email_html_template,
                "to_email": user.email,
                "email_subject": "verify your email",
            }

            SendEmail.send_email(data)

            return Response({
                            "responseCode": 200,
                            "responseMessage": _("Email have been sent Register E-Mail.")},
                            status=status.HTTP_200_OK)
        else:
            return Response({
                "responseCode": 400,
                "responseMessage": _("You are not registered.")},
                status=status.HTTP_400_BAD_REQUEST)


# Set Token For Forgetting Password
class PasswordTokenCheckAPIViews(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    authentication_clesses = [JWTAuthentication]
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, ]

    def get(self, request, uidb64, token):

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):

                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Token is not valid, please request a new one.")},
                    status=status.HTTP_401_UNAUTHORIZED)

            return Response(
                {
                    "success": True,
                    "message": "Credentials valid",
                    "uidb64": uidb64,
                    "token": token,
                },
                status=status.HTTP_200_OK,
            )

        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user):
                return Response(
                    {"error": _("Token is not valid, please request a new one")},
                    status=status.HTTP_401_UNAUTHORIZED,
                )


# Set Forget Password
class SetNewPasswordAPIView(generics.GenericAPIView):

    serializer_class = SetNewPasswordSerializer
    authentication_clesses = [JWTAuthentication]
    permission_classes = [AllowAny]
    # parser_classes = [MultiPartParser, ]

    # # parser_classes = [MultiPartParser, ]

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid(raise_exception=False):
            return Response({
                "responseCode": 200,
                "responseMessage": _("Your Password have been reseted.")},
                status=status.HTTP_200_OK)
        else:
            if serializer.errors.get('Password_Length'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("Passwords must be bewtween 6  to 25 Characters.")},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('Reset_Link'):
                return Response({
                    "responseCode": 400,
                    "responseMessage": _("The Reset link is invalid.")},
                    status=status.HTTP_400_BAD_REQUEST)
