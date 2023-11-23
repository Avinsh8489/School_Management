# Serializers
from os import defpath
from django.db import models
from django.db.models import fields
from django.db.models.query import QuerySet
from jwt.exceptions import ExpiredSignatureError
from rest_framework import serializers

# DRF-Extra-Fields
from drf_extra_fields.fields import HybridImageField
from drf_extra_fields import fields

# Language Translation
from django.utils.translation import deactivate_all, gettext_lazy as _

# JWT
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

# Default Util - Forget Password
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

# Authutication
from django.contrib import auth
from django.contrib.auth.tokens import PasswordResetTokenGenerator

# Rest Frame Work - Authentication Failed
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.password_validation import validate_password

# Setting.py
from django.conf import settings

# Regular Expression
import re

# Admin MOdel
from app_admin.models import User

"""
******************************************************************************************************************
                                 User
******************************************************************************************************************
"""


# User Sign-Up Registertion Serializers
class RegisterUserSerializers(serializers.ModelSerializer):
    password = serializers.CharField(min_length=6, max_length=50,
                                     write_only=True, required=True, style={"input_type": "password",
                                                                            "placeholder": "Password"},)

    class Meta:
        model = User

        fields = [
            'email', 'username', 'country_code', 'phone', 'password', 'first_name', 'last_name',
            'designation', 'user_tnc', 'last_login', 'profile_images'
        ]

        read_only_fields = ['last_login', "full_name"]

    # Validate Data

    def validate(self, validated_data):
        email = validated_data.get('email')
        username = validated_data.get('username')
        country_code = validated_data.get('country_code')
        phone = validated_data.get('phone')
        password = validated_data.get('password')
        first_name = validated_data.get('first_name')
        last_name = validated_data.get('last_name')
        designation = validated_data.get('designation')
        profile_images = validated_data.get('profile_images')
        user_tnc = validated_data.get('user_tnc')

        # Exists Data
        username_exists = User.objects.filter(username=username)
        email_exists = User.objects.filter(email=email)
        phone_exists = User.objects.filter(phone=phone)

        if len(password) < 6 or len(password) > 25:
            raise serializers.ValidationError({"Password_Length": _(
                "Passwords must be bewtween 6  to 25 Characters.")})
        elif user_tnc != True:
            raise serializers.ValidationError(
                {"user_tnc": _("Please agree to all the term and condition")})
        # Exists
        elif username_exists:
            raise serializers.ValidationError(
                {"username_exists": _("username already is existed.")})
        elif email_exists:
            raise serializers.ValidationError(
                {"email_exists": _("Email is already existed.")})
        elif phone_exists:
            raise serializers.ValidationError(
                {'phone_exists': _("Phone Number is already exists.")})
        # Validation
        # Email
        # elif not re.match('^[a-zA-Z].[a-zA-Z\.]*@archesoftronix.com', email):
        elif not re.match('^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$', email):
            raise serializers.ValidationError(
                {'email_validation': _("Please, Enter the Company E-Mail.")})
        # Username
        elif not re.match('^[a-zA-Z0-9].[a-zA-Z0-9\.\-_]*[a-zA-Z0-9]$', username):
            raise serializers.ValidationError(
                {"Username_validation": _("Username must be Alphanumeric & Special Character ('-','.','_')")})
        # Country Code
        elif not re.match('^[+][0-9]*$', country_code):
            raise serializers.ValidationError(
                {"Country Code": _("Country must be start with '+', and Numeric")})
        # Phone
        # Phone Digit
        elif not phone.isdigit():
            raise serializers.ValidationError(
                {"Phonedigit": _("Phone number must be numeric")})
        # Phone Length
        elif len(phone) < 8 or len(phone) > 12:
            raise serializers.ValidationError(
                {"Phonelength": _("Phone must be bewtween 8  to 12 Characters")})
        # First Name
        elif not re.match("^[a-zA-Z]*$", first_name):
            raise serializers.ValidationError(
                {"FirstName_validation": _("First Name must be alphbet.")})
        # Last Name
        elif not re.match("^[a-zA-Z]*$", last_name):
            raise serializers.ValidationError(
                {"Last_Name_validation": _("Last Name must be alphbet.")})
        # Designation
        elif not re.match("^[a-zA-Z][a-zA-Z\s]*[a-zA-Z]$", designation):
            raise serializers.ValidationError(
                {"designation_validation": _("Designation Name must be alphbet.")})

        return validated_data

    # Create user
    def create(self, validated_data):

        return User.objects.create_user(**validated_data)


class CreateAdminUserSerializers(serializers.ModelSerializer):
    password = serializers.CharField(min_length=6, max_length=50,
                                     write_only=True, required=True, style={"input_type": "password",
                                                                            "placeholder": "Password"},)

    class Meta:
        model = User

        fields = [
            'email', 'username', 'country_code', 'phone', 'password', 'first_name', 'last_name',
            'designation',  'user_tnc', 'last_login', 'profile_images'
        ]

        read_only_fields = ['last_login', "full_name"]

    # Validate Data

    def validate(self, validated_data):
        email = validated_data.get('email')
        username = validated_data.get('username')
        country_code = validated_data.get('country_code')
        phone = validated_data.get('phone')
        password = validated_data.get('password')
        first_name = validated_data.get('first_name')
        last_name = validated_data.get('last_name')
        designation = validated_data.get('designation')
        profile_images = validated_data.get('profile_images')
        user_tnc = validated_data.get('user_tnc')

        # Exists Data
        username_exists = User.objects.filter(username=username)
        email_exists = User.objects.filter(email=email)
        phone_exists = User.objects.filter(phone=phone)

        if len(password) < 6 or len(password) > 25:
            raise serializers.ValidationError({"Password_Length": _(
                "Passwords must be bewtween 6  to 25 Characters.")})
        elif user_tnc != True:
            raise serializers.ValidationError(
                {"user_tnc": _("Please agree to all the term and condition")})
        # Exists
        elif username_exists:
            raise serializers.ValidationError(
                {"username_exists": _("username already is existed.")})
        elif email_exists:
            raise serializers.ValidationError(
                {"email_exists": _("Email is already existed.")})
        elif phone_exists:
            raise serializers.ValidationError(
                {'phone_exists': _("Phone Number is already exists.")})
        # Validation
        # Email
        elif not re.match('^[a-zA-Z].[a-zA-Z\.]*@archesoftronix.com', email):
            raise serializers.ValidationError(
                {'email_validation': _("Please, Enter the Company E-Mail.")})
        # Username
        elif not re.match('^[a-zA-Z0-9].[a-zA-Z0-9\.\-_]*[a-zA-Z0-9]$', username):
            raise serializers.ValidationError(
                {"Username_validation": _("Username must be Alphanumeric & Special Character ('-','.','_')")})
        # Country Code
        elif not re.match('^[+][0-9]*$', country_code):
            raise serializers.ValidationError(
                {"Country Code": _("Country must be start with '+', and Numeric")})
        # Phone
        # Phone Digit
        elif not phone.isdigit():
            raise serializers.ValidationError(
                {"Phonedigit": _("Phone number must be numeric")})
        # Phone Length
        elif len(phone) < 8 or len(phone) > 12:
            raise serializers.ValidationError(
                {"Phonelength": _("Phone must be bewtween 8  to 12 Characters")})
        # First Name
        elif not re.match("^[a-zA-Z]*$", first_name):
            raise serializers.ValidationError(
                {"FirstName_validation": _("First Name must be alphbet.")})
        # Last Name
        elif not re.match("^[a-zA-Z]*$", last_name):
            raise serializers.ValidationError(
                {"Last_Name_validation": _("Last Name must be alphbet.")})
        # Designation
        elif not re.match("^[a-zA-Z][a-zA-Z\s]*[a-zA-Z]$", designation):
            raise serializers.ValidationError(
                {"designation_validation": _("Designation Name must be alphbet.")})

        return validated_data

    # Create user
    def create(self, validated_data):

        return User.objects.create_superuser(**validated_data)

# Email Verification Serializers


class EmailVerificationSerializers(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ["token"]


# Login User with Email
class UserLoginSerializers(serializers.ModelSerializer):

    email = serializers.EmailField(max_length=100)
    password = serializers.CharField(max_length=25, min_length=6,
                                     write_only=True)

    username = serializers.CharField(max_length=100, read_only=True)
    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        user = User.objects.get(email=obj['phone'])
        return {
            'refresh': user.tokens()['refresh'],
            'access': user.tokens()['access']
        }

    class Meta:
        model = User
        fields = ["email", "password", "username", "country_code",
                  "phone", 'tokens', 'last_login']

        read_only_fields = ['country_code', 'phone', 'last_login']

    def validate(self, attrs):
        email = attrs.get("email", "")
        password = attrs.get("password", "")
        filtered_user_by_email = User.objects.filter(email=email)

        user = auth.authenticate(email=email, password=password)

        if filtered_user_by_email.exists() and filtered_user_by_email[0].auth_provider != 'email':
            raise AuthenticationFailed(
                detail=_('Please continue your login using') + filtered_user_by_email[0].auth_provider)

        # Raise AuthenticationFailed
        if not user:
            raise serializers.ValidationError(
                {"Invalid_Credentials": _('Invalid credentials, try again')})
        elif not user.is_active:
            raise serializers.ValidationError(
                {"IsActive": _('Your Account is disable. Please contact Admin')})
        elif not user.is_verify:
            raise serializers.ValidationError(
                {"Isverify": _('Email is not verified')})
        elif user.is_staff == True or user.is_superuser == True:
            raise serializers.ValidationError(
                {"Is_Admin": _("Admin will not allow to login.")})

        return {
            "username": user.username,
            "email": user.email,
            "tokens": user.tokens,
        }


# Admin Login
class AdminLoginSerializers(serializers.ModelSerializer):

    email = serializers.EmailField(max_length=100)
    password = serializers.CharField(max_length=25, min_length=6,
                                     write_only=True)

    username = serializers.CharField(max_length=100, read_only=True)
    username = serializers.CharField(max_length=100, read_only=True)
    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        user = User.objects.get(email=obj['phone'])
        return {
            'refresh': user.tokens()['refresh'],
            'access': user.tokens()['access']
        }

    class Meta:
        model = User
        fields = ["email", "password", "username", "country_code",
                  "phone", 'tokens',  'last_login']

        read_only_fields = ['country_code', 'phone', 'last_login']

    def validate(self, attrs):
        email = attrs.get("email", "")
        password = attrs.get("password", "")
        # filtered_user_by_email = User.objects.filter(email=email)

        user = auth.authenticate(email=email, password=password)

        # if filtered_user_by_email.exists() and filtered_user_by_email[0].auth_provider != 'email':
        #     raise AuthenticationFailed(
        #         detail=_('Please continue your login using') + filtered_user_by_email[0].auth_provider)

        # Raise AuthenticationFailed
        if not user:
            raise serializers.ValidationError(
                {"Invalid_Credentials": _('Invalid credentials, try again')})
        elif not user.is_active:
            raise serializers.ValidationError(
                {"IsActive": _('Your Account is disable. Please contact Admin')})
        elif not user.is_verify:
            raise serializers.ValidationError(
                {"Isverify": _('Email is not verified')})
        elif not user.is_staff or not user.is_superuser:
            raise serializers.ValidationError(
                {"Normal_User": _('Only, Admin will allow to login.')})

        return {
            "username": user.username,
            "email": user.email,
            "tokens": user.tokens,

        }

# Request Forget Password Through E-Mail


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=1)

    redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['email']


# Set Forget Password
class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=1, max_length=100,
                                     write_only=True)

    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ['password',  'confirm_password', 'token', 'uidb64']

    def validate(self, attrs):

        password = attrs.get('password')

        if len(password) < 6 or len(password) > 25:
            raise serializers.ValidationError({"Password_Length": _(
                "Passwords must be bewtween 6  to 25 Characters.")})

        token = attrs.get('token')
        uidb64 = attrs.get('uidb64')

        id = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(id=id)

        if not PasswordResetTokenGenerator().check_token(user, token):
            # raise AuthenticationFailed(_('The reset link is invalid'), 401)
            raise serializers.ValidationError({"Reset_Link": _(
                "The Reset link is invalid")})

        user.set_password(password)
        user.save()
        return (user)

# Change Password


class UserChangePasswordSerilizer(serializers.Serializer):

    old_password = serializers.CharField(min_length=1, max_length=100,
                                         write_only=True)
    New_password = serializers.CharField(min_length=1, max_length=100,
                                         write_only=True)

    class Meta:
        # model = User
        fields = ["old_password", "New_password"]

    def validate(self, attrs):
        old_password = attrs.get("old_password")
        New_password = attrs.get("New_password")

        if len(New_password) < 6 or len(New_password) > 25:
            raise serializers.ValidationError({"Password_Length": _(
                "Passwords must be bewtween 6  to 25 Characters.")})

        return attrs
