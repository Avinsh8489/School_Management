"""
Imported Packages
"""

# By Default
from datetime import datetime
from email.policy import default
from django.db import models

# Custom User
from django.contrib.auth.models import AbstractUser, AnonymousUser

# Import UserManager Model
from app_admin.UserManager import UserManager

# JWT
from rest_framework_simplejwt.tokens import RefreshToken

# Translations
from django.utils.translation import gettext_lazy as _

"""********************** Create your models here **********************"""

"""
******************************************************************************************************************
                                    User
******************************************************************************************************************
"""

AUTH_PROVIDERS = {'email': 'email'}


# Custom User
class User(AbstractUser):

    DesignationList = [
        ("HR", "HR"),
        ("Admin", "Admin"),
        ("Teacher", "Teacher"),
        ("Student", "Student"),
    ]

    # Personal Details and Address , Username, Password
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    username = models.CharField(max_length=50, unique=True)
    country_code = models.CharField(max_length=6)
    phone = models.CharField(max_length=20, unique=True)
    email = models.EmailField(max_length=254, unique=True)
    password = models.CharField(max_length=100)

    # Office
    designation = models.CharField(max_length=50, choices=DesignationList,
                                   default="Admin")

    # Auth Provide
    auth_provider = models.CharField(max_length=255, blank=False, null=False,
                                     default=AUTH_PROVIDERS.get('email'))
    # Verify Account
    is_verify = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)

    # Account Delete
    is_deleted = models.BooleanField(default=False)

    # User Term & Condition
    user_tnc = models.BooleanField(default=False)

    # Admin
    is_staff = models.BooleanField(default=False)

    # Imp Fields
    last_login = models.DateTimeField(blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50)

    # Images
    profile_images = models.ImageField(upload_to='user_profile', null=True)

    # Username & Required Fields
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ["username", 'phone', 'user_tnc']

    # Import Module of UserMagers.py
    objects = UserManager()

    def __unicode__(self):
        return self.id

    def __str__(self):
        name = (self.first_name + " " + self.last_name)
        return (name)
        # return f'{self.review_category} ({self.review_question})'

    # Save Method with Capitalizen
    def save(self, *args, **kwargs):
        for field_name in [
            "first_name",
            "last_name",
            "designation",
            "department",
        ]:
            val = getattr(self, field_name, False)
            if val:
                setattr(self, field_name, val.title())

        super(User, self).save(*args, **kwargs)

    # For Login - LoginSerializers

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {"refresh": str(refresh), "access": str(refresh.access_token)}
