"""
*************************************
        Imported Packages 
*************************************
"""

# Create Custom user Manager
from django.db import models

# Creating Custom User model
from django.contrib.auth.models import BaseUserManager

# Language Translation
from django.utils.translation import gettext_lazy as _

# Decouple
from decouple import config

"""
**************************************************************************
                            Custom User Models 
**************************************************************************
"""

# Create User Manager base on Old User Manager


class UserManager(BaseUserManager):

    # Create User
    def create_user(self, email, username, phone="",  password=None, **extra_fields):

        # if conditions for checking value is not null.
        if not username:
            raise ValueError(_("User should have a UserName"))
        if not phone:
            raise ValueError(_("User should have a Phone"))
        if not email:
            raise ValueError(_("User should have a Email"))

        # For Saving
        user = self.model(email=self.normalize_email(email), username=username, phone=phone,
                          **extra_fields)

        # Password
        user.set_password(password)
        user.is_active = True
        user.is_verify = False
        user.save()
        return user

    # Create SuperUser
    def create_superuser(self, email, username, phone,  password=None, **extra_fields):

        if not password:
            raise ValueError(_("password should not be none"))

        # For Saving Method
        user = self.create_user(email, username, phone, password)

        user.is_active = True
        user.is_verify = True
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user
