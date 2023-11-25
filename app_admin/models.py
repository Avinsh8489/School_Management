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


# Subject
class Subject(models.Model):
    subject_code = models.CharField(max_length=50, unique=True)
    subject_name = models.CharField(max_length=100)

    is_active = models.BooleanField(default=True)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.subject_code}-{self.subject_name}"


# Department
class Department(models.Model):
    department_code = models.CharField(max_length=50, unique=True)
    department_name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.department_code}-{self.department_name}"


# Teacher
class StaffDetails(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE,
                                related_name='userSub',
                                related_query_name='userSubs',
                                limit_choices_to={'is_active': True},)

    main_subject_id = models.ForeignKey(Subject, on_delete=models.CASCADE,
                                        related_name='techerMainSub',
                                        related_query_name='techerMainSubs',
                                        limit_choices_to={'is_active': True},
                                        null=True, blank=True)

    subjects_ids = models.ManyToManyField(Subject)

    date_of_joining = models.DateField(auto_now=False, auto_now_add=False)
    date_of_leaving = models.DateField(auto_now=False, auto_now_add=False)

    gender = models.CharField(max_length=10, choices=[(
        "Male", "Male"), ("Female", "Female"), ("Other", "Other")], default="Male")

    department_id = models.ForeignKey(Department, on_delete=models.CASCADE,
                                      related_name='techerDep',
                                      related_query_name='techerDeps',
                                      limit_choices_to={'is_active': True})

    pan_card = models.CharField(max_length=11, unique=True)
    adhar_card = models.CharField(max_length=16, unique=True)

    is_active = models.BooleanField(default=True)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user_id} {self.department_id}-{self.main_subject_id}"


# Address
class Address(models.Model):

    address_type = models.CharField(max_length=100, choices=[(
        "Permanent ", "Permanent"), ("Current", "Current"), ("Other", "Other")])

    staff_id = models.ForeignKey(User, on_delete=models.CASCADE,
                                 related_name='UserAdd',
                                 related_query_name='UserAdds',
                                 limit_choices_to={'is_active': True})

    address = models.TextField()
    city = models.CharField(max_length=254)
    state = models.CharField(max_length=254)
    country = models.CharField(max_length=50)
    pincode = models.CharField(max_length=10)

    is_active = models.BooleanField(default=True)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.staff_id}-{self.address_type}"
