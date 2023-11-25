"""
Imported Packages
"""
from django.contrib import admin


from django.contrib.auth.admin import UserAdmin

from app_admin.models import (
    User,
    Subject,
    Department,
    StaffDetails,
    Address,

)

"""********************** Create your models here **********************"""
'''
Custom User
'''


# User Admin
@admin.register(User)
class UserAdmin(UserAdmin):
    list_display = ['id', 'first_name', 'last_name',
                    'email', 'is_verify', 'is_active', 'designation',]

    # list_filter = ['is_active', 'is_staff', ]

    readonly_fields = ["id",
                       "created_on", "updated_on", 'updated_by']
    fieldsets = (
        # User Informations
        (
            "Register Info:",
            {
                "fields": ("id", "email", "username", 'country_code', "phone", "password")
            }
        ),

        # Personal Informations
        (
            "Personal Info",
            {
                "fields": ("first_name", "last_name", "profile_images"),
            },
        ),

        # Office Informations
        (
            "Office Info",
            {
                "fields": ("designation", ),
            },
        ),

        # Other Informations
        (
            "Other Info",
            {
                "fields": ("auth_provider",),
            },
        ),

        # Login Informations
        (
            "Login Info",
            {
                "fields": ("updated_on", 'updated_by', "created_on", "last_login",),
            },
        ),

        # Permissions
        (
            "Permissions",
            {
                "fields": ("user_permissions", "groups"),
            },
        ),

        # Authentications
        (
            "Authentication",
            {
                "fields": (
                    "is_active",
                    "is_verify",
                    "is_deleted",
                    "user_tnc",
                ),
            },
        ),

        # Admin Login
        (
            "Admin Login",
            {
                "fields": (
                    "is_superuser",
                    "is_staff",
                ),
            },
        ),
    )


@admin.register(Subject)
class SubjectAdmin(admin.ModelAdmin):
    list_display = ["id", "subject_code", "subject_name", "is_active"]


@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ["id", "department_code", "department_name", "is_active"]


@admin.register(StaffDetails)
class StaffAdmin(admin.ModelAdmin):
    list_display = ["user_id", "gender",
                    "department_id", "is_active"]


@admin.register(Address)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ["id", "staff_id", "address_type", "is_active"]
