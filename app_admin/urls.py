
from django.contrib import admin
from django.urls import path

from app_admin.views import (
    RegisterView,
    RegisterView,
    VerifyEmailViews,
    UserLoginViews,
    AdminLoginViews,

)
urlpatterns = [
    path("Register-User/", RegisterView.as_view(), name="RegisterUser"),
    path("Register-Admin-User/", RegisterView.as_view(), name="RegisterAdminUser"),
    path("Email-Verify/", VerifyEmailViews.as_view(), name="Email-Verify"),
    path("Login-User/", UserLoginViews.as_view(), name="UserLogin"),
    path("Login-Admin/", AdminLoginViews.as_view(), name="AdminLogin"),
]
