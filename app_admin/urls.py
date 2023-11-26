
from django.contrib import admin
from django.urls import path

from app_admin.views import (
    RegisterView,
    RegisterView,
    VerifyEmailViews,
    UserLoginViews,
    AdminLoginViews,
    RequestPasswordResetEmailViews,
    PasswordTokenCheckAPIViews,
    SetNewPasswordAPIView,
    SubjectListCreateView,
    UpdateDestroyGetStudentView,
    DepartmentListCreate,
    DepartmentUpdateDeteletGet,
    StaffDetailsCreateView,
    StaffDetailsUpdateView,
)
urlpatterns = [
    path("Register-User/", RegisterView.as_view(), name="RegisterUser"),
    path("Register-Admin-User/", RegisterView.as_view(), name="RegisterAdminUser"),
    path("Email-Verify/", VerifyEmailViews.as_view(), name="Email-Verify"),
    path("Login-User/", UserLoginViews.as_view(), name="UserLogin"),
    path("Login-Admin/", AdminLoginViews.as_view(), name="AdminLogin"),
    # Reset Forget Password
    path('Request-Reset-Email/', RequestPasswordResetEmailViews.as_view(),
         name="RequestResetEmail"),
    path('Password-Reset/<uidb64>/<token>/',
         PasswordTokenCheckAPIViews.as_view(), name='passwordResetConfirm'),
    path('Password-Reset-Complete/', SetNewPasswordAPIView.as_view(),
         name='PasswordResetComplete'),

    # Subject
    path("create-list-subject/", SubjectListCreateView.as_view(),
         name="CreateLIstViewSubject"),
    path("Update-get-delete/<int:pk>/", UpdateDestroyGetStudentView.as_view()),

    path("deparmtnet-create-list-subject/", DepartmentListCreate.as_view(),),
    path("deparmtnet-Update-get-delete/<int:pk>/",
         DepartmentUpdateDeteletGet.as_view()),

    path("Create-Staff/", StaffDetailsCreateView.as_view()),
    path("update_staff/<int:pk>/", StaffDetailsUpdateView.as_view())
]
