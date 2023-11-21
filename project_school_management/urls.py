"""
*************************************
        Imported Packages 
*************************************
"""

# By Default
from django.contrib import admin
from django.urls import path, include

# Static File
from django.conf import settings
from django.conf.urls.static import static

# Swagger
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi


# Token For Login
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView
)


"""
*************************************
    Swagger Setting For ULRS
*************************************
"""
schema_view = get_schema_view(
    openapi.Info(
        title="School Management",
        default_version='v1',
        description="Test description",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@snippets.local"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny, ),
)


"""
**************************************************************************
                            ULRS
**************************************************************************
"""

urlpatterns = [

    # Default URL of JWT
    # path("loginjwt/", TokenObtainPairView.as_view(), name="loginjwt"),
    path("refresh/", TokenRefreshView.as_view(), name="refreshtoken"),

    # Swagger
    path('swaggerr(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0),
         name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger',
                                         cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc',
                                       cache_timeout=0), name='schema-redoc'),

    # Django Admin Panel
    path('adminPanel/', admin.site.urls),

    # App Admin Portal
    path("admin/", include("app_admin.urls")),

    # App Agent Portal
    path("student/", include("app_student.urls")),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
