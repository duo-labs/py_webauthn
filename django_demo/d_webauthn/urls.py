"""
   d_webauthn URL Configuration
"""
from django.contrib import admin
from django.urls import path, re_path, include
from django_webauthn.urls import urlpatterns as dw_urls
from django_webauthn.views import ( HomeView )

urlpatterns = [
    re_path(r'^$', view=HomeView.as_view(), name='home'),
    re_path(r'', include(dw_urls)),
    path('admin/', admin.site.urls),
]
