from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import re_path
from django.views.static import serve

from django_webauthn import Login, Register
from django_webauthn.views import (HomeView, LoginView, PrivateView,
                                   PublicView, RegistrationView)

admin.autodiscover()


urlpatterns = [
    re_path(
         'public.html$',
         PublicView.as_view()
    ),
    re_path(
         'private.html$',
         PrivateView.as_view()
    ),
    re_path(
         'home.html$',
         HomeView.as_view()
    ),
    re_path(
         'webauthn_begin_activate$|verify_credential_info$',
         Register.Register.as_view()
    ),
    re_path(
        r'^account/register/$',
        RegistrationView.as_view()
    ),
    re_path(
         'webauthn_begin_assertion$|verify_assertion$',
         Login.Login.as_view()
    ),
    re_path(
        r'^account/login/$',
        LoginView.as_view(),
        name='login'
    ),
    re_path(r'^account/logout/', auth_views.LogoutView.as_view(), name='logout'),
    # serve static file even when DEBUG = False
    re_path(r'^static/(?P<path>.*)$', serve, {'document_root': settings.STATIC_ROOT}),
]

if settings.DEBUG:
    # Serve static files in debug.
    urlpatterns += static(settings.STATIC_URL,
                          document_root=settings.STATIC_ROOT)
