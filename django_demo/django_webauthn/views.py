from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView


class PublicView(TemplateView):
    template_name = 'public.html'


class PrivateView(LoginRequiredMixin, TemplateView):
    template_name = 'private.html'


class HomeView(TemplateView):
    template_name = 'home.html'


class LoginView(TemplateView):
    template_name = 'login.html'


class RegistrationView(TemplateView):
    template_name = 'registration.html'
