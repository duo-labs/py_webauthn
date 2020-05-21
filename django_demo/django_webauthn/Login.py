"""
          Login webauthn client
"""
import json
import re
import sys; sys.path.append("../") # noqa

from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.http import (HttpResponse, HttpResponseBadRequest)
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from django.views.generic import View

from django_webauthn import util
from django_webauthn.models import WA_User as wa_user

from webauthn import webauthn

RP_ID = 'localhost'
RP_NAME = 'django-webauthn demo localhost'
ORIGIN = 'https://localhost:8443'
# Trust anchors (trusted attestation roots) should be
# placed in TRUST_ANCHOR_DIR.
TRUST_ANCHOR_DIR = 'trusted_attestation_roots'


class Login(View):
    """
    handle registration options and registration
    """
    template_name = 'login.html'

    @method_decorator(csrf_protect)
    def dispatch(self, *args, **kwargs):
        return super(Login, self).dispatch(*args, **kwargs)

    def __init__(self):
        super(Login, self).__init__()

    def get(self, request, *args, **kwargs):
        pass

    def post(self, request, *args, **kwargs):
        if re.search(r'webauthn_begin_assertion', request.get_full_path(), re.IGNORECASE):
            return self.webauthn_begin_assertion(request)
        elif re.search(r'verify_assertion', request.get_full_path(), re.IGNORECASE):
            return self.verify_assertion(request)
        else:
            return HttpResponseBadRequest(json.dumps('Invalid call.'), content_type='application/json')

    def webauthn_begin_assertion(self, request):
        username = request.POST['auth-username']

        if not util.validate_username(username):
            return HttpResponseBadRequest(json.dumps('Invalid username'),
                                          content_type='application/json')

        user = wa_user.objects.filter(username=username).first()

        if not user:
            return HttpResponseBadRequest(json.dumps('User does not exist.'),
                                          content_type='application/json')
        if not user.credential_id:
            return HttpResponseBadRequest(json.dumps('Unknown credential.'),
                                          content_type='application/json')

        request.session.pop('challenge', None)

        challenge = util.generate_challenge(32)

        # We strip the padding from the challenge stored in the session
        # for the reasons outlined in the comment in webauthn_begin_activate.
        request.session['challenge'] = challenge.rstrip('=')

        webauthn_user = webauthn.WebAuthnUser(
            user.ukey, user.username, user.display_name, user.icon_url,
            user.credential_id, user.pub_key, user.sign_count, user.rp_id)

        webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(
            webauthn_user, challenge)

        return HttpResponse(json.dumps(webauthn_assertion_options.assertion_dict),
                            content_type='application/json')

    def verify_assertion(self, request):
        challenge = request.session.get('challenge')
        assertion_response = request.POST
        credential_id = assertion_response.get('id')

        user = wa_user.objects.filter(credential_id=credential_id).first()
        if not user:
            return HttpResponseBadRequest(json.dumps('User does not exist'),
                                          content_type='application/json')

        webauthn_user = webauthn.WebAuthnUser(
            user.ukey, user.username, user.display_name, user.icon_url,
            user.credential_id, user.pub_key, user.sign_count, user.rp_id)

        webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
            webauthn_user,
            assertion_response,
            challenge,
            ORIGIN,
            uv_required=False)  # User Verification

        try:
            sign_count = webauthn_assertion_response.verify()
        except Exception as e:
            return HttpResponseBadRequest(json.dumps('Assertion failed. Error: {}'.format(e)),
                                          content_type='application/json')

        # Update counter.
        user.sign_count = sign_count
        wa_user.objects.filter(credential_id=credential_id).update(sign_count=sign_count)

        dj_user = User.objects.filter(username=user.username).first()
        login(request, dj_user)

        return HttpResponse(json.dumps('Successfully authenticated as {}'.format(user.username)),
                            content_type='application/json')
