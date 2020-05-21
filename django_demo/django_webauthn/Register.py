"""
          Register webauthn client
"""
import json
import os
import pytz
import re
import sys; sys.path.append("../") # noqa

from datetime import datetime
from django.contrib.auth.models import User
from django.db import Error
from django.http import (HttpResponse, HttpResponseBadRequest,
                         HttpResponseNotModified, HttpResponseServerError)
from django.utils.decorators import method_decorator
from django.utils import timezone
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
DEBUG = True


class Register(View):
    """
    handle registration options and registration
    """

    @method_decorator(csrf_protect)
    def dispatch(self, *args, **kwargs):
        return super(Register, self).dispatch(*args, **kwargs)

    def __init__(self):
        super(Register, self).__init__()

    def get(self, request, *args, **kwargs):
        pass

    def post(self, request, *args, **kwargs):
        if re.search(r'webauthn_begin_activate', request.get_full_path(), re.IGNORECASE):
            return self.webauthn_begin_activate(request)
        elif re.search(r'verify_credential_info', request.get_full_path(), re.IGNORECASE):
            return self.verify_credential_info(request)
        else:
            return HttpResponseBadRequest(json.dumps('Invalid call.'), content_type='application/json')

    def webauthn_begin_activate(self, request):
        """
        move client(s) and assoc recs to archive tables, then delete from
        current tables
        """
        # MakeCredentialOptions
        username = request.POST['auth-username']
        display_name = request.POST['auth-dispname']

        if not util.validate_username(username):
            return HttpResponseBadRequest(json.dumps('Invalid username'),
                                          content_type='application/json')
        if not util.validate_display_name(display_name):
            return HttpResponseBadRequest(json.dumps('Invalid display name'),
                                          content_type='application/json')

        if wa_user.objects.filter(username=username).first():
            return HttpResponseBadRequest(json.dumps('User already exists.'),
                                          content_type='application/json')

        # clear session variables prior to starting a new registration
        request.session.pop('register_ukey', None)
        request.session.pop('register_username', None)
        request.session.pop('register_display_name', None)
        request.session.pop('challenge', None)

        request.session['register_username'] = username
        request.session['register_display_name'] = display_name

        challenge = util.generate_challenge(32)
        ukey = util.generate_ukey()

        # We strip the saved challenge of padding, so that we can do a byte
        # comparison on the URL-safe-without-padding challenge we get back
        # from the browser.
        # We will still pass the padded version down to the browser so that the JS
        # can decode the challenge into binary without too much trouble.
        request.session['challenge'] = challenge.rstrip('=')
        request.session['register_ukey'] = ukey

        make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
            challenge, RP_NAME, RP_ID, ukey, username, display_name,
            'https://example.com')

        return HttpResponse(json.dumps(make_credential_options.registration_dict),
                            content_type='application/json')

    def verify_credential_info(self, request, *args, **kwargs):
        challenge = request.session['challenge']
        username = request.session['register_username']
        display_name = request.session['register_display_name']
        ukey = request.session['register_ukey']

        registration_response = request.POST
        trust_anchor_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), TRUST_ANCHOR_DIR)
        trusted_attestation_cert_required = True
        self_attestation_permitted = True
        none_attestation_permitted = True

        webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
            RP_ID,
            ORIGIN,
            registration_response,
            challenge,
            trust_anchor_dir,
            trusted_attestation_cert_required,
            self_attestation_permitted,
            none_attestation_permitted,
            uv_required=False)  # User Verification

        try:
            webauthn_credential = webauthn_registration_response.verify()
        except Exception as e:
            return HttpResponseBadRequest(json.dumps('{}'.format(e)),
                                          content_type='application/json')

        # Step 17.
        #
        # Check that the credentialId is not yet registered to any other user.
        # If registration is requested for a credential that is already registered
        # to a different user, the Relying Party SHOULD fail this registration
        # ceremony, or it MAY decide to accept the registration, e.g. while deleting
        # the older registration.
        credential_id_exists = wa_user.objects.filter(
            credential_id=webauthn_credential.credential_id).first()
        if credential_id_exists:
            return HttpResponseNotModified(json.dumps('Credential ID already exists.'),
                                           content_type='application/json')

        existing_user = wa_user.objects.filter(username=username).first()
        if not existing_user:
            if sys.version_info >= (3, 0):
                webauthn_credential.credential_id = str(
                    webauthn_credential.credential_id, "utf-8")
                webauthn_credential.public_key = str(
                    webauthn_credential.public_key, "utf-8")
            auth_user = User.objects.create(password='none',
                                            is_superuser=False,
                                            username=username,
                                            first_name='none',
                                            last_name='none',
                                            email='none',
                                            is_staff=False,
                                            is_active=True,
                                            date_joined=timezone.now())
            user = wa_user(
                user_id=auth_user.id,
                ukey=ukey,
                username=username,
                display_name=display_name,
                pub_key=webauthn_credential.public_key,
                credential_id=webauthn_credential.credential_id,
                sign_count=webauthn_credential.sign_count,
                rp_id=RP_ID,
                icon_url='https://example.com')

            try:
                user.save()
            except Error as e:
                User.objects.filter(id=auth_user.id).delete()
                return HttpResponseServerError(e, content_type='application/json')

        else:
            return HttpResponseNotModified(json.dumps('User already exists.'),
                                           content_type='application/json')

        return HttpResponse(json.dumps('User successfully registered'),
                            content_type='application/json')
