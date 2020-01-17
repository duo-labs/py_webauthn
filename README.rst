
PyWebAuthn
==========


.. image:: https://img.shields.io/pypi/v/webauthn.svg
   :target: https://pypi.python.org/pypi/webauthn
   :alt: PyPI


.. image:: https://img.shields.io/badge/license-BSD-blue.svg
   :target: https://raw.githubusercontent.com/duo-labs/py_webauthn/master/LICENSE
   :alt: GitHub license


PyWebAuthn is a Python module which can be used to handle `WebAuthn <https://www.w3.org/TR/webauthn/>`_ registration and assertion. Currently, WebAuthn is supported in `Firefox <https://www.mozilla.org/en-US/firefox/new/>`_\ , `Chrome <https://www.google.com/chrome/>`_\ , and `Edge <https://www.microsoft.com/en-us/windows/microsoft-edge>`_.

Installation
============

``pip install webauthn``

Usage
=====

Generating credential options, (to be passed to ``navigator.credentials.create``\ ):

.. code-block:: python

   make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
       challenge,
       rp_name,
       rp_id,
       user_id,
       username,
       display_name,
       icon_url)

Creating a ``WebAuthnUser`` object. Used during the assertion (login) process:

.. code-block:: python

   webauthn_user = webauthn.WebAuthnUser(
       user.id,
       user.username,
       user.display_name,
       user.icon_url,
       user.credential_id,
       user.pub_key,
       user.sign_count,
       user.rp_id)

Generating assertion options, (to be passed to ``navigator.credentials.get``\ ):

.. code-block:: python

   webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(
       webauthn_user,
       challenge)

Verifying a registration response, (result of ``navigator.credentials.create``\ ):

.. code-block:: python

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
       return jsonify({'fail': 'Registration failed. Error: {}'.format(e)})

   # Create User

Verifying an assertion response, (result of ``navigator.credentials.get``\ ):

.. code-block:: python

   webauthn_user = webauthn.WebAuthnUser(
       user.ukey,
       user.username,
       user.display_name,
       user.icon_url,
       user.credential_id,
       user.pub_key,
       user.sign_count,
       user.rp_id)

   webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
       webauthn_user,
       assertion_response,
       challenge,
       origin,
       uv_required=False)  # User Verification

   try:
       sign_count = webauthn_assertion_response.verify()
   except Exception as e:
       return jsonify({'fail': 'Assertion failed. Error: {}'.format(e)})

   # Update counter.
   user.sign_count = sign_count

Flask Demo
==========

There is a `Flask <http://flask.pocoo.org/>`_ demo available in the ``flask_demo`` directory. Follow these steps to run the Flask web app:


#. ``cd flask_demo``
#. ``pip install -r requirements.txt``
#. ``python create_db.py``
#. ``python app.py``
#. Go to `https://localhost:5000 <https://localhost:5000>`_ in your web browser. Try registering and logging in with a compatible U2F or WebAuthn authenticator.
#. Profit?

Flask Demo (Docker)
===================

To run the `Flask <http://flask.pocoo.org/>`_ demo with `Docker <https://www.docker.com/>`_\ :


#. Install Docker.
#. ``docker-compose up -d``
#. Go to `https://localhost:5000 <https://localhost:5000>`_ in your web browser. Try registering and logging in with a compatible U2F or WebAuthn authenticator.

Demo Troubleshooting
====================
By default, both the local and Docker demos try to run the web app using HTTPS. This may cause issues such as
``NET::ERR_CERT_AUTHORITY_INVALID`` on Chrome. To get around this issue on Chrome, you can do the following:

#. Generate a self-signed certificate through tools like mkcert_
#. Enable requests to localhost over HTTPS through the following flag: ``chrome://flags/#allow-insecure-localhost``.

For Firefox, you should be able to proceed to the page being served by the Flask app by doing the following:

#. Clicking 'Advanced'
#. Clicking 'Accept the Risk and Continue'.

.. _mkcert: https://github.com/FiloSottile/mkcert

Unit Tests
==========

To run the unit tests, use the following command:

``python3 -m unittest tests/webauthn_test.py``

Note
====

Currently, PyWebAuthn does not support performing the following verifications.


* `Token Binding ID <https://www.w3.org/TR/webauthn/#dom-collectedclientdata-tokenbindingid>`_
* `Authenticator Extensions <https://www.w3.org/TR/webauthn/#dom-collectedclientdata-authenticatorextensions>`_
