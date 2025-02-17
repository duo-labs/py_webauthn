from typing import List, Optional
import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import (
    load_der_x509_certificate,
    load_pem_x509_certificate,
    UnsupportedGeneralNameType,
)
from cryptography.x509.verification import Store, PolicyBuilder, VerificationError, ExtensionPolicy

from .exceptions import InvalidCertificateChain


def validate_certificate_chain(
    *,
    x5c: List[bytes],
    pem_root_certs_bytes: Optional[List[bytes]] = None,
    time: Optional[datetime.datetime] = None,
) -> bool:
    """Validate that the certificates in x5c chain back to a known root certificate

    Args:
        `x5c`: X5C certificates from a registration response's attestation statement
        (optional) `pem_root_certs_bytes`: Any additional (PEM-formatted)
        root certificates that may complete the certificate chain
        (optional) `time`: Sets the verifier’s verification time. If not called
        explicitly, this is set to `datetime.datetime.now()`.

    Raises:
        `helpers.exceptions.InvalidCertificateChain` if chain cannot be validated
    """
    if time is None:
        time = datetime.datetime.now(datetime.timezone.utc)

    if pem_root_certs_bytes is None or len(pem_root_certs_bytes) < 1:
        # We have no root certs to chain back to, so just pass on validation
        return True

    # Make sure we have at least one certificate to try and link back to a root cert
    if len(x5c) < 1:
        raise InvalidCertificateChain("x5c was empty")

    # Prepare leaf cert
    try:
        leaf_cert_bytes = x5c[0]
        leaf_cert = load_der_x509_certificate(leaf_cert_bytes, default_backend())
    except Exception as err:
        raise InvalidCertificateChain(f"Could not prepare leaf cert: {err}")

    # Prepare any intermediate certs
    try:
        # May be an empty array, that's fine
        intermediate_certs_bytes = x5c[1:]
        intermediate_certs = [
            load_der_x509_certificate(cert, default_backend()) for cert in intermediate_certs_bytes
        ]
    except Exception as err:
        raise InvalidCertificateChain(f"Could not prepare intermediate certs: {err}")

    # Prepare a collection of possible root certificates
    root_certs = []
    try:
        for cert in pem_root_certs_bytes:
            root_certs.append(load_pem_x509_certificate(cert))
    except Exception as err:
        raise InvalidCertificateChain(f"Could not prepare root certs: {err}")
    root_certs_store = Store(root_certs)

    # Load certs into a verifier for validation
    # FIXME: Add needed extension requirements.
    extension_policy = ExtensionPolicy.permit_all()
    verifier = (
        PolicyBuilder()
        .store(root_certs_store)
        .time(time)
        .extension_policies(
            new_ca_policy=extension_policy,
            new_ee_policy=extension_policy,
        )
        .build_client_verifier()
    )

    # Validate the chain (will raise if it can't)
    try:
        verifier.verify(leaf_cert, intermediate_certs)
    except (VerificationError, UnsupportedGeneralNameType) as e:
        raise InvalidCertificateChain("Certificate chain could not be validated") from e

    return True
