from unittest import TestCase

from pyasn1.codec.ber.decoder import decode as ber_decode

from webauthn.helpers.asn1.android_key import AuthorizationList, KeyDescription


class TestASN1AndroidKey(TestCase):
    """
    Parsing of the "android-key" attestation extension
    (OID 1.3.6.1.4.1.11129.2.1.17) is defined per the current AOSP schema,
    including fields introduced after version 3 like `mlDsaVariant` ([11])
    for attestations of ML-DSA credentials:

    https://source.android.com/docs/security/keystore/attestation#attestation-v500

    Before the missing fields were defined, parsing such an extension raised
    an error like the one reported for ML-DSA credentials:

        <TagSet object, tags 0:0:2-128:32:11> not in asn1Spec: ...

    See https://github.com/duo-labs/py_webauthn/issues/290
    """

    # KeyDescription of an attestation version 500 (KeyMint 500) extension for
    # an ML-DSA-65 credential. The `teeEnforced` AuthorizationList includes
    # purpose ([1], KM_PURPOSE_SIGN), algorithm ([2]), mlDsaVariant ([11]),
    # origin ([702], KM_ORIGIN_GENERATED), rootOfTrust ([704]), osVersion
    # ([705]), and osPatchLevel ([706]). `softwareEnforced` is empty.
    v500_ml_dsa_key_description_der = bytes.fromhex("""
        3081d0020201f40a0101020201f40a01010420000102030405060708090a
        0b0c0d0e0f101112131415161718191a1b1c1d1e1f0420a1a1a1a1a1a1a1
        a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a13000307aa1
        053103020102a203020141ab03020141bf853e03020100bf85404c304a04
        205b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b
        5b5b5b0101ff0a010004203c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c
        3c3c3c3c3c3c3c3c3c3c3c3c3cbf8541050203027100bf85420502030317
        72
        """)

    # An AuthorizationList exercising the remaining fields of the current
    # schema that were missing here: blockMode ([4]), callerNonce ([7]),
    # minMacLength ([8]), mgfDigest ([203]), earlyBootOnly ([305]),
    # usageCountLimit ([405]), and userSecureId ([502]).
    new_fields_authorization_list_der = bytes.fromhex("""
        3033a4053103020101a7020500a80402020080bf814b053103020104bf82
        31020500bf831503020105bf8376080206011f71fb0843
        """)

    def test_parses_v500_key_description_with_ml_dsa_variant(self) -> None:
        parsed, trailing = ber_decode(
            self.v500_ml_dsa_key_description_der, asn1Spec=KeyDescription()
        )

        assert not trailing
        assert int(parsed["attestationVersion"]) == 500
        assert int(parsed["attestationSecurityLevel"]) == 1
        assert int(parsed["keymasterVersion"]) == 500
        assert int(parsed["keymasterSecurityLevel"]) == 1
        assert bytes(parsed["attestationChallenge"]) == bytes(range(32))
        assert bytes(parsed["uniqueId"]) == bytes([0xA1] * 32)

        tee_enforced = parsed["teeEnforced"]
        assert int(list(tee_enforced["purpose"])[0]) == 2
        assert int(tee_enforced["algorithm"]) == 65
        assert int(tee_enforced["mlDsaVariant"]) == 65
        assert int(tee_enforced["origin"]) == 0
        root_of_trust = tee_enforced["rootOfTrust"]
        assert bytes(root_of_trust["verifiedBootKey"]) == bytes([0x5B] * 32)
        assert root_of_trust["deviceLocked"]
        assert int(root_of_trust["verifiedBootState"]) == 0
        assert bytes(root_of_trust["verifiedBootHash"]) == bytes([0x3C] * 32)
        assert int(tee_enforced["osVersion"]) == 160000
        assert int(tee_enforced["osPatchLevel"]) == 202610

        # An empty softwareEnforced means these optional fields are absent
        assert not parsed["softwareEnforced"]["mlDsaVariant"].hasValue()
        assert not parsed["softwareEnforced"]["rootOfTrust"].hasValue()

    def test_parses_authorization_list_with_previously_missing_fields(self) -> None:
        parsed, trailing = ber_decode(
            self.new_fields_authorization_list_der, asn1Spec=AuthorizationList()
        )

        assert not trailing
        assert int(list(parsed["blockMode"])[0]) == 1
        assert parsed["callerNonce"].hasValue()
        assert int(parsed["minMacLength"]) == 128
        assert int(list(parsed["mgfDigest"])[0]) == 4
        assert parsed["earlyBootOnly"].hasValue()
        assert int(parsed["usageCountLimit"]) == 5
        assert int(parsed["userSecureId"]) == 1234567891011
