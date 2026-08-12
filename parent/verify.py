#!/usr/bin/env python3

import base64
import json
import sys

import cbor2

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


ATTESTATION_FILE = "/home/ec2-user/nitro-demo/parent/attestation.json"
ROOT_CERT_FILE = "/home/ec2-user/nitro-demo/parent/certs/root.pem"


# ============================================================
# Load attestation
# ============================================================

def load_attestation():

    with open(ATTESTATION_FILE, "r") as f:
        data = json.load(f)

    if "attestation_document" not in data:
        raise ValueError(
            "attestation_document missing from attestation.json"
        )

    return base64.b64decode(
        data["attestation_document"]
    )


# ============================================================
# Decode COSE_Sign1
# ============================================================

def parse_cose(raw):

    obj = cbor2.loads(raw)

    print("COSE size:", len(raw), "bytes")
    print("Top-level type:", type(obj))
    print("Top-level length:", len(obj))

    if not isinstance(obj, list):
        raise ValueError("COSE object is not a list")

    if len(obj) != 4:
        raise ValueError(
            f"Expected COSE_Sign1 with 4 elements, got {len(obj)}"
        )

    protected = obj[0]
    unprotected = obj[1]
    payload = obj[2]
    signature = obj[3]

    print("✓ COSE_Sign1 structure decoded")

    return protected, unprotected, payload, signature


# ============================================================
# Verify certificate chain
# ============================================================

def verify_certificate_signature(child, issuer):

    issuer_public_key = issuer.public_key()

    if not isinstance(
        issuer_public_key,
        ec.EllipticCurvePublicKey
    ):
        raise ValueError(
            "Issuer certificate does not contain an EC public key"
        )

    issuer_public_key.verify(
        child.signature,
        child.tbs_certificate_bytes,
        ec.ECDSA(child.signature_hash_algorithm),
    )


def verify_certificate_chain(payload):

    print()
    print("=" * 60)
    print("Verifying Nitro Certificate Chain")
    print("=" * 60)

    # --------------------------------------------------------
    # Leaf certificate
    # --------------------------------------------------------

    leaf_der = payload["certificate"]

    leaf = x509.load_der_x509_certificate(
        leaf_der
    )

    print()
    print("Leaf certificate:")
    print("  Subject:", leaf.subject)
    print("  Issuer :", leaf.issuer)

    # --------------------------------------------------------
    # Embedded CA bundle
    #
    # AWS documents this as:
    #
    # [ ROOT, INTERMEDIATE_1, ..., INTERMEDIATE_N ]
    # --------------------------------------------------------

    cabundle = payload["cabundle"]

    print()
    print("CA bundle certificates:", len(cabundle))

    certificates = []

    for i, cert_bytes in enumerate(cabundle):

        cert = x509.load_der_x509_certificate(
            cert_bytes
        )

        certificates.append(cert)

        print()
        print(f"CA bundle [{i}]")
        print("  Subject:", cert.subject)
        print("  Issuer :", cert.issuer)

    # --------------------------------------------------------
    # Load our trusted AWS Nitro root
    # --------------------------------------------------------

    with open(ROOT_CERT_FILE, "rb") as f:
        trusted_root = x509.load_pem_x509_certificate(
            f.read()
        )

    print()
    print("Trusted AWS Nitro root:")
    print("  Subject:", trusted_root.subject)
    print("  Issuer :", trusted_root.issuer)

    # --------------------------------------------------------
    # Find root in CA bundle
    # --------------------------------------------------------

    root_found = False
    root_index = None

    for i, cert in enumerate(certificates):

        if (
            cert.subject == trusted_root.subject
            and cert.public_key().public_bytes(
                encoding=__import__(
                    "cryptography.hazmat.primitives.serialization",
                    fromlist=["Encoding"]
                ).Encoding.DER,
                format=__import__(
                    "cryptography.hazmat.primitives.serialization",
                    fromlist=["PublicFormat"]
                ).PublicFormat.SubjectPublicKeyInfo,
            )
            ==
            trusted_root.public_key().public_bytes(
                encoding=__import__(
                    "cryptography.hazmat.primitives.serialization",
                    fromlist=["Encoding"]
                ).Encoding.DER,
                format=__import__(
                    "cryptography.hazmat.primitives.serialization",
                    fromlist=["PublicFormat"]
                ).PublicFormat.SubjectPublicKeyInfo,
            )
        ):
            root_found = True
            root_index = i
            break

    if not root_found:
        raise ValueError(
            "Trusted AWS Nitro root was not found in attestation CA bundle"
        )

    print()
    print(f"✓ AWS Nitro root found in CA bundle at index {root_index}")

    # --------------------------------------------------------
    # Validate root itself
    # --------------------------------------------------------

    trusted_root.public_key().verify(
        trusted_root.signature,
        trusted_root.tbs_certificate_bytes,
        ec.ECDSA(trusted_root.signature_hash_algorithm),
    )

    print("✓ AWS Nitro root self-signature verified")

    # --------------------------------------------------------
    # Build chain.
    #
    # Leaf issuer should match one of the CA certificates.
    # --------------------------------------------------------

    current = leaf

    chain = []

    while True:

        if current.issuer == trusted_root.subject:

            issuer = trusted_root

        else:

            issuer = None

            for candidate in certificates:

                if current.issuer == candidate.subject:

                    issuer = candidate
                    break

            if issuer is None:

                raise ValueError(
                    "Could not find issuer for certificate:\n"
                    + str(current.subject)
                )

        # Don't add the trusted root twice.
        chain.append((current, issuer))

        # Verify current certificate against issuer.
        verify_certificate_signature(
            current,
            issuer
        )

        print()
        print("✓ Certificate verified")
        print("  Child :", current.subject)
        print("  Issuer:", issuer.subject)

        if issuer.subject == trusted_root.subject:
            break

        current = issuer

    print()
    print("✓ Complete certificate chain verified")
    print("✓ Chain terminates at trusted AWS Nitro root")

    return leaf


# ============================================================
# Convert COSE ECDSA signature
# ============================================================

def cose_es384_to_der(signature):

    """
    COSE ECDSA signatures are:

        R || S

    For ES384:

        R = 48 bytes
        S = 48 bytes

    Python cryptography expects ASN.1 DER encoded
    ECDSA signatures.
    """

    if len(signature) != 96:

        raise ValueError(
            f"Expected 96-byte ES384 signature, got {len(signature)}"
        )

    r = int.from_bytes(
        signature[:48],
        byteorder="big"
    )

    s = int.from_bytes(
        signature[48:],
        byteorder="big"
    )

    return encode_dss_signature(r, s)


# ============================================================
# Verify COSE signature
# ============================================================

def verify_cose_signature(
    protected,
    payload_bytes,
    signature,
    leaf
):

    print()
    print("=" * 60)
    print("Verifying COSE Signature")
    print("=" * 60)

    # --------------------------------------------------------
    # COSE Sig_structure
    #
    # [
    #     "Signature1",
    #     protected,
    #     external_aad,
    #     payload
    # ]
    # --------------------------------------------------------

    sig_structure = [
        "Signature1",
        protected,
        b"",
        payload_bytes,
    ]

    signing_bytes = cbor2.dumps(
        sig_structure
    )

    print()
    print("Protected header size:", len(protected))
    print("Payload size:", len(payload_bytes))
    print("COSE signature size:", len(signature))
    print("Sig_structure size:", len(signing_bytes))

    # --------------------------------------------------------
    # Convert COSE raw R||S to DER
    # --------------------------------------------------------

    der_signature = cose_es384_to_der(
        signature
    )

    print(
        "Converted ES384 signature to DER:",
        len(der_signature),
        "bytes"
    )

    # --------------------------------------------------------
    # Get public key from Nitro leaf certificate
    # --------------------------------------------------------

    public_key = leaf.public_key()

    if not isinstance(
        public_key,
        ec.EllipticCurvePublicKey
    ):
        raise ValueError(
            "Nitro certificate does not contain an EC public key"
        )

    # --------------------------------------------------------
    # Verify
    # --------------------------------------------------------

    public_key.verify(
        der_signature,
        signing_bytes,
        ec.ECDSA(hashes.SHA384()),
    )

    print()
    print("✓ COSE ES384 signature verified")

    return True


# ============================================================
# Display attestation payload
# ============================================================

def print_attestation_payload(payload):

    print()
    print("=" * 60)
    print("Verified Nitro Attestation Payload")
    print("=" * 60)

    print()
    print("module_id:")
    print(payload.get("module_id"))

    print()
    print("digest:")
    print(payload.get("digest"))

    print()
    print("timestamp:")
    print(payload.get("timestamp"))

    print()
    print("PCRs:")

    pcrs = payload.get("pcrs", {})

    for index in sorted(pcrs):

        value = pcrs[index]

        if isinstance(value, bytes):
            value = value.hex()

        print(
            f"  PCR{index}: {value}"
        )

    print()

    public_key = payload.get("public_key")

    if public_key is not None:

        print("public_key:")

        if isinstance(public_key, bytes):
            print(public_key.hex())
        else:
            print(public_key)

    else:

        print("public_key: None")

    print()

    nonce = payload.get("nonce")

    if nonce is not None:

        print("nonce:")

        if isinstance(nonce, bytes):
            print(nonce.hex())
        else:
            print(nonce)

    else:

        print("nonce: None")

    print()

    user_data = payload.get("user_data")

    if user_data is not None:

        print("user_data:")

        if isinstance(user_data, bytes):
            print(user_data.hex())
        else:
            print(user_data)

    else:

        print("user_data: None")


# ============================================================
# Main
# ============================================================

def main():

    print()
    print("=" * 60)
    print("AWS Nitro Attestation Verification")
    print("=" * 60)
    print()

    try:

        # 1. Load attestation
        raw = load_attestation()

        # 2. Decode COSE
        (
            protected,
            unprotected,
            payload_bytes,
            signature
        ) = parse_cose(raw)

        # 3. Decode protected headers
        protected_headers = cbor2.loads(
            protected
        )

        print()
        print("Protected headers:")
        print(protected_headers)

        print()
        print("Unprotected headers:")
        print(unprotected)

        # Confirm ES384
        algorithm = protected_headers.get(1)

        if algorithm != -35:

            raise ValueError(
                f"Unexpected COSE algorithm: {algorithm}"
            )

        print()
        print("✓ COSE algorithm: ES384 (-35)")

        # 4. Decode Nitro payload
        payload = cbor2.loads(
            payload_bytes
        )

        if not isinstance(payload, dict):

            raise ValueError(
                "Nitro payload is not a CBOR map"
            )

        print()
        print("✓ Nitro attestation payload decoded")

        # 5. Verify certificate chain
        leaf = verify_certificate_chain(
            payload
        )

        # 6. Verify COSE signature
        verify_cose_signature(
            protected,
            payload_bytes,
            signature,
            leaf
        )

        # 7. Display measurements
        print_attestation_payload(
            payload
        )

        # 8. SUCCESS

        print()
        print("=" * 60)
        print("✅ ATTESTATION VERIFICATION SUCCESS")
        print("=" * 60)
        print()
        print("AWS Nitro certificate chain: VERIFIED")
        print("COSE ES384 signature:        VERIFIED")
        print("Attestation document:        AUTHENTIC")
        print()

    except Exception as e:

        print()
        print("=" * 60)
        print("❌ VERIFICATION FAILED")
        print("=" * 60)
        print()
        print(
            type(e).__name__ + ":",
            e
        )
        print()

        sys.exit(1)


if __name__ == "__main__":
    main()
