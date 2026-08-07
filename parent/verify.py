import base64
import json
import cbor2

from pycose.messages import CoseMessage

# ----------------------------------------------------
# Load attestation from file
# ----------------------------------------------------

with open("attestation.json") as f:
    response = json.load(f)

doc_b64 = response["attestation_document"]

raw = base64.b64decode(doc_b64)

print("=" * 70)
print("AWS Nitro Attestation Verifier")
print("=" * 70)
print(f"COSE size : {len(raw)} bytes")

# ----------------------------------------------------
# AWS sends an untagged COSE_Sign1
# Wrap it with CBOR tag 18
# ----------------------------------------------------

obj = cbor2.loads(raw)

tagged = cbor2.dumps(cbor2.CBORTag(18, obj))

msg = CoseMessage.decode(tagged)

print("COSE successfully decoded")
print()

print("Protected headers")
print(msg.phdr)
print()

print("Unprotected headers")
print(msg.uhdr)
print()

print("Payload size:", len(msg.payload))
print()

# ----------------------------------------------------
# Decode CBOR payload
# ----------------------------------------------------

payload = cbor2.loads(msg.payload)

print("=" * 70)
print("Decoded Payload")
print("=" * 70)

# ----------------------------------------------------
# helper
# ----------------------------------------------------

def show(name, value):

    print(f"\n{name}")

    if value is None:
        print("None")
        return

    if isinstance(value, bytes):

        if len(value) <= 64:
            print(value.hex())
        else:
            print(f"<{len(value)} bytes>")

    elif isinstance(value, dict):

        for k, v in value.items():

            if isinstance(v, bytes):
                print(f"  {k}: {v.hex()}")
            else:
                print(f"  {k}: {v}")

    elif isinstance(value, list):

        print(f"List ({len(value)} items)")

        for i, item in enumerate(value):
            if isinstance(item, bytes):
                print(f"  [{i}] <{len(item)} bytes>")
            else:
                print(f"  [{i}] {item}")

    else:
        print(value)


# ----------------------------------------------------
# If AWS used integer keys
# ----------------------------------------------------

if all(isinstance(k, int) for k in payload.keys()):

    print("Detected integer-keyed attestation document\n")

    keymap = {
        1: "module_id",
        2: "digest",
        3: "timestamp",
        4: "pcrs",
        5: "certificate",
        6: "cabundle",
        7: "public_key",
        8: "user_data",
        9: "nonce",
    }

    for k in sorted(payload.keys()):

        name = keymap.get(k, f"unknown_{k}")

        show(name, payload[k])

else:

    print("Detected string-keyed attestation document\n")

    for k, v in payload.items():

        show(k, v)

print()
print("=" * 70)
print("Finished")
print("=" * 70)
