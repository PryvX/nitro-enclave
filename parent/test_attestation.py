import socket
import json
import sys

from protocol import send_json, recv_json

PORT = 5000


def request_attestation(cid):

    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    sock.connect((cid, PORT))

    send_json(sock, {
        "operation": "get_attestation"
    })

    response = recv_json(sock)

    sock.close()

    return response


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage:")
        print("python3 test_attestation.py <ENCLAVE_CID>")
        sys.exit(1)

    enclave_cid = int(sys.argv[1])

    print("=" * 60)
    print("Requesting Attestation Document from Enclave")
    print("=" * 60)

    result = request_attestation(enclave_cid)

    print(json.dumps(result, indent=2))

    if result is None:
        print("\n❌ No response received from enclave.")
        sys.exit(1)

    if "attestation_document" not in result:
        print("\n❌ Enclave did not return an attestation document.")
        sys.exit(1)

    print("\n✅ Attestation document received successfully.")
    print("Document size:", len(result["attestation_document"]), "characters")

    if "public_key" in result:
        print("Enclave public key:", result["public_key"])
