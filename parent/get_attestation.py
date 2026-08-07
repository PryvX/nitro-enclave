import json
import socket
import sys

from protocol import send_json, recv_json

PORT = 5000


def get_attestation(cid):

    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.connect((cid, PORT))

    send_json(sock, {
        "operation": "get_attestation"
    })

    response = recv_json(sock)

    sock.close()

    return response


cid = int(sys.argv[1])

result = get_attestation(cid)

with open("attestation.json", "w") as f:
    json.dump(result, f, indent=2)

print("Saved attestation.json")
