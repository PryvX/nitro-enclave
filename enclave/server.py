import json
import socket
import subprocess

from protocol import recv_json, send_json
from risk_engine import process_request
from crypto import crypto

PORT = 5000

server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
server.bind((socket.VMADDR_CID_ANY, PORT))
server.listen()

print("======================================", flush=True)
print("PryvX Enclave Started", flush=True)
print(f"Listening on VSOCK port {PORT}", flush=True)
print("======================================", flush=True)

while True:

    conn, addr = server.accept()

    print("\nClient connected", flush=True)

    try:

        while True:

            request = recv_json(conn)

            if request is None:
                break

            print("\nReceived:", flush=True)
            print(request, flush=True)

            # -------------------------------------------------
            # Public key request (plaintext)
            # -------------------------------------------------
            if request.get("operation") == "get_public_key":

                response = process_request(request)

            # -------------------------------------------------
            # Attestation request (plaintext)
            # -------------------------------------------------
            elif request.get("operation") == "get_attestation":

                output = subprocess.check_output(
                    ["/app/attestation_bridge"],
                    text=True
                )

                attestation = json.loads(output)

                response = {
                    "public_key": crypto.get_public_key(),
                    "attestation_document": attestation["attestation_document"]
                }

            # -------------------------------------------------
            # Everything else is encrypted
            # -------------------------------------------------
            else:

                plaintext = crypto.decrypt(request)

                print("\nDecrypted request:", flush=True)
                print(plaintext, flush=True)

                request = json.loads(plaintext)

                response = process_request(request)

            print("\nSending response:", flush=True)
            print(response, flush=True)

            send_json(conn, response)

    except Exception as e:

        print("\nERROR:", e, flush=True)

    finally:

        print("Client disconnected", flush=True)
        conn.close()
