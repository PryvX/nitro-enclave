from protocol import send_json, recv_json
from crypto import encrypt_request
import socket
import sys

ENCLAVE_CID = int(sys.argv[1])
PORT = 5000

# Connect to enclave
sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
sock.connect((ENCLAVE_CID, PORT))

# Step 1: Request enclave public key
send_json(sock, {"operation": "get_public_key"})
response = recv_json(sock)

print("Enclave Public Key:", response["public_key"])

# Step 2: Build plaintext request
request = {
    "operation": "risk_score",
    "payload": {
        "customer_id": "C123",
        "age": 32,
        "income": 75000,
        "existing_loans": 2,
        "late_payments": 1
    }
}

# Step 3: Encrypt it
encrypted_request = encrypt_request(
    response["public_key"],
    request
)

print("Encrypted Request:")
print(encrypted_request)

# Step 4: Send encrypted payload
send_json(sock, encrypted_request)

# Step 5: Receive response
response = recv_json(sock)

print(response)

sock.close()
