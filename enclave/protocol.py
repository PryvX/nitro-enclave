import json
import struct


def send_json(sock, obj):
    data = json.dumps(obj).encode("utf-8")
    length = struct.pack(">I", len(data))
    sock.sendall(length + data)


def recv_exact(sock, size):

    data = b""

    while len(data) < size:

        packet = sock.recv(size - len(data))

        if not packet:
            return None

        data += packet

    return data


def recv_json(sock):

    header = recv_exact(sock, 4)

    if header is None:
        return None

    length = struct.unpack(">I", header)[0]

    payload = recv_exact(sock, length)

    if payload is None:
        return None

    return json.loads(payload.decode("utf-8"))
