import socket
import time
from lib.packet import DataPacket, PacketType

HOST = '127.0.0.1'
PORT = 65432

def client_send():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # First packet: simulate split send
    p1 = DataPacket()
    p1.data["type"] = PacketType.PEER_LIST_REQUEST
    p1.data["message"] = "hello world"
    encoded1 = p1.as_bytes()

    part1 = encoded1[:10]  # first 10 bytes
    part2 = encoded1[10:]  # rest

    s.sendall(part1)
    time.sleep(1)  # simulate slow stream
    s.sendall(part2)

    # Second packet: just send normally
    p2 = DataPacket()
    p2.data["type"] = PacketType.PEER_LIST
    p2.data["tracker"] = ("127.0.0.1", 10000)
    p2.data["peers"] = [("127.0.0.1", 10001)]
    s.sendall(p2.as_bytes())

    s.close()

if __name__ == "__main__":
    client_send()

