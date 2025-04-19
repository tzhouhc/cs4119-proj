import json
import socket
from threading import Thread
from time import sleep

from lib.utils import setup_logger

log = setup_logger(2, name=__name__)

Addr = tuple[str, int]
Packet = tuple[bytes, Addr]


class P2P:
    """Generalized P2P actor class."""

    def __init__(self, ip: str, port: int) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.addr = (ip, port)
        self.tracker = None
        self.peers: list[Addr] = []
        self.outbound: list[Packet] = []
        self.inbound: list[Packet] = []
        self.sender_thread: Thread = Thread(target=self.sender_handler, daemon=True)
        self.receiver_thread: Thread = Thread(target=self.receiver_handler, daemon=True)
        self.done = False

    def start(self):
        self.sock.bind(self.addr)
        self.sock.listen(1)
        self.sender_thread.start()
        self.receiver_thread.start()

    def sender_handler(self):
        while not self.done:
            if self.outbound:
                payload, conn = self.outbound.pop(0)
                self.sock.sendto(payload, conn)
            sleep(0.1)

    def receiver_handler(self):
        while not self.done:
            conn, addr = self.sock.accept()
            result = conn.recv(1024)
            self.inbound += [(result, addr)]
            conn.close()
            sleep(0.1)

    def pack(self, data: dict) -> bytes:
        return json.dumps(data).encode()

    def sendto(self, payload: bytes, dest: Addr) -> None:
        self.outbound.append((payload, dest))

    def close(self):
        self.done = True

    def run(self):
        raise NotImplementedError()


class Tracker(P2P):
    """
    Tracker, whose job is to record current clients.

    On receiving JOIN notice or GET request, respond with current active peers
    list.
    On receiving DROP notice, remove peer from list.
    """

    ...


class Peer(P2P):
    """
    Peer.

    On JOIN, notify tracker and GET list of peers.
    On DROP, notify tracker.
    """

    ...
