import json
import socket
from threading import Thread
from time import sleep
from lib.utils import Addr, setup_logger
from lib.packet import DataPacket, PacketType

log = setup_logger(1, name=__name__)

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
        self.lock = Lock()
        self.buffer = b""

    def start(self):
        self.sock.bind(self.addr)
        self.sock.listen(1)
        self.sender_thread.start()
        self.receiver_thread.start()

    def sender_handler(self):
        """
        Checks the outbound queue and sends messages over TCP
        """
        while not self.done:
            if self.outbound:
                with self.lock:
                    payload, dest = self.outbound.pop(0)
                try:
                    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    temp_sock.connect(dest)
                    temp_sock.sendall(payload)
                    temp_sock.close()
                except Exception as e:
                    log.error(f"Failed to send packet to {dest}: {e}")
            sleep(0.1)

    def receiver_handler(self):
        """
        Accepts incoming connections and creates the threads to handle them 
        """
        while not self.done:
            try:
                conn, addr = self.sock.accept()
                Thread(target=self.handle_connection, args=(conn, addr), daemon=True).start()
            except Exception as e:
                log.error(f"Error accepting the connection: {e}")
    def connection_handler(self, conn: socket.socket, addr: Addr):
        """
        Handles the incoming socket connection and buffers the incoming data until complete 
        JSON received 

        Parameters:
            conn : socket.socket
                The accepted socket connection from a peer.
            addr : Addr
                The address tuple (IP, port) of the connected peer.

        Returns:
            None
        """
        try:
            buffer = b""
            while not self.done:
                data = conn.recv(4096)
                if not data:
                    break
                buffer += data
                while True:
                    try:
                        # Decode one full JSON object
                        message, idx = json.JSONDecoder().raw_decode(buffer.decode())
                        buffer = buffer[idx:].lstrip().encode()
                        with self.lock:
                            self.inbound.append((json.dumps(message).encode(), addr))
                    except json.JSONDecodeError:
                        # data imcomplete, wait for more
                        break
        except Exception as e:
            log.error(f"Error handling connection from {addr}: {e}")
        finally:
            conn.close()

    def pack(self, data: dict) -> bytes:
        """
        Encodes a Python dict into a JSON formatted byte string

        Parameters:
            data : dict
                The dictionary to encode 

        Returns:
            bytes
                The encoded JSON byte string 
        
        """
        return json.dumps(data).encode()

    def sendto(self, payload: bytes, dest: Addr) -> None:
        """
        Adds a packet to the outbound queue to be sent by the sender thread

        Parameters:
            payload : bytes
                The JSON-encoded payload to send 
            dest : Addr
                The destination address tuple (IP, port) 

        Returns:
            None
        """
        with self.lock:
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
