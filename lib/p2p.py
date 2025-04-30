import json
import socket
from threading import Lock, Thread
from time import sleep
from lib.llm import LLMContentProvider
from lib.blockchain import BlockChain, Block
from lib.packet import (
    AnnouncementPacket,
    BlockUpdatePacket,
    DataPacket,
    PeerListPacket,
    PeerListRequestPacket,
    RedirectPacket
)
from lib.utils import Addr, setup_logger

log = setup_logger(1, name=__name__)

Packet = tuple[bytes, Addr]

PEER = 0
TRACKER = 1


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
        self.decoder = json.JSONDecoder()

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
                    log.info(f"Sent packet to {dest}")
                except ConnectionAbortedError:
                    log.debug("Connected aborted presumably due to close.")
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
                Thread(
                    target=self.handle_connection, args=(conn, addr), daemon=True
                ).start()
            except ConnectionAbortedError:
                log.debug("Connected aborted presumably due to close.")
            except Exception as e:
                log.error(f"Error accepting the connection: {e}")

    def handle_connection(self, conn: socket.socket, addr: Addr):
        """
        Handles the incoming socket connection and buffers the incoming data
        until complete JSON received

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
                        decoded = buffer.decode()
                        message, idx = self.decoder.raw_decode(decoded)
                        remaining = decoded[idx:].lstrip()
                        buffer = remaining.encode()
                        packet = DataPacket.from_dict(message)
                        with self.lock:
                            self.inbound.append((json.dumps(message).encode(), addr))
                        log.info(f"Received packet from {addr}: {packet.data}")
                        print(f"Received complete JSON from {addr}")
                    except json.JSONDecodeError:
                        break
        except ConnectionAbortedError:
            log.debug("Connected aborted presumably due to close.")
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
        log.info(f"Queued packet to {dest}: {payload}")

    def close(self):
        """
        Close the connection and terminate current activities; does NOT block.

        This will terminate any ongoing socket wait or read/write, but
        will let threads finish their last loop.

        Returns:
            None
        """
        self.done = True
        # terminate connection; does NOT wait for thread finish. As such, this
        # method does not block.
        self.sock.close()

    def run(self):
        raise NotImplementedError()

    def stop(self):
        raise NotImplementedError()


class Tracker(P2P):
    """
    Tracker, whose job is to record current clients.

    On receiving JOIN notice or GET request, respond with current active peers
    list.
    On receiving DROP notice, remove peer from list.
    """

    def state(self) -> int:
        """Test method, returns current state representation int."""
        return TRACKER


class Peer(P2P):
    """
    Peer.

    On JOIN, notify tracker and GET list of peers.
    On DROP, notify tracker.
    """
    def __init__(self, ip: str, port: int):
        super().__init__(ip, port) # inherit
        self.auto_respond_thread = Thread(target=self.responder_thread, daemon=True) #create thread
        self.mine_thread = Thread(target=self.miner_thread, daemon=True)
        self.peers = set()
        self.block = None
        self.content_provider = LLMContentProvider()

    def start(self):
        """
        Start active components of Peer class, including two threads. 
        """
        super().start()
        self.auto_respond_thread.start()
        self.mine_thread.start()

        # initial request
        pkt = PeerListRequestPacket()
        self.send_packet(pkt, self.tracker)

    def respond(self, msg: dict, src: Addr) -> None:
        """
        Actual responding method that takes data dict, interpret as a
        DataPacket, then appropriately validate and respond to it, performing
        any state changes in the process as necessary.
        """
        pkt = None
        # check for valid packet
        try:
            pkt = DataPacket.from_dict(msg)
        except ValueError as e:
            log.warning(f"Failed to interpret packet: {e}")
        # valid packet, respond 
        if isinstance(pkt, PeerListRequestPacket) or isinstance(pkt, BlockUpdatePacket):
            # send redirect
            pkt = RedirectPacket(self.tracker)
            self.send_packet(pkt, src)
        elif isinstance(pkt, RedirectPacket):
            # update tracker
            self.tracker = pkt.data["tracker"]
            # resend PeerListRequest
            pkt = PeerListRequestPacket()
            self.send_packet(pkt, self.tracker)
        elif isinstance(pkt, PeerListPacket):
            # update peer list
            self.peers = set(pkt["peers"])
            # update tracker
            self.tracker = set(pkt["tracker"])
        elif isinstance(pkt, AnnouncementPacket):
            # get new chain
            new_chain = pkt["chain"]
            # check if valid
            if not new_chain.is_valid(): #invalid chain
                return
            else:  
                # stop current mining process
                if self.block:
                    self.block.set_stop_mining(True)
                # update
                self.chain = pkt["chain"]
                self.tracker = pkt["tracker"]

    def responder_thread(self) -> None:
        """
        Responder thread, which handles repeatedly receiving packets and
        handling them based on type.
        """
        while not self.done:
            if self.inbound:
                msg, src = self.inbound.pop(0)
                data = json.loads(msg.decode())
                self.respond(data, src)
            else:
                sleep(0.1)


    def miner_thread(self): 
        """
        Miner thread, mines block and once found broadcasts to peers.
        """
        while not self.done: 
            # check for chain
            if not self.chain:
                self.chain = BlockChain()
            # make new Block
            tail = self.chain.tail()
            if tail:
                prev_hash = tail.hash
            else:
                prev_hash = ""
            new_block = Block(b"hello", prev_hash) # TODO: LLM block payload
            self.mining_block = new_block
            # mine Block
            new_block.mine()
            # check if sucessful (not interrupted)
            if not new_block.done:
                self.mining_block = None
                continue
            # append to chain
            try:
                self.chain.append(new_block)
            except ValueError as e:
                self.mining_block = None
                continue
            # broadcast Block
            pkt = BlockUpdatePacket(self.chain)
            self.send_packet(pkt, self.tracker)
            # reset
            self.block = None

    def state(self) -> int:
        """Test method, returns current state representation int."""
        return PEER


class TrackerPeer(Tracker, Peer):

    def __init__(self, ip: str, port: int, state=PEER):
        P2P.__init__(self, ip, port)
        self._state = state

    def become_peer(self) -> None:
        """Start acting like a peer."""
        self._state = PEER

    def become_tracker(self) -> None:
        """Start acting like a tracker."""
        self._state = TRACKER

    # Sample inheritance
    def state(self) -> int:
        """
        Test method, returns current state representation int.

        Deliberately written like so to verify that we are calling the right
        parent's implementation.
        """
        if self._state == PEER:
            return Peer.state(self)
        else:
            return Tracker.state(self)

    def state(self) -> int:
        """Test method, returns current state representation int."""
        return PEER


class TrackerPeer(Tracker, Peer):

    def __init__(self, ip: str, port: int, state=PEER):
        P2P.__init__(self, ip, port)
        self._state = state

    def become_peer(self) -> None:
        """Start acting like a peer."""
        self._state = PEER

    def become_tracker(self) -> None:
        """Start acting like a tracker."""
        self._state = TRACKER

    # Sample inheritance
    def state(self) -> int:
        """
        Test method, returns current state representation int.

        Deliberately written like so to verify that we are calling the right
        parent's implementation.
        """
        if self._state == PEER:
            return Peer.state(self)
        else:
            return Tracker.state(self)


if __name__ == "__main__":
    server = P2P("127.0.0.1", 65432)
    server.start()
    print(f"Server listening on {server.addr}")
    while True:
        pass
