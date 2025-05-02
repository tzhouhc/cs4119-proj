import json
import socket
from threading import Thread
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

    ...
