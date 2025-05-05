import json
import random
import socket
from threading import Lock, Thread
from time import sleep

from lib.blockchain import Block, BlockChain
from lib.packet import (
    AnnouncementPacket,
    BlockUpdatePacket,
    DataPacket,
    PeerListPacket,
    PeerListRequestPacket,
    RedirectPacket,
)
from lib.provider import ContentProvider, MockContentProvider
from lib.utils import Addr, setup_logger

Packet = tuple[bytes, Addr]

PEER = 0
TRACKER = 1


class P2P:
    """Generalized P2P actor class."""

    log = setup_logger(1, name="P2P")

    def __init__(self, ip: str, port: int) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # this allows the handler threads to possibly cancel and retry and
        # thus exit their loop
        self.sock.settimeout(0.1)
        self.addr = (ip, port)
        self.tracker = None
        self.peers: set[Addr] = set()
        self.outbound: list[Packet] = []
        self.inbound: list[Packet] = []
        self.chain = None
        self.mine = True
        self.send = True
        self.receive = True
        self.terminated = False  # lifecycle over
        self.inlock = Lock()
        self.outlock = Lock()
        self.decoder = json.JSONDecoder()
        self.malicious = False  # flag for a malicious peer

    def set_tracker(self, tracker: Addr):
        """Set tracker to specified addr."""
        self.tracker = tracker

    def get_peers(self) -> list[Addr]:
        """Return current list of peers"""
        return list(self.peers)

    def history(self) -> list[str]:
        """
        Retrieve all payloads from blockchain as a list of str.

        Returns empty list if no blockchain exists.
        """
        if not self.chain:
            return []
        assert isinstance(self.chain, BlockChain)
        return [b.payload.decode() for b in self.chain]

    def start(self) -> None:
        """
        Start the active components of the P2P class.

        Notably, initializes both the handler threads and the main socket.
        While the handler threads and supporting data structures can be stopped
        or cleared, the port will remain until the final close() call.

        Returns:
            None
        """
        self.send = True
        self.receive = True
        self.mine = True
        self.sender_thread: Thread = Thread(target=self.sender_handler)
        self.receiver_thread: Thread = Thread(target=self.receiver_handler)
        self.sock.bind(self.addr)
        self.sock.listen(1)
        self.sender_thread.start()
        self.receiver_thread.start()

    def do_send(self) -> None:
        """
        Send one item from outbound queue if any. Expects the operation to be
        done while under lock due to writes to outbound queue.

        Creates a temporary socket for the purpose.
        """
        if self.outbound:
            payload, dest = self.outbound.pop(0)
            temp_sock = None
            if not dest:
                # cannot send a dest-less packet; this is possible during
                # testing if a tracker is not set but we are mining
                return
            try:
                temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                temp_sock.connect(dest)
                temp_sock.sendall(payload)
                self.log.debug(f"Sent packet to {dest}")
            except ConnectionAbortedError:
                self.log.debug("Connected aborted presumably due to close.")
            except TimeoutError:
                pass
            except Exception as e:
                self.log.error(f"Failed to send packet to {dest}: {e}")
            finally:
                if temp_sock:
                    temp_sock.close()

    def sender_handler(self):
        """
        Checks the outbound queue and sends messages over TCP.

        Will keep sending until the `done` flag is up, at which point it will
        lock the input queue and start exiting. Further entries can be added
        to the queue *after* but won't be sent until new sender thread starts.
        """
        self.log.info("Sender thread starting.")
        while self.send:
            # during normal operation: acquire lock, send, unlock
            with self.outlock:
                self.do_send()
            sleep(0.1)
        self.log.info("Sender pending closure.")
        # during stopping phase: lock, send all that is left, stop. No more
        # items can be inserted during this period.
        with self.outlock:
            while self.outbound:
                self.do_send()
        self.log.info("Sender thread stopped.")

    def receiver_handler(self):
        """
        Accepts incoming connections and creates the threads to handle them.
        """
        self.log.info("Receiver thread starting.")
        while self.receive:
            try:
                conn, addr = self.sock.accept()
                Thread(
                    target=self.handle_connection, args=(conn, addr), daemon=True
                ).start()
            except ConnectionAbortedError:
                self.log.debug("Connected aborted presumably due to close.")
            except TimeoutError:
                pass
            except Exception as e:
                self.log.error(f"Error accepting the connection: {e}")
        self.log.info("Receiver thread stopped.")

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
            while self.receive:
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
                        with self.inlock:
                            self.inbound.append((json.dumps(message).encode(), addr))
                    except json.JSONDecodeError:
                        break
        except ConnectionAbortedError:
            self.log.debug("Connected aborted presumably due to close.")
        except TimeoutError:
            pass
        except Exception as e:
            self.log.error(f"Error handling connection from {addr}: {e}")
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

    def stop(self) -> None:
        """
        Terminate current activities. Maintain current port.

        This will let threads finish their last loop and gracefully join the
        incoming/outgoing threads. This does *not* however check that the
        queues are empty.

        Returns:
            None
        """
        self.mine = False
        self.send = False
        self.sender_thread.join()
        self.receive = False
        self.receiver_thread.join()
        with self.inlock:
            # TODO: consider adopting separate locks for in/out. Buffer can
            # stick with in.
            self.inbound = []
        with self.outlock:
            self.outbound = []

    def resume(self) -> None:
        """
        Resume activity.

        Will create new threads for incoming/outgoing traffic.

        During the restart process, it will maintain the following:
        self.sock
        self.addr
        self.tracker
        self.peers
        self.chain
        self.inlock
        self.outlock
        self.decoder = json.JSONDecoder()
        """
        self.mine = True
        self.send = True
        self.receive = True
        self.sender_thread: Thread = Thread(target=self.sender_handler)
        self.receiver_thread: Thread = Thread(target=self.receiver_handler)
        self.sender_thread.start()
        self.receiver_thread.start()

    def close(self) -> None:
        """
        Close the connection and terminate current activities.

        This will let threads finish their last loop, join the threads, then
        actually close the port. Once closed, it might be troublesome to try
        to restart on the same ports, so only call this at the end of a
        session.

        Returns:
            None
        """
        self.stop()
        self.terminated = True
        self.sock.close()

    def responder_thread(self) -> None:
        """
        Responder thread, which handles repeatedly receiving packets and
        handling them based on type.

        This is a *blocking* call.
        """
        self.log.info("Responder thread starting.")
        while not self.terminated:
            if self.inbound:
                msg, src = self.inbound.pop(0)
                data = json.loads(msg.decode())
                self.respond(data, src)
            else:
                sleep(0.1)
        self.log.info("Responder thread stopped.")

    def respond(self, msg: dict, src: Addr) -> None:
        raise NotImplementedError("Should not use P2P respond method.")

    def send_packet(self, pkt: DataPacket, dst: Addr) -> None:
        """
        Shorthand for sending specifically DataPackets.
        """
        self.log.debug(f"Sending {pkt.__class__} to {dst}")
        pkt.set_src(self.addr)
        with self.outlock:
            self.outbound.append((pkt.as_bytes(), dst))

    def print_chain(self) -> None:
        """
        Pretty print current chain.
        """
        if not self.chain:
            print("No blockchain established.")
            return
        assert isinstance(self.chain, BlockChain)
        print(self.chain.pretty())


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

    def __init__(self, ip, port):
        P2P.__init__(self, ip, port)

    def start(self) -> None:
        self.log.debug("Tracker start process.")
        P2P.start(self)

    def stop(self):
        P2P.stop(self)

    def resume(self):
        P2P.resume(self)

    def announce(self, pkt: DataPacket) -> None:
        """
        Send packet to all peers.
        """
        for peer in self.peers:
            self.send_packet(pkt, peer)

    def become_peer(self) -> None:
        raise NotImplementedError("Tracker does not have become_peer implemented.")

    def respond(self, msg: dict, src: Addr) -> None:
        """
        Actual responding method that takes data dict, interpret as a
        DataPacket, then appropriately validate and respond to it, performing
        any state changes in the process as necessary.

        The `src` param is actually the temp socket.
        """
        pkt = None
        try:
            pkt = DataPacket.from_dict(msg)
        except Exception as e:
            self.log.warning(f"Failed to interpret packet: {e}")
            return
        # valid packet, add peer to list
        assert pkt is not None
        sip, sport = tuple(pkt.src)
        true_src = (sip, sport)
        self.peers.add(true_src)
        if isinstance(pkt, PeerListRequestPacket):
            # no validation necessary -- just respond
            resp = PeerListPacket(self.addr, self.get_peers())
            self.send_packet(resp, true_src)
        elif isinstance(pkt, BlockUpdatePacket):
            # validate block
            c: BlockChain = BlockChain.from_list(pkt.chain)
            cur_c = self.chain
            if not c.is_valid():
                return
            if not self.chain or self.chain < c:
                self.chain = c
            if self.chain != cur_c:
                # promote sender of updated chain as new tracker
                resp = AnnouncementPacket(self.chain, true_src)
                self.announce(resp)
                # this function is unimplemented in the Tracker class, but will
                # be available to its subclass, TrackerPeer.
                self.print_chain()
                self.set_tracker(true_src)
                self.become_peer()

        # *WHY* would a tracker receive an ann? Presumably someone else got
        # mistakenly elected.
        elif isinstance(pkt, AnnouncementPacket):
            # get new chain
            new_chain = BlockChain.from_list(pkt["chain"])
            # check if valid
            if not new_chain.is_valid():  # invalid chain
                return
            # update
            if not self.chain or new_chain > self.chain:
                self.chain = new_chain
            self.set_tracker(pkt.data["tracker"])
            # cooperative yield
            if self.tracker != self.addr:
                self.become_peer()


class Peer(P2P):
    """
    Peer.

    On JOIN, notify tracker and GET list of peers.
    On DROP, notify tracker.
    """

    def __init__(self, ip: str, port: int):
        P2P.__init__(self, ip, port)
        self.block = None
        self.provider = MockContentProvider()

    def set_provider(self, provider: ContentProvider) -> None:
        """Replace default mock content provider with specified."""
        # dependency injection to avoid soldering the provider
        self.provider = provider

    def start(self):
        """
        Start active components of Peer class, including two threads.
        """
        self.log.debug("Peer start process.")
        self.mine_thread = Thread(target=self.miner_thread, daemon=True)
        self.mine_thread.start()
        P2P.start(self)

        # initial request
        pkt = PeerListRequestPacket()
        self.send_packet(pkt, self.tracker)

    def stop(self):
        P2P.stop(self)
        self.mine_thread.join()

    def resume(self):
        P2P.resume(self)
        self.mine_thread = Thread(target=self.miner_thread, daemon=True)
        self.mine_thread.start()

    def become_tracker(self) -> None:
        raise NotImplementedError("Peer does not have become_tracker implemented.")

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
        except Exception as e:
            self.log.warning(f"Failed to interpret packet: {e}")
            return
        # valid packet, respond
        assert pkt is not None
        sip, sport = tuple(pkt.src)
        true_src = (sip, sport)
        self.peers.add(true_src)
        self.log.debug(f"Received {pkt.__class__} from {true_src}")
        if isinstance(pkt, PeerListRequestPacket) or isinstance(pkt, BlockUpdatePacket):
            # send redirect
            pkt = RedirectPacket(self.tracker)
            self.send_packet(pkt, true_src)
        elif isinstance(pkt, RedirectPacket):
            # update tracker
            self.set_tracker(pkt.data["tracker"])
            # resend PeerListRequest
            pkt = PeerListRequestPacket()
            self.send_packet(pkt, self.tracker)
        elif isinstance(pkt, PeerListPacket):
            # update peer list
            self.peers = set(pkt["peers"])
            # update tracker
            self.set_tracker(pkt.data["tracker"])
        elif isinstance(pkt, AnnouncementPacket):
            # get new chain
            new_chain = BlockChain.from_list(pkt["chain"])
            # check if valid
            if not new_chain.is_valid():  # invalid chain
                return
            else:
                # stop current mining process
                if self.block:
                    self.block.set_stop_mining(True)
                # update
                if not self.chain or new_chain > self.chain:
                    self.chain = new_chain
                self.set_tracker(pkt.data["tracker"])
                if self.tracker == self.addr:
                    self.become_tracker()

    def miner_thread(self):
        """
        Miner thread, mines block and once found broadcasts to peers.
        """
        self.log.info("Miner thread starting.")
        while self.mine:
            # check for chain
            if not self.chain:
                self.chain = BlockChain()
            # make new Block
            tail = self.chain.tail()
            if tail:
                prev_hash = tail.hash
            else:
                prev_hash = ""
            content = self.provider.generate(self.history())
            new_block = Block(content.encode(), prev_hash)
            self.mining_block = new_block
            # mine block
            new_block.mine()

            # check if sucessful (not interrupted)
            if not new_block.done:
                self.mining_block = None
                continue
            # append real block to chain
            try:
                self.chain.append(new_block)
            except ValueError:
                self.mining_block = None
                continue
            # broadcast Block
            pkt = BlockUpdatePacket(self.chain)
            # malicious behavior: corrupt packet after mining
            if self.malicious:
                self.log.warning("Malicious peer corrupting packet before sending")
                pkt.data["chain"] = {"malformed": "not a real chain"}
            self.send_packet(pkt, self.tracker)
            # reset
            self.block = None
        self.log.info("Miner thread stopped.")

    def state(self) -> int:
        """Test method, returns current state representation int."""
        return PEER


class TrackerPeer(Tracker, Peer):

    def __init__(self, ip: str, port: int, state=PEER):
        P2P.__init__(self, ip, port)
        # NOTE: if I do the init for both parent classes instead, I will get
        # two socket creations, which is not good, but I don't see how to fix
        # this elegantly yet. At least both inits are lightweight.
        self._state = state
        self.block = None
        self.provider = MockContentProvider()
        self.log.info("TrackerPeer created.")

    def set_state(self, state: int) -> None:
        """
        Set self state but don't do anything else.

        Used for initial setup.
        """
        self._state = state
        self.log.debug(f"TrackerPeer changing to state {state}.")

    def become_peer(self) -> None:
        """
        Start acting like a peer.

        Will stop currently running threads after final iteration, join them,
        switch state, then start new ones. Maintains self state otherwise.
        """
        # first, halt all processing threads; they should finish what they have
        # left and then cleanup.
        self.stop()
        self.log.info("Transitioning to PEER")
        self.set_state(PEER)
        self.resume()

    def become_tracker(self) -> None:
        """
        Start acting like a tracker.

        Will stop currently running threads after final iteration, join them,
        switch state, then start new ones. Maintains self state otherwise.
        """
        self.stop()
        self.log.info("Transitioning to TRACKER")
        self.set_state(TRACKER)
        self.resume()

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

    def start(self) -> None:
        """
        Shared start entry point.

        Will run the state-appropriate start method.
        """
        self.log.info("TrackerPeer starting.")
        if self._state == PEER:
            return Peer.start(self)
        else:
            return Tracker.start(self)

    def stop(self) -> None:
        """
        Shared stop entry point.

        Will run the state-appropriate stop method.

        This will also be invoked as part of the unified close method.
        """
        self.log.info("TrackerPeer stopping.")
        if self._state == PEER:
            return Peer.stop(self)
        else:
            return Tracker.stop(self)

    def resume(self) -> None:
        """
        Shared resume entry point.

        Will run the state-appropriate resume method.
        """
        self.log.info("TrackerPeer resuming.")
        if self._state == PEER:
            return Peer.resume(self)
        else:
            return Tracker.resume(self)

    def respond(self, msg: dict, src: Addr) -> None:
        """
        Respond to incoming packet as data dict from src.

        Will run the state-appropriate respond method. This is actually how
        the responding will change depending on state.
        """
        if self._state == PEER:
            return Peer.respond(self, msg, src)
        else:
            return Tracker.respond(self, msg, src)

    def main_loop(self) -> None:
        """
        Running main loop.

        This handles the creation and joining of the other threads, since
        threads cannot join on themselves.
        """
        self.log.info("TrackerPeer main loop running.")
        P2P.responder_thread(self)


"""
TODO:

- DO we actually need to halt the other three threads now? They are *identical*
  for tracker and peer. The only difference is whether the *miner* thread is
  running or not, which is a non-trivial difference.

"""


if __name__ == "__main__":
    ...
