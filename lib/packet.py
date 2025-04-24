from enum import IntEnum
from time import time
from typing import Any

from lib.blockchain import BlockChain
from lib.utils import Addr


class PeerState(IntEnum):
    PEER = 1
    TRACKER = 2


class PacketType(IntEnum):
    NULL = 0
    PEER_LIST_REQUEST = 1
    BLOCK_UPDATE = 2
    REDIRECT = 3
    PEER_LIST = 4
    ANNOUNCEMENT = 5


class DataPacket:
    data: dict[str, Any]

    def __init__(self):
        self.data = {"timestamp": time()}

    def as_dict(self):
        return self.data


class PeerListRequestPacket(DataPacket):
    """
    Who's in the neighborhood?

    Sent from: peer
    Expected by: tracker

    Tracker should respond with a PEER_LIST
    """

    def __init__(self):
        super().__init__()
        self.data["type"] = PacketType.PEER_LIST_REQUEST


class BlockUpdatePacket(DataPacket):
    """
    Here's a block that I mined, plz accept

    Sent from: peer
    Expected by: tracker

    Tracker should validate and then possibly make an ANNOUNCEMENT
    """

    def __init__(self, c: BlockChain):
        super().__init__()
        self.data["type"] = PacketType.BLOCK_UPDATE
        self.data["chain"] = c


class RedirectPacket(DataPacket):
    """
    These are not the droids you are looking for!

    Sent from: peer
    Expected by: peer

    Peer should update tracker info and resend PEER_LIST_REQUEST
    """

    def __init__(self, addr: Addr):
        super().__init__()
        self.data["type"] = PacketType.REDIRECT
        self.data["tracker"] = addr


class PeerListPacket(DataPacket):
    """
    Welcome to the neighborhood!

    Sent from: tracker
    Expected by: peer

    Peer should keep the data.
    """

    def __init__(self, tracker: Addr, peers: list[Addr]):
        super().__init__()
        self.data["type"] = PacketType.PEER_LIST
        self.data["tracker"] = tracker
        self.data["peers"] = peers


class AnnouncementPacket(DataPacket):
    """
    Here's a block that this guy mined, know that they shall be the tracker now

    Sent from: tracker
    Expected by: peer

    Peer should update their tracker and adjust their blockchain.
    """

    def __init__(self, c: BlockChain, tracker: Addr):
        super().__init__()
        self.data["type"] = PacketType.ANNOUNCEMENT
        self.data["chain"] = c
        self.data["tracker"] = tracker


"""
Alternatively, an announcement packet could also just be a BlockUpdatePacket
and a RedirectPacket. You can choose what you want to support.
"""
