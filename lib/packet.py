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

    def __eq__(self, other) -> bool:
        if not isinstance(other, DataPacket):
            return False
        return self.data == other.data

    def __str__(self) -> str:
        return str(self.data)

    def __getitem__(self, key: Any) -> Any:
        """Support c[i]."""
        return self.data[key]

    def __getattr__(self, key: str) -> Any:
        """Support c.key direct access."""
        if key in self.data:
            return self.data[key]
        raise AttributeError(f"Attribute {key} not found.")

    def as_dict(self):
        return self.data

    @classmethod
    def from_dict(cls, data: dict) -> "DataPacket":
        if "type" not in data:
            raise ValueError("Malformed data dict")
        dtype = data["type"]
        res = None
        if dtype == PacketType.ANNOUNCEMENT:
            res = AnnouncementPacket(
                BlockChain.from_list(data["chain"]), data["tracker"]
            )
        elif dtype == PacketType.PEER_LIST_REQUEST:
            res = PeerListRequestPacket()
        elif dtype == PacketType.BLOCK_UPDATE:
            res = BlockUpdatePacket(BlockChain.from_list(data["chain"]))
        elif dtype == PacketType.REDIRECT:
            res = RedirectPacket(data["tracker"])
        elif dtype == PacketType.PEER_LIST:
            res = PeerListPacket(data["tracker"], data["peers"])
        else:
            raise ValueError("Unknown packet type")
        res.data["timestamp"] = data["timestamp"]
        return res


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
        self.data["chain"] = c.as_list()


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
        self.data["chain"] = c.as_list()
        self.data["tracker"] = tracker


"""
Alternatively, an announcement packet could also just be a BlockUpdatePacket
and a RedirectPacket. You can choose what you want to support.
"""
