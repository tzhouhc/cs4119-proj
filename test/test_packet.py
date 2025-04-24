import unittest

from lib.blockchain import BlockChain
from lib.packet import (
    AnnouncementPacket,
    BlockUpdatePacket,
    PacketType,
    PeerListPacket,
    PeerListRequestPacket,
    RedirectPacket,
)
from lib.utils import setup_logger

log = setup_logger(1, name=__name__)


class TestAnnouncementPacket(unittest.TestCase):

    def test_creating(self):
        c = BlockChain()
        p = AnnouncementPacket(c, ("localhost", 1000))
        res = p.as_dict()
        self.assertEqual(res["type"], PacketType.ANNOUNCEMENT)
        self.assertEqual(res["chain"], c)
        self.assertEqual(res["tracker"], ("localhost", 1000))


class TestPeerListRequestPacket(unittest.TestCase):

    def test_creating(self):
        p = PeerListRequestPacket()
        res = p.as_dict()
        self.assertEqual(res["type"], PacketType.PEER_LIST_REQUEST)


class TestPeerListPacket(unittest.TestCase):

    def test_creating(self):
        tr = ("localhost", 1000)
        pl = [("127.0.0.1", 5000), ("127.0.0.1", 5001)]
        p = PeerListPacket(tr, pl)
        res = p.as_dict()
        self.assertEqual(res["type"], PacketType.PEER_LIST)
        self.assertEqual(res["tracker"], tr)
        self.assertEqual(res["peers"], pl)


class TestRedirectRequestPacket(unittest.TestCase):

    def test_creating(self):
        p = RedirectPacket(("localhost", 1000))
        res = p.as_dict()
        self.assertEqual(res["type"], PacketType.REDIRECT)
        self.assertEqual(res["tracker"], ("localhost", 1000))


class TestBlockUpdatePacket(unittest.TestCase):

    def test_creating(self):
        c = BlockChain()
        p = BlockUpdatePacket(c)
        res = p.as_dict()
        self.assertEqual(res["type"], PacketType.BLOCK_UPDATE)
        self.assertEqual(res["chain"], c)
