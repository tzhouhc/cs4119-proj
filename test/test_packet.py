import unittest
from time import sleep

from lib.blockchain import BlockChain
from lib.packet import (
    AnnouncementPacket,
    BlockUpdatePacket,
    DataPacket,
    PacketType,
    PeerListPacket,
    PeerListRequestPacket,
    RedirectPacket,
)
from lib.utils import setup_logger

log = setup_logger(1, name=__name__)


class TestDataPacketCommon(unittest.TestCase):

    def test_eq(self):
        p1 = DataPacket()
        sleep(0.01)
        p2 = DataPacket()
        # different time stamp
        self.assertNotEqual(p1, p2)

    def test_eq_only_on_datapackets(self):
        p1 = DataPacket()
        p2 = {}
        # different time stamp
        self.assertNotEqual(p1, p2)

    def test_getattr(self):
        p1 = DataPacket()
        p1.data["type"] = "hello"
        self.assertEqual(p1.type, "hello")

    def test_getattr_super(self):
        p1 = DataPacket()
        self.assertTrue(p1.__class__)

    def test_getattr_super_err(self):
        p1 = DataPacket()
        with self.assertRaises(AttributeError):
            _ = p1.nosuchattr


class TestAnnouncementPacket(unittest.TestCase):

    def test_creating(self):
        c = BlockChain()
        p = AnnouncementPacket(c, ("localhost", 1000))
        res = p.as_dict()
        self.assertEqual(res["type"], PacketType.ANNOUNCEMENT)
        self.assertEqual(res["chain"], c.as_list())
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
        self.assertEqual(res["chain"], c.as_list())


class TestDeserialize(unittest.TestCase):

    def test_deserialize_undef(self):
        bad = {"typpppp": 1}
        with self.assertRaises(ValueError):
            DataPacket.from_dict(bad)

    def test_deserialize_null(self):
        bad = {"type": 0}
        with self.assertRaises(ValueError):
            DataPacket.from_dict(bad)

    def test_deserialize_ann_req(self):
        c = BlockChain()
        c.grow(b"hello")
        p = AnnouncementPacket(c, ("localhost", 1000))
        ser = p.as_dict()
        deser = DataPacket.from_dict(ser)
        self.assertEqual(p, deser)
        self.assertEqual(c, BlockChain.from_list(deser.chain))
        self.assertEqual(("localhost", 1000), deser.tracker)

    def test_deserialize_peer_list_req(self):
        p = PeerListRequestPacket()
        ser = p.as_dict()
        deser = DataPacket.from_dict(ser)
        self.assertEqual(p, deser)

    def test_deserialize_peer_list(self):
        tr = ("localhost", 1000)
        pl = [("127.0.0.1", 5000), ("127.0.0.1", 5001)]
        p = PeerListPacket(tr, pl)
        ser = p.as_dict()
        deser = DataPacket.from_dict(ser)
        self.assertEqual(p, deser)
        self.assertEqual(tr, deser.tracker)
        self.assertEqual(pl, deser.peers)

    def test_deserialize_redirect(self):
        p = RedirectPacket(("localhost", 1000))
        ser = p.as_dict()
        deser = DataPacket.from_dict(ser)
        self.assertEqual(p, deser)
        self.assertEqual(("localhost", 1000), deser.tracker)

    def test_deserialize_block_update(self):
        c = BlockChain()
        c.grow(b"hello")
        p = BlockUpdatePacket(c)
        ser = p.as_dict()
        deser = DataPacket.from_dict(ser)
        self.assertEqual(p, deser)
        self.assertEqual(c, BlockChain.from_list(deser.chain))
