import unittest

from lib.p2p import Peer, Tracker


class TestP2P(unittest.TestCase):

    def test_creating(self):
        tracker = Tracker("0.0.0.0", 50000)
        peer = Peer("0.0.0.0", 50001)
        del tracker
        del peer
