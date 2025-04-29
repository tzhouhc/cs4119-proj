import unittest
from time import sleep

from lib.p2p import Peer, Tracker, TrackerPeer


class TestP2P(unittest.TestCase):

    def setUp(self):
        self.tracker = Tracker("0.0.0.0", 50000)
        self.peer = Peer("0.0.0.0", 50001)
        self.tracker.start()
        self.peer.start()

    def test_setup(self):
        # do something trivial to test setUp and tearDown
        sleep(0.3)

    def tearDown(self):
        self.tracker.close()
        self.peer.close()


class TestTrackerPeer(unittest.TestCase):

    def setUp(self):
        self.tp = TrackerPeer("0.0.0.0", 50002, 0)
        self.tp.start()

    def test_state_change(self):
        self.assertEqual(self.tp.state_test(), 2)
        self.tp.become_tracker()
        self.assertEqual(self.tp.state_test(), 1)

    def tearDown(self):
        self.tp.close()
        self.assertTrue(self.tp.done)
