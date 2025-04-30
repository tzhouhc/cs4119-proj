import unittest
from time import sleep

from lib.p2p import Peer, Tracker, TrackerPeer


class TestP2P(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tracker = Tracker("0.0.0.0", 50000)
        cls.peer = Peer("0.0.0.0", 50001)
        cls.tracker.start()
        cls.peer.start()

    def test_setup(self):
        # do something trivial to test setUp and tearDown
        sleep(0.3)

    def test_teardown_resetup(self):
        # verify that setUp and tearDown can be quickly invoked repeatedly
        sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.tracker.close()
        cls.peer.close()


class TestTrackerPeer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tp = TrackerPeer("0.0.0.0", 50002, 0)
        cls.tp.start()

    # note: test naming explicitly affects order of execution; otherwise the
    # tests will *not* run sequentially by the order that they are defined.

    def test_01_state_change_01(self):
        # PEER = 0
        self.assertEqual(self.tp.state(), 0)
        self.tp.become_tracker()
        # TRACKER = 1
        self.assertEqual(self.tp.state(), 1)

    def test_01_state_change_02(self):
        self.assertEqual(self.tp.state(), 1)
        self.tp.become_peer()
        self.assertEqual(self.tp.state(), 0)

    def test_02_restart_01(self):
        self.tp.stop()
        self.assertTrue(self.tp.done)
        self.tp.resume()
        self.assertFalse(self.tp.done)

    def test_02_restart_02_as_other(self):
        self.tp.stop()
        cur_state = self.tp.state()
        if self.tp.state() == 0:
            self.tp.become_tracker()
        else:
            self.tp.become_peer()
        self.assertNotEqual(cur_state, self.tp.state())
        self.assertTrue(self.tp.done)
        self.tp.resume()
        self.assertFalse(self.tp.done)

    @classmethod
    def tearDownClass(cls):
        cls.tp.close()
