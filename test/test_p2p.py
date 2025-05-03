import unittest
from logging import WARNING
from time import sleep

from lib.p2p import P2P, PEER, TRACKER, Peer, Tracker, TrackerPeer

P2P.log.setLevel(WARNING)


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


class TestTrackerPeerConversion(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tp = TrackerPeer("0.0.0.0", 50002, 0)
        cls.tp.start()

    # ----
    # test helpers; camelCase becauses unittest assertion functions are
    # already like that....
    # ----

    def assertThreadsActive(self):
        self.assertTrue(self.tp.receive)
        self.assertTrue(self.tp.send)

    def assertThreadsInactive(self):
        self.assertFalse(self.tp.receive)
        self.assertFalse(self.tp.send)

    def assertIsPeer(self):
        self.assertEqual(self.tp.state(), PEER)

    def assertIsTracker(self):
        self.assertEqual(self.tp.state(), TRACKER)

    # note: test naming explicitly affects order of execution; otherwise the
    # tests will *not* run sequentially by the order that they are defined.

    def test_01_state_change_01(self):
        """Numbered tests, start from here as default, i.e. peer."""
        self.assertIsPeer()
        self.tp.become_tracker()
        sleep(0.2)
        self.assertIsTracker()

    def test_01_state_change_02(self):
        """Test class instance should remain since last test."""
        self.assertIsTracker()
        self.tp.become_peer()
        sleep(0.2)
        self.assertIsPeer()

    def test_02_restart_01(self):
        """Stopping and restarting should maintain state."""
        self.assertIsPeer()
        self.assertThreadsActive()
        self.tp.stop()
        sleep(0.2)
        self.assertThreadsInactive()
        self.tp.resume()
        self.assertThreadsActive()
        self.assertIsPeer()

    def test_02_restart_02_set_as_other(self):
        """Stopping, changing state and restarting should update."""
        self.assertThreadsActive()
        self.tp.stop()
        sleep(0.2)
        cur_state = self.tp.state()
        if self.tp.state() == 0:
            self.tp._state = 1
        else:
            self.tp._state = 0
        self.assertNotEqual(cur_state, self.tp.state())
        self.assertThreadsInactive()
        self.tp.resume()
        self.assertThreadsActive()

    def test_02_restart_03_become_other(self):
        """Use 'become' methods to achieve the same."""
        self.assertThreadsActive()
        # "become" automatically performs stop and resume, so no checking here.
        if self.tp.state() == 0:
            self.tp.become_tracker()
        else:
            self.tp.become_peer()
        sleep(0.2)
        self.assertThreadsActive()

    @classmethod
    def tearDownClass(cls):
        cls.tp.close()
