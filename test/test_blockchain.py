import random
import unittest
from lib.blockchain import Block, BlockChain, expected_hash_prefix
from lib.utils import setup_logger

log = setup_logger(__name__, 2)


class TestBlock(unittest.TestCase):

    def test_creating(self):
        _ = Block(b'', '')

    def test_mining_has_expected_prefix(self):
        b = Block(b'', '')
        b.mine()
        self.assertTrue(b.done)
        self.assertTrue(b.hash.startswith(expected_hash_prefix()))

    def test_access_after_mining_ok(self):
        b = Block(b'', '')
        b.payload += b'1'
        b.mine()
        self.assertEqual(b.payload, b'1')

    def test_modifying_before_mining_ok(self):
        b = Block(b'', '')
        b.payload += b'1'
        b.mine()
        self.assertTrue(b.done)
        self.assertTrue(b.hash.startswith(expected_hash_prefix()))

    def test_modifying_after_mining_fail(self):
        b = Block(b'', '')
        b.mine()
        with self.assertRaises(AttributeError):
            b.payload += b'1'

    def test_validate(self):
        for _ in range(100):
            payload = random.randbytes(64)
            prev_hash = str(random.randbytes(32))
            b = Block(payload, prev_hash)
            b.mine()
            self.assertEqual(payload, b.payload)
            self.assertEqual(prev_hash, b.prev_hash)
            self.assertTrue(b.valid())


class TestBlockChain(unittest.TestCase):

    def test_creating(self):
        _ = BlockChain()

    def test_initializing(self):
        c = BlockChain()
        b = Block(b'', '')
        c.append(b)

    def test_adding(self):
        c = BlockChain()
        for _ in range(20):
            payload = random.randbytes(64)
            prev_hash = str(random.randbytes(32))
            b = Block(payload, prev_hash)
            b.mine()
            c.append(b)
