import random
import unittest
from lib.blockchain import Block, BlockChain, expected_hash_prefix
from lib.utils import setup_logger

log = setup_logger(2, name=__name__)

def random_raw_block():
    payload = random.randbytes(64)
    prev_hash = str(random.randbytes(32))
    return Block(payload, prev_hash)

def random_block():
    b = random_raw_block()
    b.mine()
    return b


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
            self.assertTrue(b.is_valid())


class TestBlockChain(unittest.TestCase):

    def test_creating(self):
        _ = BlockChain()

    def test_initializing(self):
        c = BlockChain()
        b = Block(b'', '')
        b.mine()
        c.append(b)

    def test_adding_first_invalid_fail(self):
        """The first block needs to be valid."""
        c = BlockChain()
        b = random_raw_block()
        with self.assertRaises(ValueError):
            c.append(b)

    def test_adding_first_no_prevhash_ok(self):
        """The first block does not need to have a valid prev_hash."""
        c = BlockChain()
        b = random_block()
        c.append(b)

    def test_adding_subsequent_invalid_fail(self):
        """
        All subsequent blocks need to be valid AND have matching prev_hash.
        """
        c = BlockChain()
        b = random_block()
        c.append(b)
        b2 = random_raw_block()
        with self.assertRaises(ValueError):
            c.append(b2)

    def test_adding_subsequent_mismatching_fail(self):
        """
        All subsequent blocks need to be valid AND have matching prev_hash.
        """
        c = BlockChain()
        b = random_block()
        c.append(b)
        b2 = random_block()
        with self.assertRaises(ValueError):
            c.append(b2)

    def test_grow_first_ok(self):
        c = BlockChain()
        c.grow(b'hello')

    def test_grow_second_ok(self):
        c = BlockChain()
        c.grow(b'hello')
        c.grow(b'world')

    def test_check_validity(self):
        c = BlockChain()
        for _ in range(10):
            payload = random.randbytes(64)
            c.grow(payload)
        self.assertTrue(c.is_valid())
