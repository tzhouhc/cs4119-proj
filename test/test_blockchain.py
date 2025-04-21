import random
import unittest

from lib.blockchain import Block, BlockChain, expected_hash_prefix
from lib.utils import setup_logger

log = setup_logger(1, name=__name__)


def random_raw_block() -> Block:
    payload = random.randbytes(64)
    prev_hash = str(random.randbytes(32))
    return Block(payload, prev_hash)


def random_block() -> Block:
    b = random_raw_block()
    b.mine()
    return b


def random_chain(length: int) -> BlockChain:
    c = BlockChain()
    for _ in range(length):
        payload = random.randbytes(64)
        c.grow(payload)
    return c


class TestBlock(unittest.TestCase):

    def test_creating(self):
        _ = Block(b"", "")

    def test_mining_has_expected_prefix(self):
        b = Block(b"", "")
        b.mine()
        self.assertTrue(b.done)
        self.assertTrue(b.hash.startswith(expected_hash_prefix()))

    def test_access_after_mining_ok(self):
        b = Block(b"", "")
        b.payload += b"1"
        b.mine()
        self.assertEqual(b.payload, b"1")

    def test_modifying_before_mining_ok(self):
        b = Block(b"", "")
        b.payload += b"1"
        b.mine()
        self.assertTrue(b.done)
        self.assertTrue(b.hash.startswith(expected_hash_prefix()))

    def test_modifying_after_mining_fail(self):
        b = Block(b"", "")
        b.mine()
        with self.assertRaises(AttributeError):
            b.payload += b"1"

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
        b = Block(b"", "")
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
        c.grow(b"hello")

    def test_grow_second_ok(self):
        c = BlockChain()
        c.grow(b"hello")
        c.grow(b"world")

    def test_check_grown_validity_ok(self):
        c = BlockChain()
        for _ in range(10):
            payload = random.randbytes(64)
            c.grow(payload)
        self.assertTrue(c.is_valid())

    def test_check_force_append_validity_fail(self):
        c = BlockChain()
        for _ in range(10):
            payload = random.randbytes(64)
            c._chain.append(Block(payload, ""))
        self.assertFalse(c.is_valid())

    def test_bool(self):
        c = BlockChain()
        self.assertFalse(c)
        c.grow(b"hello")
        self.assertTrue(c)

    def test_len(self):
        c = BlockChain()
        for i in range(6):
            self.assertEqual(i, len(c))
            c.grow(b"")

    def test_get_by_index(self):
        c = random_chain(5)
        self.assertEqual(c[3], c._chain[3])

    def test_get_by_hash(self):
        c = random_chain(5)
        for i in range(5):
            i_hash = c[i].hash
            self.assertTrue(i_hash in c)
            self.assertEqual(c[i_hash], c._chain[i])

    def test_iter(self):
        c = random_chain(5)
        i = 0
        for b in c:
            self.assertEqual(c[i], b)
            i += 1
