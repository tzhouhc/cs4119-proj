import json
import random
import unittest
from threading import Thread
from time import sleep

from lib.blockchain import Block, BlockChain, expected_hash_prefix
from lib.utils import setup_logger

from unittest.mock import patch

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

    def test_mining_can_be_stopped(self):
        """Test whether changing stop_mining can stop mine()."""
        b = Block(b"", "") # block

        # helper: change bool after mine() starts 
        def delayed_stop():
            sleep(0.01)
            b.stop_mining = True

        with patch.object(Block, "is_valid", return_value=False):
            # start thread
            interrupt = Thread(target=delayed_stop)
            interrupt.start()
            # call mine
            b.mine()
            interrupt.join()

        # assertions
        self.assertFalse(b.done)
        self.assertFalse(b.is_valid())

    def test_serialize(self):
        """Block can serialize to something json dumpable."""
        b = Block(b"asdf", "")
        b.mine()
        json.dumps(b.as_dict())

    def test_deserialize(self):
        """Block can be restored from json serialized data."""
        b = Block(b"asdf", "")
        b.mine()
        s = json.dumps(b.as_dict())
        b2 = Block.from_dict(json.loads(s))
        self.assertTrue(b2.is_valid())
        self.assertEqual(b, b2)

    def test_malformed_deserialize(self):
        """
        Block cannot be restored from json serialized data if tampered with.
        """
        b = random_block()
        d = b.as_dict()
        d["nonce"] -= 1
        s = json.dumps(d)
        b2 = Block.from_dict(json.loads(s))
        self.assertNotEqual(b, b2)
        self.assertFalse(b2.is_valid())

    def test_malformed_deserialize_2(self):
        b = random_block()
        d = b.as_dict()
        d["prev_hash"] = "bad_hash"
        s = json.dumps(d)
        b2 = Block.from_dict(json.loads(s))
        self.assertNotEqual(b, b2)
        self.assertFalse(b2.is_valid())

    def test_malformed_deserialize_3(self):
        b = random_block()
        d = b.as_dict()
        d["payload"] = "cXdlcg=="  # b"qwer"
        s = json.dumps(d)
        b2 = Block.from_dict(json.loads(s))
        self.assertNotEqual(b, b2)
        self.assertFalse(b2.is_valid())

    def test_malformed_deserialize_4(self):
        b = random_block()
        d = b.as_dict()
        d["timestamp"] = "1745703772.718412"  # arbitrary valid timestamp
        s = json.dumps(d)
        b2 = Block.from_dict(json.loads(s))
        self.assertNotEqual(b, b2)
        self.assertFalse(b2.is_valid())


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

    def test_serialize(self):
        """BlockChain can serialize to something json dumpable."""
        c = random_chain(5)
        json.dumps(c.as_list())

    def test_deserialize(self):
        """BlockChain can be restored from json serialized data."""
        c = random_chain(5)
        s = json.dumps(c.as_list())
        c2 = BlockChain.from_list(json.loads(s))
        self.assertEqual(c, c2)

    def test_malformed_deserialize(self):
        """
        BlockChain cannot be restored from json serialized data if tampered
        with.
        """
        c = random_chain(5)
        b = random_block()
        lst = c.as_list()
        # swap out content in the chain with bad block
        lst[3] = b.as_dict()
        s = json.dumps(lst)
        c2 = BlockChain.from_list(json.loads(s))
        self.assertNotEqual(c, c2)
        self.assertFalse(c2.is_valid())
