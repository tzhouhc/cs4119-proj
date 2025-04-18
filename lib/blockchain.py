from time import time
from hashlib import sha256
from lib.utils import setup_logger, blue, green

from typing import Any, Iterator


NONCE_LENGTH = 64
DIFFICULTY = 2

log = setup_logger(2, name=__name__)


def expected_hash_prefix():
    return "0" * DIFFICULTY


class Block:
    """A Block in the blockchain. call `mine` to finalize."""

    done: bool = False
    payload: bytes = b''
    prev_hash: str = ''
    hash: str = ''
    nonce: int = 0
    timestamp: str = ''

    def __init__(self, payload: bytes, prev_hash: str):
        self.timestamp: str = str(time())
        self.payload: bytes = payload
        self.hash: str = self.get_hash()
        self.prev_hash: str = prev_hash
        self.nonce = 0

    def __setattr__(self, key, value) -> None:
        """Prevent modification after done."""
        if not self.done:
            super().__setattr__(key, value)
        else:
            raise AttributeError(f"Can't modify read-only attribute {key}")

    def __str__(self) -> str:
        content = self.payload if len(self.payload) <= 20 \
            else self.payload[:8]
        hash = self.hash[:8]
        return f"Block[{hash}, {content}]"

    def get_hash(self) -> str:
        """Get hash based on previous hash, payload and create time."""
        raw = self.prev_hash.encode() + self.payload + \
            self.timestamp.encode()
        raw += self.nonce.to_bytes(NONCE_LENGTH)
        return sha256(raw).hexdigest()

    def mine(self) -> None:
        """Mine for required difficulty and finalize block."""
        if self.done:
            return
        while not self.is_valid():
            self.nonce += 1
            self.hash = self.get_hash()
        self.done = True

    def is_valid(self) -> bool:
        """Hash matches required difficulty and regenerated hash."""
        if not self.hash.startswith(expected_hash_prefix()):
            return False
        return self.get_hash() == self.hash

    def pretty(self) -> str:
        content = self.payload if len(self.payload) <= 20 \
            else self.payload[:8]
        hash = self.hash[:8]
        return f"Block[{blue(hash)}, {green(content)}]"


class BlockChain:

    def __init__(self):
        # always initialize chain with a null starter
        self._chain: list[Block] = []

    # ----- magic methods ----- #
    #
    # The following will make BlockChain variables behave sort of like native
    # python lists, allowing a bunch of convenient shorthands:

    def __len__(self):
        """Support len(c)."""
        return len(self._chain)

    def __str__(self) -> str:
        """Support str(c)."""
        return "\n".join([str(b) for b in self._chain])

    def __getitem__(self, key: Any) -> Block:
        """Support c[i]."""
        if isinstance(key, str):
            for block in self:
                if block.hash == key:
                    return block
            raise KeyError(f"Key {key} not found.")
        else:
            return self._chain[key]

    def __bool__(self) -> bool:
        """Support `if c`."""
        return bool(self._chain)

    def __contains__(self, value: Any) -> bool:
        """Support `key in c`."""
        if not isinstance(value, str):
            return False
        for block in self:
            if block.hash == value:
                return True
        return False

    def __iter__(self) -> Iterator:
        """Support `for block in c`."""
        for block in self._chain:
            yield block

    # ----- end of magic methods ----- #

    def tail(self) -> Block | None:
        """Last entry in the chain, or None if empty."""
        if self:
            return self[-1]
        return None

    def append(self, block: Block) -> None:
        """
        Add a new block to the chain.

        Caller has the responsibility to ensure block continuity.
        """
        if not block.is_valid():
            raise ValueError("Block is invalid")
        if not self._chain:
            self._chain += [block]
        else:
            tail = self.tail()
            assert tail is not None
            if block.prev_hash != tail.hash:
                raise ValueError("Block hash does not match chain")
            self._chain += [block]

    def is_valid(self) -> bool:
        """validate full chain."""
        for i in range(len(self) - 1):
            prev = self[i]
            cur = self[i + 1]
            if cur.is_valid():
                log.info(f"Chain entry {i} invalid.")
                return False
            if prev.hash != cur.prev_hash:
                log.info(f"Chain entry {i} and {i+1} have mismatching hash.")
                return False
        return True

    def get_block(self, i: int) -> Block | None:
        """Get block at given index, or None if i not in range."""
        if i >= len(self) or i < -len(self):
            return None
        return self[i]

    def get_block_by_hash(self, hash: str) -> Block | None:
        """Get block with given hash, or None if not found."""
        for block in self:
            if block.hash.startswith(hash):
                return block
        return None

    def grow(self, payload: bytes) -> None:
        """
        Create new Block with provided payload,
        using last Block's hash as prev_hash.
        """
        if not self._chain:
            self._chain += [Block(payload, '')]
        else:
            tail = self.tail()
            assert tail is not None
            self._chain += [Block(payload, tail.hash)]

    def pretty(self) -> str:
        """Pretty print self."""
        return "\n".join([b.pretty() for b in self._chain])
