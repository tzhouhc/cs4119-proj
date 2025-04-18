from time import time
from hashlib import sha256
from lib.utils import setup_logger


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

    def __setattr__(self, key, value) -> None:
        """Prevent modification after done."""
        if not self.done:
            super().__setattr__(key, value)
        else:
            raise AttributeError(f"Can't modify read-only attribute {key}")

    def is_valid(self) -> bool:
        """Hash matches required difficulty and regenerated hash."""
        if not self.hash.startswith(expected_hash_prefix()):
            return False
        return self.get_hash() == self.hash


class BlockChain:

    def __init__(self):
        # always initialize chain with a null starter
        self._chain: list[Block] = []

    def __len__(self):
        return len(self._chain)

    def tail(self) -> Block | None:
        if self._chain:
            return self._chain[-1]
        return None

    def append(self, block: Block) -> None:
        """Add a new block to the chain."""
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
            prev = self._chain[i]
            cur = self._chain[i + 1]
            if cur.is_valid():
                log.info(f"Chain entry {i} invalid.")
                return False
            if prev.hash != cur.prev_hash:
                log.info(f"Chain entry {i} and {i+1} have mismatching hash.")
                return False
        return True

    def get_block(self, i: int) -> Block | None:
        if i >= len(self):
            return None
        return self._chain[i]

    def get_block_by_hash(self, hash: str) -> Block | None:
        for block in self._chain:
            if block.hash.startswith(hash):
                return block
        return None

    def grow(self, payload: bytes) -> None:
        if not self._chain:
            self._chain += [Block(payload, '')]
        else:
            tail = self.tail()
            assert tail is not None
            self._chain += [Block(payload, tail.hash)]
