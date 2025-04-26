from base64 import b64decode, b64encode
from hashlib import sha256
from time import time
from typing import Any, Iterator

from lib.utils import blue, green, setup_logger

NONCE_LENGTH = 64
DIFFICULTY = 2

log = setup_logger(1, name=__name__)


def expected_hash_prefix():
    return "0" * DIFFICULTY


class Block:
    """A Block in the blockchain. call `mine` to finalize."""

    done: bool = False
    payload: bytes = b""
    prev_hash: str = ""
    hash: str = ""
    nonce: int = 0
    timestamp: str = ""

    def __init__(self, payload: bytes, prev_hash: str):
        self.timestamp: str = str(time())
        self.payload: bytes = payload
        self.hash: str = self.get_hash()
        self.prev_hash: str = prev_hash
        self.nonce = 0

    def __setattr__(self, key, value) -> None:
        """Prevent modification after done EXCEPT done & self_mining."""
        if not self.done:
            super().__setattr__(key, value)
        elif key == "stop_mining":
            super().__setattr__(key, value)
        else:
            raise AttributeError(f"Can't modify read-only attribute {key}")

    def __str__(self) -> str:
        content = self.payload if len(self.payload) <= 20 else self.payload[:8]
        hash = self.hash[:8]
        return f"Block[{hash}, {content}]"

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Block):
            return False
        return all(
            [
                self.timestamp == other.timestamp,
                self.hash == other.hash,
                self.prev_hash == other.prev_hash,
                self.payload == other.payload,
                self.nonce == other.nonce,
            ]
        )

    def get_hash(self) -> str:
        """Get hash based on previous hash, payload and create time."""
        raw = self.prev_hash.encode() + self.payload + self.timestamp.encode()
        raw += self.nonce.to_bytes(NONCE_LENGTH)
        return sha256(raw).hexdigest()
    
    def set_stop_mining(self, value: bool) -> None:
        """Safely set  stop_mining flag."""
        self.stop_mining = value

    def mine(self) -> None:
        """Mine for required difficulty and finalize block."""
        if self.done:
            return
        self.set_stop_mining(False)
        while not self.is_valid():
            if self.stop_mining:
                log.debug("Mining interrupted by stop_mining flag.")
                self.set_stop_mining(False)
                return
            self.nonce += 1
            self.hash = self.get_hash()
        self.done = True

    def is_valid(self) -> bool:
        """Hash matches required difficulty and regenerated hash."""
        if not self.hash.startswith(expected_hash_prefix()):
            return False
        return self.get_hash() == self.hash

    def pretty(self) -> str:
        content = self.payload if len(self.payload) <= 20 else self.payload[:8]
        hash = self.hash[:8]
        return f"Block[{blue(hash)}, {green(content)}]"

    def as_dict(self) -> dict[str, Any]:
        """Creates dict with primitive types to allow json serialization."""
        return {
            "timestamp": self.timestamp,
            "payload": b64encode(self.payload).decode(),
            "hash": self.hash,
            "prev_hash": self.prev_hash,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]):
        """Parse serialized data dict to recreate block."""
        org_payload = b64decode(data["payload"].encode())
        ret = cls(org_payload, data["prev_hash"])
        ret.timestamp = data["timestamp"]
        ret.hash = data["hash"]
        ret.nonce = data["nonce"]
        ret.done = True
        return ret


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

    def __eq__(self, other: Any) -> bool:
        """Check equality."""
        if not isinstance(other, BlockChain):
            return False
        if len(self) != len(other):
            return False
        return all([self[i] == other[i] for i in range(len(self))])

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
        if self:
            if not self[0].is_valid():
                log.debug("Chain root invalid.")
                return False
        for i in range(len(self) - 1):
            prev = self[i]
            cur = self[i + 1]
            if not cur.is_valid():
                log.debug(f"Chain entry {i+1} invalid.")
                return False
            if prev.hash != cur.prev_hash:
                log.debug(f"Chain entry {i} and {i+1} have mismatching hash.")
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
            new = Block(payload, "")
            new.mine()
            self._chain += [new]
        else:
            tail = self.tail()
            assert tail is not None
            new = Block(payload, tail.hash)
            new.mine()
            self._chain += [new]

    def pretty(self) -> str:
        """Pretty print self."""
        return "\n".join([b.pretty() for b in self._chain])

    def as_list(self) -> list[dict]:
        return [b.as_dict() for b in self]

    @classmethod
    def from_list(cls, lst: list[dict]):
        c = cls()
        c._chain = [Block.from_dict(d) for d in lst]
        return c
