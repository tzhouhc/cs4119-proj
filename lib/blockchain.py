from time import time
from hashlib import sha256
from lib.utils import setup_logger


NONCE_LENGTH = 64
DIFFICULTY = 2

log = setup_logger(__name__, 2)


def expected_hash_prefix():
    return "0" * DIFFICULTY


class Block:
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
        raw = self.prev_hash.encode() + self.payload + \
            self.timestamp.encode()
        raw += self.nonce.to_bytes(NONCE_LENGTH)
        return sha256(raw).hexdigest()

    def mine(self) -> None:
        if self.done:
            return
        while not self.valid():
            self.nonce += 1
            self.hash = self.get_hash()
        self.done = True

    def __setattr__(self, key, value) -> None:
        if not self.done:
            super().__setattr__(key, value)
        else:
            raise AttributeError(f"Can't modify read-only attribute {key}")

    def valid(self) -> bool:
        if not self.hash.startswith(expected_hash_prefix()):
            return False
        return self.get_hash() == self.hash


class BlockChain:
    def __init__(self):
        self.chain = []

    def append(self, block: Block) -> None:
        # TODO: actually do checks
        self.chain += [block]
