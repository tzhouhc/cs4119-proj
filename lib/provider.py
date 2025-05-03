from random import random
from time import sleep


class ContentProvider:
    def __init__(self) -> None:
        pass

    def generate(self, input: dict) -> str:
        raise NotImplementedError


class MockContentProvider(ContentProvider):
    def __init__(self) -> None:
        self.count = 0

    def generate(self, input: dict) -> str:
        self.count += 1
        sleep(random() * 2)
        return f"The {self.count}th generated sentence."
