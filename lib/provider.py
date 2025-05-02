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
        sleep(1)
        return f"This is the {self.count}th generated sentence."
