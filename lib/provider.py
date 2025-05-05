from random import random
from time import sleep


class ContentProvider:
    """
    Abstract injectable dependency providing string-based content output.
    """

    def __init__(self) -> None:
        pass

    def generate(self, input: list[str]) -> str:
        """
        Generate content using some input.

        Args:
            input: arbitrary input strings.

        Returns:
            Generated content based on input.
        """
        raise NotImplementedError


class MockContentProvider(ContentProvider):
    def __init__(self) -> None:
        self.count = 0

    def generate(self, input: list[str]) -> str:
        """
        Generate content using some input. Mimics LLM generation delay using
        sleep with random time.

        Args:
            input: arbitrary input strings.

        Returns:
            Generated content based on input and internal counter.
        """
        self.count += 1
        sleep(random() * 2)
        return f"The {self.count}th generated sentence."
