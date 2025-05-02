from random import choice

from openai import OpenAI

from lib.provider import ContentProvider

GPT_MODEL = "gpt-3.5-turbo-0125"

STORYWRITER_PROMPT = """
You are a story writer specializing in fiction. Follow the provided prompt or
storyline, write *exactly* one new paragraph that continues the story. The
paragraph should be between 20 to 140 words long, be fit for general reader
consumption. Do not write *anything else*, do not format.
"""

STORY_PROMPTS = [
    """There once was a ship that sails across the ocean, selling magical items
wherever it docks, and to all who might happen upon it...""",
    """The sun set one day. It never did rise again.""",
    """I forgot how to forget."""
    """Alice and Bob are two pen pals who enjoy writing to one another, but
    someone named Eve is always trying to eavesdrop on their communications...
    """,
]


class LLMContentProvider(ContentProvider):
    def __init__(self) -> None:
        # use the env var OPENAI_API_KEY for API
        self.client = OpenAI()

    def generate(self, input: dict) -> str:
        # Assumes input is a dictionary containing some specific data
        hist: list[str] = input.get("history", [choice(STORY_PROMPTS)])[-30:]
        prompt = "\n\n".join(hist)
        print(prompt)
        response = self.client.responses.create(
            model=GPT_MODEL,
            instructions=STORYWRITER_PROMPT,
            input=prompt,
        )
        return response.output_text
