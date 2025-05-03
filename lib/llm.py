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
]


class LLMContentProvider(ContentProvider):
    def __init__(self) -> None:
        # use the env var OPENAI_API_KEY for API
        self.client = OpenAI()

    def generate(self, input: list[str]) -> str:
        # Assumes input is a dictionary containing some specific data
        if not input:
            hist = STORY_PROMPTS
        else:
            hist = input
        prompt = "\n\n".join(hist)
        response = self.client.responses.create(
            model=GPT_MODEL,
            instructions=STORYWRITER_PROMPT,
            input=prompt,
        )
        return response.output_text
