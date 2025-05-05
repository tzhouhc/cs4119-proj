import logging
import sys
from typing import Any

BLUE = "\033[0;34m"
RED = "\033[0;31m"
GREEN = "\033[0;32m"
END = "\033[0m"

LOGFMT = "%(name)s@%(levelname)s [%(asctime)s.%(msecs)04d]: %(message)s"
DATEFMT = "%I:%M:%S"


Addr = tuple[str, int]


def blue(line: Any) -> str:
    """Render current input as blue via ANSI code"""
    return f"{BLUE}{line}{END}"


def red(line: Any) -> str:
    """Render current input as red via ANSI code"""
    return f"{RED}{line}{END}"


def green(line: Any) -> str:
    """Render current input as green via ANSI code"""
    return f"{GREEN}{line}{END}"


def setup_file_logger(suffix: str, name=None) -> logging.Logger:
    """
    Setup logging based on verbosity.

    name: logger name; you can usually just use `__name__`
    addr: str, informs what to name the log file
    """
    if not name:
        name = __name__
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    handler = logging.FileHandler(f"log_{suffix}.txt", mode="w")
    formatter = logging.Formatter(LOGFMT, datefmt=DATEFMT)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def setup_logger(verbosity: int, name=None) -> logging.Logger:
    """
    Setup logging based on verbosity.

    name: logger name; you can usually just use `__name__`
    verbosity: int -- 0 for warning only, 1 for info, 2 for all
    """
    # Create a logger
    if not name:
        name = __name__
    logger = logging.getLogger(name)
    # Set the logging level based on verbosity
    level = arg_verbosity(verbosity)
    logger.setLevel(level)
    # Create a console handler and set its level
    ch = logging.StreamHandler(sys.stderr)
    # Create a formatter
    formatter = logging.Formatter(LOGFMT, datefmt=DATEFMT)
    # Add formatter to ch
    ch.setFormatter(formatter)
    # Add ch to logger
    logger.addHandler(ch)
    return logger


def arg_verbosity(verbosity: int):
    """
    Converts verbosity in range 0, 1, 2 to logging verbosity.

    Args:
        verbosity: int

    Returns:
        verbosity in alignment with logging log levels.
    """
    level = logging.NOTSET
    if verbosity == 0:
        level = logging.WARNING
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.DEBUG
    return level
