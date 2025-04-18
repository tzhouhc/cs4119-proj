import logging
import sys


def setup_file_logger(name: str, addr: str) -> logging.Logger:
    """
    Setup logging based on verbosity.

    addr: str, informs what to name the log file
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    handler = logging.FileHandler(f"log_{addr}.txt", mode="w")
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def setup_logger(name, verbosity: int) -> logging.Logger:
    """
    Setup logging based on verbosity.

    verbosity: int -- 0 for warning only, 1 for info, 2 for all
    """
    # Create a logger
    logger = logging.getLogger(name)
    # Set the logging level based on verbosity
    if verbosity == 0:
        level = logging.WARNING
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.DEBUG
    logger.setLevel(level)
    # Create a console handler and set its level
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(level)
    # Create a formatter
    formatter = logging.Formatter(
        '%(name)s@%(levelname)s: %(message)s')
    # Add formatter to ch
    ch.setFormatter(formatter)
    # Add ch to logger
    logger.addHandler(ch)
    return logger
