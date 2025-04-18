import logging
import sys


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
    formatter = logging.Formatter('%(message)s')
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
