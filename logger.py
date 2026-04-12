import logging  # standard logging library
import sys  # to access stdout
from config import LOG_FILE  # where to write the log file


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("proxy")  # create a logger named "proxy"
    logger.setLevel(logging.DEBUG)  # capture everything from DEBUG and above

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",  # log format: time + level + message
        datefmt="%Y-%m-%d %H:%M:%S",  # human-readable timestamp
    )

    console_handler = logging.StreamHandler(sys.stdout)  # prints logs to the terminal
    console_handler.setLevel(logging.INFO)  # only show INFO and above in the terminal
    console_handler.setFormatter(formatter)  # apply the formatter

    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")  # writes logs to file
    file_handler.setLevel(logging.DEBUG)  # save everything (including DEBUG) to file
    file_handler.setFormatter(formatter)  # apply the same formatter

    logger.addHandler(console_handler)  # attach the terminal handler
    logger.addHandler(file_handler)  # attach the file handler

    return logger


logger = setup_logger()  # create the global logger used by all modules
