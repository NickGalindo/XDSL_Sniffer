import argparse
from .load_config import CONFIG

def readArguments():
    """
    Read all command line arguments
    """

    parser = argparse.ArgumentParser(description="DEFAULT DESCRIPTION")
    parser.add_argument(
        "-packetSize",
        required=False,
        type=int,
        help="Set a specific packet size if necessary"
    )

    args = parser.parse_args()

    if args.packetSize is None:
        args.packetSize = CONFIG["DEFAULT_PACKET_SIZE"]

    return args
