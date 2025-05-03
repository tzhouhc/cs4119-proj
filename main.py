from argparse import ArgumentParser

from lib.llm import LLMContentProvider
from lib.p2p import P2P, PEER, TRACKER, TrackerPeer
from lib.utils import arg_verbosity


def arg_parser() -> ArgumentParser:
    parser = ArgumentParser()
    parser.add_argument("ip", help="IP to start tracker/peer on.")
    parser.add_argument("port", help="Port to bind to.", type=int)
    parser.add_argument("tip", help="Tracker's IP.")
    parser.add_argument("tport", help="Tracker port.", type=int)
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (can be used multiple times)",
    )
    parser.add_argument(
        "--llm", action="store_true", help="Use actual LLM content provider."
    )
    return parser


def main():
    args = arg_parser().parse_args()
    vb = arg_verbosity(args.verbose)
    P2P.log.setLevel(vb)
    agent = TrackerPeer(args.ip, args.port)
    if args.llm:
        agent.set_provider(LLMContentProvider())
    if args.ip == args.tip and args.port == args.tport:
        print(f"Creating tracker at {args.ip}:{args.port}.")
        agent.set_state(TRACKER)
    else:
        print(f"Creating peer at {args.ip}:{args.port}.")
        agent.set_tracker((args.tip, args.tport))
        agent.set_state(PEER)
    agent.start()
    agent.main_loop()
    agent.close()


if __name__ == "__main__":
    main()
