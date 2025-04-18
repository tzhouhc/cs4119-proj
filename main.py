from lib.blockchain import BlockChain
from lib.p2p import P2P


def main():
    c = BlockChain()
    c.grow(b'hello ')
    c.grow(b'world!')
    print(c.pretty())


if __name__ == "__main__":
    main()
