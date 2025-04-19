from lib.blockchain import BlockChain


def main():
    c = BlockChain()
    c.grow(b"hello ")
    c.grow(b"world!")
    print(c.pretty())


if __name__ == "__main__":
    main()
