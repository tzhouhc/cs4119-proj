# Testing

## Unit Tests

We have unit tests to ensure base library classes and functions work correctly
and (to a lesser extent) prevent regressions.

The unit tests ensure that:
- Blocks and Blockchains behave as expected -- mining process, hash
  requirements, immutability after mining, validation
- P2P code behaves mostly as expected, though due to the racey nature of the
  p2p agents we haven't added too thorough of a set of tests.
- Datapacket tests to ensure their data, parsing and serialization.

## Dev Testing

To run some simple tests, run `main.py` in a few terminals. It expects, in
order, IP, port, tracker IP and tracker port:

```bash
# start tracker -- tracker is when tracker ip and port matches own ip and port
python3 main.py 0.0.0.0 50000 0.0.0.0 50000
# start peer
python3 main.py 0.0.0.0 50001 0.0.0.0 50000
```

This should give some amount of (excessive) logging.

By default, the peers are initialized with a Mock content provider that,
instead of trying to write a meaningful story, just outputs a counter after a
random delay to mimic the uncertain nature of LLMs.

What we have:

- 1 peer and 1 tracker constantly alternate incrementing the block chain as
  expected.
- 3 peer and 1 tracker have a fun event. That said, it's a bit too costly to
  _test_ with actual LLM backing too, so we're usually just testing with empty
  content.
- 3 peer and 1 tracker and 1 malicious. Malicious packets correctly blocked.

Notes:
- Sometimes a node can get two blocks sent before being told to stop mining --
  this is normal since the node mines greedily and would not stop even after
  sending out a block for review.
