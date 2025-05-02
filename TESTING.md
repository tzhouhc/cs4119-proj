# Testing

## Unit Tests

We have unit tests to ensure base library classes and functions work correctly
and (to a lesser extent) prevent regressions.

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

What we have:

- 1 tracker alone would idle.
- 1 peer would mine but fail to send.

We want to be at a stage where:

- 1 peer and 1 tracker should constantly alternate incrementing the block chain.
- 3 peer and 1 tracker should have a fun event.
