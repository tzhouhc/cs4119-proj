# CS4119 Project Readme

Team 34

## Members

Active Members: dpn2111, em3772, tz2635

No show after first team meeting: nn2622

## Dev

### Pre-commit

The repo included precommit hooks for linting and formatting. To use, devs
should locally install `pre-commit`:

```bash
pip3 install pre-commit --break-system-packages
```

then in the repo root, run `pre-commit` or `pre-commit run --all-files`.

To update checks, update `.pre-commit-config.yaml`.

### Process

I recommend developing in feature branches, validating that your changes
function without obvious breaks and passes unit tests before fast-forward
merging into `main` (or rebase first if `main` diverged) and pushing.

For major changes, consider asking for a peer to review it in your remote
branch.

### Testing

I have included some unit tests and you are most welcome to add more.

For running them, if you have `just` installed, you
can just call `just test`; normally you can run

```bash
python3 -m unittest discover test
```

To run all tests under `test`.

## Usage

Run `./run_network.sh` in TMUX will create 4 splits with 1 (initial) tracker
and 3 peers. Any CLI args to the script will be passed to the `main.py` that it
invokes, e.g. `-v` for logging and `--llm` to activate LLM story writing.

## Credits

Library used:
- OpenAI library for interacting with the ChatGPT LLM endpoints.
- Standard library for various networking, hashing and general capabilities.
