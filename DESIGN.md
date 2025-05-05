# Team 34 Design.md \- Collective Story Writing

## Members

Active Members: dpn2111, em3772, tz2635

No show after first team meeting: nn2622

## Overview

Collective story writing by LLMs competing for dominance – first peer to successfully mine the block gets to add their new paragraph to the canonical story – _the canon_ – and the natural time cost in outputting the story makes it less likely to get forks (which might be a bit of a downside?)

## Implementation:

- LLM: local LLM or OpenAI API calls via the `openai` package

  - We would likely go with cheaper, older models such as the gpt-3.5-turbo as opposed to newer models like 4o, 4.1 or similar – we don’t need the reasoning power, we just need a story that reads like one.
  - For the sake of economy and performance we will only request outputs up to 140 words per paragraph, and maintain a context window of up to 30 messages, which should be well below the bidirectional token limit on the API.
  - The response time on the API is fairly ok for human usage, but is still in the 0.1-to-5 _seconds_ range. _This likely will effectively prevent any sort of race condition_.
  - We will use a dummy generator for testing.

- Blockchain:

  - Blocks are implemented per standard – prev and current hash, payload, nonce
  - Each block’s payload will be a paragraph in story – the peer will collect the previous context from its chain, then send to the LLM along with a system-prompt to generate exactly one paragraph as the payload.
  - Each run of the process can be a story
  - 4 (number of peers) competing paragraphs, one of them becomes the next paragraph story, using the contest-resolution policy of block chains.
  - LLM take time to generate story, so everyone gets a fair share chance to get into the main story
  - Fork resolution (Forks are “divergences” in the story; a “canon” will rise from the resolution)
    - The chain with the greatest length (number of blocks) becomes the canonical chain
    - Chain length can be determined by traversing with current \= current.next

- P2P:

  - The first peer who mines a valid block becomes the tracker for the next round
    - The tracker identity gets stored in a tracker_id field of the block and is propagated to all the peers
  - Role of the tracker:
    - Maintain and broadcast the current peer list
    - Doesn’t participate in mining during the round it serves as tracker
    - After it’s tracking round is over, it becomes a peer and can participate in mining for a block
  - How to choose the tracker
    - Initially: The first tracker is hard coded and when peers join they notify it that they are there.
    - Race between the peers, whoever sends first
    - If they come at same time → fork
    - Peers who receive requests intended for the tracker will just:
      - Tell the requester where the tracker is at
      - _Maybe_ send the requester a non-authoritative answer

- Data Packets

  - Data packets will be bytes encoded from JSON-encoded dictionaries with metadata and possibly payload
  - Metadata:
    - Type (peer-list-request, block, these-are-not-the-droids-you-are-looking-for)
    - Timestamp (for logging purposes)
    - From (?)
    - To (?)
  - Payload:
    - Peer list (dict with one field for tracker and one list for peers)
    - Block
    - IP/port

- Communication

  - Each peer will be constantly listening for incoming packets and responding with the above based on its current state – and it will only have two states, Tracker or Peer.
  - In tracker mode it will do a while loop waiting for state change and in the meantime handle incoming peer-list requests.
    - Upon receiving a valid block it will become a peer and start doing peer-y things like mining; it also sends a broadcast to announce the new tracker and the new chain.
  - In Peer mode it listens for peerlist update announcements, which it just consumes quietly, or if it gets a block update that is valid, that means it has lost the game and should accept the block and restart mining.
    - If it got a peer-list request it will just tell the requester where the actual tracker is.
    - If it got a BAD chain it can just reject that.
    - If it got a valid different length chain it can just pick and save the LONGER one.
    - Eventually forks disappear because they just sort of naturally resolve because some peers have more mining power

- Dropped peer/tracker

  - Dropped peers are detected by connection refused errors and removed from
    lists.
  - Dropped trackers are replaced by the first peer that detected them
    missing.

- Testing
  - Unit Tests
  - Someone ideally tries to make a process, documenting how to test things locally using what is already available.
  - See [Testing.md](./TESTING.md) for details.

## Demo idea

Tmux script that invokes 4 peers concurrently, one of which starts off as the
tracker.

The script should demo:

- BlockChain -- implicit, the underlying block system can be seen in the unit
  test.
- P2P -- The logging will show the back and forth between different nodes as
  well as node state transitions.
- Chain building: we will see an accumulating chain of story as time goes on.

We additionally can start a malicious actor with code dedicated to produce
invalid blocks.
