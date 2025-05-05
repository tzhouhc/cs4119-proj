from lib.p2p import Peer
import time

def test_malicious_peer_behavior():
    print("Launching malicious peer...")
    peer = Peer("127.0.0.1", 65433)
    peer.set_tracker(("127.0.0.1", 65433))  # dummy tracker
    peer.malicious = True  # activates the malicious logic
    peer.start()

    print("Malicious peer is mining. Let it run for 10 seconds...")
    time.sleep(10)

    print("Stopping malicious peer...")
    peer.stop()

    print("Blockchain mined by malicious peer:")
    peer.print_chain()

    if peer.chain:
        is_valid = peer.chain.is_valid()
        print("Is chain valid?", is_valid)
        # Since packet was corrupted, but not the actual chain, it should still be valid
        assert is_valid, "Expected chain to be valid since tampering was at packet level"
        print("Malicious packets were sent — check logs for warning messages about corruption.")
    else:
        print("No chain was produced, which is unexpected in this case.")
    print("Test complete.")

if __name__ == "__main__":
    test_malicious_peer_behavior()

