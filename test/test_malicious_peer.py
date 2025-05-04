from lib.p2p import Peer
import time

def test_malicious_peer_behavior():
    print("Launching malicious peer...")
    peer = Peer("127.0.0.1", 65433)
    peer.set_tracker(("127.0.0.1", 65433))  # dummy tracker
    peer.malicious = True #activates the malicious logic
    peer.start()

    print("Malicious peer is mining. Let it run for 10 seconds...")
    time.sleep(10)

    print("Stopping malicious peer...")
    peer.stop()
    print("Test complete.")

if __name__ == "__main__":
    test_malicious_peer_behavior()
