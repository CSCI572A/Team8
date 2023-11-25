"""Example reading pcap file with scapy."""
from scapy.all import Dot11, Dot11AssoResp, Packet, rdpcap


def is_association_response_frame(frame: Packet) -> bool:
    """Return whether associative frame example."""
    return (
        Dot11 in frame
        and frame[Dot11].type == 0
        and frame[Dot11].subtype == 1
        and Dot11AssoResp in frame
    )


def main() -> None:
    """Read example."""
    capture = rdpcap("Network_Join_Nokia_Mobile.pcap")
    for frame in capture:
        if is_association_response_frame(frame):
            print(f"seq: {hex(frame[Dot11].SC)}")
            print(f"retry: {frame[Dot11].FCfield.retry}")
            print(f"AID: {hex(frame[Dot11AssoResp].AID)}")


if __name__ == "__main__":
    main()
