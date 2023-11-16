"""Detect evil twin program."""
import os

from scapy.all import Dot11, Dot11AssoReq, Dot11AssoResp, Dot11Auth, Packet, sniff

# the network interface to sniff traffic on
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", default="wlan0")
# Dot11 frames the client has received so far relating to
# 4-way handshake, de-authentication frame, and association response
# frames. Represents a database
DB = []
# the client mac address
CLIENT_MAC_ADDRESS = os.getenv("CLIENT_MAC_ADDRESS", default="00:00:00:00:00:00")


def is_association_response_frame(frame: Packet) -> bool:
    """Return whether frame is association response frame."""
    return (
        Dot11 in frame
        and frame[Dot11].type == 0
        and frame[Dot11].subtype == 1
        and Dot11AssoResp in frame
        and frame[Dot11].addr1 == CLIENT_MAC_ADDRESS
    )


def is_client_de_authentication_frame(frame: Packet) -> bool:
    """Return whether frame is a de authentication frame from client."""
    return (
        Dot11 in frame
        and frame[Dot11].type == 0
        and frame[Dot11].subtype == 12
        and frame[Dot11].addr2 == CLIENT_MAC_ADDRESS
    )


def has_evil_twin(frame: Packet) -> bool:
    """Return whether evil twin was detected.

    Receipt of two association responses indicates towards a suspicious activity.
    Taking the order in which responses were received, and frame characteristics like
    retry bits, sequence number and association ID (AID) of both responses to consider evil twin attack.
    Check if de-authentication frame is received for the same client that received the
    two association responses because it means the client connected to the AP, then
    disconnected from it and reconnected.
    """
    raise NotImplementedError


def filter_frame(packet: Packet) -> bool:
    """Filter frames captured.

    1. Discard the frames that are directed to other APs that are not being monitored.
    2. Scan or the 4-way handshake between the monitored AP and the clients,
        de-authentication frames, association request and response frames.
    """
    is_authentication_request_frame = (
        Dot11 in packet
        and packet[Dot11].type == 0
        and packet[Dot11].subtype == 11
        and Dot11Auth in packet
        and packet[Dot11].addr2 == CLIENT_MAC_ADDRESS
    )
    is_authentication_response_frame = (
        Dot11 in packet
        and packet[Dot11].type == 0
        and packet[Dot11].subtype == 12
        and Dot11Auth in packet
        and packet[Dot11].addr1 == CLIENT_MAC_ADDRESS
    )
    is_association_request_frame = (
        Dot11 in packet
        and packet[Dot11].type == 0
        and packet[Dot11].subtype == 0
        and Dot11AssoReq in packet
        and packet[Dot11].addr2 == CLIENT_MAC_ADDRESS
    )
    return (
        is_authentication_request_frame
        or is_authentication_response_frame
        or is_association_request_frame
        or is_association_response_frame(packet)
        or is_client_de_authentication_frame(packet)
    )


def process_packet(packet: Packet) -> None:
    """Process packet received from the filter."""
    if has_evil_twin(packet):
        print("EVIL TWIN DETECTED!!")
    print(packet.summary())


def main() -> None:
    """Run main program."""
    # Sniff packets infinitely
    sniff(
        iface=NETWORK_INTERFACE, lfilter=filter_frame, prn=process_packet, store=False
    )

if __name__ == '__main__':
    main()
