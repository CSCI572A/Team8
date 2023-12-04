# When running from command line, pass arguments:
# NETWORK_INTERFACE="wlan0" CLIENT_MAC_ADDRESS="00.00..." python3 wifi_buddy.py
"""Detect evil twin program."""
import argparse
from typing import List

from scapy.all import (
    Dot11,
    Dot11AssoReq,
    Dot11AssoResp,
    Dot11Auth,
    Packet,
    conf,
    rdpcap,
    sniff,
)

# Dot11 frames the client has received so far relating to
# 4-way handshake, de-authentication frame, and association response
# frames. Represents a database
DB: List[Packet] = []
# the client mac address
CLIENT_MAC_ADDRESS: str = ""


def is_association_response_frame_for_client(frame: Packet) -> bool:
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


def has_evil_twin(current_frame: Packet) -> bool:
    """Return whether evil twin was detected.

    Receipt of two association responses indicates towards a suspicious activity.
    Taking the order in which responses were received, and frame characteristics like
    retry bits, sequence number and association ID (AID) of both responses to consider evil twin attack.
    Check if de-authentication frame is received for the same client that received the
    two association responses because it means the client connected to the AP, then
    disconnected from it and reconnected.
    """
    if is_association_response_frame_for_client(current_frame):
        # find another packet that is a response frame stored in the database
        # or, find a deauthentication packet
        deauth_frame = next(
            (frame for frame in DB if is_client_de_authentication_frame(frame)), None
        )
        previous_asso_resp_frame = next(
            (frame for frame in DB if is_association_response_frame_for_client(frame)),
            None,
        )
        found_deauth_frame = (
            deauth_frame is not None
            and previous_asso_resp_frame is not None
            and previous_asso_resp_frame[Dot11].addr2
            == deauth_frame[Dot11].addr1  # the ap is the same for deauth frame
            # receiver and the sender of the association response frame from the past
        )
        if previous_asso_resp_frame is not None:
            return determine_evil_twin(
                current_frame[Dot11].FCfield.retry,
                current_frame[Dot11].SC,
                previous_asso_resp_frame[Dot11].FCfield.retry,
                previous_asso_resp_frame[Dot11].SC,
                found_deauth_frame,
            )
    return False


def determine_evil_twin(
    r1: bool, seq1: int, r2: bool, seq2: int, deauth_received: bool
) -> bool:
    """Run this algorithm from the paper by Agarwal et al."""
    global DB
    if not r1:
        # create database entry for the client
        # store MAC address, r1, and AID1 in the DB
        if deauth_received:
            # de-authorization frames being absent should raise the alarm for evil twin
            # If they are present then an evil twin is not present.
            # delete local DB entry (we aren't doing this)
            DB = []
            return False
        elif not r2:
            return True
        elif r2:
            if seq1 == seq2:
                return True
            else:
                return False
    else:  # first response with R1 = 1
        # create database entry for the client
        # store MAC address, r1, and AID1 in the DB
        if deauth_received:
            # delete DB entry for client
            DB = []
            return False
        elif not r2:
            # store MAC address, r2, seq2 and AID2 in the DB
            # Fetch seq1 value for client from DB
            return True
        elif r2:
            return True
        else:
            return False


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
        or is_association_response_frame_for_client(packet)
        or is_client_de_authentication_frame(packet)
    )


def process_packet(packet: Packet) -> None:
    """Process packet received from the filter."""
    global DB
    if has_evil_twin(packet):
        print("EVIL TWIN DETECTED!!")
        DB = []
    else:
        print(packet)
        DB.append(packet)


def handle_pcap_mode(args):
    """Handle pcap mode."""
    global CLIENT_MAC_ADDRESS
    CLIENT_MAC_ADDRESS = args.client_mac_address
    capture = rdpcap(args.file)
    for frame in capture:
        if filter_frame(frame):
            process_packet(frame)


def handle_sniff_mode(args):
    """Handle sniff mode."""
    global CLIENT_MAC_ADDRESS
    CLIENT_MAC_ADDRESS = args.client_mac_address
    # Different super sockets are available in Scapy: the native ones, and the ones that use libpcap (to send/receive packets).
    # By default, Scapy will try to use the native ones (except on Windows, where the winpcap/npcap ones are preferred). To manually use the libpcap ones, you must:
    # - On Unix/OSX: be sure to have libpcap installed.
    # - On Windows: have Npcap/Winpcap installed. (default)
    # conf.use_pcap = True will update the sockets pointing to conf.L2socket and conf.L3socket.
    conf.use_pcap = True
    # Sniff packets infinitely
    sniff(
        iface=args.network_interface,
        lfilter=filter_frame,
        prn=process_packet,
        monitor=True,
        store=False,
    )


def main() -> None:
    """Run main program."""
    parser = argparse.ArgumentParser(prog="WifiBuddy", description="Evil Twin Detector")
    subparsers = parser.add_subparsers(required=True)
    # pcap mode flags
    parser_pcap = subparsers.add_parser(
        "pcap_mode", help="read pcap file for detection mode"
    )
    parser_pcap.add_argument(
        "--file", type=str, help="pcap file to read", required=True
    )
    parser_pcap.add_argument(
        "--client-mac-address", type=str, help="client mac address", required=True
    )
    parser_pcap.set_defaults(func=handle_pcap_mode)
    # sniff mode flags
    parser_sniff = subparsers.add_parser("sniff_mode", help="sniff wifi traffic mode")
    parser_sniff.add_argument(
        "--client-mac-address", type=str, help="client mac address", required=True
    )
    parser_sniff.add_argument(
        "--network-interface",
        type=str,
        help="network interface to listen for wifi traffic",
        required=True,
    )
    parser_sniff.set_defaults(func=handle_sniff_mode)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
