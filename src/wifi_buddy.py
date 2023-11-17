# When running from command line, pass arguments:
# NETWORK_INTERFACE="wlan0" CLIENT_MAC_ADDRESS="00.00..." python3 wifi_buddy.py
"""Detect evil twin program."""
import os
from typing import List

from scapy.all import Dot11, Dot11AssoReq, Dot11AssoResp, Dot11Auth, Dot11Retry Packet, conf, sniff

# the network interface to sniff traffic on
NETWORK_INTERFACE: str = os.getenv("NETWORK_INTERFACE", default="wlan0")
# Dot11 frames the client has received so far relating to
# 4-way handshake, de-authentication frame, and association response
# frames. Represents a database
DB: List[Packet] = []
# the client mac address
CLIENT_MAC_ADDRESS: str = os.getenv("CLIENT_MAC_ADDRESS", default="00:00:00:00:00:00")


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


def has_evil_twin(frame1: Packet) -> bool:
    """Return whether evil twin was detected.
    Receipt of two association responses indicates towards a suspicious activity.
    Taking the order in which responses were received, and frame characteristics like
    retry bits, sequence number and association ID (AID) of both responses to consider evil twin attack.
    Check if de-authentication frame is received for the same client that received the
    two association responses because it means the client connected to the AP, then
    disconnected from it and reconnected.
    """

    if is_association_response_frame(frame1):
        # find another packet that is a response frame stored in the database
        # or, find a deauthentication packet
        found_deauth_frame = False
        for frame2 in DB:
            if frame2 != frame1 and is_association_response_frame(frame2):
                # this is the first packet sent to the device in response. We need to investigate for evil twin
                # Execute evil twin detection algorithm with two sequence numbers and retry bits
                # Access sequence numbers
                seq1 = frame1[Dot11].seq
                seq2 = frame2[Dot11].seq
                # Access retry bits
                r1 = frame1.FCfield & Dot11Retry    # Not tested yet.
                r2 = frame2.FCfield & Dot11Retry

                # Pass to detection function
                return determine_evil_twin(r1, seq1, r2, seq2, found_deauth_frame)

            elif is_client_de_authentication_frame(frame2):     # TODO: check to make sure that this deauth frame is associated with the original connection request
                # Boolean is true
                found_deauth_frame = True

        # We didn't find another association response in the DB. Return False
        return False
    else:
        return False

    raise NotImplementedError

def determine_evil_twin(r1, seq1, r2, seq2, deauth_received):
    if r1 == 0:
        # create database entry for the client
        # store MAC address, r1, and AID1 in the DB
        if deauth_received:
            # de-authorization frames being absent should raise the alarm for evil twin
            # If they are present then an evil twin is not present.
            # delete local DB entry (we aren't doing this)
            return False
        elif r2 == 0:
            return True
        elif r2 == 1 and seq1 == seq2:
            if seq1 == seq2:
                return True
            else:
                return False
    else:  # first response with R1 = 1
        # create database entry for the client
        # store MAC address, r1, and AID1 in the DB
        if deauth_received:
            # delete DB entry for client
            return False
        elif r2 == 0:
            # store MAC address, r2, seq2 and AID2 in the DB
            # Fetch seq1 value for client from DB
            return True
        elif r2 == 1:
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
        or is_association_response_frame(packet)
        or is_client_de_authentication_frame(packet)
    )


def process_packet(packet: Packet) -> None:
    """Process packet received from the filter."""
    if has_evil_twin(packet):
        print("EVIL TWIN DETECTED!!")
    print(packet.summary())
    # saving packet for further analysis of evil twin
    # detection
    DB.append(packet)


def main() -> None:
    """Run main program."""
    # Different super sockets are available in Scapy: the native ones, and the ones that use libpcap (to send/receive packets).
    # By default, Scapy will try to use the native ones (except on Windows, where the winpcap/npcap ones are preferred). To manually use the libpcap ones, you must:
    # - On Unix/OSX: be sure to have libpcap installed.
    # - On Windows: have Npcap/Winpcap installed. (default)
    # conf.use_pcap = True will update the sockets pointing to conf.L2socket and conf.L3socket.
    conf.use_pcap = True
    # Sniff packets infinitely
    sniff(
        iface=NETWORK_INTERFACE,
        lfilter=filter_frame,
        prn=process_packet,
        monitor=True,
        store=False,
    )


if __name__ == "__main__":
    main()
