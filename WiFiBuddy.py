# Paris Floyd, Abhaya Shrestha
# Final project: WiFiBuddy - Evil Twin Attack Mitigation

import os
import subprocess
import sys

import pyshark
import scapy


def get_ssid_windows():
    result = subprocess.check_output(["netsh", "wlan", "show", "interfaces"])
    result = result.decode("utf-8").split("\n")
    # print(result)
    for line in result:
        print(line)
        # if "SSID" in line:
        #    return line.strip().split(":")[1].strip()


import subprocess


def get_mac_address_windows():
    result = subprocess.check_output(["getmac"]).decode("utf-8")
    lines = result.splitlines()
    print(lines)
    if len(lines) >= 3:
        # The MAC address is usually in the second line, but you can adjust the index if needed.
        return (lines[1].split()[0], lines[4].split()[0])


# Inputs: r1, r2 - retry bit of first and second response
# seq1, seq2: sequence number of first, second response
# Returns: boolean - is an evil twin present (True) or absent (False)?
def detect_evil_twin(r1, seq1, r2, seq2):
    if r1 == 0:
        # create database entry for the client
        # store MAC address, r1, and AID1 in the DB
        if deauth_received:
            # delete DB entry for client
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


# Function that uses pyshark to access elements of a pcap file. Will filter for association response frames
def analyze_packet(filepath):
    # Open the PCAP file
    capture = pyshark.FileCapture(filepath)
    for packet in capture:
        timestamp = packet.sniff_timestamp
        protocol = packet.transport_layer
        print(f"Timestamp: {timestamp}, Protocol: {protocol}")

        try:
            seq = packet.wlan.seq
            retry = packet.wlan.fc_retry
            print(f"Sequence number: {seq}, Retry bit: {retry}")
        except:
            print("no sequence number or retry bit")


ssid = get_ssid_windows()
print("Current SSID:", ssid)
mac_type, mac_address = get_mac_address_windows()
print("MAC Address:", mac_address)
print("MAC Type:", mac_type)

analyze_packet("test_pcaps/Network_Join_Nokia_Mobile.pcap")
