# Paris Floyd, Abhaya Shrestha
# Final project: WiFiBuddy - Evil Twin Attack Mitigation

import subprocess
import pyshark
import os
import sys

def get_ssid_windows():
    result = subprocess.check_output(["netsh", "wlan", "show", "interfaces"])
    result = result.decode("utf-8").split("\n")
    #print(result)
    for line in result:
        print(line)
        #if "SSID" in line:
        #    return line.strip().split(":")[1].strip()

import subprocess

def get_mac_address_windows():
    result = subprocess.check_output(["getmac"]).decode("utf-8")
    lines = result.splitlines()
    print(lines)
    if len(lines) >= 3:
        # The MAC address is usually in the second line, but you can adjust the index if needed.
        return (lines[1].split()[0], lines[4].split()[0])


ssid = get_ssid_windows()
print("Current SSID:", ssid)
mac_type, mac_address = get_mac_address_windows()
print("MAC Address:", mac_address)
print("MAC Type:", mac_type)