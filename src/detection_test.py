"""Test evil twin detection."""
"""Good read on what each field for 802.11 frames are: https://howiwifi.com/2020/07/13/802-11-frame-types-and-formats/#:~:text=The%20image%20below%20shows%20the,%2C%20control%2C%20or%20data%20frame."""

import pytest
from scapy.all import Dot11, Dot11AssoReq, Dot11AssoResp, Dot11Auth, RadioTap

from . import CLIENT_MAC_ADDRESS, has_evil_twin, wifi_buddy

ap_mac = "00:11:22:33:44:55"
evil_twin_mac = "00:11:22:33:44:55"


@pytest.fixture
def mock_association_response_frame():
    """Create a mock association response frame."""

    def get_frame(ap_mac, sequence_control, association_id, retry):
        """Create frame for fixture."""
        # ap sends an association response back to client
        # Dot11 type=0 indicates management
        # subtype=1 indicates association response
        # Dot11AssoResp.status=0 indicates a successful association
        response_frame = (
            RadioTap()
            / Dot11(
                type=0,
                subtype=1,
                addr1=CLIENT_MAC_ADDRESS,
                addr2=ap_mac,
                addr3=CLIENT_MAC_ADDRESS,
            )
            / Dot11AssoResp(status=0)
        )

        # Set the sequence control field
        response_frame[Dot11].SC = sequence_control

        # Set the association ID field
        response_frame[Dot11AssoResp].assoc_id = association_id

        # Set the retry field
        response_frame[Dot11AssoResp].retry = retry

    return get_frame


def test_regular_4_way_hanshake_scenario(mock_association_response_frame, monkeypatch):
    """Test regular 4 way handshake scenario."""
    # mock what we have received in the DB so far
    monkeypatch.setattr(
        wifi_buddy,
        "DB",
        [
            # authentication request frame sent by the client
            # Dot11.type values are 0-management, 1-control, 2-data
            # Dot11.subtype field indicates the type of management control or data frame.
            RadioTap()
            / Dot11(
                type=0, subtype=11, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS, addr3=ap_mac
            )
            / Dot11Auth(algo=0, seqnum=1, status=0),
            # authentication response frame sent by the ap
            # subtype=12 to indicate an authentication response frame
            RadioTap()
            / Dot11(
                type=0,
                subtype=12,
                addr1=CLIENT_MAC_ADDRESS,
                addr2=ap_mac,
                addr3=CLIENT_MAC_ADDRESS,
            )
            / Dot11Auth(algo=0, seqnum=2, status=0),
            # client sends an association request to the ap
            # type=0 and subtype=0 to indicate an association request
            RadioTap()
            / Dot11(
                type=0, subtype=0, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS, addr3=ap_mac
            )
            / Dot11AssoReq(),
        ],
    )
    # ap sends an association response back to client
    # Dot11AssoResp.status=0 indicates a successful association
    assert (
        has_evil_twin(mock_association_response_frame(ap_mac, 0x0001, 0x0001, 1))
        == False
    )


def test_evil_twin_scenario(mock_association_response_frame, monkeypatch):
    """Test evil twin scenario from https://link.springer.com/article/10.1007/s10776-018-0396-1."""
    # mock what we have received in the DB so far
    monkeypatch.setattr(
        wifi_buddy,
        "DB",
        [
            # authentication request frame sent by the client
            # Dot11.type values are 0-management, 1-control, 2-data
            # Dot11.subtype field indicates the type of management control or data frame.
            RadioTap()
            / Dot11(
                type=0, subtype=11, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS, addr3=ap_mac
            )
            / Dot11Auth(algo=0, seqnum=1, status=0),
            # authentication response frame sent by the ap
            # subtype=12 to indicate an authentication response frame
            RadioTap()
            / Dot11(
                type=0,
                subtype=12,
                addr1=CLIENT_MAC_ADDRESS,
                addr2=ap_mac,
                addr3=CLIENT_MAC_ADDRESS,
            )
            / Dot11Auth(algo=0, seqnum=2, status=0),
            # client sends an association request to the ap
            # type=0 and subtype=0 to indicate an association request
            RadioTap()
            / Dot11(
                type=0, subtype=0, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS, addr3=ap_mac
            )
            / Dot11AssoReq(),
            # evil twin sends an association response back to client
            mock_association_response_frame(evil_twin_mac, 0x0001, 0x0001, 1),
        ],
    )
    # ap sends an association response back to client
    assert (
        has_evil_twin(mock_association_response_frame(ap_mac, 0x0001, 0x0001, 1))
        == True
    )