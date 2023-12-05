"""Test filter_frame functionality."""

from scapy.all import IP, Dot11, Dot11AssoReq, Dot11AssoResp, Dot11Auth, RadioTap

from src.wifi_buddy import CLIENT_MAC_ADDRESS, filter_frame

ap_mac = "00:11:22:33:44:55"


def test_filter_client_authentication_request_frame():
    """Test filter accept client authentication request frame."""
    assert (
        filter_frame(
            RadioTap()
            / Dot11(
                type=0, subtype=11, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS, addr3=ap_mac
            )
            / Dot11Auth(algo=0, seqnum=1, status=0)
        )
        == True
    )


def test_filter_ap_authentication_response_frame():
    """Test filter accept ap authentication response frame."""
    assert (
        filter_frame(
            RadioTap()
            / Dot11(
                type=0,
                subtype=11,
                addr1=CLIENT_MAC_ADDRESS,
                addr2=ap_mac,
            )
            / Dot11Auth(algo=0, seqnum=2, status=0),
        )
    ) == True


def test_filter_client_association_request_frame():
    """Test filter accept client association request frame."""
    assert (
        filter_frame(
            RadioTap()
            / Dot11(
                type=0, subtype=0, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS, addr3=ap_mac
            )
            / Dot11AssoReq()
        )
    ) == True


def test_filter_ap_association_response_frame():
    """Test filter accept ap association response frame."""
    assert (
        filter_frame(
            RadioTap()
            / Dot11(
                type=0,
                subtype=1,
                addr1=CLIENT_MAC_ADDRESS,
                addr2=ap_mac,
            )
            / Dot11AssoResp(status=0)
        )
    ) == True


def test_filter_client_de_authentication_frame():
    """Test filter accept client de-authentication frame."""
    assert (
        filter_frame(
            RadioTap()
            / Dot11(
                type=0,
                subtype=12,
                addr1=ap_mac,
                addr2=CLIENT_MAC_ADDRESS,
            )
        )
    ) == True


def test_filter_any_other_packet():
    """Test filter reject any other packet."""
    assert (filter_frame(IP())) == False
