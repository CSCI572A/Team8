"""Test evil twin detection."""

import pytest
from scapy.all import Dot11, Dot11AssoReq, Dot11AssoResp, Dot11Auth, RadioTap

from . import CLIENT_MAC_ADDRESS, has_evil_twin, wifi_buddy

ap_mac = "00:11:22:33:44:55"


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
            )
            / Dot11AssoResp(status=0)
        )

        # Set the sequence control field
        response_frame[Dot11].SC = sequence_control

        # Set the association ID field
        response_frame[Dot11AssoResp].AID = association_id

        # Set the retry field
        response_frame[Dot11].FCfield.retry = retry

        return response_frame

    return get_frame


@pytest.fixture
def mock_4_way_handshake_incomplete(monkeypatch):
    """Mock 4 way handshake incomplete."""
    monkeypatch.setattr(
        wifi_buddy,
        "DB",
        [
            # authentication request frame sent by the client
            # Dot11.type values are 0-management, 1-control, 2-data
            # Dot11.subtype field indicates the type of management control or data frame.
            RadioTap()
            / Dot11(type=0, subtype=11, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS)
            / Dot11Auth(algo=0, seqnum=1, status=0),
            # authentication response frame sent by the ap
            # subtype=11 to indicate an authentication response frame
            RadioTap()
            / Dot11(
                type=0,
                subtype=11,
                addr1=CLIENT_MAC_ADDRESS,
                addr2=ap_mac,
            )
            / Dot11Auth(algo=0, seqnum=2, status=0),
            # client sends an association request to the ap
            # type=0 and subtype=0 to indicate an association request
            RadioTap()
            / Dot11(type=0, subtype=0, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS)
            / Dot11AssoReq(),
        ],
    )


@pytest.fixture
def mock_4_way_handshake(monkeypatch, mock_association_response_frame):
    """Mock 4 way handshake."""
    monkeypatch.setattr(
        wifi_buddy,
        "DB",
        [
            # authentication request frame sent by the client
            # Dot11.type values are 0-management, 1-control, 2-data
            # Dot11.subtype field indicates the type of management control or data frame.
            RadioTap()
            / Dot11(type=0, subtype=11, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS)
            / Dot11Auth(algo=0, seqnum=1, status=0),
            # authentication response frame sent by the ap
            # subtype=11 to indicate an authentication response frame
            RadioTap()
            / Dot11(
                type=0,
                subtype=11,
                addr1=CLIENT_MAC_ADDRESS,
                addr2=ap_mac,
            )
            / Dot11Auth(algo=0, seqnum=2, status=0),
            # client sends an association request to the ap
            # type=0 and subtype=0 to indicate an association request
            RadioTap()
            / Dot11(type=0, subtype=0, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS)
            / Dot11AssoReq(),
            # ap/eviltwin sends association response frame,
            mock_association_response_frame(
                ap_mac=ap_mac,
                sequence_control=0x0001,
                association_id=0x0001,
                retry=False,
            ),
        ],
    )


@pytest.fixture
def mock_4_way_handshake_retry(monkeypatch, mock_association_response_frame):
    """Mock 4 way handshake in the event of retry."""
    monkeypatch.setattr(
        wifi_buddy,
        "DB",
        [
            # authentication request frame sent by the client
            # Dot11.type values are 0-management, 1-control, 2-data
            # Dot11.subtype field indicates the type of management control or data frame.
            RadioTap()
            / Dot11(type=0, subtype=11, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS)
            / Dot11Auth(algo=0, seqnum=1, status=0),
            # authentication response frame sent by the ap
            # subtype=11 to indicate an authentication response frame
            RadioTap()
            / Dot11(
                type=0,
                subtype=11,
                addr1=CLIENT_MAC_ADDRESS,
                addr2=ap_mac,
            )
            / Dot11Auth(algo=0, seqnum=2, status=0),
            # client sends an association request to the ap
            # type=0 and subtype=0 to indicate an association request
            RadioTap()
            / Dot11(type=0, subtype=0, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS)
            / Dot11AssoReq(),
            # ap/eviltwin sends association response frame,
            mock_association_response_frame(
                ap_mac=ap_mac,
                sequence_control=0x0001,
                association_id=0x0001,
                retry=True,
            ),
        ],
    )


@pytest.fixture
def mock_4_way_handshake_retry_deauth(monkeypatch, mock_association_response_frame):
    """Mock 4 way handshake in the event of retry."""
    monkeypatch.setattr(
        wifi_buddy,
        "DB",
        [
            # authentication request frame sent by the client
            # Dot11.type values are 0-management, 1-control, 2-data
            # Dot11.subtype field indicates the type of management control or data frame.
            RadioTap()
            / Dot11(type=0, subtype=11, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS)
            / Dot11Auth(algo=0, seqnum=1, status=0),
            # authentication response frame sent by the ap
            # subtype=11 to indicate an authentication response frame
            RadioTap()
            / Dot11(
                type=0,
                subtype=11,
                addr1=CLIENT_MAC_ADDRESS,
                addr2=ap_mac,
            )
            / Dot11Auth(algo=0, seqnum=2, status=0),
            # client sends an association request to the ap
            # type=0 and subtype=0 to indicate an association request
            RadioTap()
            / Dot11(type=0, subtype=0, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS)
            / Dot11AssoReq(),
            # ap/eviltwin sends association response frame,
            mock_association_response_frame(
                ap_mac=ap_mac,
                sequence_control=0x0001,
                association_id=0x0001,
                retry=True,
            ),
            # de authentication frame from client
            RadioTap()
            / Dot11(type=0, subtype=12, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS),
        ],
    )


@pytest.fixture
def mock_4_way_handshake_with_deauth(monkeypatch, mock_association_response_frame):
    """Mock 4 way handshake with deauth frame received."""
    monkeypatch.setattr(
        wifi_buddy,
        "DB",
        [
            # authentication request frame sent by the client
            # Dot11.type values are 0-management, 1-control, 2-data
            # Dot11.subtype field indicates the type of management control or data frame.
            RadioTap()
            / Dot11(type=0, subtype=11, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS)
            / Dot11Auth(algo=0, seqnum=1, status=0),
            # authentication response frame sent by the ap
            # subtype=11 to indicate an authentication response frame
            RadioTap()
            / Dot11(
                type=0,
                subtype=11,
                addr1=CLIENT_MAC_ADDRESS,
                addr2=ap_mac,
            )
            / Dot11Auth(algo=0, seqnum=2, status=0),
            # client sends an association request to the ap
            # type=0 and subtype=0 to indicate an association request
            RadioTap()
            / Dot11(type=0, subtype=0, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS)
            / Dot11AssoReq(),
            # ap/evil twin sends response asso frame back to client
            mock_association_response_frame(
                ap_mac=ap_mac,
                sequence_control=0x0001,
                association_id=0x0001,
                retry=False,
            ),
            # de authentication frame from client
            RadioTap()
            / Dot11(type=0, subtype=12, addr1=ap_mac, addr2=CLIENT_MAC_ADDRESS),
        ],
    )


def test_regular_4_way_hanshake_scenario(
    mock_association_response_frame, mock_4_way_handshake_incomplete
):
    """Test regular 4 way handshake scenario."""
    assert (
        has_evil_twin(
            mock_association_response_frame(
                ap_mac=ap_mac,
                sequence_control=0x0001,
                association_id=0x0001,
                retry=False,
            )
        )
        == False
    )


def test_evil_twin_scenario_1(mock_association_response_frame, mock_4_way_handshake):
    """Test case R1 = 0, R2 = 0, Seq1 = Seq2."""
    assert (
        has_evil_twin(
            mock_association_response_frame(
                ap_mac=ap_mac,
                sequence_control=0x0001,
                association_id=0x0001,
                retry=False,
            )
        )
        == True
    )


def test_evil_twin_scenario_2(mock_association_response_frame, mock_4_way_handshake):
    """Test case R1 = 0, R2 = 0, Seq1 != Seq2."""
    assert (
        has_evil_twin(
            mock_association_response_frame(
                ap_mac=ap_mac,
                sequence_control=0x0002,
                association_id=0x0001,
                retry=False,
            )
        )
        == True
    )


def test_evil_twin_scenario_2_deauth(
    mock_association_response_frame, mock_4_way_handshake_with_deauth
):
    """Test case R1 = 0, R2 = 0, Seq1 != Seq2, and deauth frame received."""
    assert (
        has_evil_twin(
            mock_association_response_frame(
                ap_mac=ap_mac,
                sequence_control=0x0002,
                association_id=0x0001,
                retry=False,
            )
        )
        == False
    )


def test_evil_twin_scenario_3(mock_association_response_frame, mock_4_way_handshake):
    """Test case R1 = 0, R2 = 1, Seq1 = Seq2, AID1 != AID2."""
    assert (
        has_evil_twin(
            mock_association_response_frame(
                ap_mac=ap_mac,
                sequence_control=0x0001,
                association_id=0x0002,
                retry=True,
            )
        )
        == True
    )


def test_evil_twin_scenario_4(mock_association_response_frame, mock_4_way_handshake):
    """Test case R1 = 0, R2 = 1, Seq1 != Seq2."""
    assert (
        has_evil_twin(
            mock_association_response_frame(
                ap_mac=ap_mac,
                sequence_control=0x0002,
                association_id=0x0001,
                retry=True,
            )
        )
        == True
    )


def test_evil_twin_scenario_5(
    mock_association_response_frame, mock_4_way_handshake_retry
):
    """Test case R1 = 1, R2 = 0, Seq1 = Seq2."""
    assert (
        has_evil_twin(
            mock_association_response_frame(
                ap_mac=ap_mac,
                sequence_control=0x0001,
                association_id=0x0001,
                retry=False,
            )
        )
        == True
    )


def test_evil_twin_scenario_6(
    mock_association_response_frame, mock_4_way_handshake_retry
):
    """Test case R1 = 1, R2 = 0, Seq1 != Seq2."""
    assert (
        has_evil_twin(
            mock_association_response_frame(
                ap_mac=ap_mac,
                sequence_control=0x0002,
                association_id=0x0001,
                retry=False,
            )
        )
        == True
    )


def test_evil_twin_scenario_6_deauth(
    mock_association_response_frame, mock_4_way_handshake_retry_deauth
):
    """Test case R1 = 1, R2 = 0, Seq1 != Seq2."""
    assert (
        has_evil_twin(
            mock_association_response_frame(
                ap_mac=ap_mac,
                sequence_control=0x0002,
                association_id=0x0001,
                retry=False,
            )
        )
        == False
    )


def test_evil_twin_scenario_7(
    mock_association_response_frame, mock_4_way_handshake_retry
):
    """Test case R1 = 1, R2 = 1, Seq1 = Seq2, AID1 != AID2."""
    assert (
        has_evil_twin(
            mock_association_response_frame(
                ap_mac=ap_mac,
                sequence_control=0x0001,
                association_id=0x0002,
                retry=True,
            )
        )
        == True
    )


def test_evil_twin_scenario_8(
    mock_association_response_frame, mock_4_way_handshake_retry
):
    """Test case R1 = 1, R2 = 1, Seq1 != Seq2."""
    assert (
        has_evil_twin(
            mock_association_response_frame(
                ap_mac=ap_mac,
                sequence_control=0x0002,
                association_id=0x0001,
                retry=True,
            )
        )
        == True
    )


def test_evil_twin_scenario_8_deauth(
    mock_association_response_frame, mock_4_way_handshake_retry_deauth
):
    """Test case R1 = 1, R2 = 1, Seq1 != Seq2 with deauth."""
    assert (
        has_evil_twin(
            mock_association_response_frame(
                ap_mac=ap_mac,
                sequence_control=0x0002,
                association_id=0x0001,
                retry=True,
            )
        )
        == False
    )
