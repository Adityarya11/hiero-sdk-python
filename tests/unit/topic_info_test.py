import pytest

from hiero_sdk_python.account.account_id import AccountId
from hiero_sdk_python.consensus.topic_info import TopicInfo
from hiero_sdk_python.crypto.private_key import PrivateKey
from hiero_sdk_python.Duration import Duration
from hiero_sdk_python.hapi.services import consensus_topic_info_pb2
from hiero_sdk_python.hapi.services.basic_types_pb2 import AccountID, Key
from hiero_sdk_python.hapi.services.timestamp_pb2 import Timestamp
from hiero_sdk_python.tokens.custom_fixed_fee import CustomFixedFee

pytestmark = pytest.mark.unit


@pytest.fixture
def topic_info():
    """Create a TopicInfo instance with all parameters for testing."""
    public_key = PrivateKey.generate_ed25519().public_key()

    # Create protobuf timestamp
    timestamp = Timestamp()
    timestamp.seconds = 1625097600  # 2021-07-01 00:00:00 UTC
    timestamp.nanos = 0

    # Create protobuf account ID
    account_id = AccountID()
    account_id.shardNum = 0
    account_id.realmNum = 0
    account_id.accountNum = 100

    # Create protobuf key
    key = Key()
    key.ed25519 = public_key.to_bytes_raw()

    # Create custom fee
    custom_fee = CustomFixedFee(
        amount=1000,
        denominating_token_id=None,
        fee_collector_account_id=AccountId(0, 0, 200),
        all_collectors_are_exempt=False,
    )

    return TopicInfo(
        memo="Test topic memo",
        running_hash=b"\x01\x02\x03\x04\x05\x06\x07\x08",
        sequence_number=42,
        expiration_time=timestamp,
        admin_key=key,
        submit_key=key,
        auto_renew_period=Duration(7776000),  # 90 days
        auto_renew_account=account_id,
        ledger_id=b"\x09\x0a\x0b\x0c",
        fee_schedule_key=public_key,
        fee_exempt_keys=[public_key],
        custom_fees=[custom_fee],
    )


@pytest.fixture
def proto_topic_info():
    """Create a protobuf ConsensusTopicInfo for testing."""
    public_key = PrivateKey.generate_ed25519().public_key()

    # Create protobuf timestamp
    timestamp = Timestamp()
    timestamp.seconds = 1625097600  # 2021-07-01 00:00:00 UTC
    timestamp.nanos = 0

    # Create protobuf account ID
    account_id = AccountID()
    account_id.shardNum = 0
    account_id.realmNum = 0
    account_id.accountNum = 100

    # Create protobuf key
    key = Key()
    key.ed25519 = public_key.to_bytes_raw()

    # Create custom fee
    custom_fee = CustomFixedFee(
        amount=1000,
        denominating_token_id=None,
        fee_collector_account_id=AccountId(0, 0, 200),
        all_collectors_are_exempt=False,
    )

    proto = consensus_topic_info_pb2.ConsensusTopicInfo()
    proto.memo = "Test topic memo"
    proto.runningHash = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    proto.sequenceNumber = 42
    proto.expirationTime.CopyFrom(timestamp)
    proto.adminKey.CopyFrom(key)
    proto.submitKey.CopyFrom(key)
    proto.autoRenewPeriod.seconds = 7776000
    proto.autoRenewAccount.CopyFrom(account_id)
    proto.ledger_id = b"\x09\x0a\x0b\x0c"
    proto.fee_schedule_key.CopyFrom(public_key._to_proto())
    proto.fee_exempt_key_list.append(public_key._to_proto())
    proto.custom_fees.append(custom_fee._to_topic_fee_proto())
    return proto


def test_topic_info_initialization(topic_info):
    """Test the initialization of the TopicInfo class with all parameters."""
    assert topic_info.memo == "Test topic memo"
    assert topic_info.running_hash == b"\x01\x02\x03\x04\x05\x06\x07\x08"
    assert topic_info.sequence_number == 42
    assert topic_info.expiration_time is not None
    assert topic_info.admin_key is not None
    assert topic_info.submit_key is not None
    assert topic_info.auto_renew_period == Duration(7776000)
    assert topic_info.auto_renew_account is not None
    assert topic_info.ledger_id == b"\x09\x0a\x0b\x0c"
    assert topic_info.fee_schedule_key is not None
    assert len(topic_info.fee_exempt_keys) == 1
    assert len(topic_info.custom_fees) == 1
    assert topic_info.custom_fees[0].amount == 1000


def test_topic_info_initialization_with_none_values():
    """Test the initialization of the TopicInfo class with None values for optional parameters."""
    topic_info = TopicInfo(
        memo="Test memo",
        running_hash=b"\x01\x02",
        sequence_number=1,
        expiration_time=None,
        admin_key=None,
        submit_key=None,
        auto_renew_period=None,
        auto_renew_account=None,
        ledger_id=None,
        fee_schedule_key=None,
        fee_exempt_keys=None,
        custom_fees=None,
    )

    assert topic_info.memo == "Test memo"
    assert topic_info.running_hash == b"\x01\x02"
    assert topic_info.sequence_number == 1
    assert topic_info.expiration_time is None
    assert topic_info.admin_key is None
    assert topic_info.submit_key is None
    assert topic_info.auto_renew_period is None
    assert topic_info.auto_renew_account is None
    assert topic_info.ledger_id is None
    assert topic_info.fee_schedule_key is None
    assert not topic_info.fee_exempt_keys
    assert not topic_info.custom_fees


def test_topic_info_initialization_with_empty_lists():
    """Test the initialization of the TopicInfo class with empty lists."""
    topic_info = TopicInfo(
        memo="Test memo",
        running_hash=b"\x01\x02",
        sequence_number=1,
        expiration_time=None,
        admin_key=None,
        submit_key=None,
        auto_renew_period=None,
        auto_renew_account=None,
        ledger_id=None,
        fee_schedule_key=None,
        fee_exempt_keys=[],
        custom_fees=[],
    )

    assert not topic_info.fee_exempt_keys
    assert not topic_info.custom_fees


def test_from_proto(proto_topic_info):
    """Test the _from_proto method of the TopicInfo class."""
    topic_info = TopicInfo._from_proto(proto_topic_info)

    assert topic_info.memo == "Test topic memo"
    assert topic_info.running_hash == b"\x01\x02\x03\x04\x05\x06\x07\x08"
    assert topic_info.sequence_number == 42
    assert topic_info.expiration_time is not None
    assert topic_info.admin_key is not None
    assert topic_info.submit_key is not None
    assert topic_info.auto_renew_period == Duration(7776000)
    assert topic_info.auto_renew_account is not None
    assert topic_info.ledger_id == b"\x09\x0a\x0b\x0c"
    assert topic_info.fee_schedule_key is not None
    assert len(topic_info.fee_exempt_keys) == 1
    assert len(topic_info.custom_fees) == 1
    assert topic_info.custom_fees[0].amount == 1000


def test_from_proto_with_auto_renew_period():
    """Test the _from_proto method with auto renew period."""
    proto = consensus_topic_info_pb2.ConsensusTopicInfo()
    proto.memo = "Test memo"
    proto.runningHash = b"\x01\x02"
    proto.sequenceNumber = 1
    proto.autoRenewPeriod.seconds = 86400  # 1 day

    topic_info = TopicInfo._from_proto(proto)

    assert topic_info.auto_renew_period == Duration(86400)


def test_from_proto_with_fee_exempt_keys():
    """Test the _from_proto method with fee exempt keys."""
    public_key = PrivateKey.generate_ed25519().public_key()

    proto = consensus_topic_info_pb2.ConsensusTopicInfo()
    proto.memo = "Test memo"
    proto.runningHash = b"\x01\x02"
    proto.sequenceNumber = 1
    proto.fee_exempt_key_list.append(public_key._to_proto())
    proto.fee_exempt_key_list.append(public_key._to_proto())

    topic_info = TopicInfo._from_proto(proto)

    assert len(topic_info.fee_exempt_keys) == 2
    # Compare hex representations since PublicKey objects don't compare directly
    assert topic_info.fee_exempt_keys[0].to_bytes_raw() == public_key.to_bytes_raw()
    assert topic_info.fee_exempt_keys[1].to_bytes_raw() == public_key.to_bytes_raw()


def test_from_proto_with_custom_fees():
    """Test the _from_proto method with custom fees."""
    custom_fee = CustomFixedFee(
        amount=1000,
        denominating_token_id=None,
        fee_collector_account_id=AccountId(0, 0, 200),
        all_collectors_are_exempt=False,
    )

    proto = consensus_topic_info_pb2.ConsensusTopicInfo()
    proto.memo = "Test memo"
    proto.runningHash = b"\x01\x02"
    proto.sequenceNumber = 1
    proto.custom_fees.append(custom_fee._to_topic_fee_proto())
    proto.custom_fees.append(custom_fee._to_topic_fee_proto())

    topic_info = TopicInfo._from_proto(proto)

    assert len(topic_info.custom_fees) == 2
    assert topic_info.custom_fees[0].amount == custom_fee.amount
    assert topic_info.custom_fees[1].amount == custom_fee.amount
    
def test_topic_info_str_with_all_fields(topic_info):
    """Test the string representation of TopicInfo with all fields populated."""
    proto = consensus_topic_info_pb2.ConsensusTopicInfo()
    proto.memo = topic_info.memo
    proto.runningHash = topic_info.running_hash
    proto.sequenceNumber = 10
    proto.expirationTime.seconds = 1625097600
    
    info = TopicInfo._from_proto(proto)
    # Manually set ledger_id since proto might not support it
    info.ledger_id = b"\xff"
    
    s = str(info)
    
    # Verify hex conversion and formatting
    assert "TopicInfo(" in s
    assert f"memo='{topic_info.memo}'" in s
    assert f"running_hash=0x{topic_info.running_hash.hex()}" in s  # b"hash" in hex
    assert "sequence_number=10" in s
    assert "ledger_id=0xff" in s
    assert "expiration_time=" in s

def test_topic_info_str_with_none_expiration_time():
    """Test string representation when expiration_time is None."""
    proto = consensus_topic_info_pb2.ConsensusTopicInfo()
    proto.memo = "No Expiration"
    proto.sequenceNumber = 1
    
    info = TopicInfo._from_proto(proto)
    s = str(info)
    
    assert "expiration_time=None" in s

def test_topic_info_str_with_none_running_hash():
    """Test string representation when running_hash is None/Empty."""
    proto = consensus_topic_info_pb2.ConsensusTopicInfo()
    proto.memo = "No Hash"
    proto.runningHash = b""
    proto.sequenceNumber = 1
    
    info = TopicInfo._from_proto(proto)
    s = str(info)
    
    # Updated expectation: should be running_hash=None, not 0xNone
    assert "running_hash=None" in s

def test_topic_info_str_with_none_auto_renew_period():
    """Test string representation when auto_renew_period is None."""
    proto = consensus_topic_info_pb2.ConsensusTopicInfo()
    proto.memo = "No Renew"
    proto.sequenceNumber = 1
    # Do not set autoRenewPeriod
    
    info = TopicInfo._from_proto(proto)
    s = str(info)
    
    assert "auto_renew_period=None" in s

def test_topic_info_str_with_non_bytes_ledger_id():
    """Test string representation when ledger_id is not bytes (invalid type)."""
    proto = consensus_topic_info_pb2.ConsensusTopicInfo()
    proto.memo = "Bad Ledger ID"
    proto.sequenceNumber = 1
    
    info = TopicInfo._from_proto(proto)
    # Manually inject invalid type
    info.ledger_id = "invalid_string_not_bytes"
    
    s = str(info)
    
    # Logic: if isinstance(self.ledger_id, (bytes, bytearray)) is False -> None
    # Updated expectation based on corrected logic in topic_info.py
    assert "ledger_id=None" in s

def test_topic_info_repr(topic_info):
    """Test that __repr__ matches __str__ output."""
    proto = consensus_topic_info_pb2.ConsensusTopicInfo()
    proto.memo = topic_info.memo
    
    info = TopicInfo._from_proto(proto)
    assert repr(info) == str(info)

def test_topic_info_from_proto_without_admin_key():
    """Test parsing without admin key."""
    proto = consensus_topic_info_pb2.ConsensusTopicInfo()
    proto.memo = "No Admin"
    
    # Ensure adminKey is NOT set
    assert not proto.HasField("adminKey")
    
    info = TopicInfo._from_proto(proto)
    assert info.admin_key is None

def test_topic_info_from_proto_without_submit_key():
    """Test parsing without submit key."""
    proto = consensus_topic_info_pb2.ConsensusTopicInfo()
    proto.memo = "No Submit"
    
    assert not proto.HasField("submitKey")
    
    info = TopicInfo._from_proto(proto)
    assert info.submit_key is None

def test_topic_info_from_proto_without_auto_renew_period():
    """Test parsing without auto renew period."""
    proto = consensus_topic_info_pb2.ConsensusTopicInfo()
    proto.memo = "No Period"
    
    assert not proto.HasField("autoRenewPeriod")
    
    info = TopicInfo._from_proto(proto)
    assert info.auto_renew_period is None

def test_topic_info_from_proto_without_auto_renew_account():
    """Test parsing without auto renew account."""
    proto = consensus_topic_info_pb2.ConsensusTopicInfo()
    proto.memo = "No Account"
    
    assert not proto.HasField("autoRenewAccount")
    
    info = TopicInfo._from_proto(proto)
    assert info.auto_renew_account is None

def test_topic_info_from_proto_without_fee_schedule_key():
    """Test parsing without fee schedule key."""
    proto = consensus_topic_info_pb2.ConsensusTopicInfo()
    proto.memo = "No Fee Key"
    
    assert not proto.HasField("fee_schedule_key")
    
    info = TopicInfo._from_proto(proto)
    assert info.fee_schedule_key is None

def test_topic_info_from_proto_minimal():
    """Test parsing a minimal proto with only required fields."""
    proto = consensus_topic_info_pb2.ConsensusTopicInfo()
    proto.memo = "Minimal"
    proto.sequenceNumber = 123
    proto.runningHash = b"\x00"
    
    info = TopicInfo._from_proto(proto)
    
    assert info.memo == "Minimal"
    assert info.sequence_number == 123
    assert info.running_hash == b"\x00"
    
    # Verify all optional fields are None
    assert info.admin_key is None
    assert info.submit_key is None
    assert info.auto_renew_period is None
    assert info.auto_renew_account is None
    assert info.expiration_time is None
    assert info.fee_schedule_key is None