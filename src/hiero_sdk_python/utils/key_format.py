from hiero_sdk_python.hapi.services.basic_types_pb2 import Key
from hiero_sdk_python.crypto.public_key import PublicKey

def format_key(key) -> str:
    """
    Converts a protobuf Key or SDK PublicKey into a nicely formatted string.
    
    Args:
        key: A Protobuf Key object or an SDK PublicKey wrapper.
        
    Returns:
        str: Formatted string representation.
    """
    if key is None:
        return "None"
    
    # Fix: Handle SDK PublicKey wrapper object which doesn't have HasField
    if isinstance(key, PublicKey):
        return str(key)

    # Handle Protobuf Key object
    if hasattr(key, "HasField"):
        if key.HasField("ed25519"):
            return f"ed25519(hex={key.ed25519.hex()})"
        elif key.HasField("ecdsa_secp256k1"):
            return f"ecdsa(hex={key.ecdsa_secp256k1.hex()})"
        elif key.HasField("thresholdKey"):
            return "thresholdKey(...)"
        elif key.HasField("keyList"):
            return "keyList(...)"
        elif key.HasField("contractID"):
            return f"contractID({key.contractID.contractNum})"
        elif key.HasField("delegatable_contract_id"):
            return f"delegatable_contract({key.delegatable_contract_id.contractNum})"

    return str(key).replace("\n", " ")