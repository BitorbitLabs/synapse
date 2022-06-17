"""
Provide implementation of the constants for vaccount auth provider.
"""
from solana.publickey import PublicKey
from borsh_construct import (
    Bool,
    CStruct, 
    Enum, 
    U8,
    U16,
)

VACCOUNT_PROGRAM_ID = PublicKey("VAcccHVjpknkW5N5R9sfRppQxYJrJYVV7QJGKchkQj5")
VACCOUNT_SEED = b'vaccount'
VELAS_RPC_URI = 'https://api.testnet.velas.com'
BASE_OPERATIONAL_LEN = 134

SIGN_TIMESTAMP_TOLERANCE = 120

VACCOUNT_INFO = CStruct(
    'version' / U8,
    'owners' / U8[96],
    'genesis_seed_key' / U8[32],
    'operational_storage_nonce' / U16,
    'token_storage_nonce' / U16,
    'programs_storage_nonce' / U16
)

OPERATIONAL_STATE = Enum (
    'Initialized',
    'Frozen',
    enum_name="OperationalState"
)

OPERATIONAL_INFO = CStruct(
    'pubkey' / U8[32],
    'state' / OPERATIONAL_STATE,
    'agent_type' / U8[32],
    'scopes' / U8[4],
    'tokens_indices' / U8[32],
    'external_programs_indices' / U8[32],
    'is_master_key' / Bool,
)
