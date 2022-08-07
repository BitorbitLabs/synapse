from typing import List, Tuple, Union
import sha3

from solana.publickey import PublicKey
from solana.rpc.api import Client
from unpaddedbase64 import decode_base64
from borsh_construct import U16

from synapse.handlers.vaccount_auth.constants import (
    BASE_OPERATIONAL_LEN,
    VACCOUNT_PROGRAM_ID, 
    VACCOUNT_SEED,
    VACCOUNT_INFO,
    OPERATIONAL_INFO,
)


def is_valid_vaccount_address(genesis_key_seed: PublicKey, vaccount_id: PublicKey) -> bool:
    """Is valid `Vaccount` address.

    Valid `Vaccount` addresses must fall off the ed25519 curve.  This function
    iterates a nonce until it finds one that when combined with the seeds
    results in a valid `Vaccount` address.

    Args:
        genesis_key_seed: owner pubkey seed to generate Vaccount address
        vaccount_id: derived address that generated by [`genesis_key_seed` + b'vaccount']

    Returns:
        Is equal `vaccount_id` to generated address
    """
    seeds = [bytes(genesis_key_seed), VACCOUNT_SEED]
    for i in range(255, 0, -1):
        try:
            expected_seeds = seeds + [bytes([i])]
            generated_vaccount_address = PublicKey.create_program_address(
                seeds=expected_seeds,
                program_id=VACCOUNT_PROGRAM_ID,
            )

            if generated_vaccount_address == vaccount_id:
                return True

        except Exception:
            continue

    return False


def find_vaccount_address(genesis_key_seed: PublicKey) -> Union[Tuple[PublicKey, int], None]:
    """Find valid `Vaccount` address.

    Valid `Vaccount` addresses must fall off the ed25519 curve.  This function
    iterates a nonce until it finds one that when combined with the seeds
    results in a valid `Vaccount` address.

    Args:
        genesis_key_seed: owner pubkey seed to generate Vaccount address
        vaccount_id: derived address that generated by [`genesis_key_seed` + b'vaccount']

    Returns:
        Vaccount address and bump seed.
    """
    seeds = [bytes(genesis_key_seed), VACCOUNT_SEED]
    for i in range(255, 0, -1):
        try:
            expected_seeds = seeds + [bytes([i])]
            vaccount_address = PublicKey.create_program_address(seeds=expected_seeds, program_id=VACCOUNT_PROGRAM_ID)

        except Exception:
            continue

        else:
            return vaccount_address, i

    return None


def find_vaccount_storage_address(vaccount_address: PublicKey, storage_type: str, storage_version: int) -> PublicKey:
    """Find a program storage address of a `Vaccount`.
    
    Find a specific storage address of the `Vaccount` with provided version.
    Storage can be 3 types: 'operationals', 'programs', 'tokens'.

    Args:
        vaccount_address: address for which the storage address will be generated
        storage_type: type of the storage to be found ('operational', 'program', 'tokens')
        storage_version: current number of the storage version

    Returns:
        Storage address and bump seed.
    """
    seeds = [bytes(vaccount_address), bytes(storage_type), U16.build(storage_version)]

    return PublicKey.find_program_address(seeds, VACCOUNT_PROGRAM_ID)[0]


def get_vaccount_evm_address(vaccount_address: PublicKey) -> str:
    """Get an Vaccount address representing in ethereum base format.
    Args:
        vaccount_address: solana based pubkey 40 bytes
    Returns:
        Ethereum based address
    """
    keccak = sha3.keccak_256()
    keccak.update(bytes(vaccount_address))
    evm_address = '0xacc0' + keccak.digest()[14:32].hex()

    return evm_address


class VaccountInfo:
    """Parsed representing Vaccount information"""
    
    def __init__(self, vaccount_pubkey: Union[PublicKey, bytearray, bytes, int, str, List[int]], client: Client):
        self.client = client
        self.pubkey = vaccount_pubkey if isinstance(vaccount_pubkey, PublicKey) else PublicKey(vaccount_pubkey)
        self.version = None
        self.owners = None
        self.genesis_seed_key = None
        self.operational_storage_nonce = None
        self.token_storage_nonce = None
        self.programs_storage_nonce = None
        self.operational_storage = []
        
        self._set_vaccount_info()
        self._set_operational_storage()

    def _set_vaccount_info(self):
        try:
            vaccount_data = self.client.get_account_info(self.pubkey)['result']['value']['data'][0]
            vaccount_info = VACCOUNT_INFO.parse(decode_base64(vaccount_data))

            self.version = vaccount_info.version
            self.owners = [PublicKey(vaccount_info.owners[0:32]), PublicKey(vaccount_info.owners[32:64]), PublicKey(vaccount_info.owners[64:96])]
            self.genesis_seed_key = PublicKey(vaccount_info.genesis_seed_key)
            self.operational_storage_nonce = vaccount_info.operational_storage_nonce
            self.token_storage_nonce = vaccount_info.token_storage_nonce
            self.programs_storage_nonce = vaccount_info.programs_storage_nonce
        except Exception:
            return

    def _set_operational_storage(self):
        operational_storage = []
        try: 
            operational_storage_address = find_vaccount_storage_address(self.pubkey, b'operationals', self.operational_storage_nonce)
            operational_storage_data = self.client.get_account_info(operational_storage_address)['result']['value']['data'][0]
            operational_storage_data = decode_base64(operational_storage_data)
            num_operationals = int(len(operational_storage_data) / BASE_OPERATIONAL_LEN)

            for i in range(num_operationals):
                start = i * BASE_OPERATIONAL_LEN
                operational = OPERATIONAL_INFO.parse(operational_storage_data[start:start+BASE_OPERATIONAL_LEN])
                operational.pubkey = PublicKey(operational.pubkey)
                
                operational_storage.append(operational)

            self.operational_storage = operational_storage

        except Exception:
            return

    
    def is_ephemeral(self) -> bool:
        """Is the ephemeral Vaccount.
        Ephemeral Vaccount - is the account that not initialized yet in blockchain
        
        Returns:
            True if the account is initialized
        """
        return not self.version
