# -*- coding: utf-8 -*-
#
# Shared Secret Authenticator module for Matrix Synapse
# Copyright (C) 2018 Slavi Pantaleev
#
# http://devture.com/
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
from base58 import b58decode
from unpaddedbase64 import encode_base64
from hashlib import sha256

from twisted.internet import defer
from solana.rpc.api import Client
from solana.publickey import PublicKey
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from redis import Redis

import logging

from synapse.handlers.vaccount_auth.constants import SIGN_TIMESTAMP_TOLERANCE, OPERATIONAL_STATE, VELAS_API_URI, VELAS_RPC_URI
from synapse.handlers.vaccount_auth.utils import VaccountInfo, get_vaccount_evm_address
from synapse.api.errors import HttpResponseException
from synapse.handlers.vaccount_auth.utils import is_valid_vaccount_address
from synapse.module_api import ModuleApi
from synapse.storage import Databases, DataStore

logger = logging.getLogger(__name__)


class VaccountAuthProvider:
    """
    Provide a login/registration by Vaccount flow.
    """

    def __init__(self, config, account_handler: ModuleApi):
        self.account_handler = account_handler
        self.store: DataStore = account_handler._hs.get_datastore()
        self.network = config.get('VELAS_RPC_URI', VELAS_RPC_URI)
        self.velas_client = Client(
            endpoint=config.get('VELAS_API_URI', VELAS_API_URI),
        ) 
        self.redis = Redis(
            host=config.get('REDIS_HOSTNAME'),
            port=config.get('REDIS_PORT'),
            password=config.get('REDIS_PASSWORD'),
        )

    @staticmethod
    def get_supported_login_types():
        supported_login_types = {
            'com.bitorbit.login.vaccount': (
                'vaccount_address',
                'signature',
                'signer',
                'signed_timestamp',
                'signer_type',
            )
        }

        return supported_login_types

    async def check_auth(self, evm_vaccount_address, login_type, login_dict):
        """Attempt to authenticate a user by Vaccount flow and register an account if none exists.

        Args:
            evm_vaccount_address: ethereum based interpretation of the Vaccount address
            login_type: type of authentication
            login_dict: authentication parameters `supported_login_types`

        Returns:
            Canonical user ID if authentication was successful
        """
        vaccount_address = login_dict.get('vaccount_address')
        signature = login_dict.get('signature')
        signer_key = login_dict.get('signer')
        signer_type = login_dict.get('signer_type')
        signed_timestamp = int(login_dict.get('signed_timestamp'))
        display_name = login_dict.get('displayname')

        if not signature or not signer_key or not signed_timestamp or not vaccount_address or not signer_type:
            logger.error("Vaccount: error reading login json body")
            return False

        if evm_vaccount_address.startswith("@") and ":" in evm_vaccount_address:
            # username is of the form @V4Bw2..:bar.com
            evm_vaccount_address = evm_vaccount_address.split(":", 1)[0][1:]
        
        # if evm_vaccount_address.startswith("0x"):
        #     evm_vaccount_address = evm_vaccount_address[2:]

        msg = f'{vaccount_address}*{signed_timestamp}'
        signed_msg = sha256(msg.encode()).digest()

        is_valid_signature = self._is_valid_signature(
            signature=bytes.fromhex(signature),
            signer_key=signer_key,
            signed_msg=signed_msg
        )

        is_active_vaccount = await self._is_active_vaccount(
            vaccount_address=PublicKey(vaccount_address),
            signer=PublicKey(signer_key),
            signer_type=signer_type,
        )

        expected_evm_address = get_vaccount_evm_address(PublicKey(vaccount_address))
        is_valid_evm_address = expected_evm_address == evm_vaccount_address

        if not is_valid_signature or not is_active_vaccount or not is_valid_evm_address:
            logger.error("""
                Vaccount: Failed auth check for %s
                is_valid_signature: %s
                is_active_vaccount: %s
                is_valid_evm_address: %s
                """,
                evm_vaccount_address, str(is_valid_signature), str(is_active_vaccount), str(is_valid_evm_address))
            return False

        if not self._is_valid_sign_timestamp(evm_vaccount_address, signed_timestamp):
            logger.error("Vaccount: Failed auth timestamp check for %s", evm_vaccount_address)
            return False

        user_id = self.account_handler.get_qualified_user_id(username=evm_vaccount_address)

        if await self.account_handler.check_user_exists(user_id):
            return user_id

        else:
            logger.info("Vaccount: User %s (%s) does not exist. Registering.", display_name, evm_vaccount_address)
            user_id = await self.register_user(
                localpart=evm_vaccount_address,
                displayname=display_name,
            )

        # signer_key = encode_base64(b58decode(signer_key))
        # vaccount_signing_key = {
        #     'keys': {
        #         f'ed25519{signer_key}': signer_key,
        #     },
        # }

        # await self.store.set_e2e_cross_signing_key(
        #     user_id,
        #     "vaccount",
        #     vaccount_signing_key,
        # )

        # async with self.store._cross_signing_id_gen.get_next() as stream_id:
        #     await self.store.db_pool.runInteraction(
        #         "add_e2e_cross_signing_key",
        #         self.store._set_e2e_cross_signing_key_txn,
        #         user_id,
        #         "vaccount",
        #         vaccount_signing_key,
        #         stream_id,
        #     )
        # await self.store.set_e2e_cross_signing_key(
        #     user_id, "master", vaccount_signing_key
        # )
        self._commit_last_sign_timestamp(evm_vaccount_address, signed_timestamp)

        return user_id

    @staticmethod
    def _is_valid_signature(signature, signer_key, signed_msg) -> bool:
        signer_key = b58decode(signer_key)
        try:
            VerifyKey(signer_key).verify(signed_msg, signature)

        except BadSignatureError as e:
            logger.error("Vaccount: Invalid signature provided for %s.", signer_key)
            return False

        return True

    def _is_valid_sign_timestamp(self, evm_vaccount_address: str, signed_timestamp: int):
        """Check if signed timestamp is valid
        Args:
            evm_vaccount_address: ethereum representing of the VA address
            signed_timestamp: last signed timestamp by VA key
        Returns:
            True if timestamp is greater than last signed timestamp
        """
        current_timestamp = int(self.account_handler._hs.get_clock().time())
        ts_window = current_timestamp - signed_timestamp
        last_signed_timestamp = self.redis.get(evm_vaccount_address) or signed_timestamp

        if signed_timestamp >= int(last_signed_timestamp) and ts_window <= SIGN_TIMESTAMP_TOLERANCE:
            return True
        else:
            logger.error("Vaccount: Invalid signin timestamp for %s", evm_vaccount_address)
        
        return False

    async def register_user(self, localpart, displayname):
        """Register a Synapse user, first checking if they exist.
        Args:
            localpart (str): Localpart of the user to register on this homeserver.
            displayname (str): Full name of the user.
        Returns:
            user_id (str): User ID of the newly registered user.
        """
        # Get full user id from localpart
        user_id = self.account_handler.get_qualified_user_id(localpart)

        if await self.account_handler.check_user_exists(user_id):
            # exists, authentication complete
            logger.info("Vaccount: User %s already registered, proceeding with login.", displayname)
            return user_id

        user_id = await self.account_handler.register_user(
            localpart=localpart,
            displayname=displayname,
        )

        logger.info("Vaccount: Registration was successful: %s", user_id)
        return user_id

    async def _is_active_vaccount(self, vaccount_address: PublicKey, signer: PublicKey, signer_type: str) -> bool:
        """
        """
        vaccount_info = VaccountInfo(vaccount_address, self.velas_client)

        if vaccount_info.is_ephemeral():
            logger.info("Vaccount: account is ephemeral: %s", vaccount_address)
            return is_valid_vaccount_address(signer, vaccount_address)
        else:
            logger.info("Vaccount: account is not ephemeral: %s", vaccount_address)

        logger.info("Vaccount: %s signer_type is %s", vaccount_address, signer_type)

        if signer_type == 'owner' and signer in vaccount_info.owners:
            return True

        if signer_type == 'operational':
            for operational in vaccount_info.operational_storage:

                if operational.pubkey == signer and operational.state == OPERATIONAL_STATE.enum.Initialized():
                    return True

        return False

    async def _get_parsed_account_info(self, account_address):
        """
        """
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            'params': [
                str(account_address),
                {
                    'encoding': 'jsonParsed'
                }
            ]
        }
        try:
            account_data = await self.account_handler.http_client.post_json_get_json(
                uri=self.network,
                post_json=payload,
            )
        except HttpResponseException as e:
            logger.info("Vaccount: HttpResponseException: %s", e)
            return None

        account_data = account_data.get('result').get('value').get('data').get('parsed').get('info')

        return account_data

    def _commit_last_sign_timestamp(self, evm_vaccount_address, last_timestamp):
        is_commit = self.redis.set(
            name=evm_vaccount_address,
            value=last_timestamp,
            # ex=SIGN_TIMESTAMP_TOLERANCE,
        )

        return is_commit

    @staticmethod
    def parse_config(config):
        return config
