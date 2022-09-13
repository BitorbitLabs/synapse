import json
import time
import hmac
from hashlib import sha256
import hashlib
import sha3
# from construct import V
from typing import Any, List, Optional, Tuple, Union
from unpaddedbase64 import decode_base64, encode_base64
import requests
from solana.rpc.api import Client
from solana.account import Account
from solana.publickey import PublicKey
from synapse.api.errors import SynapseError
from synapse.handlers.vaccount_auth.utils import find_vaccount_address, find_vaccount_storage_address, get_vaccount_evm_address

account = Account()
vaccount = find_vaccount_address(account.public_key())[0]


def obtain_access_token(user_id, homeserver_api_url, shared_secret):
    login_api_url = homeserver_api_url + '/_matrix/client/r0/login'

    password = hmac.new(shared_secret.encode('utf-8'), user_id.encode('utf-8'), hashlib.sha512).hexdigest()

    payload = {
        'type': 'm.login.password',
        'user': user_id,
        'password': password,
    }

    response = requests.post(login_api_url, data=json.dumps(payload))

    print(response.json())
    return response.json()['access_token']


def register_account(homeserver_api_url):
    print(f'ACCOUNT PRIVATE KEY: {account.keypair()}')
    register_api_url = homeserver_api_url + '/_matrix/client/r0/login'

    timestamp = int(time.time())
    msg = f'{vaccount.to_base58().decode()}*{timestamp}'
    signed_msg = sha256(msg.encode()).digest()
    signature = account.sign(msg=signed_msg)
    evm_address = get_vaccount_evm_address(vaccount)

    payload = {
        'type': 'com.bitorbit.login.vaccount',
        'user': '@' + evm_address + ':my.domain.name',
        'vaccount_address': vaccount.to_base58().decode(),
        'signature': signature.signature.hex(),
        'signer': account.public_key().to_base58().decode(),
        'signed_timestamp': timestamp,
        'signer_type': 'operational',
    }
    print(payload)

    response = requests.post(register_api_url, data=json.dumps(payload))
    print(response.json())
    print(response.status_code)

    return response.json()['access_token']


def login(homeserver_api_url, token):
    register_api_url = homeserver_api_url + '/_matrix/client/r0/login'
    payload = {
        'type': 'm.login.token',
        'token': token
    }
    print("payload: ", payload)
    response = requests.post(register_api_url, data=json.dumps(payload))

    return response


def register_account1(homeserver_api_url):
    register_api_url = homeserver_api_url + '/_matrix/client/r0/register'

    timestamp = '1'
    display_name = 'dick'
    msg = f'{vaccount.to_base58().decode()}*{timestamp}*{display_name}'
    signed_msg = sha256(msg.encode()).digest()
    signature = account.sign(msg=signed_msg)

    payload = {
        'type': 'm.login.dummy',
        'username': vaccount.to_base58().decode(),
        'signature': signature.signature.hex(),
        'signer': account.public_key().to_base58().decode(),
        'signed_timestamp': timestamp,
        'display_name': display_name,
        'password': '12345678'
    }

    response = requests.post(register_api_url, data=json.dumps(payload))
    print(response.json())
    payload.pop('type')
    payload['auth'] = {
        'session': response.json()['session'],
        'type': 'm.login.dummy',
    }

    print(payload)

    response = requests.post(register_api_url, data=json.dumps(payload))
    print(response.json())

    return response.json()['access_token']


if __name__ == '__main__':
    # vaccount = VaccountInfo('BvAjgfumLMH8FtAkV235PQVvTAgX76xaEwWN56pW13XT')
    # print(vaccount.operational_storage[0].state == OPERATIONAL_STATE.enum.Initialized())
    # secret = "YOUR SHARED SECRET GOES HERE"

    TEST_URL = "/_matrix/client/r0/account/whoami"
    access_token = register_account("http://localhost:8008")
    access_token = register_account("http://localhost:8008")
    print(access_token)
    res = requests.get("http://localhost:8008" + TEST_URL, params={'access_token': access_token})
    print(res.json())

    
    # res = login("http://localhost:8008", access_token)
    # print(res.json())
    # access_token = obtain_access_token(account.public_key().to_base58().decode(), "http://localhost:8008", secret)
