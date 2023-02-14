import hashlib

import base58
import base64
import requests
from coincurve import PrivateKey
from google.protobuf.wrappers_pb2 import StringValue

from aelf.types_pb2 import Transaction, Hash, Address


class AElf(object):
    _get_request_header = None
    _post_request_header = None
    _url = None
    _version = None
    _userName = None
    _password = None

    _private_key = 'b344570eb80043d7c5ae9800c813b8842660898bf03cbd41e583b4e54af4e7fa'

    def __init__(self, url='http://127.0.0.1:8000', userName=None, password=None, version=None):
        self._url = '%s/api' % url
        self._userName = userName
        self._password = password

        version = '' if version is None else ';v=%s' % version
        self._post_request_header = {'Content-Type': 'application/json' + version}
        self._get_request_header = {'Accept': 'application/json' + version}

    def get_chain_status(self):
        """
        Get chain status
        :return: chain status
        """
        return requests.get('%s/blockchain/chainStatus' % self._url, headers=self._get_request_header).json()

    def get_block_height(self):
        """
        Get block height
        :return: block height
        """
        block_height = requests.get('%s/blockchain/blockHeight' % self._url, headers=self._get_request_header).content
        return int(block_height)

    def get_block(self, block_hash, include_transactions=False):
        """
        Get block
        :param block_hash: block hash
        :param include_transactions: whether include transactions
        :return: block
        """
        api = '%s/blockchain/block?includeTransactions=%s&blockHash=%s' % (self._url, include_transactions, block_hash)
        return requests.get(api, headers=self._get_request_header).json()

    def get_block_by_height(self, block_height, include_transactions=False):
        """
        Get block by height
        :param block_height: block height
        :param include_transactions: whether include transaction
        :return: block
        """
        api = '%s/blockchain/blockByHeight?includeTransactions=%s&blockHeight=%s' % (
            self._url, include_transactions, block_height)
        return requests.get(api, headers=self._get_request_header).json()

    def get_transaction_pool_status(self):
        """
        Get transaction pool status
        :return: transaction pool status
        """
        return requests.get('%s/blockchain/transactionPoolStatus' % self._url, headers=self._get_request_header).json()

    def create_raw_transaction(self, transaction):
        """
        Create raw transaction
        :param transaction: the json format transaction
            {
              "From": "string",
              "To": "string",
              "RefBlockNumber": 0,
              "RefBlockHash": "string",
              "MethodName": "string",
              "Params": "string"
            }
        :return: the raw transaction string
        """
        return requests.post('%s/blockchain/rawTransaction' % self._url,
                             json=transaction, headers=self._post_request_header).json()

    def send_transaction(self, transaction):
        """
        Send transaction
        :param transaction: transaction hex string
        :return: transaction id
        """
        return requests.post('%s/blockchain/sendTransaction' % self._url,
                             json={'RawTransaction': transaction}, headers=self._post_request_header).json()

    def send_raw_transaction(self, raw_transaction):
        """
        Send raw transaction
        :param raw_transaction: the json format transaction
            {
              "Transaction": "string",
              "Signature": "string",
              "ReturnTransaction": true
            }
        :return: transaction id
        """
        return requests.post('%s/blockchain/sendRawTransaction' % self._url,
                             json=raw_transaction, headers=self._post_request_header).json()

    def send_transactions(self, transactions):
        """
        Send transactions
        :param transactions: transactions (join by ',')
        :return: the list of transaction ids
        """
        return requests.post('%s/blockchain/sendTransaction' % self._url,
                             json={'RawTransactions': transactions}, headers=self._post_request_header).json()

    def execute_transaction(self, transaction):
        """
        Execute transaction
        :param transaction: Transaction object or transaction hex string
        :return: executed result
        """
        if isinstance(transaction, Transaction):
            transaction = transaction.SerializePartialToString().hex()

        response = requests.post('%s/blockchain/executeTransaction' % self._url,
                                 json={'RawTransaction': transaction},
                                 headers=self._post_request_header)
        return response.content

    def execute_raw_transaction(self, raw_transaction):
        """
        Execute raw transaction
        :param raw_transaction: raw transaction
        :return: executed result
        """
        return requests.post('%s/blockchain/executeRawTransaction' % self._url,
                             json=raw_transaction, headers=self._post_request_header).content

    def get_transaction_result(self, transaction_id):
        """
        Get transaction result
        :param transaction_id: transaction id
        :return: transaction result
        """
        api = '%s/blockchain/transactionResult?transactionId=%s' % (self._url, transaction_id)
        return requests.get(api, headers=self._get_request_header).json()

    def get_transaction_results(self, block_hash):
        """
        Get transaction results
        :param block_hash: block hash
        :return: transaction results
        """
        api = '%s/blockchain/transactionResults?blockHash=%s' % (self._url, block_hash)
        return requests.get(api, headers=self._get_request_header).json()

    def get_peers(self):
        """
        Get peers
        """
        return requests.get('%s/net/peers' % self._url, headers=self._get_request_header).json()

    def add_peer(self, peer_address):
        """
        Add peer
        :param peer_address: peer address
        :return: True/False
        """
        json_data = {'Address': peer_address}
        self._post_request_header['Authorization'] = "Basic " + base64.b64encode(
            "{0}:{1}".format(self._userName, self._password).encode()).decode()
        return requests.post('%s/net/peer' % self._url, json=json_data, headers=self._post_request_header).json()

    def remove_peer(self, address):
        """
        Remove peer
        :param address: peer address
        :return: True/False
        """
        api = '%s/net/peer?address=%s' % (self._url, address)
        self._get_request_header['Authorization'] = "Basic " + base64.b64encode(
            "{0}:{1}".format(self._userName, self._password).encode()).decode()
        status_code = requests.delete(api, headers=self._get_request_header).status_code
        return status_code == 200

    def get_network_info(self):
        """
        Get network info
        :return: network info
        """
        return requests.get('%s/net/networkInfo' % self._url, headers=self._get_request_header).json()

    def get_task_queue_status(self):
        """
        Get task queue status
        :return: task queue status
        """
        return requests.get('%s/blockchain/taskQueueStatus' % self._url, headers=self._get_request_header).json()

    def get_merkle_path(self, transaction_id):
        """
        Get task queue status
        :return: task queue status
        """
        api = '%s/blockChain/merklePathByTransactionId?transactionId=%s' % (self._url, transaction_id)
        return requests.get(api, headers=self._get_request_header).json()

    def get_genesis_contract_address_string(self):
        """
        Get genesis contract address
        :return: address
        """
        chain_status = self.get_chain_status()
        return chain_status['GenesisContractAddress']

    def get_system_contract_address(self, contract_name):
        """
        Get system contract address
        :param contract_name: system contract name
        :return: contract address object
        """
        to_address_string = self.get_genesis_contract_address_string()
        params = Hash()
        params.value = hashlib.sha256(contract_name.encode('utf8')).digest()
        transaction = self.create_transaction(to_address_string, 'GetContractAddressByName', params.SerializeToString())
        transaction = self.sign_transaction(self._private_key, transaction)
        raw_address_hex = self.execute_transaction(transaction)
        to_address = Address()
        to_address.ParseFromString(bytes.fromhex(raw_address_hex.decode()))
        return to_address

    def get_system_contract_address_string(self, contract_name):
        """
        Get system contract address
        :param contract_name: system contract name
        :return: contract address base58 string
        """
        to_address = self.get_system_contract_address(contract_name)
        return base58.b58encode_check(to_address.value).decode()

    def create_transaction(self, to_address, method_name, params=None):
        """
        Create transaction
        :param to_address: to address
        :param method_name: method name
        :param params: params for method
        :return: transaction object
        """
        chain_status = self.get_chain_status()
        best_chain_hash = chain_status['BestChainHash']
        best_chain_height = chain_status['BestChainHeight']

        if not isinstance(to_address, Address):
            to_address_string = to_address
            to_address = Address()
            to_address.value = base58.b58decode_check(to_address_string)

        transaction = Transaction()
        transaction.to_address.CopyFrom(to_address)
        transaction.method_name = method_name
        if params is not None:
            transaction.params = params
        transaction.ref_block_number = best_chain_height
        transaction.ref_block_prefix = bytes(bytearray.fromhex(best_chain_hash)[:4])
        return transaction

    def sign_transaction(self, private_key, transaction):
        """
        Sign
        :param private_key: private key
        :param transaction: transaction
        :return: the signed transaction
        """
        assert isinstance(transaction, Transaction), 'Invalid transaction'
        if isinstance(private_key, str):
            private_key = bytes(bytearray.fromhex(private_key))
        if isinstance(private_key, bytes):
            private_key = PrivateKey(private_key)
        public_key = private_key.public_key.format(compressed=False)
        transaction.from_address.CopyFrom(self.get_address_from_public_key(public_key))
        transaction.signature = private_key.sign_recoverable(transaction.SerializeToString())
        return transaction

    @staticmethod
    def get_address_from_public_key(public_key):
        """ get address from public key
        """
        address = Address()
        public_key_hash = hashlib.sha256()
        public_key_hash.update(hashlib.sha256(public_key).digest())
        address.value = public_key_hash.digest()
        return address

    @staticmethod
    def get_address_string_from_public_key(public_key):
        """ get address string from public key
        """
        address = Address()
        public_key_hash = hashlib.sha256()
        public_key_hash.update(hashlib.sha256(public_key).digest())
        address.value = public_key_hash.digest()
        return base58.b58encode_check(address.value).decode()

    def get_chain_id(self):
        """
        Get chain id
        :return: chain id (int)
        """
        chain_status = self.get_chain_status()
        chain_id = chain_status['ChainId']
        chain_id_bytes = base58.b58decode(chain_id)
        return int.from_bytes(chain_id_bytes, byteorder='little')

    def get_formatted_address(self, address):
        """
        Get formatted address
        :param address: address
        :return: the formatted address
        """
        if isinstance(address, Address):
            address = base58.b58encode_check(address.value).decode()

        token_contract_address = self.get_system_contract_address('AElf.ContractNames.Token')
        transaction = self.create_transaction(token_contract_address, 'GetPrimaryTokenSymbol')
        transaction = self.sign_transaction(self._private_key, transaction)
        raw_symbol = self.execute_transaction(transaction)
        symbol = StringValue()
        symbol.ParseFromString(bytes.fromhex(raw_symbol.decode()))

        chain_status = self.get_chain_status()
        return '%s_%s_%s' % (symbol.value, address, chain_status['ChainId'])

    def calculate_transaction_fee_result(self, transaction):
        """
        calculate_transaction_fee_result
        :param transaction: the json format transaction
            {
              "RawTransaction": "string",
            }
        :return: the CalculateTransactionFeeOutput formatted
        """
        return requests.post('%s/blockChain/calculateTransactionFee' % self._url,
                             json=transaction, headers=self._post_request_header).json()

    def is_connected(self):
        """
        Check connection
        """
        try:
            self.get_chain_status()
        except:
            return False
        return True
