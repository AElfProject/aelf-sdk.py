import unittest

from coincurve import PrivateKey

from aelf import Transaction
from aelf import AElf, AElfToolkit


class AElfTest(unittest.TestCase):
    _url = 'http://127.0.0.1:8000'
    _private_key = None
    _public_key = None

    def setUp(self):
        private_key_string = 'b344570eb80043d7c5ae9800c813b8842660898bf03cbd41e583b4e54af4e7fa'
        self._private_key = PrivateKey(bytes(bytearray.fromhex(private_key_string)))
        self._public_key = self._private_key.public_key.format(compressed=False)
        self.chain = AElf(self._url)
        self.toolkit = AElfToolkit(self._url, self._private_key)

    def test_chain_api(self):
        chain_status = self.chain.get_chain_status()
        print('# get_chain_status', chain_status)
        self.assertTrue(chain_status['BestChainHeight'] > 0)
        chain_id = self.chain.get_chain_id()
        print('# get_chain_id', chain_id)

    def test_block_api(self):
        block_height = self.chain.get_block_height()
        print('# get_block_height', block_height)
        self.assertTrue(block_height > 0)

        block = self.chain.get_block_by_height(1, include_transactions=True)
        print('# get_block_by_height', block)
        self.assertTrue(block['Header']['Height'] == 1)

        block2 = self.chain.get_block(block['BlockHash'], include_transactions=False)
        print('# get_block', block2)
        self.assertTrue(block['Header']['Height'] == 1)

    def test_transaction_result_api(self):
        block = self.chain.get_block_by_height(1, include_transactions=True)
        transaction_result = self.chain.get_transaction_result(block['Body']['Transactions'][0])
        print('# get_transaction_result', transaction_result)
        self.assertTrue(transaction_result['Status'] == 'MINED')
        transaction_results = self.chain.get_transaction_results(block['BlockHash'])
        print('# get_transaction_results', transaction_results)
        merkle_path = self.chain.get_merkle_path(block['Body']['Transactions'][0])
        self.assertTrue(isinstance(merkle_path['MerklePathNodes'], list))

    def test_raw_transaction_api(self):
        transaction = {
            "From": self.chain.get_address_string_from_public_key(self._public_key),
            "To": self.chain.get_system_contract_address_string("AElf.ContractNames.Consensus"),
            "RefBlockNumber": 0,
            "RefBlockHash": "b344570eb80043d7c5ae9800c813b8842660898bf03cbd41e583b4e54af4e7fa",
            "MethodName": "GetCurrentMinerList",
            "Params": '{}'
        }
        raw_transaction = self.chain.create_raw_transaction(transaction)
        signature = self._private_key.sign_recoverable(bytes.fromhex(raw_transaction['RawTransaction']))
        transaction_1 = {
            "RawTransaction": raw_transaction['RawTransaction'],
            "Signature": signature.hex()
        }
        # test execute_raw_transaction
        print('# execute_raw_transaction', self.chain.execute_raw_transaction(transaction_1))

        # test send_raw_transaction
        transaction_2 = {
            "Transaction": raw_transaction['RawTransaction'],
            'Signature': signature.hex(),
            'ReturnTransaction': True
        }
        print('# send_raw_transaction', self.chain.send_raw_transaction(transaction_2))

    def test_send_transaction_api(self):
        current_height = self.chain.get_block_height()
        block = self.chain.get_block_by_height(current_height, include_transactions=False)
        transaction = Transaction()
        transaction.to_address.CopyFrom(self.chain.get_system_contract_address("AElf.ContractNames.Consensus"))
        transaction.ref_block_number = current_height
        transaction.ref_block_prefix = bytes.fromhex(block['BlockHash'])[0:4]
        transaction.method_name = 'GetCurrentMinerList'
        transaction = self.chain.sign_transaction(self._private_key, transaction)
        result = self.chain.send_transaction(transaction.SerializePartialToString().hex())
        print('# send_transaction', result)
        self.assertTrue(result['TransactionId'] != "")

    def test_tx_pool_api(self):
        tx_pool_status = self.chain.get_transaction_pool_status()
        print('# get_transaction_pool_status', tx_pool_status)
        self.assertTrue(tx_pool_status['Queued'] >= 0)

    def test_task_queue_api(self):
        task_queue_status = self.chain.get_task_queue_status()
        print('# get_task_queue_status', task_queue_status)
        self.assertTrue(len(task_queue_status) > 0)

    def test_network_api(self):
        print('# get_network_info', self.chain.get_network_info())
        print('# remove_peer')
        self.assertTrue(self.chain.remove_peer('127.0.0.1:6801'))
        print('# add_peer')
        self.assertTrue(self.chain.add_peer('127.0.0.1:6801'))

    def test_miner_api(self):
        balance = self.toolkit.get_balance('ELF', '28Y8JA1i2cN6oHvdv7EraXJr9a1gY6D1PpJXw9QtRMRwKcBQMK')
        print('# get_balance', balance)

        miners = self.toolkit.get_current_miners()
        self.assertTrue(len(miners) > 0)
        print('# get_current_miners', len(miners))
        for miner in miners:
            print('  > miner:', miner['public_key'], miner['address'])

        candidates = self.toolkit.get_candidates()
        print('# get_candidates', len(candidates))
        self.assertTrue(len(candidates) >= 0)
        for candidate in candidates:
            print('  > candidate:', candidate['public_key'], candidate['address'])

    def test_helpers(self):
        is_connected = self.chain.is_connected()
        self.assertTrue(is_connected)

        address = self.chain.get_system_contract_address("AElf.ContractNames.Consensus")
        formatted_address = self.chain.get_formatted_address(address)
        print('formatted address', formatted_address)
        self.assertIsNotNone(formatted_address)


if __name__ == '__main__':
    unittest.main()
