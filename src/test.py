import unittest
import time
import base64
import base58

from coincurve import PrivateKey

from aelf import Transaction, Transferred, TransactionFeeCharged, TransferInput
from aelf import AElf, AElfToolkit, KeyPair, utils

class AElfTest(unittest.TestCase):
    _url = 'http://127.0.0.1:8000'
    _keypair = None

    def setUp(self):
        private_key_string = 'cd86ab6347d8e52bbbe8532141fc59ce596268143a308d1d40fedf385528b458'
        self._keypair = KeyPair(private_key_string)
        self.chain = AElf(self._url)
        self.toolkit = AElfToolkit(self._url, self._keypair)

    def test_chain_api(self):
        chain_status = self.chain.get_chain_status()
        print('# get_chain_status', chain_status)
        self.assertEqual("AELF", chain_status['ChainId'])
        self.assertTrue(len(chain_status['Branches']) > 0)
        self.assertTrue(chain_status['LongestChainHeight'] > 0)
        self.assertTrue(len(chain_status['LongestChainHash']) > 0)
        self.assertTrue(len(chain_status['GenesisContractAddress']) > 0)
        self.assertTrue(len(chain_status['GenesisBlockHash']) > 0)
        self.assertTrue(chain_status['LastIrreversibleBlockHeight'] > 0)
        self.assertTrue(len(chain_status['LastIrreversibleBlockHash']) > 0)
        self.assertTrue(chain_status['BestChainHeight'] > 0)
        self.assertTrue(len(chain_status['BestChainHash']) > 0)

        longest_chain_block = self.chain.get_block(chain_status['LongestChainHash'])
        self.assertEqual(longest_chain_block['Header']['Height'], chain_status['LongestChainHeight'])

        best_chain_block = self.chain.get_block(chain_status['BestChainHash'])
        self.assertEqual(best_chain_block['Header']['Height'], chain_status['BestChainHeight'])

        last_irreversible_block = self.chain.get_block(chain_status['LastIrreversibleBlockHash'])
        self.assertEqual(last_irreversible_block['Header']['Height'], chain_status['LastIrreversibleBlockHeight'])

        genesis_block = self.chain.get_block(chain_status['GenesisBlockHash'])
        self.assertEqual(genesis_block['Header']['Height'], 1)

        genesis_contract_address = self.chain.get_genesis_contract_address_string()
        self.assertEqual(genesis_contract_address, chain_status['GenesisContractAddress'])

        chain_id = self.chain.get_chain_id()
        self.assertEqual(9992731, chain_id)

    def test_get_contract_file_descriptor_set_api(self):
        genesis_contract_address = self.chain.get_genesis_contract_address_string()
        file_descriptor_set = self.chain.get_contract_file_descriptor_set(genesis_contract_address)
        ##print('# get_contract_file_descriptor_set', file_descriptor_set)
        self.assertTrue(len(file_descriptor_set) > 0)

    def test_get_block_api(self):
        block_height = self.chain.get_block_height()
        print('# get_block_height', block_height)
        self.assertTrue(block_height > 0)

        block_by_height = self.chain.get_block_by_height(block_height)
        block_by_hash = self.chain.get_block(block_by_height['BlockHash'])

        self.assertEqual(block_by_height, block_by_hash)
        self.assertEqual(block_by_height['Header']['Height'], block_height)
        self.verify_block(block_by_height, False)

    def test_get_block_include_transactions_api(self):
        block_height = self.chain.get_block_height()
        print('# get_block_height', block_height)
        self.assertTrue(block_height > 0)

        block_by_height = self.chain.get_block_by_height(block_height, True)
        block_by_hash = self.chain.get_block(block_by_height['BlockHash'], True)

        self.assertEqual(block_by_height, block_by_hash)
        self.assertEqual(block_by_height['Header']['Height'], block_height)
        self.verify_block(block_by_height, True)

    def verify_block(self, block, include_transactions):
        self.assertTrue(len(block['Header']['PreviousBlockHash']) > 0)
        self.assertTrue(len(block['Header']['MerkleTreeRootOfTransactions']) > 0)
        self.assertTrue(len(block['Header']['MerkleTreeRootOfWorldState']) > 0)
        self.assertTrue(len(block['Header']['MerkleTreeRootOfTransactionState']) > 0)
        self.assertTrue(len(block['Header']['Extra']) > 0)
        self.assertEqual(block['Header']['ChainId'], 'AELF')
        self.assertTrue(len(block['Header']['Bloom']) > 0)
        self.assertTrue(len(block['Header']['SignerPubkey']) > 0)
        self.assertTrue(len(block['Header']['Time']) > 0)

        self.assertTrue(block['Body']['TransactionsCount'] > 0)
        if include_transactions:
            self.assertEqual(len(block['Body']['Transactions']), block['Body']['TransactionsCount'])
            for id in block['Body']['Transactions']:
                self.assertTrue(len(id) > 0)
        else:
            self.assertEqual(len(block['Body']['Transactions']), 0)

        previous_block = self.chain.get_block(block['Header']['PreviousBlockHash'])
        self.assertEqual(previous_block['BlockHash'], block['Header']['PreviousBlockHash'])
        self.assertEqual(previous_block['Header']['Height'], block['Header']['Height']-1)
    
    def test_key_pair(self):
        user_keypair = KeyPair()
        print('# keypair', user_keypair.private_key.to_hex())
        print('# keypair', user_keypair.public_key.hex())
        self.assertTrue(len(user_keypair.private_key.to_hex()) > 0)
        self.assertTrue(len(user_keypair.public_key.hex()) > 0)
        address = self.chain.get_address_string_from_public_key(user_keypair.public_key)
        print('# address', address)
        self.assertTrue(len(address) > 0)
        format_address = self.chain.get_formatted_address(address)
        self.assertEqual(format_address, '%s_%s_%s' % ('ELF', address, "AELF"))

    def test_transaction_result_api(self):
        height = self.chain.get_block_height()
        block = self.chain.get_block_by_height(height, True)
        transaction_result = self.chain.get_transaction_result(block['Body']['Transactions'][0])
        print('# get_transaction_result', transaction_result)
        self.assertEqual(block['Body']['Transactions'][0], transaction_result['TransactionId'])
        self.assertEqual('MINED', transaction_result['Status'])
        self.assertEqual(block['Header']['Height'], transaction_result['BlockNumber'])
        self.assertEqual(block['BlockHash'], transaction_result['BlockHash'])
        self.assertTrue(len(transaction_result['Bloom']) > 0)
        self.assertTrue(transaction_result['Transaction'] != None)

    def test_transaction_results_api(self):
        block = self.chain.get_block_by_height(1, include_transactions=True)
        transaction_results = self.chain.get_transaction_results(block['BlockHash'], 0, 10)
        self.assertEqual(10, len(transaction_results))
        for transaction_result in transaction_results:
            self.assertEqual('MINED', transaction_result['Status'])
            self.assertEqual(block['Header']['Height'], transaction_result['BlockNumber'])
            self.assertEqual(block['BlockHash'], transaction_result['BlockHash'])
            self.assertTrue(len(transaction_result['Bloom']) > 0)
            self.assertTrue(transaction_result['Transaction'] != None)

    def test_get_merkle_path_api(self):
        block = self.chain.get_block_by_height(1, include_transactions=True)
        merkle_path = self.chain.get_merkle_path(block["Body"]['Transactions'][0])
        print('# get_merkle_path', merkle_path)
        self.assertEqual(len(merkle_path['MerklePathNodes']), 4)

    def test_raw_transaction_api(self):
        chain_status = self.chain.get_chain_status()
        token_contract_address = self.chain.get_system_contract_address_string("AElf.ContractNames.Token")
        user_keypair = KeyPair()
        to_address = self.chain.get_address_string_from_public_key(user_keypair.public_key)

        transfer_transaction = {
            "From": self.chain.get_address_string_from_public_key(self._keypair.public_key),
            "To": token_contract_address,
            "RefBlockNumber": chain_status["BestChainHeight"],
            "RefBlockHash": chain_status["BestChainHash"],
            "MethodName": "Transfer",
            "Params": "{\"to\":{\"value\":\"%s\"}, \"symbol\":\"ELF\", \"amount\":\"1000000000\", \"memo\":\"transfer in test\"}" 
            % str(base64.b64encode(self.chain.get_address_from_public_key(user_keypair.public_key).value), 'utf-8')
        }
        raw_transaction = self.chain.create_raw_transaction(transfer_transaction)
        signature = self._keypair.private_key.sign_recoverable(bytes.fromhex(raw_transaction['RawTransaction']))
        transaction = {
            "Transaction": raw_transaction['RawTransaction'],
            "Signature": signature.hex(),
            "ReturnTransaction": True
        }
        transfer_result = self.chain.send_raw_transaction(transaction)
        self.assertTrue(len(transfer_result['TransactionId']) > 0)
        self.assertEqual(self.chain.get_address_string_from_public_key(self._keypair.public_key), transfer_result['Transaction']['From'])
        self.assertEqual(token_contract_address, transfer_result['Transaction']['To'])
        self.assertEqual(chain_status["BestChainHeight"], transfer_result['Transaction']['RefBlockNumber'])
        self.assertEqual(str(base64.b64encode(bytes(bytearray.fromhex(chain_status["BestChainHash"])[:4])), 'utf-8'), transfer_result['Transaction']['RefBlockPrefix'])
        self.assertEqual("Transfer", transfer_result['Transaction']['MethodName'])
        self.assertEqual('{ "to": "%s", "symbol": "ELF", "amount": "1000000000", "memo": "transfer in test" }' % to_address, transfer_result['Transaction']['Params'])

        time.sleep(4)

        get_balance_transaction = {
            "From": self.chain.get_address_string_from_public_key(user_keypair.public_key),
            "To": token_contract_address,
            "RefBlockNumber": chain_status["BestChainHeight"],
            "RefBlockHash": chain_status["BestChainHash"],
            "MethodName": "GetBalance",
            "Params": "{\"owner\":{ \"value\": \"%s\" },\"symbol\":\"ELF\"}" 
            % str(base64.b64encode(self.chain.get_address_from_public_key(user_keypair.public_key).value), 'utf-8')
        }
        get_balance_raw_transaction = self.chain.create_raw_transaction(get_balance_transaction)
        signature = user_keypair.private_key.sign_recoverable(bytes.fromhex(get_balance_raw_transaction['RawTransaction']))
        transaction = {
            "RawTransaction": get_balance_raw_transaction['RawTransaction'],
            'Signature': signature.hex()
        }
        get_balance_result = self.chain.execute_raw_transaction(transaction)
        self.assertEqual("ELF", get_balance_result['symbol'])
        self.assertEqual(to_address, get_balance_result['owner'])
        self.assertEqual(1000000000, int(get_balance_result['balance']))

    def test_raw_transaction_api_without_return_transaction(self):
        chain_status = self.chain.get_chain_status()
        token_contract_address = self.chain.get_system_contract_address_string("AElf.ContractNames.Token")
        user_keypair = KeyPair()

        transfer_transaction = {
            "From": self.chain.get_address_string_from_public_key(self._keypair.public_key),
            "To": token_contract_address,
            "RefBlockNumber": chain_status["BestChainHeight"],
            "RefBlockHash": chain_status["BestChainHash"],
            "MethodName": "Transfer",
            "Params": "{\"to\":{\"value\":\"%s\"}, \"symbol\":\"ELF\", \"amount\":\"1000000000\", \"memo\":\"transfer in test\"}" 
            % str(base64.b64encode(self.chain.get_address_from_public_key(user_keypair.public_key).value), 'utf-8')
        }
        raw_transaction = self.chain.create_raw_transaction(transfer_transaction)
        signature = self._keypair.private_key.sign_recoverable(bytes.fromhex(raw_transaction['RawTransaction']))
        transaction = {
            "Transaction": raw_transaction['RawTransaction'],
            "Signature": signature.hex(),
            "ReturnTransaction": False
        }
        transfer_result = self.chain.send_raw_transaction(transaction)
        self.assertTrue(len(transfer_result['TransactionId']) > 0)
        self.assertTrue(transfer_result['Transaction'] == None)

    def test_send_transaction_api(self):
        token_contract_address = self.chain.get_system_contract_address_string("AElf.ContractNames.Token")
        user_keypair = KeyPair()
        user_address = self.chain.get_address_string_from_public_key(user_keypair.public_key)
        send_result = self.toolkit.transfer(user_address, "ELF", 1000000000, "transfer in test")
        print('# transfer', send_result)
        self.assertTrue(len(send_result['TransactionId']) > 0)
        
        time.sleep(4)

        transfer_result = self.chain.get_transaction_result(send_result['TransactionId'])
        print('# transfer_result', transfer_result)
        self.assertEqual(send_result['TransactionId'], transfer_result['TransactionId'])
        self.assertEqual("MINED", transfer_result['Status'])
        self.assertTrue(transfer_result['Error'] == None)
        self.assertTrue(len(transfer_result['ReturnValue']) == 0)
        self.assertTrue(len(transfer_result['Logs']) == 2)

        self.assertEqual(token_contract_address, transfer_result['Logs'][0]['Address'])
        self.assertEqual('TransactionFeeCharged', transfer_result['Logs'][0]['Name'])
        fee_charged = TransactionFeeCharged()
        fee_charged.ParseFromString(base64.b64decode(transfer_result['Logs'][0]['NonIndexed']))
        self.assertEqual('ELF', fee_charged.symbol)
        self.assertTrue(fee_charged.amount > 0)

        self.assertEqual(token_contract_address, transfer_result['Logs'][1]['Address'])
        self.assertEqual('Transferred', transfer_result['Logs'][1]['Name'])
        transferred = Transferred()
        transferred.ParseFromString(base64.b64decode(transfer_result['Logs'][1]['Indexed'][0]))
        self.assertEqual(self.chain.get_address_string_from_public_key(self._keypair.public_key), utils.address_to_b58string(transferred.__getattribute__('from')))

        transferred = Transferred()
        transferred.ParseFromString(base64.b64decode(transfer_result['Logs'][1]['Indexed'][1]))
        self.assertEqual(user_address, utils.address_to_b58string(transferred.to))

        transferred = Transferred()
        transferred.ParseFromString(base64.b64decode(transfer_result['Logs'][1]['Indexed'][2]))
        self.assertEqual('ELF', transferred.symbol)

        transferred = Transferred()
        transferred.ParseFromString(base64.b64decode(transfer_result['Logs'][1]['NonIndexed']))
        self.assertEqual(1000000000, transferred.amount)
        self.assertEqual('transfer in test', transferred.memo)
        
        balance = self.toolkit.get_balance("ELF", user_address)
        self.assertEqual("ELF", balance.symbol)
        self.assertEqual(1000000000, balance.balance)
        self.assertEqual(user_address, utils.address_to_b58string(balance.owner))

    def test_send_failed_transaction_api(self):
        token_contract_address = self.chain.get_system_contract_address_string("AElf.ContractNames.Token")
        user_keypair = KeyPair()
        user_address = self.chain.get_address_from_public_key(user_keypair.public_key)

        transfer_input = TransferInput()
        transfer_input.to.CopyFrom(user_address)
        transfer_input.symbol = "ELF"
        transfer_input.amount = 1000000000
        transfer_input.memo = 'transfer in test'
        transaction = self.chain.create_transaction(token_contract_address, "Transfer", transfer_input.SerializeToString())
        transaction = self.chain.sign_transaction(user_keypair.private_key,transaction)
        send_result = self.chain.send_transaction(transaction.SerializePartialToString().hex())
        self.assertTrue(len(send_result['TransactionId']) > 0)
        
        time.sleep(4)

        transfer_result = self.chain.get_transaction_result(send_result['TransactionId'])
        print('# transfer_result', transfer_result)
        self.assertEqual(send_result['TransactionId'], transfer_result['TransactionId'])
        self.assertEqual("NODEVALIDATIONFAILED", transfer_result['Status'])
        self.assertTrue(transfer_result['Error'] == 'Pre-Error: Transaction fee not enough.')

    def test_send_transactions_api(self):
        transactions = []
        token_contract_address = self.chain.get_system_contract_address_string("AElf.ContractNames.Token")
        for i in range(0,2):
            user_keypair = KeyPair()
            user_address = self.chain.get_address_from_public_key(user_keypair.public_key)
            transfer_input = TransferInput()
            transfer_input.to.CopyFrom(user_address)
            transfer_input.symbol = "ELF"
            transfer_input.amount = 1000000000
            transfer_input.memo = 'transfer in test'
            transaction = self.chain.create_transaction(token_contract_address, "Transfer", transfer_input.SerializeToString())
            transaction = self.chain.sign_transaction(self._keypair.private_key,transaction)
            transactions.append(transaction.SerializePartialToString().hex())

        send_result = self.chain.send_transactions(','.join(transactions))
        self.assertEqual(2, len(send_result))

        time.sleep(4)

        for id in send_result:
            transaction_result = self.chain.get_transaction_result(id)
            self.assertEqual("MINED", transaction_result['Status'])

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
        self.assertTrue(self.chain.remove_peer('127.0.0.1:6800'))
        print('# add_peer')
        self.assertFalse(self.chain.add_peer('127.0.0.1:6800'))

    def test_miner_api(self):
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

    def test_connect(self):
        is_connected = self.chain.is_connected()
        self.assertTrue(is_connected)

        is_connected = AElf('http://127.0.0.1:1234').is_connected()
        self.assertFalse(is_connected)

if __name__ == '__main__':
    unittest.main()
