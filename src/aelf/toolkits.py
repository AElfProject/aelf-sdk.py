import base58
from aelf.client import AElf

from aelf.types_pb2 import MinerList, StringInput, CandidateVote, PublicKeysList, ContractDeploymentInput, \
    ContractUpdateInput, GetBalanceInput, GetBalanceOutput, TransferInput, CrossChainTransferInput, \
    CrossChainReceiveTokenInput


class AElfToolkit(object):

    def __init__(self, url, private_key, version=None):
        self._private_key = private_key
        self.aelf = AElf(url, version)

    def deploy_contract(self, deploy_contract_bytes):
        """
        Deploy smart contract
        :param deploy_contract_bytes: contract bytes
        :return: deployed address
        """
        contract_deployment_input = ContractDeploymentInput()
        contract_deployment_input.code = deploy_contract_bytes
        contract_deployment_input.category = 3

        genesis_contract_address = self.aelf.get_genesis_contract_address_string()
        transaction = self.aelf.create_transaction(genesis_contract_address, 'DeploySmartContract',
                                                   contract_deployment_input.SerializeToString())
        transaction = self.aelf.sign_transaction(self._private_key, transaction)
        return self.aelf.send_transaction(transaction)

    def update_contract(self, contract_address, update_contract_bytes):
        """
        Update smart contract
        :param contract_address: contract update address
        :param update_contract_bytes: contract bytes
        :return: updated address
        """
        contract_update_input = ContractUpdateInput()
        contract_update_input.code = update_contract_bytes
        contract_update_input.category = 3
        genesis_contract_address = self.aelf.get_genesis_contract_address_string()
        transaction = self._create_and_sign_transaction(genesis_contract_address, 'DeploySmartContract',
                                                        contract_update_input)
        transaction = self.aelf.sign_transaction(self._private_key, transaction)
        return self.aelf.send_transaction(transaction)

    def transfer(self, to_address_string, symbol, amount, memo):
        """
        Transfer token to address
        :param to_address_string: to address
        :param symbol: symbol
        :param amount: amount
        :param memo: memo
        :return:
        """
        transfer_input = TransferInput()
        transfer_input.to.value = base58.b58decode_check(to_address_string)
        transfer_input.symbol = symbol
        transfer_input.amount = amount
        transfer_input.memo = memo
        multi_token_contract_address = self.aelf.get_system_contract_address('AElf.ContractNames.Token')
        transaction = self._create_and_sign_transaction(multi_token_contract_address, 'Transfer', transfer_input)
        return self.aelf.execute_transaction(transaction)

    def cross_chain_transfer(self, to_address_string, symbol, amount, memo, to_chain_id):
        """
        Cross chain transfer
        :param to_address_string: to address string
        :param symbol: symbol
        :param amount: amount
        :param memo: memo
        :param to_chain_id: to chain id
        :return:
        """
        cross_chain_transfer_input = CrossChainTransferInput()
        cross_chain_transfer_input.to.value = base58.b58decode_check(to_address_string)
        cross_chain_transfer_input.symbol = symbol
        cross_chain_transfer_input.amount = amount
        cross_chain_transfer_input.memo = memo
        cross_chain_transfer_input.to_chain_id = to_chain_id
        cross_chain_transfer_input.issue_chain_id = self.aelf.get_chain_id()
        multi_token_contract_address = self.aelf.get_system_contract_address('AElf.ContractNames.Token')
        transaction = self._create_and_sign_transaction(multi_token_contract_address, 'CrossChainTransfer',
                                                        cross_chain_transfer_input)
        return self.aelf.execute_transaction(transaction)

    def cross_chain_receive(self, from_chain_id, parent_chain_height, transfer_transaction_bytes, merkle_path):
        cross_chain_receive_token_input = CrossChainReceiveTokenInput()
        cross_chain_receive_token_input.from_chain_id = from_chain_id
        cross_chain_receive_token_input.parent_chain_height = parent_chain_height
        cross_chain_receive_token_input.transfer_transaction_bytes = transfer_transaction_bytes
        raise NotImplementedError()

    def get_balance(self, symbol, address):
        """
        Get balance
        :param symbol:
        :param address:
        :return:
        """
        get_balance_input = GetBalanceInput()
        get_balance_input.symbol = symbol
        get_balance_input.owner.value = base58.b58decode_check(address)
        multi_token_contract_address = self.aelf.get_system_contract_address('AElf.ContractNames.Token')
        transaction = self._create_and_sign_transaction(multi_token_contract_address, 'GetBalance', get_balance_input)
        balance = self.aelf.execute_transaction(transaction)
        get_balance_output = GetBalanceOutput()
        get_balance_output.ParseFromString(bytes.fromhex(balance.decode()))
        return get_balance_output.balance

    def buy_resource(self):
        raise NotImplementedError()

    def sell_resource(self):
        raise NotImplementedError()

    def vote(self):
        raise NotImplementedError()

    def change_vote_option(self):
        raise NotImplementedError()

    def vote_withdraw(self):
        raise NotImplementedError()

    def create_propose(self):
        raise NotImplementedError()

    def approve_propose(self):
        raise NotImplementedError()

    def release_propose(self):
        raise NotImplementedError()

    def get_current_miners(self):
        """
        Get current miners
        :return: current miners
        """
        consensus_contract_address = self.aelf.get_system_contract_address('AElf.ContractNames.Consensus')
        transaction = self._create_and_sign_transaction(consensus_contract_address, 'GetCurrentMinerList')
        raw_miner_list = self.aelf.execute_transaction(transaction)

        current_miners = []
        miner_list = MinerList()
        miner_list.ParseFromString(bytes.fromhex(raw_miner_list.decode()))

        for public_key in miner_list.pubkeys:
            current_miners.append(self._build_node_info(public_key))
        return current_miners

    def get_candidates(self):
        """
        Get candidates
        :return: candidates
        """
        election_contract_address = self.aelf.get_system_contract_address('AElf.ContractNames.Election')
        transaction = self._create_and_sign_transaction(election_contract_address, 'GetCandidates')
        raw_candidates = self.aelf.execute_transaction(transaction)

        candidates = []
        public_key_list = PublicKeysList()
        public_key_list.ParseFromString(bytes.fromhex(raw_candidates.decode()))

        for public_key in public_key_list.value:
            candidates.append(self._build_node_info(public_key))
        return candidates

    def get_vote_info(self, public_keys):
        """
        Get vote info
        :param public_keys: public key for candidates/miners
        :return:
        """
        vote_info = []
        for public_key in public_keys:
            election_contract_address = self.aelf.get_system_contract_address('AElf.ContractNames.Election')
            params = StringInput()
            params.string_value = public_key
            transaction = self._create_and_sign_transaction(election_contract_address, 'GetCandidateVote', params)
            raw_candidate_vote = self.aelf.execute_transaction(transaction)
            candidate_vote = CandidateVote()
            candidate_vote.ParseFromString(bytes.fromhex(raw_candidate_vote.decode()))
            vote_info.append({
                'obtained_active_voted_votes_amount': candidate_vote.obtained_active_voted_votes_amount,
                'all_obtained_voted_votes_amount': candidate_vote.all_obtained_voted_votes_amount
            })
        return vote_info

    def _create_and_sign_transaction(self, to_address, method_name, params=None):
        if params is not None:
            transaction = self.aelf.create_transaction(to_address, method_name, params.SerializeToString())
        else:
            transaction = self.aelf.create_transaction(to_address, method_name)
        return self.aelf.sign_transaction(self._private_key, transaction)

    def _build_node_info(self, public_key):
        address = self.aelf.get_address_string_from_public_key(public_key)
        return {
            'public_key': public_key.hex(),
            'address': address
        }
