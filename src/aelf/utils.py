import base58
from aelf.types_pb2 import Address

def address_to_b58string(address):
    if not isinstance(address, Address):
        raise ValueError('The address is not Address instance.')
    return str(base58.b58encode_check(address.value), 'utf-8')