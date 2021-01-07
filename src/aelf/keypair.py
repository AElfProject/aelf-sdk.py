from coincurve import PrivateKey

class KeyPair:

    def __init__(self, private_key = None):
        secret = None
        if private_key is not None:
            secret = bytes(bytearray.fromhex(private_key))
        self.private_key = PrivateKey(secret)
        self.public_key = self.private_key.public_key.format(compressed=False)