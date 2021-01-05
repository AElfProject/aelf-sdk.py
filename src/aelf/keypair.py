from coincurve import PrivateKey

class KeyPair:

    def __init__(self):
        self.private_key = PrivateKey(None)
        self.public_key = self.private_key.public_key.format(compressed=False)