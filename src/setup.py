from setuptools import setup

setup(
    name='aelf-client',
    version='1.2.3',
    description='Python SDK for AElf',
    url='https://github.com/AElf/aelf-sdk.py',
    packages=['aelf'],
    install_requires=['requests', 'protobuf', 'base58', 'coincurve']
)
