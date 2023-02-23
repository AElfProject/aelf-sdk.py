from setuptools import setup

setup(
    name='aelf-client',
    version='0.1.4',
    description='Python SDK for AElf',
    url='https://github.com/AElf/aelf-sdk.py',
    packages=['aelf'],
    install_requires=['requests', 'protobuf<=3.20', 'base58', 'coincurve']
)
