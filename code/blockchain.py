from typing import Dict
from dataclasses import dataclass

import hashlib
import ecdsa
import json
import datetime
import base58

assert "sha256" in hashlib.algorithms_available, "SHA256 is unavailable"
assert "ripemd160" in hashlib.algorithms_available , "RIPEMD160 is unavailable"

GLOBAL_INDENT = 2

def verify_signature(verifying_key: ecdsa.VerifyingKey, signature: str, message: str) -> bool:
    try:
        verifying_key.verify(bytes.fromhex(signature), message.encode())
    except ecdsa.BadSignatureError:
        return False

    return True

class BlockchainIdentity:
    def __init__(self, public_address: str, wif_private_key: str, is_miner=True):
        self.public_address = public_address
        self.wif_private_key = wif_private_key
        self.is_miner = is_miner

        # Get the signing key for transacations from the private key
        self.signing_key = ecdsa.SigningKey.from_string(bytes.fromhex(self.hex_private_key), curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
        self.verifying_key: ecdsa.keys.VerifyingKey = self.signing_key.get_verifying_key() # type: ignore

    @property
    def hex_private_key(self) -> str:
        # Keys generated are in the WIF format
        # To decode, base58 decode and check the checksum then check the first byte is 0x80 and the last byte is 0x01
        # Then take the bytes inbetween as the hex private key
        private_key_bytes = self.wif_private_key.encode()
        base_decoded = base58.b58decode_check(private_key_bytes)
        assert base_decoded[0] == 0x80 and base_decoded[-1] == 0x01, f"Invalid WIF format private key specified {self.wif_private_key}"
        hpv = base_decoded[1:-1].hex()
        return hpv

    @property
    def hex_public_key(self) -> str:
        # Get the public key in hexadecimal (128 bytes)
        return self.verifying_key.to_string().hex()

    @property
    def compressed_hex_public_key(self) -> str:
        # Get the compressed public key in hexadecimal (66 bytes)
        # Uses the raw elliptic curve points
        # Ref: https://github.com/sr-gi/bitcoin_tools/blob/0f6ea45b6368200e481982982822f0416e0c438d/bitcoin_tools/core/keys.py#L74
        x, y = self.verifying_key.pubkey.point.x(), self.verifying_key.pubkey.point.y() # type: ignore
        prefix = "03" if y & 1 else "02"
        hex_x = hex(x)[2:]

        if len(hex_x) == 63:
            hex_x = "0" + hex_x
        
        assert len(hex_x) == 64

        return prefix + hex_x

    def sign(self, message: str) -> str:
        # Sign an arbitrary message, returns the signature as a hex value
        return self.signing_key.sign(message.encode()).hex()

    def verify_signature(self, signature, message) -> bool:
        # Just for completeness, not used since we don't actually have a register of identities at runtime
        return verify_signature(self.verifying_key, signature, message)


class Transaction:
    @dataclass
    class SignedTransaction:
        signature: str
        sender_pub_key: str
        hashed_sender_pub_key: str
        data: Dict[str, str]
        timestamp: float

        @property
        def transaction_id(self):
           return hashlib.sha256(hashlib.sha256(json.dumps(self.to_dict(exclude_id=True), indent=2).encode()).digest()).hexdigest()

        def to_dict(self, exclude_id=False):
            tx = {}

            if not exclude_id:
                tx["id"] = self.transaction_id
            
            idless = {
                "signature": self.signature, 
                "sender_pub_key": self.sender_pub_key,
                "hashed_sender_pub_key": self.hashed_sender_pub_key,
                "timestamp": self.timestamp,
                "data": self.data,
            }

            return {**tx, **idless}

        def to_verifiable_json(self):
            return json.dumps(self.data)

        def __str__(self):
            return json.dumps(self.to_dict(exclude_id=False), indent=GLOBAL_INDENT)

    def __init__(self, sender: BlockchainIdentity, resource, quantity, receiver: BlockchainIdentity):
        self.sender = sender
        self.resource = resource
        self.quantity = quantity
        self.receiver = receiver

        self.locked = False

    def sign(self) -> SignedTransaction:
        assert not self.locked, "Transaction has already been signed"

        data = {
            "receiver": self.receiver.public_address,
            "resource": self.resource,
            "quantity": self.quantity
        }

        json_data = json.dumps(data)
        signature = self.sender.sign(json_data)
        self.locked = True

        return Transaction.SignedTransaction(signature, self.sender.compressed_hex_public_key, self.sender.public_address, data, datetime.datetime.now().timestamp())

    """
    SIG SENDER_PUB OP_DUP OP_HASH160 HASHED_SENDER_PUB OP_EQUAL_VERIFY OP_CHECKSIG
    """
    @staticmethod
    def verify_transaction(transaction: str) -> bool:
        parsed = json.loads(transaction)
        reconstructed = Transaction.SignedTransaction(parsed["signature"], parsed["sender_pub_key"], parsed["hashed_sender_pub_key"], parsed["data"], parsed["timestamp"])

        # First, verify the integrity of the transaction
        # i.e. does the hash == tx_id?
        if parsed["id"] != reconstructed.transaction_id:
            return False

        # Then verify the signature this is equiv to OP_HASH160
        fromhex_hash = hashlib.sha256(bytes.fromhex(reconstructed.sender_pub_key))
        ripe = hashlib.new("ripemd160", fromhex_hash.digest())
        prefixed = bytearray(b"\0") + bytearray(ripe.digest())
        double_hashed = hashlib.sha256(hashlib.sha256(prefixed).digest())
        checked = prefixed + double_hashed.digest()[:4]
        computed_address = base58.b58encode(checked).decode()

        if computed_address != reconstructed.hashed_sender_pub_key:
            return False

        # Now check the signature is correct
        verifying_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(reconstructed.sender_pub_key), curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
        verified_signature = verify_signature(verifying_key, reconstructed.signature, reconstructed.to_verifiable_json())

        if not verified_signature:
            return False

        # Should also do some checking i.e. they have the money or resources
        # This becomes difficult though! The farmer is producing new resources
        # And the others are converting resources so it is difficult

        return True

class MerkleTree:
    def __init__(self):
        self.hashes = []
    
    def __hash_data(self, data):
        return hashlib.sha256(hashlib.sha256(str(data).encode()).digest()).hexdigest()

    def add_data(self, data):
        hashed =  self.__hash_data(data)
        self.hashes.append(hashed)

    def add_hash(self, hashed):
        self.hashes.append(hashed)

    def compute_hash_root(self):
        working_hashes = self.hashes

        while len(working_hashes) != 1:
            # Require an even number of hashes
            # Duplicate the end hash if we don't have this
            if len(working_hashes) % 2 != 0:
                working_hashes.append(working_hashes[-1])

            next_working_hashes = []

            # Work through and hash the pairs
            for i in range(len(working_hashes) // 2):
                left = working_hashes[2 * i]
                right = working_hashes[2 * i + 1]
                joined = f"{left}{right}"

                hashed = self.__hash_data(joined)
                next_working_hashes.append(hashed)
            
            # Move up a layer in the tree
            working_hashes = next_working_hashes
        
        # Return the root hash
        return working_hashes[0]

class Block:
    def __init__(self):
        self.block_id = None
        self.version = 1
        self.timestamp = None
        self.tx_count = None
        self.prev_block_hash = None
        self.nonce = None
        self.merkle_tree_root = None
        self.blocks = []

    def generate_header_hash(self, nonce):
        header = self.get_header(nonce=nonce)

    def is_mined(self):
        pass

    # Slide 35 Lecture 4
    def get_header(self, nonce=None):
        return {
            "version": self.version,
            "previous_block_hash": self.prev_block_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce if nonce is None else nonce,
            "difficulty": None,
            "merkle_tree_root": self.merkle_tree_root
        }

identities = {
    "farmer_1": BlockchainIdentity("1GTpnkyNdR8foqbdfgv8JkWxMgvDNRGxHV", "KyYAA6BXCkW1H2ZxL9UgpdsL7Y8RZNRmr25xGirR7YbqHsXCPgL1"),
    "manufacturer_1": BlockchainIdentity("1G6zJsQy7WxpySxjovkidSb8aaZsMaTqaC", "KyMgXMMeMPvDtbpEcC4qxZ4e9NMFcCCYB1HwUkj3mXZJXzYuoLBE"),
    "wholesaler_1": BlockchainIdentity("1MRHcvxBaqiiAVYCGG8F2Dom4xoRnutLGZ", "KzGwaUyL3wTm7DrhVSNBLZgYczAH8R5kX6yicycN4B6zcaGbQLKK"),
    "retailer_1": BlockchainIdentity("1C2yiq3HAfBvZhWrGh3cF6MXprACpDDZeq", "Kzvx8dh3XhyfHheW69gya4gK2y6bSn1WjVZX6vurbaszLw1EstV8")
}