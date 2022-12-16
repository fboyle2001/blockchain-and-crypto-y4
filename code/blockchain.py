from typing import Dict, List, Any
from dataclasses import dataclass

import hashlib
import ecdsa
import json
import datetime
import base58

assert "sha256" in hashlib.algorithms_available, "SHA256 is unavailable"
assert "ripemd160" in hashlib.algorithms_available , "RIPEMD160 is unavailable"

GLOBAL_INDENT = 2

def pprint(a):
    if type(a) in [int, str]:
        print(a) 
    
    print(json.dumps(a, indent=2))

def verify_signature(verifying_key: ecdsa.VerifyingKey, signature: str, message: str) -> bool:
    try:
        verifying_key.verify(bytes.fromhex(signature), message.encode())
    except ecdsa.BadSignatureError:
        return False

    return True

class BlockchainIdentity:
    def __init__(self,
        name: str,
        public_address: str, 
        wif_private_key: str, 
        is_miner: bool = True
    ):
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

    def verify_signature(self, signature: str, message: str) -> bool:
        # Just for completeness, not used since we don't actually have a register of identities at runtime
        return verify_signature(self.verifying_key, signature, message)

class Transaction:
    transaction_types: List[str] = ["raw_material_creation", "material_conversion", "material_transfer", "financial_transfer"]

    def __init__(self, sender: BlockchainIdentity, tx_type: str):
        assert tx_type in Transaction.transaction_types, "Invalid transaction type"

        self.sender = sender
        self.inp: List[Dict] = []
        self.out: List[Dict] = []
        self.tx_type = tx_type

    def add_input(self, txid: str, resource: str, quantity: int) -> None:
        self.inp.append({ 
            "txid": txid, 
            "resource": resource, 
            "quantity": quantity 
        })

    def add_output(self, receiver: str, resource: str, quantity: int) -> None:
        self.out.append({ 
            "receiver": receiver, 
            "resource": resource, 
            "quantity": quantity 
        })

    def sign(self):
        content = {
            "timestamp": datetime.datetime.now().timestamp(),
            "tx_type": self.tx_type,
            "inp": self.inp,
            "out": self.out
        }

        content_str = json.dumps(content)
        signature = self.sender.sign(content_str)

        header = {
            "signature": signature,
            "sender_public_key": self.sender.compressed_hex_public_key,
            "hashed_sender_public_key": self.sender.public_address,
            "version": 1,
        }

        unlabelled_transaction = {
            "header": header,
            "content": content
        }

        unlabelled_transaction_str = json.dumps(unlabelled_transaction)
        txid = hashlib.sha256(hashlib.sha256(json.dumps(unlabelled_transaction_str).encode()).digest()).hexdigest()

        return {
            "txid": txid,
            **unlabelled_transaction
        }

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
    "farmer_1": BlockchainIdentity("Farmer 1", "1GTpnkyNdR8foqbdfgv8JkWxMgvDNRGxHV", "KyYAA6BXCkW1H2ZxL9UgpdsL7Y8RZNRmr25xGirR7YbqHsXCPgL1"),
    "manufacturer_1": BlockchainIdentity("Manufacturer 1", "1G6zJsQy7WxpySxjovkidSb8aaZsMaTqaC", "KyMgXMMeMPvDtbpEcC4qxZ4e9NMFcCCYB1HwUkj3mXZJXzYuoLBE"),
    "wholesaler_1": BlockchainIdentity("Wholesaler 1", "1MRHcvxBaqiiAVYCGG8F2Dom4xoRnutLGZ", "KzGwaUyL3wTm7DrhVSNBLZgYczAH8R5kX6yicycN4B6zcaGbQLKK"),
    "retailer_1": BlockchainIdentity("Retailer 1", "1C2yiq3HAfBvZhWrGh3cF6MXprACpDDZeq", "Kzvx8dh3XhyfHheW69gya4gK2y6bSn1WjVZX6vurbaszLw1EstV8")
}

transaction = Transaction(identities["farmer_1"], "raw_material_creation")
transaction.add_output(identities["farmer_1"].public_address, "wheat", 500)
signed = transaction.sign()