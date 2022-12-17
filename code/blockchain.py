from typing import Dict, List, Any, Optional

import hashlib
import ecdsa
import json
import datetime
import base58
import time

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
    transaction_types: List[str] = ["raw_material_creation", "material_conversion", "material_transfer", "financial_transfer", "miner_reward"]

    def __init__(self, sender: BlockchainIdentity, tx_type: str):
        assert tx_type in Transaction.transaction_types, "Invalid transaction type"

        self.sender = sender
        self.inp: List[Dict] = []
        self.out: List[Dict] = []
        self.tx_type = tx_type

        self.signed = False
        self.txid = None
        self.signature = None
        self.timestamp = None

    def add_input(self, txid: str, resource: str, quantity: int) -> None:
        self.inp.append({ 
            "idx": len(self.inp),
            "txid": txid, 
            "resource": resource, 
            "quantity": quantity 
        })

    def add_output(self, receiver: str, resource: str, quantity: int) -> None:
        self.out.append({ 
            "idx": len(self.out),
            "receiver": receiver, 
            "resource": resource, 
            "quantity": quantity 
        })

    def sign(self) -> None:
        assert not self.signed, "Transaction already signed"
        self.timestamp = datetime.datetime.now().timestamp()

        content = {
            "timestamp": self.timestamp,
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

        self.signature = signature
        self.txid = txid
        self.signed = True

    def to_dict(self) -> Dict[str, Any]:
        content = {
            "timestamp": self.timestamp,
            "tx_type": self.tx_type,
            "inp": self.inp,
            "out": self.out
        }

        header = {
            "signature": self.signature,
            "sender_public_key": self.sender.compressed_hex_public_key,
            "hashed_sender_public_key": self.sender.public_address,
            "version": 1,
        }

        return {
            "txid": self.txid,
            "header": header,
            "content": content
        }

    def to_json(self, indent: Optional[int] =None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def __str__(self) -> str:
        return self.to_json(indent=2)

class MerkleTree:
    def __init__(self):
        self.hashes: List[str] = []
    
    def __hash_data(self, data) -> str:
        return hashlib.sha256(hashlib.sha256(str(data).encode()).digest()).hexdigest()

    def add_data(self, data: str) -> None:
        hashed =  self.__hash_data(data)
        self.hashes.append(hashed)

    def add_hash(self, hashed: str) -> None:
        self.hashes.append(hashed)

    def compute_hash_root(self) -> str:
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
    def __init__(
        self,
        prospective_miner: BlockchainIdentity,
        prev_hash: str,
        transactions: List[Transaction],
        difficulty: int
    ):
        self.prev_hash = prev_hash
        self.timestamp = datetime.datetime.now().timestamp()
        self.transactions = transactions
        self.difficulty = difficulty

        # Coinbase transaction
        miner_reward = Transaction(prospective_miner, "miner_reward")
        miner_reward.add_output(prospective_miner.public_address, "money", 100)
        miner_reward.sign()

        self.transactions.append(miner_reward)
        self.n_tx = len(self.transactions)

        self.merkle_root = self.__compute_merkle_root()

        self.hash = None
        self.nonce = None

        self.mined = False

    def __compute_merkle_root(self) -> str:
        tree = MerkleTree()

        for transaction in self.transactions:
            assert transaction.signed is not None and transaction.txid is not None, "Transaction is unsigned in the block!"
            tree.add_hash(transaction.txid)
        
        return tree.compute_hash_root()

    def try_nonce(self, nonce: int) -> bool:
        start = "0" * self.difficulty
        hashable = json.dumps({
            "header": {
                "nonce": nonce,
                "merkle_root": self.merkle_root,
                "prev_hash": self.prev_hash,
                "timestamp": self.timestamp,
                "n_tx": self.n_tx,
                "difficulty": self.difficulty
            },
            "transactions": [tx.to_dict() for tx in self.transactions]
        })

        hashed = hashlib.sha256(hashlib.sha256(hashable.encode()).digest()).hexdigest()

        if hashed.startswith(start):
            self.nonce = nonce
            self.hash = hashed
            return True

        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hash": self.hash,
            "header": {
                "nonce": self.nonce,
                "merkle_root": self.merkle_root,
                "prev_hash": self.prev_hash,
                "timestamp": self.timestamp,
                "n_tx": self.n_tx,
                "difficulty": self.difficulty
            },
            "transactions": [tx.to_dict() for tx in self.transactions]
        }

    def to_json(self, indent=None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def __str__(self) -> str:
        return self.to_json(indent=2)

    @staticmethod
    def verify_nonce(block_dict: Dict[str, Any]):
        expected_hash = block_dict["hash"]
        minimum_difficulty = block_dict["header"]["difficulty"]

        hashable = {
            "header": block_dict["header"],
            "transactions": block_dict["transactions"]
        }

        hashed = hashlib.sha256(hashlib.sha256(json.dumps(hashable).encode()).digest()).hexdigest()
        req = "0" * minimum_difficulty

        return hashed == expected_hash and expected_hash.startswith(req)

class Blockchain:
    def __init__(self, difficulty):
        self.blocks = []
        self.difficulty = difficulty
    
    def init_genesis_block(self):
        assert len(self.blocks) == 0
        return

    def get_latest_block(self):
        return self.blocks[-1]
    
    def __len__(self):
        return len(self.blocks)

def mine(block):
    nonce = 0

    while not block.try_nonce(nonce):
        nonce += 1

identities = {
    "farmer_1": BlockchainIdentity("Farmer 1", "1GTpnkyNdR8foqbdfgv8JkWxMgvDNRGxHV", "KyYAA6BXCkW1H2ZxL9UgpdsL7Y8RZNRmr25xGirR7YbqHsXCPgL1"),
    "manufacturer_1": BlockchainIdentity("Manufacturer 1", "1G6zJsQy7WxpySxjovkidSb8aaZsMaTqaC", "KyMgXMMeMPvDtbpEcC4qxZ4e9NMFcCCYB1HwUkj3mXZJXzYuoLBE"),
    "wholesaler_1": BlockchainIdentity("Wholesaler 1", "1MRHcvxBaqiiAVYCGG8F2Dom4xoRnutLGZ", "KzGwaUyL3wTm7DrhVSNBLZgYczAH8R5kX6yicycN4B6zcaGbQLKK"),
    "retailer_1": BlockchainIdentity("Retailer 1", "1C2yiq3HAfBvZhWrGh3cF6MXprACpDDZeq", "Kzvx8dh3XhyfHheW69gya4gK2y6bSn1WjVZX6vurbaszLw1EstV8")
}

["raw_material_creation", "material_conversion", "material_transfer", "financial_transfer", "miner_reward"]

difficulty = 4
miner = identities["farmer_1"]

# BLOCK 1
tx_1_1 = Transaction(identities["farmer_1"], "raw_material_creation")
tx_1_1.add_output(identities["farmer_1"].public_address, "wheat", 500)
tx_1_1.sign()

block_1 = Block(miner, "genesis", [tx_1_1], difficulty)
mine(block_1)
print(block_1)
assert block_1.hash is not None
assert tx_1_1.txid is not None

# BLOCK 2
tx_2_1 = Transaction(identities["farmer_1"], "material_transfer")
tx_2_1.add_input(tx_1_1.txid, "wheat", 500)
tx_2_1.add_output(identities["manufacturer_1"].public_address, "wheat", 500)
tx_2_1.sign()

tx_2_2 = Transaction(identities["manufacturer_1"], "financial_transfer")
tx_2_2.add_output(identities["farmer_1"].public_address, "money", 1000)
tx_2_2.sign()

block_2 = Block(miner, block_1.hash, [tx_2_1, tx_2_2], difficulty)
mine(block_2)
print(block_2)
assert block_2.hash is not None
assert tx_2_1.txid is not None
assert tx_2_2.txid is not None

# BLOCK 3
tx_3_1 = Transaction(identities["manufacturer_1"], "material_conversion")
tx_3_1.add_input(tx_2_1.txid, "wheat", 500)
tx_3_1.add_input(tx_2_1.txid, "wheat", 1000)
tx_3_1.add_output(identities["manufacturer_1"].public_address, "bread", 250)
tx_3_1.sign()

block_3 = Block(miner, block_2.hash, [tx_3_1], difficulty)
mine(block_3)
print(block_3)

