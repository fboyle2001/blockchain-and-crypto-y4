from typing import List, Optional
from dataclasses import dataclass

import hashlib
import ecdsa
import json
import datetime
import base58
import multiprocessing
import time

assert "sha256" in hashlib.algorithms_available, "SHA256 is required for but it is unavailable on your system"
assert "ripemd160" in hashlib.algorithms_available , "RIPEMD160 is required for but it is unavailable on your system"

def verify_signature(verifying_key: ecdsa.VerifyingKey, signature: str, message: str) -> bool:
    try:
        verifying_key.verify(bytes.fromhex(signature), message.encode())
    except ecdsa.BadSignatureError:
        return False

    return True

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
        hex_pk = base_decoded[1:-1].hex()
        return hex_pk

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

@dataclass
class Transaction:
    @dataclass
    class Header:
        signature: str
        sender_public_key: str
        hashed_sender_public_key: str
        version: int
    
    @dataclass
    class Content:
        @dataclass
        class TXInput:
            txid: str
            resource: str
            quantity: int
            idx: Optional[int] = None
        
        @dataclass
        class TXOutput:
            receiver: str
            resource: str
            quantity: int
            idx: Optional[int] = None

        timestamp: float
        tx_type: str
        inp: List[TXInput]
        out: List[TXOutput]

    txid: str
    header: Header
    content: Content

    def __str__(self) -> str:
        return json.dumps({
            "txid": self.txid,
            "header": self.header,
            "content": self.content
        }, default=lambda x: getattr(x, "__dict__", str(x)), indent=2)

    def validate_integrity(self) -> bool:
        """
        Validate the txid is correct for the {header, content} and the signature validates the {content}
        """

        # First check the txid
        # Recursive JSON trick from https://stackoverflow.com/a/49003922
        idless_tx_str = json.dumps({
            "header": self.header,
            "content": self.content
        }, default=lambda x: getattr(x, "__dict__", str(x)))

        computed_txid = hashlib.sha256(hashlib.sha256(json.dumps(idless_tx_str).encode()).digest()).hexdigest()

        if computed_txid != self.txid:
            return False
        
        # Now check the signature
        tx_content_str = json.dumps(self.content, default=lambda x: getattr(x, "__dict__", str(x)))
        verifying_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(self.header.sender_public_key), curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
        verified = verify_signature(verifying_key, self.header.signature, tx_content_str)

        return verified

    @staticmethod
    def create_new_transaction(
        sender: BlockchainIdentity,
        inp: List[Content.TXInput],
        out: List[Content.TXOutput],
        tx_type: str
    ):
        """
        Creates a new transaction, signs it and computes the transaction hash (txid)
        **This does not validate the inp and out, this is the responsibilty of the miner!**
        """

        indexed_inp = [
            Transaction.Content.TXInput(
                ip.txid,
                ip.resource,
                ip.quantity,
                idx
            )
            for idx, ip in enumerate(inp)
        ]

        indexed_out = [
            Transaction.Content.TXOutput(
                op.receiver,
                op.resource,
                op.quantity,
                idx
            )
            for idx, op in enumerate(out)
        ]

        content = Transaction.Content(
            timestamp=datetime.datetime.now().timestamp(),
            tx_type=tx_type,
            inp=indexed_inp,
            out=indexed_out
        )

        tx_content_str = json.dumps(content, default=lambda x: getattr(x, "__dict__", str(x)))
        signature = sender.sign(tx_content_str)

        header = Transaction.Header(
            signature=signature,
            sender_public_key=sender.compressed_hex_public_key,
            hashed_sender_public_key=sender.public_address,
            version=1
        )

        idless_tx_str = json.dumps({
            "header": header,
            "content": content
        }, default=lambda x: getattr(x, "__dict__", str(x)))

        txid = hashlib.sha256(hashlib.sha256(json.dumps(idless_tx_str).encode()).digest()).hexdigest()
        return Transaction(txid, header, content)

@dataclass
class Block:
    @dataclass
    class Header:
        merkle_root: str
        previous_block_hash: str
        timestamp: float
        n_tx: int
        difficulty: int
        nonce: Optional[int] = None
    
    header: Header
    transactions: List[Transaction]
    header_hash: Optional[str] = None

    def __str__(self) -> str:
        return json.dumps({
            "header_hash": self.header_hash,
            "header": self.header,
            "transactions": self.transactions
        }, default=lambda x: getattr(x, "__dict__", str(x)), indent=2)

    def validate_header_hash(self):
        # Check that the header hash equals the hash of the blocks header with the nonce
        assert self.is_mined(), "Block is not mined!"
        
        header_str = json.dumps(self.header.__dict__)
        computed_header_hash = hashlib.sha256(hashlib.sha256(header_str.encode()).digest()).hexdigest()

        return computed_header_hash == self.header_hash

    def validate_transactions(self):
        merkle_tree = MerkleTree()

        # 1. Check that each transaction has a valid txid and a valid signature
        for tx in self.transactions:
            # print(transaction)
            if not tx.validate_integrity():
                return False
            
            merkle_tree.add_hash(tx.txid)
        
        # 2. Check that the merkle root equals the merkle root in the header of the block
        return merkle_tree.compute_hash_root() == self.header.merkle_root

    def validate_integrity(self):
        # 1. Check the transactions are valid
        transactions_valid = self.validate_transactions()

        if not transactions_valid:
            return False

        # 2. Check the header hash is valid
        header_hash_valid = self.validate_header_hash()
        return header_hash_valid

    def set_mined_information(self, header_hash: str, nonce: int) -> None:
        self.header_hash = header_hash
        self.header.nonce = nonce

    def is_mined(self) -> bool:
        return self.header_hash is not None and self.header.nonce is not None

    def get_mallable_mining_str(self) -> str:
        # ends with {..., "nonce": |
        return json.dumps({**self.header.__dict__, "nonce": 1})[:-2]

    @staticmethod
    def create_unmined_block(
        miner: BlockchainIdentity,
        previous_block_hash: str,
        difficulty: int,
        transactions: List[Transaction]
    ):
        # Add the coinbase transaction
        coinbase_transaction = Transaction.create_new_transaction(miner, [], [Transaction.Content.TXOutput(miner.public_address, "money", 100)], "coinbase")
        transactions = transactions[:] + [coinbase_transaction]

        merkle_tree = MerkleTree()

        for tx in transactions:
            merkle_tree.add_hash(tx.txid)
        
        merkle_root = merkle_tree.compute_hash_root()
        
        header = Block.Header(
            merkle_root=merkle_root,
            previous_block_hash=previous_block_hash,
            timestamp=datetime.datetime.now().timestamp(),
            n_tx=len(transactions),
            difficulty=difficulty
        )

        return Block(header, transactions)

identities = {
    "farmer_1": BlockchainIdentity("Farmer 1", "1GTpnkyNdR8foqbdfgv8JkWxMgvDNRGxHV", "KyYAA6BXCkW1H2ZxL9UgpdsL7Y8RZNRmr25xGirR7YbqHsXCPgL1"),
    "manufacturer_1": BlockchainIdentity("Manufacturer 1", "1G6zJsQy7WxpySxjovkidSb8aaZsMaTqaC", "KyMgXMMeMPvDtbpEcC4qxZ4e9NMFcCCYB1HwUkj3mXZJXzYuoLBE"),
    "wholesaler_1": BlockchainIdentity("Wholesaler 1", "1MRHcvxBaqiiAVYCGG8F2Dom4xoRnutLGZ", "KzGwaUyL3wTm7DrhVSNBLZgYczAH8R5kX6yicycN4B6zcaGbQLKK"),
    "retailer_1": BlockchainIdentity("Retailer 1", "1C2yiq3HAfBvZhWrGh3cF6MXprACpDDZeq", "Kzvx8dh3XhyfHheW69gya4gK2y6bSn1WjVZX6vurbaszLw1EstV8")
}

_tx = Transaction.create_new_transaction(
    sender=identities["farmer_1"],
    inp=[
        Transaction.Content.TXInput(
            txid="Fake",
            resource="wheat",
            quantity=500
        ),
        Transaction.Content.TXInput(
            txid="FakeAgain",
            resource="money",
            quantity=5000
        )
    ],
    out=[
        Transaction.Content.TXOutput(
            receiver=identities["manufacturer_1"].public_address,
            resource="money",
            quantity=400
        ),
        Transaction.Content.TXOutput(
            receiver=identities["wholesaler_1"].public_address,
            resource="money",
            quantity=4000
        )
    ],
    tx_type="??"
)



def multi_process_mine(completed, block):
    md = block.get_mallable_mining_str()
    req = "0" * block.header.difficulty
    
    nonce = 0
    chk_time = time.time()
    start_time = time.time()

    while True and completed.value == False:
        c = md + str(nonce) + "}"
        header_hash = hashlib.sha256(hashlib.sha256(c.encode()).digest()).hexdigest()

        if header_hash.startswith(req):
            block.set_mined_information(header_hash, nonce)
            completed.value = True
            print(nonce, header_hash, block.header.merkle_root)
            break

        if nonce % 1000000 == 0 and nonce != 0:
            delta = time.time() - chk_time
            print("Time taken for 1000000 hashes", delta)
            chk_time = time.time()

        nonce += 1

if __name__ == "__main__":
    # print(tx)
    # print("Validated integrity:", tx.validate_integrity())

    difficulty = 4

    _block = Block.create_unmined_block(
        miner=identities["retailer_1"],
        previous_block_hash="0" * 64,
        difficulty=difficulty,
        transactions=[_tx]
    )

    _block_2 = Block.create_unmined_block(
        miner=identities["farmer_1"],
        previous_block_hash="0" * 64,
        difficulty=difficulty,
        transactions=[_tx]
    )

    # def faster_mine(block):
    #     md = block.get_mallable_mining_str()
        
    #     nonce = 0
    #     chk_time = time.time()
    #     start_time = time.time()

    #     while True:
    #         c = md + str(nonce) + "}"
    #         header_hash = hashlib.sha256(hashlib.sha256(c.encode()).digest()).hexdigest()

    #         if header_hash.startswith(req):
    #             block.set_mined_information(header_hash, nonce)
    #             break

    #         if nonce % 1000000 == 0 and nonce != 0:
    #             delta = time.time() - chk_time
    #             print("Time taken for 1000000 hashes", delta)
    #             chk_time = time.time()

    #         nonce += 1

    #     print(block)
    #     print("Mined in:", time.time() - start_time, "s")
    #     print("Nonce:", block.header.nonce)
    #     print("Valid:", block.validate_integrity())
    #     print()

    _completed = multiprocessing.Value("b", False)

    m_1 = multiprocessing.Process(target=multi_process_mine, args=(_completed, _block))
    m_2 = multiprocessing.Process(target=multi_process_mine, args=(_completed, _block_2))

    m_1.start()
    m_2.start()
    m_1.join()
    m_2.join()

    print(_block)
    print(_block.header.nonce)
    print(_block_2)
    print(_block_2.header.nonce)