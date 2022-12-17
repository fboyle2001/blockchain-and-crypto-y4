from typing import List, Optional, Dict
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

transaction_types: List[str] = ["raw_material_creation", "material_conversion", "material_transfer", "financial_transfer", "coinbase"]

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
        public_address: str, 
        wif_private_key: str, 
    ):
        self.public_address = public_address
        self.wif_private_key = wif_private_key

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
            txid_idx: int
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
                ip.txid_idx,
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
        coinbase_count = 0

        # 1. Check that each transaction has a valid txid and a valid signature
        for tx in self.transactions:
            # print(transaction)
            if not tx.validate_integrity():
                return False
            
            if tx.content.tx_type == "coinbase":
                coinbase_count += 1

            merkle_tree.add_hash(tx.txid)

        # 2. Check that there is exactly one coinbase transaction
        if coinbase_count != 1:
            return False
        
        # 3. Check that the merkle root equals the merkle root in the header of the block
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
        transactions: List[Transaction],
        previous_block_hash: str,
        difficulty: int,
        coinbase_reward: int
    ):
        # Add the coinbase transaction
        coinbase_transaction = Transaction.create_new_transaction(miner, [], [Transaction.Content.TXOutput(miner.public_address, "money", coinbase_reward)], "coinbase")
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

class Blockchain:
    def __init__(self, difficulty: int, coinbase_reward: int = 100):
        self.blocks: List[Block] = []
        self.difficulty = difficulty
        self.utxos: Dict[str, Dict[int, Transaction.Content.TXOutput]] = {}
        self.coinbase_reward = coinbase_reward

    def create_unmined_block(self, miner: BlockchainIdentity, transactions: List[Transaction]):
        previous_block_hash = "0" * 64

        # Check it links to the previous block
        if len(self) > 0:
            previous_block_hash = self.get_last_block().header_hash
            assert previous_block_hash is not None

        # It is not the responsibility of the chain to check unmined transactions
        # It should check that only UTXOs have been used during the consensus phase
        # See {Blockchain:append_mined_block} instead

        return Block.create_unmined_block(miner, transactions, previous_block_hash, self.difficulty, self.coinbase_reward)
    
    def __len__(self):
        return len(self.blocks)

    def get_last_block(self) -> Block:
        return self.blocks[-1]

    def append_mined_block(self, block: Block) -> bool:
        # Acts as consensus for the chain, in reality each client would
        # have to accept that the block is valid
        # TODO: Improve consensus
        # 1. Check block is mined
        # 2. Check that it links to the head of the chain
        # 3. Validate the block's cryptographic assurances
        # 4. Check the transactions are legitmate

        if not block.is_mined():
            return False
        
        if len(self) > 0 and block.header.previous_block_hash != self.get_last_block().header_hash:
            return False

        # Check the cryptographic integrity of the block and its transactions
        if not block.validate_integrity():
            return False

        # Check the validity of the spending, i.e. no double spends and only UTXOs used
        outputs = {}
        spent_txids_with_idx = []

        for tx in block.transactions:
            if len(tx.content.inp) == 0 and len(tx.content.out) == 0:
                return False

            if tx.content.tx_type == "raw_material_creation":
                # No way to check legitimacy 
                if len(tx.content.inp) != 0:
                    return False

                if len(tx.content.out) != 1:
                    return False
                
                if tx.content.out[0].quantity <= 0:
                    return False

            elif tx.content.tx_type == "financial_transfer":
                # No way to check legitimacy so can't enforce that money exists on the chain
                if len(tx.content.inp) != 0:
                    return False

                # Can send some back to self
                if len(tx.content.out) < 1:
                    return False
                
                if tx.content.inp[0].quantity <= 0:
                    return False

                if tx.content.inp[0].resource != "money":
                    return False

            elif tx.content.tx_type == "coinbase":
                # No way to check legitimacy 
                if len(tx.content.inp) != 0:
                    return False
                
                # No way to check legitimacy 
                if len(tx.content.out) != 1:
                    return False

                if tx.header.hashed_sender_public_key != tx.content.out[0].receiver:
                    return False

                if tx.content.out[0].quantity != self.coinbase_reward:
                    return False

            elif tx.content.tx_type == "material_conversion":
                if len(tx.content.inp) < 1:
                    return False

                if len(tx.content.out) < 1:
                    return False

                # Check that the inputs are UTXO transactions
                in_total = 0

                for inp in tx.content.inp:
                    in_total += inp.quantity

                    txid_with_idx = f"{inp.txid}-{inp.txid_idx}"

                    # Prevent double spend
                    if txid_with_idx in spent_txids_with_idx:
                        return False
                    
                    # Can only spend UTXOs
                    if inp.txid not in self.utxos:
                        return False

                    if inp.txid_idx not in self.utxos[inp.txid]:
                        return False

                    # Can't spend someone elses UTXOs!
                    if self.utxos[inp.txid][inp.txid_idx].receiver != tx.header.hashed_sender_public_key:
                        return False
                    
                    spent_txids_with_idx.append(txid_with_idx)

                # We force that the amount in >= amount out of the new resource
                # May be unrealistic in reality?
                # Conversions only allow transformation of resources to self
                out_total = 0

                for out in tx.content.out:
                    if out.receiver != tx.header.hashed_sender_public_key:
                        return False
                    
                    out_total += out.quantity

                if out_total > in_total:
                    return False

            elif tx.content.tx_type == "material_transfer":
                if len(tx.content.inp) < 1:
                    return False

                if len(tx.content.out) < 1:
                    return False

                # Total IN = Total OUT
                out_totals = {}

                for out in tx.content.out:
                    if out.resource not in out_totals.keys():
                        out_totals[out.resource] = 0
                    
                    out_totals[out.resource] += out.quantity
                
                in_totals = {}

                for inp in tx.content.inp:
                    txid_with_idx = f"{inp.txid}-{inp.txid_idx}"

                    # Prevent double spend
                    if txid_with_idx in spent_txids_with_idx:
                        return False
                    
                    # Can only spend UTXOs
                    if inp.txid not in self.utxos:
                        return False

                    if inp.txid_idx not in self.utxos[inp.txid]:
                        return False

                    expected_utxo = self.utxos[inp.txid][inp.txid_idx]

                    if inp.resource != expected_utxo.resource:
                        return False

                    if inp.quantity != expected_utxo.quantity:
                        return False

                    # Can't spend someone elses UTXOs!
                    if expected_utxo.receiver != tx.header.hashed_sender_public_key:
                        return False

                    spent_txids_with_idx.append(txid_with_idx)

                    if inp.resource not in in_totals.keys():
                        in_totals[inp.resource] = 0
                    
                    in_totals[inp.resource] += inp.quantity

                if out_totals.keys() != in_totals.keys():
                    return False
                
                for resource in out_totals.keys():
                    if out_totals[resource] != in_totals[resource]:
                        return False
                    
            else:
                return False

            indexed = {}

            for out in tx.content.out:
                indexed[out.idx] = out

            outputs[tx.txid] = indexed

        # Remove the spent UTXOs
        reduced_utxos = {**self.utxos}

        for txid_with_idx in spent_txids_with_idx:
            split = txid_with_idx.split("-")
            txid, idx = split[0], int(split[1])

            del reduced_utxos[txid][idx]

        self.utxos = {**reduced_utxos, **outputs}
        self.blocks.append(block)

        return True

    def get_wallet(self, identity: BlockchainIdentity) -> Dict[str, int]:
        wallet: Dict[str, int] = {}

        for utxo_parent in self.utxos.values():
            for utxo in utxo_parent.values():
                if utxo.receiver == identity.public_address:
                    if utxo.resource not in wallet.keys():
                        wallet[utxo.resource] = 0
                    
                    wallet[utxo.resource] += utxo.quantity
        
        return wallet

    def __str__(self):
        return json.dumps(self.blocks, indent=2, default=lambda x: getattr(x, "__dict__", str(x)))

def non_multi_threaded_block_miner(block: Block, verbose: bool = False):
    mallable = block.get_mallable_mining_str()
    req = "0" * block.header.difficulty
    
    nonce = 0
    chk_time = time.time()
    start_time = time.time()

    while True:
        testable = mallable + str(nonce) + "}"
        header_hash = hashlib.sha256(hashlib.sha256(testable.encode()).digest()).hexdigest()

        if header_hash.startswith(req):
            block.set_mined_information(header_hash, nonce)

            if verbose:
                print("Mined block in", time.time() - start_time, "seconds, nonce:" , nonce)

            break

        if nonce % 1000000 == 0 and nonce != 0 and verbose:
            delta = time.time() - chk_time
            print("Time taken for 1000000 hashes", delta)
            chk_time = time.time()

        nonce += 1

def part_3_a(blockchain: Blockchain, miner: BlockchainIdentity):
    genesis = blockchain.create_unmined_block(miner, [])
    non_multi_threaded_block_miner(genesis, verbose=True)
    blockchain.append_mined_block(genesis)

if __name__ == "__main__":
    miner_identities = {
        "miner_1": BlockchainIdentity("1J5txDKRWLtHCc4ppFKYLEkWicAy5PtZ6S", "Kwc4dJTvEeFMMg3fHwuE1ZujDPckztiFGKespwoPKN3qx2wm8wFT"),
        "miner_2": BlockchainIdentity("1CePNpiphrENh1jPyhWrBPFh8wihUbodLc", "L1Q23cZnwTDbcPUL9pBb9PiUsbGTwFsxMnzqKamCnyXrwKULdriR"),
        "miner_3": BlockchainIdentity("18i6ajSi9TvN8RMN1bKP3UFAciAeiZzcov", "L5nyTvjeS8niFU8W6MRXVbJyb9d4Gqgcnq9QfNM7xZDf3by1EneM"),
        "miner_4": BlockchainIdentity("14WZS1BX5t9YxTc7dyPWmYAM71m8jKt7eK", "L2r2b3cmdem9gUzw73oFqnQ7ppoVb4cCGUE9DMsXcNbAEZjWbDpa")
    }

    participant_identities = {
        "farmer_1": BlockchainIdentity("1GTpnkyNdR8foqbdfgv8JkWxMgvDNRGxHV", "KyYAA6BXCkW1H2ZxL9UgpdsL7Y8RZNRmr25xGirR7YbqHsXCPgL1"),
        "manufacturer_1": BlockchainIdentity("1G6zJsQy7WxpySxjovkidSb8aaZsMaTqaC", "KyMgXMMeMPvDtbpEcC4qxZ4e9NMFcCCYB1HwUkj3mXZJXzYuoLBE"),
        "wholesaler_1": BlockchainIdentity("1MRHcvxBaqiiAVYCGG8F2Dom4xoRnutLGZ", "KzGwaUyL3wTm7DrhVSNBLZgYczAH8R5kX6yicycN4B6zcaGbQLKK"),
        "retailer_1": BlockchainIdentity("1C2yiq3HAfBvZhWrGh3cF6MXprACpDDZeq", "Kzvx8dh3XhyfHheW69gya4gK2y6bSn1WjVZX6vurbaszLw1EstV8")
    }

    blockchain = Blockchain(difficulty=4)
    competing_miners = 1
    assert 1 <= competing_miners <= len(miner_identities), "Invalid number of miners"
    selected_miners = list(miner_identities.values())[:competing_miners]
    miner = miner_identities["miner_1"]

    part_3_a(blockchain, miner)
    # print(blockchain)
    print(blockchain.utxos)

    farmer_resource_block = blockchain.create_unmined_block(miner, [
        Transaction.create_new_transaction(
            participant_identities["farmer_1"],
            [],
            [
                Transaction.Content.TXOutput(
                    participant_identities["farmer_1"].public_address,
                    "wheat",
                    500
                )
            ],
            "raw_material_creation"
        )
    ])
    non_multi_threaded_block_miner(farmer_resource_block, verbose=True)
    blockchain.append_mined_block(farmer_resource_block)
    # print(blockchain)
    print(blockchain.utxos)

    farmer_transfer = blockchain.create_unmined_block(miner, [
        Transaction.create_new_transaction(
            participant_identities["farmer_1"],
            [],
            [
                Transaction.Content.TXOutput(
                    participant_identities["farmer_1"].public_address,
                    "wheat",
                    350
                )
            ],
            "raw_material_creation"
        ),
        Transaction.create_new_transaction(
            participant_identities["farmer_1"],
            [
                Transaction.Content.TXInput(
                    blockchain.get_last_block().transactions[0].txid,
                    0,
                    "wheat",
                    500
                )
            ],
            [
                Transaction.Content.TXOutput(
                    participant_identities["farmer_1"].public_address,
                    "wheat",
                    100
                ),
                Transaction.Content.TXOutput(
                    participant_identities["manufacturer_1"].public_address,
                    "wheat",
                    400
                )
            ],
            "material_transfer"
        )
    ])

    for participant, identity in (participant_identities | miner_identities).items():
        print(participant)
        print(json.dumps(blockchain.get_wallet(identity), indent=2))
        print()
