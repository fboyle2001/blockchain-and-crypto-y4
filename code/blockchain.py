### Blockchain and Cryptocurrency Coursework by chpf93
### Any code or webpages used for reference are linked in the relevant parts of the code
### Prior to running this, please create a virtual environment and run "pip install -r requirements.txt"
### This code has been tested on Python 3.10.7 on a Windows 10 64-bit computer

# This Python code uses type hints (PEP 484)
from typing import List, Optional, Dict, Tuple
# Dataclass is syntactic sugar, similar to a struct in C
from dataclasses import dataclass

# Necessary for cryptographic operations and key manipulation
import hashlib
import ecdsa
import json
import datetime
import base58

# For mining
# Multiprocessing is optional and can be disabled if it is not permitted!
import multiprocessing
import time

# SHA256 and RIPEMD160 are required to manipulate the keys
assert "sha256" in hashlib.algorithms_available, "SHA256 is required but it is unavailable on your system"
assert "ripemd160" in hashlib.algorithms_available , "RIPEMD160 is required but it is unavailable on your system"

# The blockchain supports some different types of transactions
# This is a global variable as the submission needs to be a single file so it cannot be owned by the Blockchain class
transaction_types: List[str] = ["raw_material_creation", "material_conversion", "material_transfer", "financial_transfer", "coinbase"]

# Verify an ECDSA signature and message
def verify_signature(verifying_key: ecdsa.VerifyingKey, signature: str, message: str) -> bool:
    try:
        verifying_key.verify(bytes.fromhex(signature), message.encode())
    except ecdsa.BadSignatureError:
        return False

    return True

class MerkleTree:
    """
    Implementation of a Merkle Tree
    Provides a way to record a hash of all of the transactions in a block
    """
    def __init__(self):
        self.hashes: List[str] = []
    
    def __hash_data(self, data) -> str:
        # Double hash as in Bitcoin
        return hashlib.sha256(hashlib.sha256(str(data).encode()).digest()).hexdigest()

    def add_data(self, data: str) -> None:
        # Add data to the tree by hashing it
        hashed =  self.__hash_data(data)
        self.hashes.append(hashed)

    def add_hash(self, hashed: str) -> None:
        # Or directly add a hash to the tree
        self.hashes.append(hashed)

    def compute_hash_root(self) -> str:
        # Iteratively reduce the tree to compute the hash of the root node
        working_hashes = self.hashes

        # Until we reach the root node do the following
        while len(working_hashes) != 1:
            # Require an even number of hashes, duplicate the end hash if we don't have this
            # Reference: https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees
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

# Represents a user of the blockchain and stores their public address and their WIF private key
# Provides utilities to sign messages and convert between key types easily
class BlockchainIdentity:
    def __init__(self,
        public_address: str, 
        wif_private_key: str, 
    ):
        # The identities generated in Task 2 consist of hashed public addresses and Wallet Import Format private keys
        # Reference: https://en.bitcoin.it/wiki/Wallet_import_format
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
        # References: https://secretscan.org/PrivateKeyWif and https://en.bitcoin.it/wiki/Wallet_import_format 
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
        # Reference: https://github.com/sr-gi/bitcoin_tools/blob/0f6ea45b6368200e481982982822f0416e0c438d/bitcoin_tools/core/keys.py#L74
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
    """
    This class acts as a type checker for the Transaction data
    Enables easier translation between JSON and a Python object with the correct attributes
    Provides methods for signing and validating a single transaction
    """
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
        # Useful for visualising all of the transaction information
        # Recursive JSON trick from https://stackoverflow.com/a/49003922
        return json.dumps({
            "txid": self.txid,
            "header": self.header,
            "content": self.content
        }, default=lambda x: getattr(x, "__dict__", str(x)), indent=2)

    def validate_integrity(self) -> bool:
        # Validate the txid is correct for the {header, content} and the signature validates the {content}

        # First check the txid, do not indent the JSON
        idless_tx_str = json.dumps({
            "header": self.header,
            "content": self.content
        }, default=lambda x: getattr(x, "__dict__", str(x)))

        # Compute the hash of the header and content
        computed_txid = hashlib.sha256(hashlib.sha256(json.dumps(idless_tx_str).encode()).digest()).hexdigest()
        
        # This should match the assigned ID of the transaction
        if computed_txid != self.txid:
            return False
        
        # Now check the signature, we only sign the contents of the transaction
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
        **This does not validate the inp and out, this is the responsibilty of the miner and the consensus!**
        """

        # Assigns incremental indexes to each input as there could be multiple in the same transaction
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

        # Assigns incremental indexes to each output as there could be multiple in the same transaction
        indexed_out = [
            Transaction.Content.TXOutput(
                op.receiver,
                op.resource,
                op.quantity,
                idx
            )
            for idx, op in enumerate(out)
        ]

        # Create, timestamp, and sign the transaction
        content = Transaction.Content(
            timestamp=datetime.datetime.now().timestamp(),
            tx_type=tx_type,
            inp=indexed_inp,
            out=indexed_out
        )

        tx_content_str = json.dumps(content, default=lambda x: getattr(x, "__dict__", str(x)))
        signature = sender.sign(tx_content_str)

        # Construct the header and compute the transaction hash which is used as its ID
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
    """
    Same idea as with the Transaction class, structures the data of a block
    Provides useful methods for validating the block and its transactions
    """
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
        # For visualisation
        return json.dumps({
            "header_hash": self.header_hash,
            "header": self.header,
            "transactions": self.transactions
        }, default=lambda x: getattr(x, "__dict__", str(x)), indent=2)

    def validate_header_hash(self):
        # Check that the header hash equals the hash of the blocks header with the nonce
        # Requires the block to have been mined
        assert self.is_mined(), "Block is not mined!"
        
        header_str = json.dumps(self.header.__dict__)
        computed_header_hash = hashlib.sha256(hashlib.sha256(header_str.encode()).digest()).hexdigest()

        return computed_header_hash == self.header_hash

    def validate_transactions(self):
        merkle_tree = MerkleTree()
        coinbase_count = 0

        # 1. Check that each transaction has a valid txid and a valid signature
        # We build the Merkle Tree to ensure that the root is valid and thus the transactions should be in the block
        for tx in self.transactions:
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

    def get_malleable_mining_str(self) -> str:
        # Used for mining, returns the header string to be hashed without the nonce
        # The nonce is simply appended at the end with a trailing } to close the JSON
        # This is then hashed, see the mining code below for more information
        # The [:-2] trims the "1}" from the end of the JSON string
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

        # Compute the MerkleTree root of the transactions
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

        # Return the unmined block
        return Block(header, transactions)

class BlockchainTracebackException(Exception):
    pass

class BlockchainAppendException(Exception):
    pass

class Blockchain:
    """
    Defines a blockchain with a list of blocks in the order they were appended
    A list of UTXOs is maintained like in Bitcoin
    """
    def __init__(self, difficulty: int, coinbase_reward: int = 100):
        self.blocks: List[Block] = []
        self.difficulty = difficulty
        self.utxos: Dict[str, Dict[int, Transaction.Content.TXOutput]] = {}
        self.coinbase_reward = coinbase_reward

    def create_unmined_block(self, miner: BlockchainIdentity, transactions: List[Transaction], difficulty: Optional[int] = None):
        # Create a new block that can be mined by the specified miner

        # Link to the previous block, if there are none then use 0x00...00 as the previous block hash
        previous_block_hash = "0" * 64
        # Can override the difficulty for testing if necessary
        difficulty = difficulty if difficulty is not None else self.difficulty

        if len(self) > 0:
            previous_block_hash = self.get_last_block().header_hash
            assert previous_block_hash is not None

        # It is not the responsibility of the chain to check unmined transactions
        # It should check that only UTXOs have been used when a new block is wanting to be accepted in to the chain
        # See {Blockchain:append_mined_block} instead, it is the responsibility of the consensus
        return Block.create_unmined_block(miner, transactions, previous_block_hash, self.difficulty, self.coinbase_reward)
    
    def __len__(self):
        return len(self.blocks)

    def get_last_block(self) -> Block:
        return self.blocks[-1]

    def append_mined_block(self, block: Block) -> bool:
        # Acts as consensus for the chain, in reality each client would have to accept that the block is valid
        # A block will only be accepted by the chain if it is valid and does not violate principles such as double spending etc
        # 1. Check block is mined
        # 2. Check that it links to the head of the chain
        # 3. Validate the block's cryptographic assurances
        # 4. Check the transactions are legitmate

        if not block.is_mined():
            raise BlockchainAppendException("Block is not mined")
        
        if len(self) > 0 and block.header.previous_block_hash != self.get_last_block().header_hash:
            raise BlockchainAppendException("Block is out of sync")

        # Check the cryptographic integrity of the block and its transactions
        if not block.validate_integrity():
            raise BlockchainAppendException("Block is cryptographically invalid")

        # Check the validity of the spending, i.e. no double spends and only UTXOs used
        outputs = {}
        spent_txids_with_idx = []

        for tx in block.transactions:
            if len(tx.content.inp) == 0 and len(tx.content.out) == 0:
                raise BlockchainAppendException("Empty transaction")

            if tx.content.tx_type == "raw_material_creation":
                # No way to check legitimacy of the raw material creation
                # This would be to do with the physical setup of the 
                if len(tx.content.inp) != 0:
                    raise BlockchainAppendException("RMC type should have no inputs")

                if len(tx.content.out) != 1:
                    raise BlockchainAppendException("RMC type should have a single output")
                
                if tx.content.out[0].quantity <= 0:
                    raise BlockchainAppendException("RMC type should have positive quantity")

            elif tx.content.tx_type == "financial_transfer":
                # No way to check legitimacy so can't enforce that money exists on the chain
                if len(tx.content.inp) != 0:
                    raise BlockchainAppendException("FT type should have at least one input")

                if len(tx.content.out) == 0:
                    raise BlockchainAppendException("FT type should have at least one output")
                
                for out in tx.content.out:
                    if out.quantity <= 0:
                        raise BlockchainAppendException("FT type outputs must be positive")

                    if out.resource != "money":
                        raise BlockchainAppendException("FT type outputs can only transfer money")

            elif tx.content.tx_type == "coinbase":
                if len(tx.content.inp) != 0:
                    raise BlockchainAppendException("CB type should not have inputs")
                
                # No way to check legitimacy 
                if len(tx.content.out) != 1:
                    raise BlockchainAppendException("CB type should have exactly one output")

                if tx.header.hashed_sender_public_key != tx.content.out[0].receiver:
                    raise BlockchainAppendException("CB type can only be sent to the miner")

                if tx.content.out[0].quantity != self.coinbase_reward:
                    raise BlockchainAppendException("CB type quantity must equal the mining reward")

            elif tx.content.tx_type == "material_conversion":
                if len(tx.content.inp) < 1:
                    raise BlockchainAppendException("MC type should have at least one input")

                if len(tx.content.out) < 1:
                    raise BlockchainAppendException("MC type should have at least one output")

                # Check that the inputs are UTXO transactions
                in_total = 0

                for inp in tx.content.inp:
                    in_total += inp.quantity

                    txid_with_idx = f"{inp.txid}-{inp.txid_idx}"

                    # Prevent double spend
                    if txid_with_idx in spent_txids_with_idx:
                        raise BlockchainAppendException("MC TXID->IDX cannot be double spent")
                    
                    # Can only spend UTXOs
                    if inp.txid not in self.utxos:
                        raise BlockchainAppendException("MC TXID must be in the UTXO set")

                    if inp.txid_idx not in self.utxos[inp.txid]:
                        raise BlockchainAppendException("MC TXID->IDX must be in the UTXO set")

                    # Can't spend someone elses UTXOs!
                    if self.utxos[inp.txid][inp.txid_idx].receiver != tx.header.hashed_sender_public_key:
                        raise BlockchainAppendException("MC TXID->IDX must be owned by the sender")
                    
                    expected_utxo = self.utxos[inp.txid][inp.txid_idx]

                    if inp.resource != expected_utxo.resource:
                        raise BlockchainAppendException("MC TXID->IDX must match the UTXO record resource")

                    if inp.quantity != expected_utxo.quantity:
                        raise BlockchainAppendException("MC TXID->IDX must match the UTXO record quantity")
                    
                    spent_txids_with_idx.append(txid_with_idx)

                # We force that the amount in >= amount out of the new resource
                # May be unrealistic in reality but is an example of a constraint the consensus could impose
                # Conversions only allow transformation of resources to self
                out_total = 0

                for out in tx.content.out:
                    if out.receiver != tx.header.hashed_sender_public_key:
                        raise BlockchainAppendException("MC type can only be self-received")
                    
                    out_total += out.quantity

                if out_total > in_total:
                    raise BlockchainAppendException("MC type cannot produce additional resource quantity")

            elif tx.content.tx_type == "material_transfer":
                if len(tx.content.inp) < 1:
                    raise BlockchainAppendException("MT type should have at least one input")

                if len(tx.content.out) < 1:
                    raise BlockchainAppendException("MT type should have at least one input")

                # Total IN = Total OUT so record as we verify the transactions
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
                        raise BlockchainAppendException("MT TXID->IDX cannot be double spent")
                    
                    # Can only spend UTXOs
                    if inp.txid not in self.utxos:
                        raise BlockchainAppendException("MT TXID must be in the UTXO set")

                    if inp.txid_idx not in self.utxos[inp.txid]:
                        raise BlockchainAppendException("MT TXID->IDX must be in the UTXO set")

                    expected_utxo = self.utxos[inp.txid][inp.txid_idx]

                    # Can't spend someone elses UTXOs!
                    if expected_utxo.receiver != tx.header.hashed_sender_public_key:
                        raise BlockchainAppendException("MT TXID->IDX must be owned by the sender")

                    if inp.resource != expected_utxo.resource:
                        raise BlockchainAppendException("MT TXID->IDX must match the UTXO record resource")

                    if inp.quantity != expected_utxo.quantity:
                        raise BlockchainAppendException("MT TXID->IDX must match the UTXO record quantity")


                    spent_txids_with_idx.append(txid_with_idx)

                    if inp.resource not in in_totals.keys():
                        in_totals[inp.resource] = 0
                    
                    in_totals[inp.resource] += inp.quantity

                if out_totals.keys() != in_totals.keys():
                    raise BlockchainAppendException("MT total IN must equal total OUT (key alignment)")
                
                for resource in out_totals.keys():
                    if out_totals[resource] != in_totals[resource]:
                        raise BlockchainAppendException("MT total IN must equal total OUT (value alignment)")
                    
            else:
                raise BlockchainAppendException("Invalid transaction type")

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

        # Update the UTXOs
        self.utxos = {**reduced_utxos, **outputs}
        # The block has been approved and appended
        self.blocks.append(block)

        return True

    def get_wallet(self, identity: BlockchainIdentity) -> Dict[str, int]:
        # Get the owned resources for a specific identity
        # Like in Bitcoin, the wallet is actually the UTXO records that a public address controls
        # But they can only be spent by the knowing the private key to sign the transaction
        wallet: Dict[str, int] = {}

        for utxo_parent in self.utxos.values():
            for utxo in utxo_parent.values():
                if utxo.receiver == identity.public_address:
                    if utxo.resource not in wallet.keys():
                        wallet[utxo.resource] = 0
                    
                    wallet[utxo.resource] += utxo.quantity
        
        return wallet

    def __str__(self):
        # Visualise the blockchain's block
        return json.dumps(self.blocks, indent=2, default=lambda x: getattr(x, "__dict__", str(x)))

    def trace_transaction(self, txid: str, idx: int, start_block: Optional[int] = None):
        # Trace a specific transaction and find all linked inputs and outputs from the chain
        start_block = start_block if start_block is not None else len(self.blocks)
        details = {}

        # Traverse backwards
        for i, block in enumerate(self.blocks[:start_block][::-1]):
            real_block_idx = start_block - i

            for tx in block.transactions:
                # Found the transaction we were searching for
                if tx.txid == txid:
                    # Record relevant details
                    details["block_hash"] = block.header_hash
                    details["block_timestamp"] = block.header.timestamp
                    details["txid"] = tx.txid
                    details["type"] = tx.content.tx_type
                    details["tx_timestamp"] = tx.content.timestamp
                    details["relevant_output"] = list(filter(lambda x: x.idx == idx, tx.content.out))[0]

                    traceback = None
                    
                    # If there are no inputs then this was an initial transaction
                    if len(tx.content.inp) == 0:
                        traceback = tx.content.tx_type
                    else:
                        traceback = []

                        # Otherwise trace back the inputs to this transaction
                        for in_txo in tx.content.inp:
                            # Recursively continue the search, move backwards in time
                            trace = self.trace_transaction(in_txo.txid, in_txo.txid_idx, real_block_idx - 1)
                            traceback.append(trace)
                    
                    details["traceback"] = traceback
                    break
            
            # If we have found the transaction then stop the search
            if len(details.keys()) > 0:
                break
        
        return details

    def trace_transactions_by_attributes(
        self, 
        start_time: Optional[float] = None, 
        end_time: Optional[float] = None, 
        products: Optional[List[str]] = None, 
        txids: Optional[List[Tuple[str, int]]] = None,
        tx_types: Optional[List[str]] = None,
        participants: Optional[List[str]] = None
    ):
        """
        Task 5: Trace a transaction according to its attributes
        You can trace a transaction by time period, resource type, specific transaction IDs, transaction type, and identity (public address)
        Any combination of these can be used, all set conditions must be met for a transaction to be found (AND not OR)

        Args:
            start_time (Optional[float], optional): Time period start. Defaults to None.
            end_time (Optional[float], optional): Time period end. Defaults to None.
            products (Optional[List[str]], optional): Products to search for. Defaults to None.
            txids (Optional[List[Tuple[str, int]]], optional): Transaction IDs and indexes to search for. Defaults to None.
            tx_types (Optional[List[str]], optional): Transaction types to search for. Defaults to None.
            participants (Optional[List[str]], optional): Hashed public addresses to search for. Defaults to None.

        Raises:
            BlockchainTracebackException: Raised if there is an issue with the search parameters

        Returns: The tracebacks of every transaction found by the search
        """
        # Ensure at least one attribute is set
        non_zeros = (start_time is not None) + (end_time is not None) + (products is not None) + (txids is not None) + (tx_types is not None) + (participants is not None)

        # Validate the attributes and set defaults if necessary
        if non_zeros == 0:
            raise BlockchainTracebackException("Must specify at least one attribute to search by")

        start_time = start_time if start_time is not None else 0
        end_time = end_time if end_time is not None else datetime.datetime.now().timestamp()

        if end_time <= start_time:
            raise BlockchainTracebackException("end_time must be after the start_time for tracebacks")
        
        products = products if products is not None and len(products) != 0 else []
        txids = txids if txids is not None and len(txids) != 0 else []

        if len(txids) > 0 and non_zeros != 1:
            raise BlockchainTracebackException("Searching by transaction IDs is mutually exclusive to other criteria")

        tx_types = tx_types if tx_types is not None and len(tx_types) != 0 else []

        for tx_type in tx_types:
            if tx_type not in transaction_types:
                raise BlockchainTracebackException(f"Invalid transaction type {tx_type}, valid options are: {transaction_types}")

        participants = participants if participants is not None and len(participants) != 0 else []
        txids_with_blocks: List[Tuple[str, int]] = []

        # Find the transaction IDs according to the criteria
        if len(txids) == 0:
            for block in self.blocks: 
                # Block must be mined
                if not block.is_mined():
                    raise BlockchainTracebackException(f"Block {block.header_hash} has not been mined")
                
                # Just for type checking, cannot fail if block is mined did not throw an exception
                assert block.header_hash is not None

                # Verify the ownership of the transactions [Task 5(b)]
                # Validate Integrity checks transactions and block cryptographic signatures etc.
                if not block.validate_integrity(): 
                    raise BlockchainTracebackException(f"Unable to validate the transactions in block {block.header_hash}")
                
                for transaction in block.transactions:
                    # Outside of the time range
                    if not (start_time <= transaction.content.timestamp <= end_time):
                        continue

                    # Search by tx type
                    if len(tx_types) > 0:
                        if transaction.content.tx_type not in tx_types:
                            continue

                    sender_is_participant = len(participants) == 0 or (transaction.header.hashed_sender_public_key in participants)

                    for output in transaction.content.out:
                        if output.idx is None:
                            raise BlockchainTracebackException(f"Output does not have an index")

                        # Search by product
                        if len(products) > 0:
                            if output.resource not in products:
                                continue
                        
                        # Search by participant
                        if len(participants) > 0:
                            if not(sender_is_participant or output.receiver in participants):
                                continue
                        
                        # If we make here then this is a transaction we want
                        txids_with_blocks.append((transaction.txid, output.idx))
        else:
            for block in self.blocks:
                if not block.is_mined():
                    raise BlockchainTracebackException(f"Block {block.header_hash} has not been mined")
                
                # Just for type checking
                assert block.header_hash is not None

                if not block.validate_integrity():
                    raise BlockchainTracebackException(f"Unable to validate the transactions in block {block.header_hash}")
                
                for transaction in block.transactions:
                    for output in transaction.content.out:
                        for entry in txids:
                            if transaction.txid == entry[0] and output.idx == entry[1]:
                                txids_with_blocks.append(entry)
                        
                        if len(txids_with_blocks) == len(txids):
                            break

        # At this point we have the transactions to trace
        traces = {}

        # Now compute the traces for each transaction
        for (txid, idx) in txids_with_blocks:
            traces[(txid, idx)] = self.trace_transaction(txid, idx)
        
        return traces

#### MINING ####

def single_threaded_block_miner(block: Block, verbose: bool = False):
    # Runs a single thread to mine a block, utilises a single core and is inefficient as a result
    malleable = block.get_malleable_mining_str()
    req = "0" * block.header.difficulty
    
    nonce = 0
    chk_time = time.time()
    start_time = time.time()

    while True:
        # Hash with the nonce value
        testable = malleable + str(nonce) + "}"
        header_hash = hashlib.sha256(hashlib.sha256(testable.encode()).digest()).hexdigest()

        # Check if the header meets the difficulty requirement
        if header_hash.startswith(req):
            block.set_mined_information(header_hash, nonce)

            if verbose:
                print("Mined block in", time.time() - start_time, "seconds, nonce:" , nonce)

            break
        
        # Useful for high difficulty that might a long time to get some feedback on the process
        if nonce % 1000000 == 0 and nonce != 0 and verbose:
            delta = time.time() - chk_time
            print(f"Time taken for 1000000 hashes, took {delta}s (rate: {(1000000 / (delta + 1e-8)):.2f} H/s)")
            chk_time = time.time()

        # If we failed, increase the nonce and try again
        nonce += 1

def multi_threaded_miner_target(idx: int, malleable: str, difficulty: int, queue: multiprocessing.Queue, private_queue: multiprocessing.Queue, start_nonce: int, time_remaining: float):
    # Multi-threaded mining utilises the CPU more effectively as each core can be mining
    # Each core is mining with a different coinbase transaction so that they can all start from nonce = 0

    # Define the target based on the difficulty
    target = "0" * difficulty
    nonce = start_nonce

    # Once we find the nonce we stop, but there is no point going back to 0 for the later difficulty
    # Instead, restart from nonce - 1 since we know that nonce has at least n zeroes, so check if by chance (1/16) it has (n + 1) zeroes 
    print(f"{idx}: Restarting with difficulty {difficulty} with start nonce {nonce}, time remaining is {time_remaining}s")

    start_time = time.time()

    # Prehash the initial block string, saves computation as we only have to hash the nonce each tiem 
    prehashed = hashlib.sha256(malleable.encode())

    while True:
        header_hash = prehashed.copy()
        # __str__ is faster than str() as we do not have to determine the type
        nonce_str = nonce.__str__() + "}"

        # Update the copied hash with the new nonce
        header_hash.update(nonce_str.encode())
        # Get the digest bytes directly
        header_hash_digest = hashlib.sha256(header_hash.digest()).digest()
        
        # value = int.from_bytes(header_hash_digest[::-1], "little")

        if nonce != 0 and nonce % 1000000 == 0:
            runtime = time.time() - start_time
            hash_rate = (nonce - start_nonce) / (runtime + 1e-8)

            # Single value queue
            if private_queue.full():
                private_queue.get()

            # Save state information so we can resume if another thread beats us
            private_queue.put({ "hash_rate": hash_rate, "interrupt_nonce": nonce, "time_remaining": time_remaining - runtime })
            print(f"{idx}: Nonce: {nonce}, hashes/second: {hash_rate} hashes/s [D: {difficulty}]")

            # Out of time, check every 1m nonce values which is about every ~1.8s
            if runtime > time_remaining:
                queue.put({ "success": False })
                return

        # Alternative method to use integer comparisons but testing suggests it was ~14% slower
        # if value < int_goal:
        #     print(f"{idx}: Found sol as {nonce} for difficulty {known_diff}")
        #     print(f"Hashes/second: {nonce / (time.time() - start_time)} hashes/s")
        #     print(f"As int: L: {hex(int.from_bytes(header_hash_digest[::-1], 'little'))} B: {hex(int.from_bytes(header_hash_digest[::-1], 'big'))}")
        #     known_diff += 1
        #     shared_difficulty.value = known_diff
        #     target = "0" * known_diff
        #     q.put(1)

        # Fast check, if the first byte is not 0x00 then it cannot be the solution
        # This is a direct memory comparison for a single byte so it is quick and leads to
        # a small (~5%) increase to the hashing rate by avoiding the need to convert to hex
        if header_hash_digest[0] == 0x00:
            header_hash_hex = header_hash_digest.hex()

            # Check the hash meets the difficulty requirements
            if header_hash_hex.startswith(target):
                runtime = time.time() - start_time
                hash_rate = (nonce - start_nonce) / (runtime + 1e-8)

                if private_queue.full():
                    private_queue.get()

                # Save the state information and save the found nonce value (and the miner thread that found it)
                private_queue.put({ "hash_rate": hash_rate, "interrupt_nonce": nonce - 1, "time_remaining": time_remaining - runtime })
                queue.put({ "success": True, "idx": idx, "solution": nonce })
                print(f"idx: {idx}, Solved difficulty {difficulty} with nonce {nonce}")
                return nonce

        # Increment the nonce on failure and try again
        nonce += 1

def part_3_a(blockchain: Blockchain, miner: BlockchainIdentity):
    # Task 3a: Generate the genesis block with the required attributes
    # This actually finds the nonce as the genesis block should be mined
    genesis = blockchain.create_unmined_block(miner, [])
    print("Created genesis block, mining started...")
    single_threaded_block_miner(genesis, verbose=True)
    genesis_appended = blockchain.append_mined_block(genesis)
    print("Mined block 0 (genesis) appended:", genesis_appended)
    print()
    print(f"Genesis Block (Block ID: {blockchain.blocks[0].header_hash}):")
    print(blockchain.blocks[0])

def part_3_b(blockchain: Blockchain, miner: BlockchainIdentity, participant_identities: Dict[str, BlockchainIdentity]):
    # Task 3b: Creates multiple new blocks (rather than just 1 so that we can do some more in-depth transaction tracing)
    # Adds sample transactions, links to the previous block and uses the single-threaded miner to mine the block
    # I have chosen to model a basic bread supply chain taking Wheat -> Bread from Farmer -> Manufacturer -> Wholesaler -> Retailer
    # There are multiple of each type of entity so that we can do some in-depth transaction tracing to test the blockchain capability

    # Create raw materials
    farmer_gen_block = blockchain.create_unmined_block(miner, [
        Transaction.create_new_transaction(
            participant_identities["farmer_1"], [], [Transaction.Content.TXOutput(participant_identities["farmer_1"].public_address, "wheat", 350)], "raw_material_creation"
        ),
        Transaction.create_new_transaction(
            participant_identities["farmer_2"], [], [Transaction.Content.TXOutput(participant_identities["farmer_2"].public_address, "wheat", 500)], "raw_material_creation"
        ),
        Transaction.create_new_transaction(
            participant_identities["farmer_3"], [], [Transaction.Content.TXOutput(participant_identities["farmer_3"].public_address, "wheat", 250)], "raw_material_creation"
        ),
        Transaction.create_new_transaction(
            participant_identities["farmer_4"], [], [Transaction.Content.TXOutput(participant_identities["farmer_4"].public_address, "wheat", 300)], "raw_material_creation"
        )
    ])

    # Mine and append
    single_threaded_block_miner(farmer_gen_block, verbose=True)
    appended = blockchain.append_mined_block(farmer_gen_block)
    print("Mined block 1/5, appended:", appended)

    f1_tx = blockchain.get_last_block().transactions[0]
    f2_tx = blockchain.get_last_block().transactions[1]
    f3_tx = blockchain.get_last_block().transactions[2]
    f4_tx = blockchain.get_last_block().transactions[3]

    # Transfer the wheat to the manufacturers in exchange for money
    farmer_manu_transfer_block = blockchain.create_unmined_block(miner, [
        Transaction.create_new_transaction(
            participant_identities["farmer_1"], [
                Transaction.Content.TXInput(f1_tx.txid, 0, "wheat", 350)
            ], [
                Transaction.Content.TXOutput(participant_identities["manufacturer_1"].public_address, "wheat", 250),
                Transaction.Content.TXOutput(participant_identities["farmer_1"].public_address, "wheat", 100)
            ], "material_transfer"
        ),
        Transaction.create_new_transaction(
            participant_identities["farmer_2"], [
                Transaction.Content.TXInput(f2_tx.txid, 0, "wheat", 500)
            ], [
                Transaction.Content.TXOutput(participant_identities["manufacturer_1"].public_address, "wheat", 300),
                Transaction.Content.TXOutput(participant_identities["manufacturer_2"].public_address, "wheat", 150),
                Transaction.Content.TXOutput(participant_identities["farmer_2"].public_address, "wheat", 50)
            ], "material_transfer"
        ),
        Transaction.create_new_transaction(
            participant_identities["farmer_3"], [
                Transaction.Content.TXInput(f3_tx.txid, 0, "wheat", 250)
            ], [
                Transaction.Content.TXOutput(participant_identities["manufacturer_1"].public_address, "wheat", 125),
                Transaction.Content.TXOutput(participant_identities["manufacturer_2"].public_address, "wheat", 125)
            ], "material_transfer"
        ),
        Transaction.create_new_transaction(
            participant_identities["farmer_4"], [
                Transaction.Content.TXInput(f4_tx.txid, 0, "wheat", 300)
            ], [
                Transaction.Content.TXOutput(participant_identities["manufacturer_2"].public_address, "wheat", 270),
                Transaction.Content.TXOutput(participant_identities["farmer_4"].public_address, "wheat", 30)
            ], "material_transfer"
        ),
        Transaction.create_new_transaction(
            participant_identities["manufacturer_1"], [], [
                Transaction.Content.TXOutput(participant_identities["farmer_1"].public_address, "money", 250),
                Transaction.Content.TXOutput(participant_identities["farmer_2"].public_address, "money", 300),
                Transaction.Content.TXOutput(participant_identities["farmer_3"].public_address, "money", 125)
            ],
            "financial_transfer"
        ),
        Transaction.create_new_transaction(
            participant_identities["manufacturer_2"], [], [
                Transaction.Content.TXOutput(participant_identities["farmer_2"].public_address, "money", 150),
                Transaction.Content.TXOutput(participant_identities["farmer_3"].public_address, "money", 125),
                Transaction.Content.TXOutput(participant_identities["farmer_4"].public_address, "money", 270)
            ],
            "financial_transfer"
        ),
    ])

    # Mine and append
    single_threaded_block_miner(farmer_manu_transfer_block, verbose=True)
    appended = blockchain.append_mined_block(farmer_manu_transfer_block)
    print("Mined block 2/5, appended:", appended)

    lt = blockchain.get_last_block().transactions
    man_1_wheat = [(lt[0].txid, 0), (lt[1].txid, 0), (lt[2].txid, 0)]
    man_2_wheat = [(lt[1].txid, 1), (lt[2].txid, 1), (lt[3].txid, 0)]

    # Manufacture the wheat into bread
    manu_mat_conv_block = blockchain.create_unmined_block(miner, [
        Transaction.create_new_transaction(
            participant_identities["manufacturer_1"], [
                Transaction.Content.TXInput(man_1_wheat[0][0], man_1_wheat[0][1], "wheat", 250),
                Transaction.Content.TXInput(man_1_wheat[1][0], man_1_wheat[1][1], "wheat", 300)
            ], [
                Transaction.Content.TXOutput(participant_identities["manufacturer_1"].public_address, "bread", 55)
            ],
            "material_conversion"
        ),
        Transaction.create_new_transaction(
            participant_identities["manufacturer_1"], [
                Transaction.Content.TXInput(man_1_wheat[2][0], man_1_wheat[2][1], "wheat", 125),
            ], [
                Transaction.Content.TXOutput(participant_identities["manufacturer_1"].public_address, "bread", 12),
                Transaction.Content.TXOutput(participant_identities["manufacturer_1"].public_address, "wheat", 5)
            ],
            "material_conversion"
        ),
        Transaction.create_new_transaction(
            participant_identities["manufacturer_2"], [
                Transaction.Content.TXInput(man_2_wheat[0][0], man_2_wheat[0][1], "wheat", 150),
                Transaction.Content.TXInput(man_2_wheat[1][0], man_2_wheat[1][1], "wheat", 125)
            ], [
                Transaction.Content.TXOutput(participant_identities["manufacturer_2"].public_address, "bread", 37),
                Transaction.Content.TXOutput(participant_identities["manufacturer_2"].public_address, "wheat", 5)
            ],
            "material_conversion"
        ),
        Transaction.create_new_transaction(
            participant_identities["manufacturer_2"], [
                Transaction.Content.TXInput(man_2_wheat[2][0], man_2_wheat[2][1], "wheat", 270),
            ], [
                Transaction.Content.TXOutput(participant_identities["manufacturer_2"].public_address, "bread", 27),
            ],
            "material_conversion"
        ),
    ])

    # Mine and append
    single_threaded_block_miner(manu_mat_conv_block, verbose=True)
    appended = blockchain.append_mined_block(manu_mat_conv_block)
    print("Mined block 3/5, appended:", appended)

    lt = blockchain.get_last_block().transactions
    man_1_bread = [(lt[0].txid, 0), (lt[1].txid, 0)]
    man_2_bread = [(lt[2].txid, 0), (lt[3].txid, 0)]

    # Transfer the bread to the wholesalers in exchange for money
    manu_wholesaler_transfer_block = blockchain.create_unmined_block(miner, [
        Transaction.create_new_transaction(
            participant_identities["manufacturer_1"], [ 
                Transaction.Content.TXInput(man_1_bread[0][0], man_1_bread[0][1], "bread", 55),
                Transaction.Content.TXInput(man_1_bread[1][0], man_1_bread[1][1], "bread", 12)
            ],
            [
                Transaction.Content.TXOutput(participant_identities["wholesaler_1"].public_address, "bread", 40),
                Transaction.Content.TXOutput(participant_identities["wholesaler_2"].public_address, "bread", 27),
            ],
            "material_transfer"
        ),
        Transaction.create_new_transaction(
            participant_identities["manufacturer_2"], [ 
                Transaction.Content.TXInput(man_2_bread[0][0], man_2_bread[0][1], "bread", 37),
                Transaction.Content.TXInput(man_2_bread[1][0], man_2_bread[1][1], "bread", 27)
            ],
            [
                Transaction.Content.TXOutput(participant_identities["wholesaler_2"].public_address, "bread", 32),
                Transaction.Content.TXOutput(participant_identities["wholesaler_3"].public_address, "bread", 32)
            ],
            "material_transfer"
        ),
        Transaction.create_new_transaction(
            participant_identities["wholesaler_1"], [], [
                Transaction.Content.TXOutput(participant_identities["manufacturer_1"].public_address, "money", 5000)
            ],
            "financial_transfer"
        ),
        Transaction.create_new_transaction(
            participant_identities["wholesaler_2"], [], [
                Transaction.Content.TXOutput(participant_identities["manufacturer_1"].public_address, "money", 3375),
                Transaction.Content.TXOutput(participant_identities["manufacturer_2"].public_address, "money", 4000)
            ],
            "financial_transfer"
        ),
        Transaction.create_new_transaction(
            participant_identities["wholesaler_3"], [], [
                Transaction.Content.TXOutput(participant_identities["manufacturer_2"].public_address, "money", 4000)
            ],
            "financial_transfer"
        )
    ])

    # Mine and append
    single_threaded_block_miner(manu_wholesaler_transfer_block, verbose=True)
    appended = blockchain.append_mined_block(manu_wholesaler_transfer_block)
    print("Mined block 4/5, appended:", appended)

    lt = blockchain.get_last_block().transactions
    ws_1_bread = [(lt[0].txid, 0)]
    ws_2_bread = [(lt[0].txid, 1), (lt[1].txid, 0)]
    ws_3_bread = [(lt[1].txid, 1)]

    # Transfer the bread to the retailers in exchange for money
    wholesaler_retailer_transfer_block = blockchain.create_unmined_block(miner, [
        Transaction.create_new_transaction(
            participant_identities["wholesaler_1"], [ 
                Transaction.Content.TXInput(ws_1_bread[0][0], ws_1_bread[0][1], "bread", 40),
            ],
            [
                Transaction.Content.TXOutput(participant_identities["retailer_1"].public_address, "bread", 25),
                Transaction.Content.TXOutput(participant_identities["retailer_2"].public_address, "bread", 15),
            ],
            "material_transfer"
        ),
        Transaction.create_new_transaction(
            participant_identities["wholesaler_2"], [ 
                Transaction.Content.TXInput(ws_2_bread[0][0], ws_2_bread[0][1], "bread", 27),
                Transaction.Content.TXInput(ws_2_bread[1][0], ws_2_bread[1][1], "bread", 32)
            ],
            [
                Transaction.Content.TXOutput(participant_identities["retailer_2"].public_address, "bread", 15),
                Transaction.Content.TXOutput(participant_identities["retailer_3"].public_address, "bread", 30),
                Transaction.Content.TXOutput(participant_identities["retailer_4"].public_address, "bread", 14),
            ],
            "material_transfer"
        ),
        Transaction.create_new_transaction(
            participant_identities["wholesaler_3"], [ 
                Transaction.Content.TXInput(ws_3_bread[0][0], ws_3_bread[0][1], "bread", 32),
            ],
            [
                Transaction.Content.TXOutput(participant_identities["retailer_4"].public_address, "bread", 16),
                Transaction.Content.TXOutput(participant_identities["retailer_5"].public_address, "bread", 16),
            ],
            "material_transfer"
        ),
        Transaction.create_new_transaction(
            participant_identities["retailer_1"], [], [
                Transaction.Content.TXOutput(participant_identities["wholesaler_1"].public_address, "money", 4375)
            ],
            "financial_transfer"
        ),
        Transaction.create_new_transaction(
            participant_identities["retailer_2"], [], [
                Transaction.Content.TXOutput(participant_identities["wholesaler_1"].public_address, "money", 2625),
                Transaction.Content.TXOutput(participant_identities["wholesaler_2"].public_address, "money", 2625)
            ],
            "financial_transfer"
        ),
        Transaction.create_new_transaction(
            participant_identities["retailer_3"], [], [
                Transaction.Content.TXOutput(participant_identities["wholesaler_2"].public_address, "money", 5250)
            ],
            "financial_transfer"
        ),
        Transaction.create_new_transaction(
            participant_identities["retailer_4"], [], [
                Transaction.Content.TXOutput(participant_identities["wholesaler_2"].public_address, "money", 2450),
                Transaction.Content.TXOutput(participant_identities["wholesaler_3"].public_address, "money", 2800)
            ],
            "financial_transfer"
        ),
        Transaction.create_new_transaction(
            participant_identities["retailer_5"], [], [
                Transaction.Content.TXOutput(participant_identities["wholesaler_3"].public_address, "money", 2800)
            ],
            "financial_transfer"
        )
    ])

    # Mine and append
    single_threaded_block_miner(wholesaler_retailer_transfer_block, verbose=True)
    appended = blockchain.append_mined_block(wholesaler_retailer_transfer_block)
    print("Mined block 5/5, appended:", appended)

def visualise_tx(txid, block_hash, idx, address, resource, quantity, timestamp, tx_type, lookup):
    # Visualise an individual transaction 
    shortened_txid = f"{txid[:4]}...{txid[-4:]}[{idx}]"
    shortened_address = f"{address[:4]}...{address[-4:]}"

    # Details about the transaction
    lines = [
        "",
        f"{shortened_txid}",
        "",
        f"block: {block_hash[:4]}...{block_hash[-4:]}",
        f"ts: {timestamp}",
        f"type: {tx_type}",
        f"address: {shortened_address}",
        f"owner: {lookup[address]}",
        f"resource: {resource}",
        f"quantity: {quantity}",
        ""
    ]

    # Convert to a nice string for visualisation
    max_len = max(max([len(x) for x in lines]) + 2, 29)
    out = ""
    sep = "-" * (max_len + 2) + "\n"

    for line in lines:
        if line == "":
            out += sep
            continue

        padded = f" {line} "

        while len(padded) != max_len:
            padded = f"{padded} "

        out += f"|{padded}|\n"

    return out

def _rec_vis(traceback, lookup):
    # End of the recursion
    if type(traceback) == str:
        return None
    
    # Visualise the transaction
    into_self = []
    self_block = visualise_tx(
        traceback["txid"], 
        traceback["block_hash"],
        traceback["relevant_output"]["idx"], 
        traceback["relevant_output"]["receiver"], 
        traceback["relevant_output"]["resource"], 
        traceback["relevant_output"]["quantity"], 
        traceback["tx_timestamp"], 
        traceback["type"], 
        lookup
    )

    # Find the next transactions to visualise in the traceback
    for deeper_traceback in traceback["traceback"]:
        res = rec_vis(deeper_traceback, lookup)

        if res == None:
            continue

        into_self.append(res)

    if len(into_self) == 0:
        return self_block

    # This code visualises the connections between the transaction
    # It is just string manipulation
    out = []

    for i, block in enumerate(into_self):
        if i == 0:
            self_split = self_block.split("\n")

            for j, line in enumerate(block.split("\n")):
                if j < len(self_split):
                    if j == 5:
                        rejigged_line = line + " ----> " + self_split[j] 
                    else:
                        rejigged_line = line + " " * 7 + self_split[j] 

                    out.append(rejigged_line)
                else:
                    out.append(line)
                
                if j != len(block.split("\n")) - 1:
                    out.append("\n")
        else:
            for j, line in enumerate(block.split("\n")):
                if j == 0:
                    pos = len(line) + 3
                    new_out = []
                    go = False

                    for q in out:
                        pad = q

                        if pad != "\n":
                            if len(pad) < pos:
                                while len(pad) < pos:
                                    pad += " "
                                
                                pad += "|"
                            else:
                                if not go:
                                    go = pad[pos] == "-"
                                else:
                                    pad = pad[:pos] + "|" + pad[pos + 1:]

                        new_out.append(pad)

                    out = new_out

                out += line

                if j == 5:
                    out.append(" ---")
                
                if j < 5:
                    out.append("   |")

                if j != len(block.split("\n")) - 1:
                    out.append("\n")
        
        if i != len(into_self) - 1:
            out.append("\n")
    
    # Return the concatenated transaction traceback visulation
    return "".join(out)

def rec_vis(traceback, lookup):
    # Visualise the traceback and its connections to previous transactions
    blocks = _rec_vis(traceback, lookup)
    return blocks

def part_4(blockchain: Blockchain, miners: List[BlockchainIdentity], max_difficulty: int = 10):
    # Part 4: Implements Proof-of-Work
    # Can use either a single threaded of multi threaded approach
    # Note: wasn't sure if multi-threaded was allowed but to disable it just specify a single miner in the list
    # it will then fallback to using a single thread without the multiprocessing import!

    max_duration = 3600 # 1 hour in seconds
    results = {}

    # Single-threaded mining
    if len(miners) == 1:
        miner = miners[0]
        # Difficulty is irrelevant this is only used for testing the mining
        # Best to use the same base string for hashing to ensure it is a fair test
        test_block = blockchain.create_unmined_block(miner, [], 1)

        try:
            # Incrementally try the difficulty
            for difficulty in range(1, max_difficulty + 1):
                print(f"Starting difficulty {difficulty}")
                target = "0" * difficulty
                nonce = 0
                success = False

                start_time = time.time()

                # See {single_threaded_block_miner} for more information
                prehashed = hashlib.sha256(test_block.get_malleable_mining_str().encode())

                while True:
                    header_hash = prehashed.copy()
                    nonce_str = nonce.__str__() + "}"

                    header_hash.update(nonce_str.encode())
                    header_hash_digest = hashlib.sha256(header_hash.digest()).digest()

                    if nonce != 0 and nonce % 1000000 == 0:
                        current_time = time.time()
                        print(f"Nonce: {nonce}, hashes/second: {nonce / (current_time - start_time)} hashes/s")

                        # Halt if it has been more than hour
                        if current_time - start_time > max_duration:
                            break
                    
                    # Check it meets the difficulty
                    if header_hash_digest[0] == 0x00:
                        header_hash_hex = header_hash_digest.hex()
                        if header_hash_hex.startswith(target):
                            success = True
                            break

                    nonce += 1

                end_time = time.time()
                delta_time = end_time - start_time

                print(f"Mining completed at difficulty {difficulty} in {delta_time}s")

                if success:
                    print(f"Solution nonce: {nonce}")
                else:
                    print("Failed to find the solution hash in the allocated time")
                
                hash_rate = nonce / (delta_time + 1e-8)
                print(f"Final hash rate: {hash_rate} hashes/s")
                print()

                # Log the results
                results[difficulty] = {
                    "success": success,
                    "hash_rate": hash_rate,
                    "nonce": nonce if success else -1,
                    "delta_time": delta_time
                }
        except KeyboardInterrupt:
            print("Halted")
    else:
        # Multi-threaded mining, recommended that len(miners) = #cores on CPU
        miner_blocks = [blockchain.create_unmined_block(miner, [], 1) for miner in miners]

        # State information so we don't have to start from 0 every time
        # but still able to respect the time limits
        # Important to avoid damaging the CPU by running too hot for too long!
        interrupt_nonces = [0 for _ in range(len(miners))]
        time_remaining_arr = [3600 for _ in range(len(miners))]
        cum_time = 0

        try:
            for difficulty in range(1, max_difficulty + 1):
                processes = []
                private_queues = []
                halting_queue = multiprocessing.Queue(maxsize=1)

                # Prepare each thread
                # Each miner has their own block string for mining that is used over each difficulty for a fair test
                for idx, miner in enumerate(miners):
                    private_queue = multiprocessing.Queue(maxsize=1)
                    process = multiprocessing.Process(
                        target=multi_threaded_miner_target,
                        args=(idx, miner_blocks[idx].get_malleable_mining_str(), difficulty, halting_queue, private_queue, interrupt_nonces[idx], time_remaining_arr[idx])
                    )
                    processes.append(process)
                    private_queues.append(private_queue)
                
                # Time the process
                start_time = time.time()

                # Get thr 
                for process in processes:
                    process.start()

                # Wait for one of the miners to either reach the time limit or find the solution nonce
                result = halting_queue.get()
                # Account for time spent in the previous difficulties
                delta_time = cum_time + time.time() - start_time
                cum_time = delta_time

                # Stop the other mining threads
                for process in processes:
                    process.terminate()

                hash_rate_sum = 0
                real_count = 0

                # Update state information for the restart
                for i, private_queue in enumerate(private_queues):
                    if private_queue.empty():
                        continue

                    state_dict = private_queue.get()

                    hash_rate_sum += state_dict["hash_rate"]
                    interrupt_nonces[i] = state_dict["interrupt_nonce"]
                    time_remaining_arr[i] = state_dict["time_remaining"]
                    real_count += 1

                # Measure hash rates
                avg_hash_rate = hash_rate_sum / len(miners)
                success = result["success"]

                print(f"Difficulty {difficulty}")
                print(f"Overall Hash Rate: {hash_rate_sum} hashes/s")
                print(f"Avg. Hash Rate per Miner: {avg_hash_rate} hashes/s")
                print(f"Took {delta_time}s (cum: {cum_time})")
                print(json.dumps(result))
                print()

                # Log results
                results[difficulty] = {
                    "success": success,
                    "hash_rate": hash_rate_sum,
                    "per_hash_rate": avg_hash_rate,
                    "nonce": result["solution"] if success else -1,
                    "miner_idx": result["idx"] if success else -1,
                    "delta_time": delta_time,
                    "interrupt_nonces": [x for x in interrupt_nonces]
                }
        except KeyboardInterrupt:
            pass
    
    # Save the results for analysis
    with open(f"hashing_result_{time.time()}.json", "w+") as fp:
        json.dump({
            "miner_count": len(miners),
            "results": results
        }, fp, indent=2)

    print("Complete")

def part_5(blockchain: Blockchain, participant_identities: Dict[str, BlockchainIdentity], participant_lookup: Dict[str, str]):
    continue_task_5 = True

    while continue_task_5:
        print()
        print("Please set the attributes you wish to search by:")
        print("You must set at least one attribute, if you do not wish to set it just press Enter to skip it!")
        print()

        start_time_str = input("Start time (Unix Timestamp): ")
        start_time = 0

        try:
            temp_st = float(start_time_str)
            start_time = temp_st
        except ValueError:
            pass

        end_time_str = input("End time (Unix Timestamp): ")
        end_time = time.time()

        try:
            temp_et = float(end_time_str)
            end_time = temp_et
        except ValueError:
            pass

        resources = []
        valid_resources = ["wheat", "bread", "money"]
        print("Valid options: wheat, bread, money")
        print("Input them as a comma separated string e.g. 'bread, wheat' without the quotes")
        resources_inp = input("Resources: ")

        if resources_inp.strip() != "":
            for resource in resources_inp.split(","):
                cleaned_resource = resource.lower().strip()

                if cleaned_resource not in valid_resources:
                    print(f"Skipped {resource} invalid resource {cleaned_resource}")
                    continue
                    
                if cleaned_resource in resources:
                    print(f"Skipped {cleaned_resource}, already in list")
                    continue
            
                resources.append(cleaned_resource)

        print("For transaction IDs, enter them as a comma separated string with each entry as txid:idx")
        print("e.g. 62a984c6beb84bf5ab4e9435f4f1208c798c5329c641a6975518374b836aa5dc:0, 37bbd61fb840816334373fca86ba0c8b77e10db8c6f0c4210cee2b4f8b3b3567:0")
        txiws_inp = input("IDs: ")
        txids: List[Tuple[str, int]] = []

        if txiws_inp.strip() != "":
            for txiw in txiws_inp.split(","):
                cleaned_txiw = txiw.lower().strip()
                split = cleaned_txiw.split(":")

                if len(split) != 2:
                    print(f"Skipped {txiw} as it does not contain exactly one colon")
                    continue

                txid, idx = split[0], split[1]

                try:
                    int(idx)
                except ValueError:
                    print(f"Skipped {txiw} as the index is not an integer")
                    continue

                txids.append((txid, int(idx)))

        tx_types = []
        print(f"Valid options: {', '.join(transaction_types)}")
        print("Input them as a comma separated string e.g. 'coinbase, material_transfer' without the quotes")
        tx_types_inp = input("Transaction Types: ")

        if tx_types_inp.strip() != "":
            for tx_type in tx_types_inp.split(","):
                cleaned_tx_type = tx_type.lower().strip()

                if cleaned_tx_type not in transaction_types:
                    print(f"Skipped {tx_type} invalid resource {cleaned_tx_type}")
                    continue
                    
                if cleaned_tx_type in tx_types:
                    print(f"Skipped {cleaned_tx_type}, already in list")
                    continue
            
                tx_types.append(cleaned_tx_type)

        list_identities = input("Do you want to see a list of possible public addresses? (y/n) ")

        if list_identities.strip().lower().startswith("y"): 
            print()

            for name, identity in participant_identities.items():
                print(f"{name}: {identity.public_address}")

            print()
        
        print("For public addresses, enter them as a comma separated string")
        print("e.g. 1C2yiq3HAfBvZhWrGh3cF6MXprACpDDZeq, 1B4daVXZPWW8NMzag6F4uS2L8hcSKivy4A")

        address_str = input("Public addresses: ")
        participants = [address.strip() for address in address_str.split(",")] if address_str.strip() != "" else []

        print("Search Criteria Attributes:")
        print("Start Time:", start_time)
        print("End Time", end_time)
        print("Resources:", resources)
        print("Transactions:", txids)
        print("Transaction Types:", tx_types)
        print("Public Addresses:", participants)

        print()
        print("Searching...")

        traces = {}
        trace_start_time = time.time()

        try:
            traces = blockchain.trace_transactions_by_attributes(
                start_time,
                end_time,
                resources,
                txids,
                tx_types,
                participants
            )
        except BlockchainTracebackException as e:
            print()
            print(f"***An issue occurred while searching, check your attribute input: {e}***")
            print()

        delta_time = time.time() - trace_start_time

        print(f"Found {len(traces)} transactions matching the criteria, search took {delta_time}s")

        want_vis = input("Do you want to visualise the traces and the transaction relationships? (y/n) ")

        if want_vis.lower().strip().startswith("y"):
            for (txid, idx) in traces.keys():
                print()
                print(f"Found transaction {txid}[{idx}] matching criteria")
                dict_trace = json.loads(json.dumps(traces[(txid, idx)], default=lambda x: getattr(x, "__dict__", str)))
                vis_trace = rec_vis(dict_trace, participant_lookup)
                print(vis_trace)

        print()
        continue_task_5 = input("Do you want to perform another trace with different criteria? (y/n) ").lower().strip().startswith("y")

def prepare_blockchain(difficulty: int = 5):
    # A bunch of identities generated using Part 2
    participant_identities = {
        "miner_1": BlockchainIdentity("1J5txDKRWLtHCc4ppFKYLEkWicAy5PtZ6S", "Kwc4dJTvEeFMMg3fHwuE1ZujDPckztiFGKespwoPKN3qx2wm8wFT"),
        "miner_2": BlockchainIdentity("1Ngr135S5Y5S8fN5netTNVwLfaXG1yMDW9", "L3XqqsYsC5EysNBX4qrF67WYzb1hGpTG59cRjNDo4uU4LnHPFErK"),

        "farmer_1": BlockchainIdentity("1GTpnkyNdR8foqbdfgv8JkWxMgvDNRGxHV", "KyYAA6BXCkW1H2ZxL9UgpdsL7Y8RZNRmr25xGirR7YbqHsXCPgL1"),
        "farmer_2": BlockchainIdentity("1Gq7q7CjhFLLJVsFKV72rbNJQNZ3TCtXd2", "L1ABw5f7tbAmxaL2vzKF8qMwPFEJszkLYJzLyxekccJjJrmQ4La9"),
        "farmer_3": BlockchainIdentity("19mGEKM611fHFnztN8BmVRRjyhSAfGf4aP", "L4Mv6qu6kguwpf8WyMpoifgqYt6BsDiD1esYQqfVLszfaSeYSJt9"),
        "farmer_4": BlockchainIdentity("1K81wn79X6r495N2PcEMDdujAcxKF5JVYT", "L1K5kYNinu19PQhh2bGm31nJs6ahz5HCsD4HSiMzxTiRyG7LrEDD"),

        "manufacturer_1": BlockchainIdentity("1G6zJsQy7WxpySxjovkidSb8aaZsMaTqaC", "KyMgXMMeMPvDtbpEcC4qxZ4e9NMFcCCYB1HwUkj3mXZJXzYuoLBE"),
        "manufacturer_2": BlockchainIdentity("13jHFqxxn3MnXAR1Drv5DgG24ZvQwbXtxt", "KxPGZWDRJhFg676SRfKAA2EzqiLXUDrzRz3F8HYzMzn62sAv8k4X"),

        "wholesaler_1": BlockchainIdentity("1MRHcvxBaqiiAVYCGG8F2Dom4xoRnutLGZ", "KzGwaUyL3wTm7DrhVSNBLZgYczAH8R5kX6yicycN4B6zcaGbQLKK"),
        "wholesaler_2": BlockchainIdentity("1LBQ8jjfnpAJ6tck9pcMf2QMbEhL5nqVqR", "KycvKsfWXbAkY3GGjxYyFPakEu3V7FFa3NFWnHg7xF9SwVLzbxyK"),
        "wholesaler_3": BlockchainIdentity("1682GahbBriPZdGQ4DYgU29TV3Ff6zvTgr", "L5mkSj2rKhpnbEGKAxLfzRRaML7vXqpj87s6A6XeZnksGJhyiVAW"),

        "retailer_1": BlockchainIdentity("1C2yiq3HAfBvZhWrGh3cF6MXprACpDDZeq", "Kzvx8dh3XhyfHheW69gya4gK2y6bSn1WjVZX6vurbaszLw1EstV8"),
        "retailer_2": BlockchainIdentity("1LAMSiaEdox8ZcPtWdN5dN6CELKf116tkR", "L5YPZCEVrJdEwDqR1NUG6F8HKg6r5nSGMCNGiSvywYZcKgT6We2c"),
        "retailer_3": BlockchainIdentity("14g8cTU97W9gWkRzKS3gYuuMja11mKJDQY", "Kzttkaav8BUMo8Evim6GTUvyZZuQeWstX2LodLeqm3GjPbdhvNNK"),
        "retailer_4": BlockchainIdentity("1B4daVXZPWW8NMzag6F4uS2L8hcSKivy4A", "KyDccbXQAgtmKuueAW8KMpXsH5K3bsmxrZYgMCQUpQRRCjtWS5Va"),
        "retailer_5": BlockchainIdentity("1LW2uNLuRjRW14qg855NHNHudnnu4aPk4Z", "L471B8sYTpvroueVyCCT5dKBZgLxyEUsEnbNHf1LmShSak3kcog2")
    }

    # Associate each public address with a name for visualisation
    # In reality we wouldn't know all of these!
    participant_lookup = {iden.public_address: key for key, iden in participant_identities.items()}

    # For all except Part 4, just use a single miner for simplicity
    # Part 4 supports multi-threaded mining
    blockchain = Blockchain(difficulty=difficulty)
    primary_miner = participant_identities["miner_1"]

    return participant_identities, participant_lookup, blockchain, primary_miner

def main(difficulty: int = 5):
    # This function is not essential but it provides a basic CLI to interact with the relevant tasks
    # and proves that the blockchain code works as intended

    participant_identities, participant_lookup, blockchain, primary_miner = prepare_blockchain(difficulty)

    print("Blockchain and Cryptocurrency Coursework by chpf93")
    print("This code covers Task 3, Task 4, and Task 5. Task 1 and 2 are in the write up and Task 6 is in the .sol file instead")

    print()
    print('Prior to running this, please create a virtual environment and run "pip install -r requirements.txt"')
    print("This code has been tested on Python 3.10.7 on a Windows 10 64-bit computer")
    print()

    print("For my example transactions, I have modelled a simplified supply chain producing bread")
    print(f"Identities: {len(participant_identities)}, Difficulty: {blockchain.difficulty}")
    print()
    print("Task 3: Blockchain Tasks")
    print("Task 3(a): Generation of Genesis Block")
    _ = input("Press Enter to run the Task 3(a) code")

    part_3_a(blockchain, primary_miner)
    print()
    
    print("Task 3(b): Additional Block Creation")
    print("This will add multiple new blocks with a number of transactions")
    print("I have added additional blocks for use in the tracing task [Task 5]")
    _ = input("Press Enter to run the Task 3(b) code")

    part_3_b(blockchain, primary_miner, participant_identities)
    print()

    show_chain_3b = input("Do you want to output the blockchain? (y/n) ")
    show_chain_3b = show_chain_3b.lower().strip()
    print(f"Received input '{show_chain_3b}'")

    if show_chain_3b.startswith("y"):
        print("Showing blockchain starting with genesis block:")
        print(blockchain)
    else:
        print("Opted not to show the blockchain")
    
    show_wallets_3b = input("Do you want to output the wallets of each identity? (y/n) ")
    show_wallets_3b = show_wallets_3b.lower().strip()
    print(f"Received input '{show_wallets_3b}'")

    if show_wallets_3b.startswith("y"):
        print("Showing wallets:")

        for name, identity in participant_identities.items():
            print(name)
            print(json.dumps(blockchain.get_wallet(identity), indent=2))
    else:
        print("Opted not to show the wallets")

    print()

    print("Task 4: Mining Tasks")
    print("4(a) implements Proof-of-Work with increasing difficulty")
    print("4(b) and 4(c) analysis is in the write up")
    print("You can optionally skip the mining test and move on to tracing instead as this takes a while!")

    run_task_4 = input("Do you want to run Task 4(a), it will take up to an hour? (y/n) ")
    run_task_4 = run_task_4.lower().strip()
    print(f"Received input '{run_task_4}'")

    if run_task_4.startswith("y"):
        task_4_miners = None

        while task_4_miners is None:
            temp = None

            try:
                temp = int(input("How many miners do you wish to use? (1 miner per core is optimal, up to 16): "))
            except ValueError:
                print("Must enter a number")
                continue

            if temp < 1 or temp > 16:
                print("Must enter a number >= 1 and <= 16")
                continue

            task_4_miners = temp
        
        print(f"Using {task_4_miners} miner(s) (multi-threaded: {task_4_miners > 1})")
        selected_miners = list(participant_identities.values())[:task_4_miners]
        print("Starting mining...")
        print()

        part_4(blockchain, selected_miners, max_difficulty=10)
        print("Task 4(a) completed")
    else:
        print("Opted not to run the mining task")

    print()

    print("Task 5: Traceback and Verification Tasks")
    print("This combines 5(a) and 5(b) by verifying ownership of the transactions during tracing (see line 771 of blockchain.py)")
    part_5(blockchain, participant_identities, participant_lookup)

    print("That's all, exiting... :)")

if __name__ == "__main__":
    main(difficulty=5)