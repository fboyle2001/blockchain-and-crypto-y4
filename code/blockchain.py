from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass

import hashlib
import ecdsa
import json
import datetime
import base58
import multiprocessing
import time

assert "sha256" in hashlib.algorithms_available, "SHA256 is required but it is unavailable on your system"
assert "ripemd160" in hashlib.algorithms_available , "RIPEMD160 is required but it is unavailable on your system"

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
        **This does not validate the inp and out, this is the responsibilty of the miner and the consensus!**
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

    def get_malleable_mining_str(self) -> str:
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

class BlockchainTracebackException(Exception):
    pass

class Blockchain:
    def __init__(self, difficulty: int, coinbase_reward: int = 100):
        self.blocks: List[Block] = []
        self.difficulty = difficulty
        self.utxos: Dict[str, Dict[int, Transaction.Content.TXOutput]] = {}
        self.coinbase_reward = coinbase_reward

    def create_unmined_block(self, miner: BlockchainIdentity, transactions: List[Transaction], difficulty: Optional[int] = None):
        previous_block_hash = "0" * 64
        difficulty = difficulty if difficulty is not None else self.difficulty

        # Link it to the previous blocks
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
            assert False
        
        if len(self) > 0 and block.header.previous_block_hash != self.get_last_block().header_hash:
            assert False

        # Check the cryptographic integrity of the block and its transactions
        if not block.validate_integrity():
            assert False

        # Check the validity of the spending, i.e. no double spends and only UTXOs used
        outputs = {}
        spent_txids_with_idx = []

        for tx in block.transactions:
            if len(tx.content.inp) == 0 and len(tx.content.out) == 0:
                assert False

            if tx.content.tx_type == "raw_material_creation":
                # No way to check legitimacy 
                if len(tx.content.inp) != 0:
                    assert False

                if len(tx.content.out) != 1:
                    assert False
                
                if tx.content.out[0].quantity <= 0:
                    assert False

            elif tx.content.tx_type == "financial_transfer":
                # No way to check legitimacy so can't enforce that money exists on the chain
                if len(tx.content.inp) != 0:
                    assert False

                if len(tx.content.out) < 1:
                    assert False
                
                for out in tx.content.out:
                    if out.quantity <= 0:
                        assert False

                    if out.resource != "money":
                        assert False

            elif tx.content.tx_type == "coinbase":
                # No way to check legitimacy 
                if len(tx.content.inp) != 0:
                    assert False
                
                # No way to check legitimacy 
                if len(tx.content.out) != 1:
                    assert False

                if tx.header.hashed_sender_public_key != tx.content.out[0].receiver:
                    assert False

                if tx.content.out[0].quantity != self.coinbase_reward:
                    assert False

            elif tx.content.tx_type == "material_conversion":
                if len(tx.content.inp) < 1:
                    assert False

                if len(tx.content.out) < 1:
                    assert False

                # Check that the inputs are UTXO transactions
                in_total = 0

                for inp in tx.content.inp:
                    in_total += inp.quantity

                    txid_with_idx = f"{inp.txid}-{inp.txid_idx}"

                    # Prevent double spend
                    if txid_with_idx in spent_txids_with_idx:
                        assert False
                    
                    # Can only spend UTXOs
                    if inp.txid not in self.utxos:
                        assert False

                    if inp.txid_idx not in self.utxos[inp.txid]:
                        assert False

                    # Can't spend someone elses UTXOs!
                    if self.utxos[inp.txid][inp.txid_idx].receiver != tx.header.hashed_sender_public_key:
                        assert False
                    
                    spent_txids_with_idx.append(txid_with_idx)

                # We force that the amount in >= amount out of the new resource
                # May be unrealistic in reality?
                # Conversions only allow transformation of resources to self
                out_total = 0

                for out in tx.content.out:
                    if out.receiver != tx.header.hashed_sender_public_key:
                        assert False
                    
                    out_total += out.quantity

                if out_total > in_total:
                    assert False

            elif tx.content.tx_type == "material_transfer":
                if len(tx.content.inp) < 1:
                    assert False

                if len(tx.content.out) < 1:
                    assert False

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
                        assert False
                    
                    # Can only spend UTXOs
                    if inp.txid not in self.utxos:
                        assert False

                    if inp.txid_idx not in self.utxos[inp.txid]:
                        assert False

                    expected_utxo = self.utxos[inp.txid][inp.txid_idx]

                    if inp.resource != expected_utxo.resource:
                        assert False

                    if inp.quantity != expected_utxo.quantity:
                        assert False

                    # Can't spend someone elses UTXOs!
                    if expected_utxo.receiver != tx.header.hashed_sender_public_key:
                        assert False

                    spent_txids_with_idx.append(txid_with_idx)

                    if inp.resource not in in_totals.keys():
                        in_totals[inp.resource] = 0
                    
                    in_totals[inp.resource] += inp.quantity

                if out_totals.keys() != in_totals.keys():
                    assert False
                
                for resource in out_totals.keys():
                    if out_totals[resource] != in_totals[resource]:
                        assert False
                    
            else:
                assert False

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

    def trace_transaction(self, txid: str, idx: int, start_block: Optional[int] = None):
        start_block = start_block if start_block is not None else len(self.blocks)
        details = {}

        # Traverse backwards
        for i, block in enumerate(self.blocks[:start_block][::-1]):
            real_block_idx = start_block - i

            for tx in block.transactions:
                # Found the transaction we were searching for
                if tx.txid == txid:
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
                            # Recursively continue the search
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
        non_zeros = (start_time is not None) + (end_time is not None) + (products is not None) + (txids is not None) + (tx_types is not None) + (participants is not None)

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
                if not block.is_mined():
                    raise BlockchainTracebackException(f"Block {block.header_hash} has not been mined")
                
                # Just for type checking
                assert block.header_hash is not None

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
                    
                    transaction.content.tx_type

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

def non_multi_threaded_block_miner(block: Block, verbose: bool = False):
    malleable = block.get_malleable_mining_str()
    req = "0" * block.header.difficulty
    
    nonce = 0
    chk_time = time.time()
    start_time = time.time()

    while True:
        testable = malleable + str(nonce) + "}"
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
    genesis_appended = blockchain.append_mined_block(genesis)
    print("Mined block 0 (genesis) appended:", genesis_appended)

def part_3_b(blockchain: Blockchain, miner: BlockchainIdentity, participant_identities: Dict[str, BlockchainIdentity]):
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

    non_multi_threaded_block_miner(farmer_gen_block, verbose=True)
    appended = blockchain.append_mined_block(farmer_gen_block)
    print("Mined block 1, appended:", appended)

    f1_tx = blockchain.get_last_block().transactions[0]
    f2_tx = blockchain.get_last_block().transactions[1]
    f3_tx = blockchain.get_last_block().transactions[2]
    f4_tx = blockchain.get_last_block().transactions[3]

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

    non_multi_threaded_block_miner(farmer_manu_transfer_block, verbose=True)
    appended = blockchain.append_mined_block(farmer_manu_transfer_block)
    print("Mined block 2, appended:", appended)

    lt = blockchain.get_last_block().transactions
    man_1_wheat = [(lt[0].txid, 0), (lt[1].txid, 0), (lt[2].txid, 0)]
    man_2_wheat = [(lt[1].txid, 1), (lt[2].txid, 1), (lt[3].txid, 0)]

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

    non_multi_threaded_block_miner(manu_mat_conv_block, verbose=True)
    appended = blockchain.append_mined_block(manu_mat_conv_block)
    print("Mined block 3, appended:", appended)

    lt = blockchain.get_last_block().transactions
    man_1_bread = [(lt[0].txid, 0), (lt[1].txid, 0)]
    man_2_bread = [(lt[2].txid, 0), (lt[3].txid, 0)]

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

    non_multi_threaded_block_miner(manu_wholesaler_transfer_block, verbose=True)
    appended = blockchain.append_mined_block(manu_wholesaler_transfer_block)
    print("Mined block 4, appended:", appended)

    lt = blockchain.get_last_block().transactions
    ws_1_bread = [(lt[0].txid, 0)]
    ws_2_bread = [(lt[0].txid, 1), (lt[1].txid, 0)]
    ws_3_bread = [(lt[1].txid, 1)]

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

    non_multi_threaded_block_miner(wholesaler_retailer_transfer_block, verbose=True)
    appended = blockchain.append_mined_block(wholesaler_retailer_transfer_block)
    print("Mined block 5, appended:", appended)

def get_wallets(blockchain: Blockchain, identities: Dict[str, BlockchainIdentity]) -> Dict[str, Dict[str, int]]:
    wallets: Dict[str, Dict[str, int]] = {}

    for name, identity in identities.items():
        wallets[name] = blockchain.get_wallet(identity)
    
    return wallets

def visualise_tx(txid, block_hash, idx, address, resource, quantity, timestamp, tx_type, lookup):
    shortened_txid = f"{txid[:4]}...{txid[-4:]}[{idx}]"
    shortened_address = f"{address[:4]}...{address[-4:]}"

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
    if type(traceback) == str:
        return None
    
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

    for deeper_traceback in traceback["traceback"]:
        res = rec_vis(deeper_traceback, lookup)

        if res == None:
            continue

        into_self.append(res)

    if len(into_self) == 0:
        return self_block

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
    
    return "".join(out)

def rec_vis(traceback, lookup):
    blocks = _rec_vis(traceback, lookup)
    return blocks

def multi_threaded_miner_target(idx: int, malleable: str, difficulty: int, queue: multiprocessing.Queue, private_queue: multiprocessing.Queue, start_nonce: int, time_remaining: float):
    target = "0" * difficulty
    nonce = start_nonce

    print(f"{idx}: Restarting with difficulty {difficulty} with start nonce {nonce}, time remaining is {time_remaining}s")

    start_time = time.time()

    prehashed = hashlib.sha256(malleable.encode())

    while True:
        header_hash = prehashed.copy()
        nonce_str = nonce.__str__() + "}"

        header_hash.update(nonce_str.encode())
        header_hash_digest = hashlib.sha256(header_hash.digest()).digest()

        if nonce != 0 and nonce % 1000000 == 0:
            runtime = time.time() - start_time
            hash_rate = (nonce - start_nonce) / (runtime + 1e-8)

            if private_queue.full():
                private_queue.get()

            private_queue.put({ "hash_rate": hash_rate, "interrupt_nonce": nonce, "time_remaining": time_remaining - runtime })
            print(f"{idx}: Nonce: {nonce}, hashes/second: {hash_rate} hashes/s [D: {difficulty}]")

            if runtime > time_remaining:
                queue.put({ "success": False })
                return

        if header_hash_digest[0] == 0x00:
            header_hash_hex = header_hash_digest.hex()
            if header_hash_hex.startswith(target):
                runtime = time.time() - start_time
                hash_rate = (nonce - start_nonce) / (runtime + 1e-8)

                if private_queue.full():
                    private_queue.get()

                private_queue.put({ "hash_rate": hash_rate, "interrupt_nonce": nonce - 1, "time_remaining": time_remaining - runtime })
                queue.put({ "success": True, "idx": idx, "solution": nonce })
                print(f"idx: {idx}, Solved difficulty {difficulty} with nonce {nonce}")
                return nonce

        nonce += 1

def part_4(blockchain: Blockchain, miners: List[BlockchainIdentity], max_difficulty: int = 10):
    max_duration = 3600 # 1 hour in seconds
    results = {}

    if len(miners) == 1:
        miner = miners[0]
        # Difficulty is irrelevant this is only used for testing the mining
        test_block = blockchain.create_unmined_block(miner, [], 1)

        try:
            for difficulty in range(1, max_difficulty + 1):
                print(f"Starting difficulty {difficulty}")
                target = "0" * difficulty
                nonce = 0
                success = False

                start_time = time.time()

                prehashed = hashlib.sha256(test_block.get_malleable_mining_str().encode())

                while True:
                    header_hash = prehashed.copy()
                    nonce_str = nonce.__str__() + "}"

                    header_hash.update(nonce_str.encode())
                    header_hash_digest = hashlib.sha256(header_hash.digest()).digest()

                    if nonce != 0 and nonce % 1000000 == 0:
                        current_time = time.time()
                        print(f"Nonce: {nonce}, hashes/second: {nonce / (current_time - start_time)} hashes/s")

                        if current_time - start_time > max_duration:
                            break

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

                results[difficulty] = {
                    "success": success,
                    "hash_rate": hash_rate,
                    "nonce": nonce if success else -1,
                    "delta_time": delta_time
                }
        except KeyboardInterrupt:
            print("Halted")
    else:
        # multiprocess
        miner_blocks = [blockchain.create_unmined_block(miner, [], 1) for miner in miners]
        interrupt_nonces = [0 for _ in range(len(miners))]
        time_remaining_arr = [3600 for _ in range(len(miners))]
        cum_time = 0

        try:
            for difficulty in range(1, max_difficulty + 1):
                processes = []
                private_queues = []
                halting_queue = multiprocessing.Queue(maxsize=1)

                for idx, miner in enumerate(miners):
                    private_queue = multiprocessing.Queue(maxsize=1)
                    process = multiprocessing.Process(
                        target=multi_threaded_miner_target,
                        args=(idx, miner_blocks[idx].get_malleable_mining_str(), difficulty, halting_queue, private_queue, interrupt_nonces[idx], time_remaining_arr[idx])
                    )
                    processes.append(process)
                    private_queues.append(private_queue)
                
                start_time = time.time()

                for process in processes:
                    process.start()

                result = halting_queue.get()
                delta_time = cum_time + time.time() - start_time
                cum_time = delta_time

                for process in processes:
                    process.terminate()

                hash_rate_sum = 0
                real_count = 0

                for i, private_queue in enumerate(private_queues):
                    if private_queue.empty():
                        continue

                    state_dict = private_queue.get()

                    hash_rate_sum += state_dict["hash_rate"]
                    interrupt_nonces[i] = state_dict["interrupt_nonce"]
                    time_remaining_arr[i] = state_dict["time_remaining"]
                    real_count += 1

                avg_hash_rate = hash_rate_sum / len(miners)
                success = result["success"]

                print(f"Difficulty {difficulty}")
                print(f"Overall Hash Rate: {hash_rate_sum} hashes/s")
                print(f"Avg. Hash Rate: {avg_hash_rate} hashes/s")
                print(f"Took {delta_time}s (cum: {cum_time})")
                print(json.dumps(result))
                print()

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

    with open(f"hashing_result_{time.time()}.json", "w+") as fp:
        json.dump({
            "miner_count": len(miners),
            "results": results
        }, fp, indent=2)

    print("Complete")

if __name__ == "__main__":
    participant_identities = {
        "miner_1": BlockchainIdentity("1J5txDKRWLtHCc4ppFKYLEkWicAy5PtZ6S", "Kwc4dJTvEeFMMg3fHwuE1ZujDPckztiFGKespwoPKN3qx2wm8wFT"),

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

    lookup = {iden.public_address: key for key, iden in participant_identities.items()}

    blockchain = Blockchain(difficulty=1)
    miner = participant_identities["miner_1"]

    part_3_a(blockchain, miner)
    part_3_b(blockchain, miner, participant_identities)

    # print(json.dumps(get_wallets(blockchain, participant_identities | miner_identities), indent=2))
    # txid = blockchain.blocks[-1].transactions[0].txid
    # idx = 0

    # s = time.time()
    # traced = blockchain.trace_transactions_by_attributes(end_time=time.time())
    # trace_d = time.time() - s

    # s = time.time()
    # for (txid, idx) in traced.keys():
    #     print(f"Found transaction {txid}[{idx}] matching criteria")
    #     dict_trace = json.loads(json.dumps(traced[(txid, idx)], default=lambda x: getattr(x, "__dict__", str)))
    #     vis_trace = rec_vis(dict_trace, lookup)
    #     print(vis_trace)
    #     print()
    # display_d = time.time() - s

    # print(f"Tracing took {trace_d}s, displaying took {display_d}s, total matching transactions was {len(traced.keys())}")

    part_4(blockchain, list(participant_identities.values())[:8])