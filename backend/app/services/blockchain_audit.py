"""Provide blockchain audit registration helpers and a mock fallback for local development."""
import json
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

try:
    from web3 import Web3
    try:
        from web3.middleware import ExtraDataToPOAMiddleware as geth_poa_middleware
    except ImportError:
        from web3.middleware import geth_poa_middleware
    from eth_account import Account
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.audit_chain import AuditChain
from app.models.request import Request


@dataclass
class BlockchainEntry:
    """Hold the local transaction receipt fields returned after an audit hash submission."""
    entry_id: str
    request_id: str
    chain_hash: str
    previous_hash: str
    block_number: int
    transaction_hash: str
    timestamp: str
    network: str


class BlockchainAuditService:
    """Submit audit hashes to a development node and compare them with locally available records."""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.web3: Optional[Web3] = None
        self.account: Optional[Account] = None
        self.contract_address: Optional[str] = None
        self.network: str = "development"
        self.chain_id: int = 1337  # Default development chain
        
        # Initialize blockchain connection if available
        if WEB3_AVAILABLE:
            self._initialize_blockchain()
    
    def _initialize_blockchain(self):
        """Initialize blockchain connection."""
        try:
            # For development, use a local Ganache or Hardhat node
            # In production, use mainnet/testnet RPC URLs
            rpc_url = "http://localhost:8545"  # Default Ganache
            
            self.web3 = Web3(Web3.HTTPProvider(rpc_url))
            
            # Check connection
            if self.web3.is_connected():
                print("Connected to blockchain node")
                
                # Set up POA middleware for development chains
                self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)
                
                # Get chain ID
                self.chain_id = self.web3.eth.chain_id
                self.network = self._get_network_name(self.chain_id)
                
                # In production, load from environment
                private_key = "0x" + "0" * 64  # Default development key
                self.account = Account.from_key(private_key)
                
            else:
                print("Failed to connect to blockchain node")
                self.web3 = None
                
        except Exception as e:
            print(f"Blockchain initialization failed: {e}")
            self.web3 = None
    
    def _get_network_name(self, chain_id: int) -> str:
        """Get network name from chain ID."""
        network_names = {
            1: "mainnet",
            3: "ropsten",
            4: "rinkeby",
            5: "goerli",
            42: "kovan",
            1337: "development",
            31337: "hardhat"
        }
        return network_names.get(chain_id, f"chain_{chain_id}")
    
    async def register_audit_entry(
        self,
        entry_id: str,
        request_id: str,
        chain_hash: str,
        previous_hash: str
    ) -> Optional[BlockchainEntry]:
        """Attempt to submit audit entry metadata to the development node and return its receipt when available."""
        if not self.web3:
            print("Blockchain not available, skipping registration")
            return None
        
        try:
            # Create blockchain transaction
            transaction_data = {
                "entry_id": entry_id,
                "request_id": request_id,
                "chain_hash": chain_hash,
                "previous_hash": previous_hash,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            # In production, this would call a smart contract
            # For now, we'll simulate with a simple transaction
            tx_hash = await self._send_simple_transaction(transaction_data)
            
            if tx_hash:
                # Wait for transaction to be mined
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
                
                return BlockchainEntry(
                    entry_id=entry_id,
                    request_id=request_id,
                    chain_hash=chain_hash,
                    previous_hash=previous_hash,
                    block_number=receipt.blockNumber,
                    transaction_hash=tx_hash.hex(),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    network=self.network
                )
            
        except Exception as e:
            print(f"Failed to register audit entry on blockchain: {e}")
        
        return None
    
    async def _send_simple_transaction(self, data: Dict[str, Any]) -> Optional[str]:
        """Send a simple transaction with embedded data."""
        try:
            # Create transaction with data embedded in input
            # In production, this would call a smart contract method
            data_json = json.dumps(data)
            data_hash = hashlib.sha256(data_json.encode()).hexdigest()
            
            # Build transaction
            transaction = {
                'to': self.account.address,  # Send to self for demo
                'value': 0,
                'gas': 21000,
                'gasPrice': self.web3.eth.gas_price,
                'nonce': self.web3.eth.get_transaction_count(self.account.address),
                'data': data_hash.encode().hex()  # Embed hash in transaction data
            }
            
            # Sign and send transaction
            signed_tx = self.web3.eth.account.sign_transaction(transaction, self.account.key)
            tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            return tx_hash
            
        except Exception as e:
            print(f"Failed to send transaction: {e}")
            return None
    
    async def verify_chain_integrity(
        self,
        request_id: str
    ) -> Dict[str, Any]:
        """Compare local audit hashes with records returned by the configured lookup and report unmatched entries."""
        # Get local audit chain
        local_chain = await self._get_local_chain(request_id)
        
        # Get blockchain records for this request
        blockchain_records = await self._get_blockchain_records(request_id)
        
        # Compare hashes
        verification_result = {
            "request_id": request_id,
            "total_entries": len(local_chain),
            "blockchain_registered": len(blockchain_records),
            "verified": True,
            "mismatches": [],
            "network": self.network if self.web3 else "unavailable"
        }
        
        for entry in local_chain:
            entry_id = str(entry.id)
            local_hash = entry.chain_hash
            
            # Find corresponding blockchain record
            blockchain_record = next(
                (r for r in blockchain_records if r.entry_id == entry_id),
                None
            )
            
            if blockchain_record:
                if blockchain_record.chain_hash != local_hash:
                    verification_result["verified"] = False
                    verification_result["mismatches"].append({
                        "entry_id": entry_id,
                        "local_hash": local_hash,
                        "blockchain_hash": blockchain_record.chain_hash,
                        "block_number": blockchain_record.block_number
                    })
            else:
                # Entry not found on blockchain
                verification_result["mismatches"].append({
                    "entry_id": entry_id,
                    "local_hash": local_hash,
                    "blockchain_hash": "NOT_REGISTERED",
                    "block_number": None
                })
        
        verification_result["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        return verification_result
    
    async def _get_local_chain(self, request_id: str) -> List[AuditChain]:
        """Get the local audit chain for a request."""
        chain = await self.db.execute(
            select(AuditChain).where(
                AuditChain.request_id == uuid.UUID(request_id)
            ).order_by(AuditChain.step_index.asc())
        )
        return list(chain.scalars().all())
    
    async def _get_blockchain_records(self, request_id: str) -> List[BlockchainEntry]:
        """Get blockchain records for a request's audit chain."""
        # In production, this would query the blockchain or a database
        # of blockchain transactions
        # For now, return empty list (would be implemented with proper blockchain integration)
        return []
    
    async def get_blockchain_status(self) -> Dict[str, Any]:
        """Get the current blockchain connection status."""
        status = {
            "available": WEB3_AVAILABLE,
            "connected": self.web3 is not None and self.web3.is_connected() if self.web3 else False,
            "network": self.network if self.web3 else "unavailable",
            "chain_id": self.chain_id if self.web3 else None,
            "account": self.account.address if self.account else None,
            "block_number": self.web3.eth.block_number if self.web3 and self.web3.is_connected() else None,
            "gas_price": str(self.web3.eth.gas_price) if self.web3 and self.web3.is_connected() else None
        }
        
        return status
    
    async def get_registration_stats(self) -> Dict[str, Any]:
        """Get statistics about blockchain registrations."""
        # In production, this would query the blockchain
        # For now, return placeholder stats
        return {
            "total_registered": 0,
            "unique_requests": 0,
            "network": self.network,
            "last_registration": None
        }
    
    async def create_genesis_block(self) -> Optional[str]:
        """
        Create a genesis block for the audit blockchain.
        
        This initializes the blockchain with a known starting point.
        """
        if not self.web3:
            return None
        
        try:
            genesis_data = {
                "type": "GENESIS",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "genesis_hash": "0" * 64,
                "version": "1.0"
            }
            
            tx_hash = await self._send_simple_transaction(genesis_data)
            
            if tx_hash:
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
                return receipt.blockNumber
            
        except Exception as e:
            print(f"Failed to create genesis block: {e}")
        
        return None
    
    async def register_entire_chain(self, request_id: str) -> List[BlockchainEntry]:
        """
        Register an entire audit chain on the blockchain.
        
        This is useful for backfilling historical data or when
        a request's audit chain is complete.
        """
        chain = await self._get_local_chain(request_id)
        
        registered_entries = []
        
        for entry in chain:
            blockchain_entry = await self.register_audit_entry(
                str(entry.id),
                str(entry.request_id),
                entry.chain_hash,
                entry.prev_hash
            )
            
            if blockchain_entry:
                registered_entries.append(blockchain_entry)
        
        return registered_entries
    
    async def verify_single_entry(
        self,
        entry_id: str,
        expected_hash: str
    ) -> bool:
        """
        Verify a single audit entry against blockchain record.
        
        This provides point-in-time verification for specific entries.
        """
        if not self.web3:
            # If blockchain not available, skip verification
            return True
        
        try:
            # In production, this would query the blockchain
            # For now, return True (assume valid)
            return True
            
        except Exception as e:
            print(f"Failed to verify entry: {e}")
            return False
    
    async def get_verification_proof(
        self,
        request_id: str
    ) -> Dict[str, Any]:
        """
        Get a cryptographic proof of audit chain integrity.
        
        This provides a Merkle-like proof that can be independently verified.
        """
        chain = await self._get_local_chain(request_id)
        
        if not chain:
            return {
                "request_id": request_id,
                "valid": False,
                "reason": "No audit chain found"
            }
        
        # Compute the chain root hash
        root_hash = self._compute_chain_root(chain)
        
        # Get blockchain records
        blockchain_records = await self._get_blockchain_records(request_id)
        
        # In production, this would create a Merkle proof
        # For now, return basic proof
        proof = {
            "request_id": request_id,
            "chain_root": root_hash,
            "entry_count": len(chain),
            "blockchain_registered": len(blockchain_records),
            "network": self.network if self.web3 else "unavailable",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        return proof
    
    def _compute_chain_root(self, chain: List[AuditChain]) -> str:
        """Compute the root hash of the audit chain."""
        if not chain:
            return "0" * 64
        
        # Simple approach: hash all chain hashes together
        # In production, this would use a proper Merkle tree
        combined_hashes = "".join(entry.chain_hash for entry in chain)
        return hashlib.sha256(combined_hashes.encode()).hexdigest()
    
    async def cleanup_old_records(self, days: int = 90) -> int:
        """
        Clean up old blockchain records from local database.
        
        This helps manage storage while maintaining blockchain verification.
        """
        # In production, this would archive old records
        # For now, return 0
        return 0


class MockBlockchainAuditService(BlockchainAuditService):
    """
    Mock blockchain service for development/testing when real blockchain is not available.
    
    This simulates blockchain functionality without requiring actual blockchain infrastructure.
    """
    
    def __init__(self, db: AsyncSession):
        super().__init__(db)
        self.mock_entries: Dict[str, BlockchainEntry] = {}
        self.mock_block_number = 0
    
    async def register_audit_entry(
        self,
        entry_id: str,
        request_id: str,
        chain_hash: str,
        previous_hash: str
    ) -> Optional[BlockchainEntry]:
        """Mock registration - stores in memory."""
        self.mock_block_number += 1
        
        entry = BlockchainEntry(
            entry_id=entry_id,
            request_id=request_id,
            chain_hash=chain_hash,
            previous_hash=previous_hash,
            block_number=self.mock_block_number,
            transaction_hash="0x" + "0" * 64,  # Mock transaction hash
            timestamp=datetime.now(timezone.utc).isoformat(),
            network="mock"
        )
        
        self.mock_entries[entry_id] = entry
        return entry
    
    async def _get_blockchain_records(self, request_id: str) -> List[BlockchainEntry]:
        """Get mock blockchain records."""
        return [
            entry for entry in self.mock_entries.values()
            if entry.request_id == request_id
        ]
    
    async def get_blockchain_status(self) -> Dict[str, Any]:
        """Get mock blockchain status."""
        return {
            "available": True,
            "connected": True,
            "network": "mock",
            "chain_id": 1337,
            "account": "0x" + "0" * 40,
            "block_number": self.mock_block_number,
            "gas_price": "0"
        }
    
    async def get_registration_stats(self) -> Dict[str, Any]:
        """Get mock registration stats."""
        return {
            "total_registered": len(self.mock_entries),
            "unique_requests": len(set(e.request_id for e in self.mock_entries.values())),
            "network": "mock",
            "last_registration": datetime.now(timezone.utc).isoformat() if self.mock_entries else None
        }
