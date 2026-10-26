"""
API router for blockchain audit trail operations.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
import uuid

from app.database import get_db
from app.dependencies import get_current_user, require_role
from app.models.user import User
from app.services.blockchain_audit import BlockchainAuditService, MockBlockchainAuditService

router = APIRouter()


def get_blockchain_service(db: AsyncSession) -> BlockchainAuditService:
    """Get blockchain service (uses mock if real blockchain unavailable)."""
    try:
        return BlockchainAuditService(db)
    except Exception:
        # Fall back to mock service if blockchain initialization fails
        return MockBlockchainAuditService(db)


@router.get("/status")
async def get_blockchain_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get the current blockchain connection status.
    """
    service = get_blockchain_service(db)
    status = await service.get_blockchain_status()
    
    return status


@router.post("/register-entry")
async def register_audit_entry(
    entry_id: str,
    request_id: str,
    chain_hash: str,
    previous_hash: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("SYS_ADMIN")),
):
    """
    Register a single audit entry on the blockchain.
    
    Admin only endpoint - typically called automatically during audit logging.
    """
    service = get_blockchain_service(db)
    result = await service.register_audit_entry(
        entry_id,
        request_id,
        chain_hash,
        previous_hash
    )
    
    if result:
        return {
            "success": True,
            "blockchain_entry": {
                "entry_id": result.entry_id,
                "block_number": result.block_number,
                "transaction_hash": result.transaction_hash,
                "network": result.network
            }
        }
    else:
        return {
            "success": False,
            "message": "Failed to register entry on blockchain"
        }


@router.post("/register-chain/{request_id}")
async def register_entire_chain(
    request_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("SYS_ADMIN")),
):
    """
    Register an entire audit chain on the blockchain.
    
    Admin only endpoint - useful for backfilling or completed requests.
    """
    service = get_blockchain_service(db)
    registered_entries = await service.register_entire_chain(request_id)
    
    return {
        "success": True,
        "request_id": request_id,
        "registered_count": len(registered_entries),
        "entries": [
            {
                "entry_id": entry.entry_id,
                "block_number": entry.block_number,
                "transaction_hash": entry.transaction_hash
            }
            for entry in registered_entries
        ]
    }


@router.get("/verify/{request_id}")
async def verify_chain_integrity(
    request_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Verify audit chain integrity using blockchain records.
    
    Compares local audit chain hashes with blockchain-registered hashes.
    """
    service = get_blockchain_service(db)
    verification = await service.verify_chain_integrity(request_id)
    
    return verification


@router.get("/proof/{request_id}")
async def get_verification_proof(
    request_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get a cryptographic proof of audit chain integrity.
    
    Provides a Merkle-like proof that can be independently verified.
    """
    service = get_blockchain_service(db)
    proof = await service.get_verification_proof(request_id)
    
    return proof


@router.get("/stats")
async def get_registration_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("HR_ADMIN", "SYS_ADMIN")),
):
    """
    Get statistics about blockchain registrations.
    
    Admin only endpoint.
    """
    service = get_blockchain_service(db)
    stats = await service.get_registration_stats()
    
    return stats


@router.post("/genesis")
async def create_genesis_block(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("SYS_ADMIN")),
):
    """
    Create a genesis block for the audit blockchain.
    
    Admin only endpoint - initializes the blockchain with a known starting point.
    """
    service = get_blockchain_service(db)
    block_number = await service.create_genesis_block()
    
    if block_number:
        return {
            "success": True,
            "block_number": block_number,
            "message": "Genesis block created successfully"
        }
    else:
        return {
            "success": False,
            "message": "Failed to create genesis block"
        }