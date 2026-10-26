"""
API router for anomaly detection and security monitoring.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
import uuid

from app.database import get_db
from app.dependencies import get_current_user, require_role
from app.models.user import User
from app.services.anomaly_detection import AnomalyDetectionService

router = APIRouter()


@router.get("/user-analysis")
async def analyze_user(
    user_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Analyze user behavior for security anomalies.
    
    Users can analyze themselves, admins can analyze any user.
    """
    # Only allow users to analyze themselves or admins to analyze anyone
    target_user_id = uuid.UUID(user_id) if user_id else current_user.id
    
    if target_user_id != current_user.id and current_user.role not in ["HR_ADMIN", "SYS_ADMIN"]:
        raise HTTPException(403, "You can only analyze your own behavior")
    
    service = AnomalyDetectionService(db)
    analysis = await service.analyze_user_behavior(target_user_id)
    
    return analysis


@router.get("/suspicious-requests")
async def get_suspicious_requests(
    user_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get suspicious requests from a user.
    
    Users can check their own requests, admins can check any user.
    """
    target_user_id = uuid.UUID(user_id) if user_id else current_user.id
    
    if target_user_id != current_user.id and current_user.role not in ["HR_ADMIN", "SYS_ADMIN"]:
        raise HTTPException(403, "You can only check your own requests")
    
    service = AnomalyDetectionService(db)
    suspicious = await service.detect_suspicious_requests(target_user_id)
    
    return {
        "user_id": str(target_user_id),
        "suspicious_requests": suspicious,
        "count": len(suspicious)
    }


@router.get("/system-analysis")
async def analyze_system(
    hours: int = 24,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("HR_ADMIN", "SYS_ADMIN")),
):
    """
    Analyze system-wide request patterns for anomalies.
    
    Admin only endpoint.
    """
    service = AnomalyDetectionService(db)
    analysis = await service.analyze_request_patterns(hours=hours)
    
    return analysis


@router.get("/health-report")
async def get_health_report(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("HR_ADMIN", "SYS_ADMIN")),
):
    """
    Get comprehensive system security health report.
    
    Admin only endpoint.
    """
    service = AnomalyDetectionService(db)
    report = await service.get_system_health_report()
    
    return report


@router.post("/train-model")
async def train_model(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("SYS_ADMIN")),
):
    """
    Train the anomaly detection model on historical data.
    
    Admin only endpoint - should be run periodically.
    """
    service = AnomalyDetectionService(db)
    await service.train_model()
    
    return {
        "success": True,
        "message": "Model training completed"
    }