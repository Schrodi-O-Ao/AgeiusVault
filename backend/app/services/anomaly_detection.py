"""
ML-based anomaly detection for security monitoring.

This service uses machine learning to detect unusual patterns in:
- Request submission patterns
- User behavior
- Login attempts
- Request content that might indicate fraud or abuse
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional, Any
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import json
import uuid

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.user import User
from app.models.request import Request
from app.models.audit_chain import AuditChain
from app.models.session import Session


class AnomalyDetectionService:
    """
    Machine learning-based anomaly detection for security monitoring.
    
    Uses unsupervised learning to detect patterns that deviate from normal behavior.
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.isolation_forest = IsolationForest(
            contamination=0.1,  # Expected 10% anomalies
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.model_trained = False
        self.feature_means = {}
        self.feature_stds = {}
    
    async def analyze_user_behavior(self, user_id: uuid.UUID) -> Dict[str, any]:
        """
        Analyze user behavior for anomalies.
        
        Returns:
            Dictionary with anomaly scores and detected issues
        """
        # Collect user activity data
        user_data = await self._collect_user_activity(user_id)
        
        if len(user_data) < 5:  # Not enough data for reliable analysis
            return {
                "user_id": str(user_id),
                "anomaly_score": 0.0,
                "risk_level": "LOW",
                "issues": [],
                "message": "Insufficient data for analysis"
            }
        
        # Extract features
        features = self._extract_behavior_features(user_data)
        
        # Normalize features
        normalized_features = self._normalize_features(features)
        
        # Detect anomalies
        anomaly_score = self._detect_anomaly(normalized_features)
        
        # Analyze specific patterns
        issues = await self._analyze_specific_patterns(user_id, user_data)
        
        # Determine risk level
        risk_level = self._calculate_risk_level(anomaly_score, issues)
        
        return {
            "user_id": str(user_id),
            "anomaly_score": float(anomaly_score),
            "risk_level": risk_level,
            "issues": issues,
            "features": features,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    async def analyze_request_patterns(self, hours: int = 24) -> Dict[str, any]:
        """
        Analyze request patterns across all users for the specified time period.
        
        Returns:
            Dictionary with overall system anomaly analysis
        """
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        # Collect system-wide request data
        system_data = await self._collect_system_requests(cutoff_time)
        
        if len(system_data) < 10:
            return {
                "time_period_hours": hours,
                "total_requests": len(system_data),
                "anomaly_score": 0.0,
                "risk_level": "LOW",
                "issues": [],
                "message": "Insufficient data for analysis"
            }
        
        # Extract features
        features = self._extract_system_features(system_data)
        
        # Detect anomalies
        anomaly_score = self._detect_anomaly(features)
        
        # Analyze specific patterns
        issues = await self._analyze_system_patterns(system_data)
        
        return {
            "time_period_hours": hours,
            "total_requests": len(system_data),
            "anomaly_score": float(anomaly_score),
            "risk_level": self._calculate_risk_level(anomaly_score, issues),
            "issues": issues,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    async def detect_suspicious_requests(self, user_id: uuid.UUID) -> List[Dict[str, any]]:
        """
        Detect potentially suspicious requests from a specific user.
        
        Returns:
            List of suspicious requests with anomaly scores
        """
        cutoff_time = datetime.now(timezone.utc) - timedelta(days=7)
        
        # Get user's recent requests
        requests = await self.db.execute(
            select(Request).where(
                Request.requester_id == user_id,
                Request.submitted_at >= cutoff_time
            ).order_by(Request.submitted_at.desc())
        )
        user_requests = requests.scalars().all()
        
        suspicious_requests = []
        
        for req in user_requests:
            # Analyze each request for suspicious patterns
            features = self._extract_request_features(req)
            anomaly_score = self._detect_request_anomaly(features)
            
            if anomaly_score > 0.5:  # Threshold for suspicious
                suspicious_requests.append({
                    "request_id": str(req.id),
                    "type": req.type,
                    "submitted_at": str(req.submitted_at),
                    "anomaly_score": float(anomaly_score),
                    "status": req.status,
                    "is_anonymous": req.is_anonymous
                })
        
        return suspicious_requests
    
    async def _collect_user_activity(self, user_id: uuid.UUID) -> List[Dict]:
        """Collect user activity data for analysis."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(days=30)
        
        # Get login sessions
        sessions = await self.db.execute(
            select(Session).where(
                Session.user_id == user_id,
                Session.created_at >= cutoff_time
            ).order_by(Session.created_at.desc())
        )
        session_data = sessions.scalars().all()
        
        # Get requests
        requests = await self.db.execute(
            select(Request).where(
                Request.requester_id == user_id,
                Request.submitted_at >= cutoff_time
            ).order_by(Request.submitted_at.desc())
        )
        request_data = requests.scalars().all()
        
        # Get audit entries
        audit_entries = await self.db.execute(
            select(AuditChain).where(
                AuditChain.actor_id == user_id,
                AuditChain.recorded_at >= cutoff_time
            ).order_by(AuditChain.recorded_at.desc())
        )
        audit_data = audit_entries.scalars().all()
        
        return self._aggregate_user_data(session_data, request_data, audit_data)
    
    def _aggregate_user_data(
        self, 
        sessions: List[Session], 
        requests: List[Request], 
        audit_entries: List[AuditChain]
    ) -> List[Dict]:
        """Aggregate user data into activity records."""
        activities = []
        
        # Add session activities
        for session in sessions:
            activities.append({
                "type": "login",
                "timestamp": session.created_at,
                "ip_country": session.ip_country,
                "device_label": session.device_label,
                "user_agent": session.device_label  # Simplified
            })
        
        # Add request activities
        for req in requests:
            activities.append({
                "type": "request",
                "timestamp": req.submitted_at,
                "request_type": req.type,
                "is_anonymous": req.is_anonymous,
                "status": req.status
            })
        
        # Add audit activities
        for audit in audit_entries:
            activities.append({
                "type": "audit_action",
                "timestamp": audit.recorded_at,
                "action": audit.action
            })
        
        return sorted(activities, key=lambda x: x["timestamp"], reverse=True)
    
    def _extract_behavior_features(self, activities: List[Dict]) -> Dict[str, float]:
        """Extract behavioral features from user activities."""
        if not activities:
            return {}
        
        features = {
            "total_activities": len(activities),
            "unique_days": len(set(a["timestamp"].date() for a in activities)),
            "login_count": sum(1 for a in activities if a["type"] == "login"),
            "request_count": sum(1 for a in activities if a["type"] == "request"),
            "audit_action_count": sum(1 for a in activities if a["type"] == "audit_action"),
            "anonymous_request_ratio": 0.0,
            "different_request_types": 0,
            "different_countries": 0,
            "activities_per_day": 0.0,
        }
        
        if features["total_activities"] > 0:
            # Calculate ratios
            request_activities = [a for a in activities if a["type"] == "request"]
            if request_activities:
                features["anonymous_request_ratio"] = sum(
                    1 for a in request_activities if a.get("is_anonymous", False)
                ) / len(request_activities)
                features["different_request_types"] = len(set(
                    a.get("request_type") for a in request_activities
                ))
            
            # Calculate location diversity
            login_activities = [a for a in activities if a["type"] == "login"]
            if login_activities:
                features["different_countries"] = len(set(
                    a.get("ip_country") for a in login_activities if a.get("ip_country")
                ))
            
            # Calculate activity frequency
            if features["unique_days"] > 0:
                features["activities_per_day"] = features["total_activities"] / features["unique_days"]
        
        return features
    
    def _extract_system_features(self, requests: List[Request]) -> np.ndarray:
        """Extract features from system-wide requests."""
        features_list = []
        
        for req in requests:
            features = self._extract_request_features(req)
            features_list.append([
                features.get("hour_of_day", 0),
                features.get("day_of_week", 0),
                features.get("is_anonymous", 0),
                features.get("request_type_encoded", 0),
                features.get("time_since_last_request", 0),
            ])
        
        return np.array(features_list)
    
    def _extract_request_features(self, request: Any) -> Dict[str, float]:
        submitted_at = getattr(request, "submitted_at", None)
        if submitted_at is None and isinstance(request, dict):
            submitted_at = request.get("timestamp") or request.get("submitted_at")
        if submitted_at is None:
            submitted_at = datetime.now(timezone.utc)
            
        req_type = getattr(request, "type", None)
        if req_type is None and isinstance(request, dict):
            req_type = request.get("type") or request.get("request_type") or "UNKNOWN"
            
        is_anon = getattr(request, "is_anonymous", False)
        if isinstance(request, dict):
            is_anon = request.get("is_anonymous", False)
            
        return {
            "hour_of_day": float(submitted_at.hour),
            "day_of_week": float(submitted_at.weekday()),
            "is_anonymous": 1.0 if is_anon else 0.0,
            "request_type_encoded": self._encode_request_type(str(req_type)),
            "time_since_last_request": 0.0
        }
    
    def _encode_request_type(self, request_type: str) -> float:
        type_mapping = {
            "ANNUAL_LEAVE": 0,
            "SICK_LEAVE": 1,
            "EXPENSE": 2,
            "IT_ACCESS": 3,
            "ANON_HR": 4
        }
        return float(type_mapping.get(request_type, 0))
    
    def _normalize_features(self, features: Dict[str, float]) -> np.ndarray:
        feature_values = np.array(list(features.values()))
        if not self.model_trained or not self.feature_means:
            return feature_values
        
        if isinstance(self.feature_means, dict):
            means = np.array([self.feature_means.get(k, 0.0) for k in features.keys()])
            stds = np.array([self.feature_stds.get(k, 1.0) or 1.0 for k in features.keys()])
            stds = np.where(stds == 0, 1.0, stds)
            return (feature_values - means) / stds
        return (feature_values - self.feature_means) / (self.feature_stds or 1.0)
    
    def _detect_anomaly(self, features: np.ndarray) -> float:
        """Detect anomaly using isolation forest."""
        if len(features) == 0:
            return 0.0
        
        # Reshape for single sample
        if len(features.shape) == 1:
            features = features.reshape(1, -1)
        
        try:
            # Fit if not trained
            if not self.model_trained and len(features) > 10:
                self.isolation_forest.fit(features)
                self.model_trained = True
            
            # Predict anomalies (-1 for anomalies, 1 for normal)
            predictions = self.isolation_forest.predict(features)
            
            # Convert to anomaly score (0 to 1)
            anomaly_count = sum(1 for p in predictions if p == -1)
            anomaly_score = anomaly_count / len(predictions)
            
            return anomaly_score
        except Exception as e:
            print(f"Error in anomaly detection: {e}")
            return 0.0
    
    def _detect_request_anomaly(self, features: Dict[str, float]) -> float:
        """Detect if a specific request is anomalous."""
        feature_array = np.array(list(features.values())).reshape(1, -1)
        
        try:
            prediction = self.isolation_forest.predict(feature_array)
            return 1.0 if prediction[0] == -1 else 0.0
        except Exception:
            return 0.0
    
    async def _analyze_specific_patterns(self, user_id: uuid.UUID, user_data: List[Dict]) -> List[str]:
        issues = []
        for a in user_data:
            if a.get("failed_logins", 0) > 3:
                issues.append("Multiple failed login attempts detected")
            if a.get("suspicious_ips"):
                issues.append("Suspicious IP addresses detected")
        
        login_activities = [a for a in user_data if a.get("type") == "login"]
        if len(login_activities) > 0:
            recent_logins = [
                a for a in login_activities
                if a.get("timestamp") and (datetime.now(timezone.utc) - a["timestamp"]).total_seconds() < 3600
            ]
            if len(recent_logins) > 5:
                issues.append("Multiple login attempts in short time period")
        
        request_activities = [a for a in user_data if a.get("type") == "request"]
        if len(request_activities) > 0:
            anonymous_count = sum(1 for a in request_activities if a.get("is_anonymous", False))
            if len(request_activities) > 5 and anonymous_count / len(request_activities) > 0.7:
                issues.append("High ratio of anonymous requests")
            
            recent_requests = [
                a for a in request_activities
                if a.get("timestamp") and (datetime.now(timezone.utc) - a["timestamp"]).total_seconds() < 300
            ]
            if len(recent_requests) > 10:
                issues.append("Rapid request submission pattern detected")
        
        audit_activities = [a for a in user_data if a.get("type") == "audit_action"]
        rejection_count = sum(1 for a in audit_activities if a.get("action") == "REJECTED")
        if len(audit_activities) > 0 and rejection_count / len(audit_activities) > 0.8:
            issues.append("High rejection rate in user actions")
        
        return issues
    
    async def _collect_system_requests(self, cutoff_time: datetime) -> List[Request]:
        """Collect system-wide request data."""
        requests = await self.db.execute(
            select(Request).where(
                Request.submitted_at >= cutoff_time
            ).order_by(Request.submitted_at.desc())
        )
        return requests.scalars().all()
    
    async def _analyze_system_patterns(self, requests: List[Any]) -> List[str]:
        issues = []
        if len(requests) == 0:
            return issues
        
        type_counts = {}
        for req in requests:
            req_type = getattr(req, "type", None) or (req.get("type") or req.get("request_type") or "UNKNOWN" if isinstance(req, dict) else "UNKNOWN")
            type_counts[req_type] = type_counts.get(req_type, 0) + 1
        
        max_count = max(type_counts.values()) if type_counts else 0
        if max_count / len(requests) > 0.9:
            dominant_type = max(type_counts, key=type_counts.get)
            issues.append(f"Unusual concentration of {dominant_type} requests")
        
        anonymous_count = sum(
            1 for req in requests
            if (getattr(req, "is_anonymous", False) or (req.get("is_anonymous", False) if isinstance(req, dict) else False))
        )
        if anonymous_count / len(requests) > 0.5:
            issues.append("High system-wide anonymous request ratio")
        
        unusual_hour_count = 0
        for req in requests:
            dt = getattr(req, "submitted_at", None) or (req.get("timestamp") or req.get("submitted_at") if isinstance(req, dict) else None)
            if dt and (dt.hour < 6 or dt.hour > 22):
                unusual_hour_count += 1
        if unusual_hour_count / len(requests) > 0.3:
            issues.append("High volume of requests outside normal business hours")
        
        return issues
    
    def _calculate_risk_level(self, anomaly_score: float, issues: List[str]) -> str:
        """Calculate overall risk level from anomaly score and issues."""
        if anomaly_score > 0.7 or len(issues) > 3:
            return "HIGH"
        elif anomaly_score > 0.4 or len(issues) > 1:
            return "MEDIUM"
        else:
            return "LOW"
    
    async def train_model(self):
        """Train the anomaly detection model on historical data."""
        # Collect historical data
        cutoff_time = datetime.now(timezone.utc) - timedelta(days=90)
        
        requests = await self.db.execute(
            select(Request).where(
                Request.submitted_at >= cutoff_time
            )
        )
        request_data = requests.scalars().all()
        
        if len(request_data) < 50:
            print("Insufficient data for model training")
            return
        
        # Extract features
        features = self._extract_system_features(request_data)
        
        # Train the model
        self.isolation_forest.fit(features)
        self.model_trained = True
        
        # Store feature statistics for normalization
        self.feature_means = np.mean(features, axis=0)
        self.feature_stds = np.std(features, axis=0)
        
        print(f"Model trained on {len(request_data)} historical requests")
    
    async def get_system_health_report(self) -> Dict[str, any]:
        """Generate a comprehensive system security health report."""
        # Analyze recent patterns
        recent_analysis = await self.analyze_request_patterns(hours=24)
        
        # Get user statistics
        total_users = await self.db.execute(
            select(func.count(User.id)).where(User.is_active == True)
        )
        active_user_count = total_users.scalar()
        
        # Get request statistics
        total_requests = await self.db.execute(
            select(func.count(Request.id)).where(
                Request.submitted_at >= datetime.now(timezone.utc) - timedelta(days=7)
            )
        )
        recent_request_count = total_requests.scalar()
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "active_users": active_user_count,
            "recent_requests_7days": recent_request_count,
            "anomaly_analysis": recent_analysis,
            "model_trained": self.model_trained,
            "system_health": "HEALTHY" if recent_analysis["risk_level"] == "LOW" else "ATTENTION"
        }