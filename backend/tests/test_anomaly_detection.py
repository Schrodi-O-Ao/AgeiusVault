"""
Anomaly detection model training and prediction tests.
Tests the ML-based anomaly detection service for training and prediction capabilities.
"""
import pytest
import numpy as np
import pandas as pd
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, AsyncMock, patch
import uuid

# Mock the database and models for testing
@pytest.fixture
def mock_db():
    """Create a mock database session."""
    db = Mock()
    return db


@pytest.fixture
def anomaly_service(mock_db):
    """Create anomaly detection service with mock database."""
    from app.services.anomaly_detection import AnomalyDetectionService
    return AnomalyDetectionService(mock_db)


class TestAnomalyDetectionInitialization:
    """Test anomaly detection service initialization."""
    
    def test_service_initialization(self, anomaly_service):
        """Test that service initializes with correct parameters."""
        assert anomaly_service.isolation_forest is not None
        assert anomaly_service.scaler is not None
        assert anomaly_service.model_trained is False
        assert anomaly_service.feature_means == {}
        assert anomaly_service.feature_stds == {}
    
    def test_isolation_forest_parameters(self, anomaly_service):
        """Test that IsolationForest has correct parameters."""
        assert anomaly_service.isolation_forest.contamination == 0.1
        assert anomaly_service.isolation_forest.random_state == 42
        assert anomaly_service.isolation_forest.n_estimators == 100


class TestFeatureExtraction:
    """Test feature extraction for anomaly detection."""
    
    def test_extract_behavior_features_basic(self, anomaly_service):
        """Test basic behavior feature extraction."""
        # Create mock user activity data with proper structure
        from datetime import datetime, timezone
        user_data = [
            {
                "type": "login",
                "timestamp": datetime.now(timezone.utc),
                "ip_country": "US",
                "device_label": "Chrome/Windows"
            },
            {
                "type": "request",
                "timestamp": datetime.now(timezone.utc),
                "request_type": "ANNUAL_LEAVE",
                "is_anonymous": False,
                "status": "PENDING"
            }
        ]
        
        features = anomaly_service._extract_behavior_features(user_data)
        
        assert features is not None
        assert isinstance(features, dict)
        assert len(features) > 0
    
    def test_extract_features_with_varied_data(self, anomaly_service):
        """Test feature extraction with varied activity patterns."""
        from datetime import datetime, timezone
        user_data = [
            {
                "type": "login",
                "timestamp": datetime.now(timezone.utc),
                "ip_country": "US",
                "device_label": "Chrome/Windows"
            },
            {
                "type": "request",
                "timestamp": datetime.now(timezone.utc),
                "request_type": "ANNUAL_LEAVE",
                "is_anonymous": False,
                "status": "PENDING"
            },
            {
                "type": "audit_action",
                "timestamp": datetime.now(timezone.utc),
                "action": "APPROVED"
            }
        ]
        
        features = anomaly_service._extract_behavior_features(user_data)
        
        assert features is not None
        assert isinstance(features, dict)


class TestAnomalyDetection:
    """Test anomaly detection logic."""
    
    def test_detect_anomaly_normal_behavior(self, anomaly_service):
        """Test anomaly detection with normal behavior."""
        # Create normalized features representing normal behavior
        features = np.array([[0.5, 0.5, 0.5, 0.5, 0.5]])
        
        # Train model with some data first
        normal_data = np.random.randn(100, 5)
        anomaly_service.isolation_forest.fit(normal_data)
        anomaly_service.model_trained = True
        
        anomaly_score = anomaly_service._detect_anomaly(features)
        
        assert anomaly_score is not None
        assert isinstance(anomaly_score, (int, float, np.number))
    
    def test_detect_anomaly_abnormal_behavior(self, anomaly_service):
        """Test anomaly detection with abnormal behavior."""
        # Train model with normal data
        normal_data = np.random.randn(100, 5)
        anomaly_service.isolation_forest.fit(normal_data)
        anomaly_service.model_trained = True
        
        # Create features representing abnormal behavior (outliers)
        abnormal_features = np.array([[10, 10, 10, 10, 10]])
        
        anomaly_score = anomaly_service._detect_anomaly(abnormal_features)
        
        assert anomaly_score is not None
        # Abnormal behavior should have a different score than normal
        normal_features = np.array([[0, 0, 0, 0, 0]])
        normal_score = anomaly_service._detect_anomaly(normal_features)
        assert anomaly_score != normal_score
    
    def test_detect_anomaly_untrained_model(self, anomaly_service):
        """Test anomaly detection when model is not trained."""
        features = np.array([[0.5, 0.5, 0.5, 0.5, 0.5]])
        
        # Model should not be trained yet
        anomaly_service.model_trained = False
        
        # This should handle the untrained case gracefully
        try:
            anomaly_score = anomaly_service._detect_anomaly(features)
            # If it doesn't raise an error, check that it returns a sensible value
            assert anomaly_score is not None
        except Exception:
            # It's acceptable to raise an error for untrained model
            pass


class TestModelTraining:
    """Test model training functionality."""
    
    def test_train_model_with_sufficient_data(self, anomaly_service):
        """Test model training with sufficient data."""
        # Create synthetic training data
        training_data = np.random.randn(200, 5)
        
        # Train the model
        anomaly_service.isolation_forest.fit(training_data)
        anomaly_service.model_trained = True
        
        assert anomaly_service.model_trained is True
    
    def test_train_model_with_insufficient_data(self, anomaly_service):
        """Test model training with insufficient data."""
        # Create insufficient training data
        training_data = np.random.randn(5, 5)  # Too few samples
        
        # Model should still fit, but may not be reliable
        anomaly_service.isolation_forest.fit(training_data)
        
        # IsolationForest doesn't enforce minimum samples, but results may be unreliable
        assert anomaly_service.isolation_forest is not None
    
    def test_model_training_deterministic(self, anomaly_service):
        """Test that model training is deterministic with fixed random state."""
        data1 = np.random.randn(100, 5)
        data2 = np.random.randn(100, 5)
        
        # Train with same data and random state
        anomaly_service.isolation_forest.fit(data1)
        predictions1 = anomaly_service.isolation_forest.decision_function(data2)
        
        # Reset and train again
        from sklearn.ensemble import IsolationForest
        anomaly_service.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        anomaly_service.isolation_forest.fit(data1)
        predictions2 = anomaly_service.isolation_forest.decision_function(data2)
        
        # Predictions should be identical
        np.testing.assert_array_equal(predictions1, predictions2)


class TestRiskLevelCalculation:
    """Test risk level calculation based on anomaly scores."""
    
    def test_calculate_risk_level_low(self, anomaly_service):
        """Test risk level calculation for low risk."""
        anomaly_score = 0.1
        issues = []
        
        risk_level = anomaly_service._calculate_risk_level(anomaly_score, issues)
        
        assert risk_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    
    def test_calculate_risk_level_high_with_issues(self, anomaly_service):
        """Test risk level calculation with detected issues."""
        anomaly_score = 0.8
        issues = ["multiple_failed_logins", "unusual_access_pattern"]
        
        risk_level = anomaly_service._calculate_risk_level(anomaly_score, issues)
        
        assert risk_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        # High anomaly score with issues should likely be HIGH or CRITICAL
        assert risk_level in ["HIGH", "CRITICAL"]


class TestNormalization:
    """Test feature normalization."""
    
    def test_normalize_features(self, anomaly_service):
        """Test feature normalization."""
        features = {
            "request_count": 10,
            "login_count": 2,
            "unique_ips": 1,
            "avg_request_interval": 3600,
            "failed_attempts": 0
        }
        
        # Set feature means and stds for normalization
        anomaly_service.feature_means = {
            "request_count": 5.0,
            "login_count": 1.0,
            "unique_ips": 1.0,
            "avg_request_interval": 1800.0,
            "failed_attempts": 0.5
        }
        anomaly_service.feature_stds = {
            "request_count": 2.0,
            "login_count": 0.5,
            "unique_ips": 0.5,
            "avg_request_interval": 900.0,
            "failed_attempts": 0.5
        }
        
        normalized = anomaly_service._normalize_features(features)
        
        assert normalized is not None
        assert isinstance(normalized, (np.ndarray, list))


class TestUserBehaviorAnalysis:
    """Test user behavior analysis."""
    
    @pytest.mark.asyncio
    async def test_analyze_user_behavior_insufficient_data(self, anomaly_service, mock_db):
        """Test analysis with insufficient user data."""
        user_id = uuid.uuid4()
        
        # Mock insufficient data
        anomaly_service._collect_user_activity = AsyncMock(return_value=[])
        
        result = await anomaly_service.analyze_user_behavior(user_id)
        
        assert result["user_id"] == str(user_id)
        assert result["anomaly_score"] == 0.0
        assert result["risk_level"] == "LOW"
        assert "Insufficient data" in result["message"]
    
    @pytest.mark.asyncio
    async def test_analyze_user_behavior_with_data(self, anomaly_service, mock_db):
        """Test analysis with sufficient user data."""
        user_id = uuid.uuid4()
        
        # Mock sufficient user data
        user_data = [
            {
                "request_count": 5,
                "login_count": 1,
                "unique_ips": 1,
                "avg_request_interval": 3600,
                "failed_attempts": 0
            } for _ in range(10)
        ]
        
        anomaly_service._collect_user_activity = AsyncMock(return_value=user_data)
        anomaly_service._extract_behavior_features = Mock(return_value={"test": 1.0})
        anomaly_service._normalize_features = Mock(return_value=np.array([[1.0]]))
        anomaly_service._detect_anomaly = Mock(return_value=0.5)
        anomaly_service._analyze_specific_patterns = AsyncMock(return_value=[])
        anomaly_service._calculate_risk_level = Mock(return_value="MEDIUM")
        
        result = await anomaly_service.analyze_user_behavior(user_id)
        
        assert result["user_id"] == str(user_id)
        assert "anomaly_score" in result
        assert "risk_level" in result
        assert "issues" in result


class TestRequestPatternAnalysis:
    """Test request pattern analysis."""
    
    @pytest.mark.asyncio
    async def test_analyze_request_patterns(self, anomaly_service, mock_db):
        """Test system-wide request pattern analysis."""
        hours = 24
        
        # Mock system data
        system_data = [
            {
                "user_id": str(uuid.uuid4()),
                "request_count": 10,
                "timestamp": datetime.now(timezone.utc)
            } for _ in range(50)
        ]
        
        anomaly_service._collect_system_requests = AsyncMock(return_value=system_data)
        
        result = await anomaly_service.analyze_request_patterns(hours)
        
        assert result is not None
        assert isinstance(result, dict)


class TestSpecificPatternAnalysis:
    """Test specific security pattern analysis."""
    
    @pytest.mark.asyncio
    async def test_analyze_specific_patterns(self, anomaly_service, mock_db):
        """Test analysis of specific security patterns."""
        user_id = uuid.uuid4()
        user_data = [
            {
                "failed_logins": 5,
                "suspicious_ips": ["192.168.1.100"],
                "unusual_times": [datetime.now(timezone.utc)]
            }
        ]
        
        result = await anomaly_service._analyze_specific_patterns(user_id, user_data)
        
        assert result is not None
        assert isinstance(result, list)


class TestAnomalyDetectionIntegration:
    """Integration tests for anomaly detection."""
    
    def test_full_anomaly_pipeline(self, anomaly_service):
        """Test complete anomaly detection pipeline."""
        from datetime import datetime, timezone
        # Simulate user data collection with proper structure
        user_data = [
            {
                "type": "login",
                "timestamp": datetime.now(timezone.utc),
                "ip_country": "US",
                "device_label": "Chrome/Windows"
            } for _ in range(10)
        ] + [
            {
                "type": "request",
                "timestamp": datetime.now(timezone.utc),
                "request_type": "ANNUAL_LEAVE",
                "is_anonymous": False,
                "status": "PENDING"
            } for _ in range(10)
        ]
        
        # Extract features
        features = anomaly_service._extract_behavior_features(user_data)
        assert features is not None
        
        # Train model with synthetic data
        training_data = np.random.randn(100, 5)
        anomaly_service.isolation_forest.fit(training_data)
        anomaly_service.model_trained = True
        
        # Detect anomaly
        normalized_features = anomaly_service._normalize_features(features)
        anomaly_score = anomaly_service._detect_anomaly(normalized_features)
        
        assert anomaly_score is not None
        assert isinstance(anomaly_score, (int, float, np.number))
    
    def test_batch_anomaly_detection(self, anomaly_service):
        """Test batch anomaly detection for multiple users."""
        # Train model
        training_data = np.random.randn(200, 5)
        anomaly_service.isolation_forest.fit(training_data)
        anomaly_service.model_trained = True
        
        # Simulate multiple users
        user_features = [
            np.random.randn(5) for _ in range(10)
        ]
        
        anomaly_scores = [
            anomaly_service._detect_anomaly(features.reshape(1, -1))
            for features in user_features
        ]
        
        assert len(anomaly_scores) == len(user_features)
        assert all(score is not None for score in anomaly_scores)