"""
Test suite for Breach Analyzer
"""

import pytest
import os
import pandas as pd
from src.breach_analyzer import BreachAnalyzer
import config


class TestBreachAnalyzer:
    """
    Test cases for BreachAnalyzer class
    """
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance"""
        return BreachAnalyzer()
    
    @pytest.fixture
    def sample_breach_data(self, tmp_path):
        """Create sample breach data"""
        df = pd.DataFrame({
            'email': ['user1@example.com', 'user2@example.com', 'user1@example.com'],
            'password': ['pass123', 'pass456', 'pass789'],
            'source': ['Breach1', 'Breach2', 'Breach1'],
            'date': ['2021-01-01', '2021-02-01', '2021-01-01']
        })
        
        file_path = tmp_path / "breach_data.csv"
        df.to_csv(file_path, index=False)
        return str(file_path)
    
    def test_analyzer_initialization(self, analyzer):
        """Test analyzer initialization"""
        assert analyzer is not None
        assert analyzer.breach_data is None
        assert analyzer.analysis_results == {}
    
    def test_load_breach_data(self, analyzer, sample_breach_data):
        """Test loading breach data"""
        data = analyzer.load_breach_data(sample_breach_data)
        assert data is not None
        assert len(data) == 3
        assert 'email' in data.columns
    
    def test_analyze_breach_data(self, analyzer, sample_breach_data):
        """Test breach data analysis"""
        results = analyzer.analyze_breach_data(sample_breach_data)
        
        assert results is not None
        assert 'total_records' in results
        assert 'statistics' in results
        assert 'patterns' in results
        assert results['total_records'] == 3
    
    def test_find_duplicates(self, analyzer, sample_breach_data):
        """Test duplicate detection"""
        analyzer.load_breach_data(sample_breach_data)
        duplicates = analyzer._find_duplicates()
        
        assert 'duplicate_emails' in duplicates
        assert duplicates['duplicate_emails'] > 0
    
    def test_check_credential_in_breach(self, analyzer, sample_breach_data):
        """Test credential checking"""
        analyzer.load_breach_data(sample_breach_data)
        result = analyzer.check_credential_in_breach('user1@example.com')
        
        assert result['found'] == True
        assert result['match_count'] > 0


class TestCredentialDetector:
    """
    Test cases for CredentialDetector
    """
    
    @pytest.fixture
    def detector(self):
        from src.credential_detector import CredentialDetector
        return CredentialDetector()
    
    def test_detector_initialization(self, detector):
        """Test detector initialization"""
        assert detector is not None
        assert len(detector.detection_history) == 0
    
    def test_sha1_hash(self, detector):
        """Test SHA1 hashing"""
        password = 'testpassword'
        hash_result = detector._sha1_hash(password)
        
        assert hash_result is not None
        assert len(hash_result) == 40  # SHA1 is 40 chars
    
    def test_calculate_risk_score(self, detector):
        """Test risk score calculation"""
        email = 'user@example.com'
        weak_password = 'weak'
        
        score = detector._calculate_risk_score(email, weak_password)
        assert 0 <= score <= 100
        assert score > 50  # Weak password should have high score


class TestMalwareDetector:
    """
    Test cases for MalwareDetector
    """
    
    @pytest.fixture
    def detector(self):
        from src.malware_detector import MalwareDetector
        return MalwareDetector()
    
    def test_detector_initialization(self, detector):
        """Test detector initialization"""
        assert detector is not None
        assert len(detector.detected_threats) == 0
    
    def test_check_known_malware_hash(self, detector):
        """Test detection of known malware hash"""
        # Known malicious hash from detector
        result = detector.check_hash('d41d8cd98f00b204e9800998ecf8427e')
        
        assert result is not None
        assert 'hash' in result
        assert 'threat_level' in result
    
    def test_check_ip_reputation(self, detector):
        """Test IP reputation checking"""
        result = detector.check_ip_reputation('8.8.8.8')
        
        assert result is not None
        assert 'ip' in result
        assert 'threat_level' in result
    
    def test_check_domain(self, detector):
        """Test malicious domain detection"""
        result = detector.check_domain('malware-c2.net')
        
        assert result is not None
        assert result['is_malicious'] == True


class TestCVEAnalyzer:
    """
    Test cases for CVEAnalyzer
    """
    
    @pytest.fixture
    def analyzer(self):
        from src.cve_analyzer import CVEAnalyzer
        return CVEAnalyzer()
    
    def test_analyzer_initialization(self, analyzer):
        """Test analyzer initialization"""
        assert analyzer is not None
        assert len(analyzer.cve_history) == 0
    
    def test_severity_threshold(self, analyzer):
        """Test severity threshold checking"""
        assert analyzer._meets_severity_threshold('CRITICAL', 'HIGH') == True
        assert analyzer._meets_severity_threshold('LOW', 'HIGH') == False
        assert analyzer._meets_severity_threshold('HIGH', 'HIGH') == True


class TestIncidentResponder:
    """
    Test cases for IncidentResponder
    """
    
    @pytest.fixture
    def responder(self):
        from src.incident_responder import IncidentResponder
        return IncidentResponder()
    
    def test_responder_initialization(self, responder):
        """Test responder initialization"""
        assert responder is not None
        assert len(responder.incidents) == 0
    
    def test_create_incident(self, responder):
        """Test incident creation"""
        threat_data = {
            'is_malicious': True,
            'threat_level': 'HIGH'
        }
        
        incident = responder.create_incident(threat_data)
        
        assert incident is not None
        assert 'incident_id' in incident
        assert incident['severity'] == 'HIGH'
        assert len(responder.incidents) == 1
    
    def test_generate_alert(self, responder):
        """Test alert generation"""
        threat_data = {'threat_level': 'HIGH'}
        incident = responder.create_incident(threat_data)
        
        alert = responder.generate_alert(incident['incident_id'], 'Test alert')
        
        assert alert is not None
        assert 'alert_id' in alert
        assert len(responder.alerts) == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])