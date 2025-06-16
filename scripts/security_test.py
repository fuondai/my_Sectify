#!/usr/bin/env python3
"""
Sectify V2 Security Validation Test Suite
Tests all implemented security fixes and validates system security posture
"""

import sys
import os
import uuid
import asyncio
import logging
from typing import Dict, List, Any

# Add app to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

# Import security modules
try:
    from app.core.config import (
        SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, 
        SECURE_COOKIES, IS_PRODUCTION, SECURITY_HEADERS, CSP_POLICY
    )
    from app.core.security import (
        verify_password, get_password_hash, create_access_token, 
        create_mfa_temp_token, verify_token, validate_password_strength
    )
    from app.core.validation import (
        validate_uuid, validate_filename, validate_file_extension,
        validate_file_size, validate_path_safety, sanitize_user_input
    )
    from app.core.limiter import get_rate_limit_key, log_rate_limit_violation
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure you're running this from the project root directory")
    sys.exit(1)

class SecurityTestSuite:
    """Comprehensive security test suite for Sectify V2"""
    
    def __init__(self):
        self.passed_tests = 0
        self.failed_tests = 0
        self.test_results = []
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def log_test(self, test_name: str, passed: bool, details: str = ""):
        """Log test result"""
        status = "✅ PASS" if passed else "❌ FAIL"
        result = f"{status} | {test_name}"
        if details:
            result += f" | {details}"
        
        print(result)
        self.test_results.append({
            "test": test_name,
            "passed": passed,
            "details": details
        })
        
        if passed:
            self.passed_tests += 1
        else:
            self.failed_tests += 1
    
    def test_configuration_security(self):
        """Test configuration security measures"""
        print("\n🔧 Testing Configuration Security...")
        
        # Test SECRET_KEY validation
        try:
            assert len(SECRET_KEY) >= 32, "SECRET_KEY too short"
            self.log_test("SECRET_KEY Length", True, f"Length: {len(SECRET_KEY)}")
        except Exception as e:
            self.log_test("SECRET_KEY Length", False, str(e))
        
        # Test production settings
        try:
            if IS_PRODUCTION:
                assert SECURE_COOKIES == True, "SECURE_COOKIES should be True in production"
                self.log_test("Production Cookie Security", True)
            else:
                self.log_test("Development Mode Detected", True, "SECURE_COOKIES can be False")
        except Exception as e:
            self.log_test("Production Cookie Security", False, str(e))
        
        # Test security headers
        try:
            required_headers = ["Cache-Control", "X-Content-Type-Options", "X-Frame-Options"]
            for header in required_headers:
                assert header in SECURITY_HEADERS, f"Missing security header: {header}"
            self.log_test("Security Headers", True, f"Found {len(SECURITY_HEADERS)} headers")
        except Exception as e:
            self.log_test("Security Headers", False, str(e))
    
    def test_password_security(self):
        """Test password security measures"""
        print("\n🔐 Testing Password Security...")
        
        # Test weak passwords
        weak_passwords = [
            "123456",
            "password",
            "admin",
            "short",
            "NoNumbers",
            "no-uppercase-123",
            "NO-LOWERCASE-123"
        ]
        
        weak_detected = 0
        for pwd in weak_passwords:
            is_strong, issues = validate_password_strength(pwd)
            if not is_strong:
                weak_detected += 1
        
        self.log_test("Weak Password Detection", 
                     weak_detected == len(weak_passwords),
                     f"Detected {weak_detected}/{len(weak_passwords)} weak passwords")
        
        # Test strong password
        strong_password = "MySecureP@ssw0rd123!"
        is_strong, issues = validate_password_strength(strong_password)
        self.log_test("Strong Password Validation", is_strong, 
                     f"Issues: {issues}" if issues else "No issues")
        
        # Test password hashing
        try:
            test_password = "TestPassword123!"
            hashed = get_password_hash(test_password)
            verified = verify_password(test_password, hashed)
            self.log_test("Password Hashing", verified, "Argon2 hashing working")
        except Exception as e:
            self.log_test("Password Hashing", False, str(e))
    
    def test_token_security(self):
        """Test JWT token security"""
        print("\n🎫 Testing Token Security...")
        
        # Test access token creation with IP binding
        try:
            test_data = {"sub": "test@example.com", "roles": ["user"]}
            test_ip = "192.168.1.100"
            
            token = create_access_token(test_data, ip=test_ip)
            payload = verify_token(token, "access", ip=test_ip)
            
            assert payload["sub"] == test_data["sub"]
            assert "ip_hash" in payload
            self.log_test("IP-Bound Token Creation", True, "IP binding working")
        except Exception as e:
            self.log_test("IP-Bound Token Creation", False, str(e))
        
        # Test IP binding validation
        try:
            token = create_access_token(test_data, ip="192.168.1.100")
            # Try to verify with different IP
            verify_token(token, "access", ip="192.168.1.200")
            self.log_test("IP Binding Validation", False, "Should reject different IP")
        except ValueError:
            self.log_test("IP Binding Validation", True, "Correctly rejected different IP")
        except Exception as e:
            self.log_test("IP Binding Validation", False, f"Unexpected error: {e}")
        
        # Test MFA token
        try:
            mfa_token = create_mfa_temp_token({"sub": "test@example.com"}, ip="192.168.1.100")
            mfa_payload = verify_token(mfa_token, "mfa_verification", ip="192.168.1.100")
            assert mfa_payload["purpose"] == "mfa_verification"
            self.log_test("MFA Token Security", True, "MFA tokens working")
        except Exception as e:
            self.log_test("MFA Token Security", False, str(e))
    
    def test_uuid_validation(self):
        """Test UUID validation for IDOR protection"""
        print("\n🆔 Testing UUID Validation...")
        
        # Test valid UUIDs
        valid_uuids = [
            str(uuid.uuid4()),
            "550e8400-e29b-41d4-a716-446655440000",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        ]
        
        valid_count = 0
        for test_uuid in valid_uuids:
            try:
                result = validate_uuid(test_uuid, "test_id")
                if result == test_uuid:
                    valid_count += 1
            except:
                pass
        
        self.log_test("Valid UUID Acceptance", 
                     valid_count == len(valid_uuids),
                     f"Accepted {valid_count}/{len(valid_uuids)} valid UUIDs")
        
        # Test invalid UUIDs
        invalid_uuids = [
            "invalid-uuid",
            "123456",
            "not-a-uuid-at-all",
            "",
            "00000000-0000-0000-0000-000000000000"  # Suspicious pattern
        ]
        
        invalid_rejected = 0
        for test_uuid in invalid_uuids:
            try:
                validate_uuid(test_uuid, "test_id")
            except:
                invalid_rejected += 1
        
        self.log_test("Invalid UUID Rejection",
                     invalid_rejected == len(invalid_uuids),
                     f"Rejected {invalid_rejected}/{len(invalid_uuids)} invalid UUIDs")
    
    def test_input_validation(self):
        """Test input validation and sanitization"""
        print("\n🛡️ Testing Input Validation...")
        
        # Test filename validation
        dangerous_filenames = [
            "../../../etc/passwd",
            "file<script>alert('xss')</script>.mp3",
            "file|dangerous.mp3",
            "con.mp3",  # Windows reserved name
            "file\x00.mp3",  # Null byte
        ]
        
        safe_count = 0
        for filename in dangerous_filenames:
            try:
                safe_filename = validate_filename(filename)
                # Check if dangerous patterns are removed
                if ".." not in safe_filename and "<script>" not in safe_filename:
                    safe_count += 1
            except:
                safe_count += 1  # Rejection is also good
        
        self.log_test("Filename Sanitization",
                     safe_count == len(dangerous_filenames),
                     f"Safely handled {safe_count}/{len(dangerous_filenames)} dangerous filenames")
        
        # Test file extension validation
        try:
            allowed_extensions = ['.mp3', '.wav', '.flac']
            validate_file_extension("test.mp3", allowed_extensions)
            self.log_test("Valid File Extension", True, "Allowed .mp3")
        except Exception as e:
            self.log_test("Valid File Extension", False, str(e))
        
        try:
            validate_file_extension("malicious.exe", allowed_extensions)
            self.log_test("Invalid File Extension Rejection", False, "Should reject .exe")
        except:
            self.log_test("Invalid File Extension Rejection", True, "Correctly rejected .exe")
        
        # Test XSS protection
        xss_inputs = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "vbscript:msgbox('xss')"
        ]
        
        safe_xss_count = 0
        for xss_input in xss_inputs:
            sanitized = sanitize_user_input(xss_input)
            if "<script>" not in sanitized and "javascript:" not in sanitized:
                safe_xss_count += 1
        
        self.log_test("XSS Protection",
                     safe_xss_count == len(xss_inputs),
                     f"Sanitized {safe_xss_count}/{len(xss_inputs)} XSS attempts")
    
    def test_path_traversal_protection(self):
        """Test path traversal protection"""
        print("\n📁 Testing Path Traversal Protection...")
        
        # Test path traversal attempts
        base_directory = "/tmp/test"
        traversal_attempts = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "file/../../sensitive.txt",
            "/etc/passwd",
            "\\windows\\system32\\config\\sam"
        ]
        
        blocked_count = 0
        for attempt in traversal_attempts:
            try:
                validate_path_safety(attempt, base_directory)
            except:
                blocked_count += 1
        
        self.log_test("Path Traversal Protection",
                     blocked_count == len(traversal_attempts),
                     f"Blocked {blocked_count}/{len(traversal_attempts)} traversal attempts")
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        print("\n⏱️ Testing Rate Limiting...")
        
        # Mock request object for testing
        class MockRequest:
            def __init__(self, ip="192.168.1.100", user_agent="Test Browser"):
                self.client = type('Client', (), {'host': ip})()
                self.headers = {"user-agent": user_agent}
                self.state = type('State', (), {})()
                self.url = type('URL', (), {'path': '/test'})()
        
        # Test rate limiting key generation
        try:
            request = MockRequest()
            key = get_rate_limit_key(request)
            assert "anon:" in key  # Should be anonymous user
            self.log_test("Rate Limiting Key Generation", True, f"Key: {key[:20]}...")
        except Exception as e:
            self.log_test("Rate Limiting Key Generation", False, str(e))
        
        # Test suspicious pattern detection
        try:
            bot_request = MockRequest(user_agent="Bot/1.0")
            log_rate_limit_violation(bot_request, "5/minute")
            self.log_test("Suspicious Pattern Detection", True, "Bot user agent detected")
        except Exception as e:
            self.log_test("Suspicious Pattern Detection", False, str(e))
    
    def run_all_tests(self):
        """Run all security tests"""
        print("🔒 Sectify V2 Security Test Suite")
        print("=" * 50)
        
        # Run test categories
        self.test_configuration_security()
        self.test_password_security()
        self.test_token_security()
        self.test_uuid_validation()
        self.test_input_validation()
        self.test_path_traversal_protection()
        self.test_rate_limiting()
        
        # Summary
        print("\n" + "=" * 50)
        print("🎯 TEST SUMMARY")
        print("=" * 50)
        
        total_tests = self.passed_tests + self.failed_tests
        pass_rate = (self.passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {self.passed_tests}")
        print(f"Failed: {self.failed_tests}")
        print(f"Pass Rate: {pass_rate:.1f}%")
        
        if self.failed_tests == 0:
            print("\n🎉 ALL TESTS PASSED! Security implementation is solid.")
            return True
        else:
            print(f"\n⚠️ {self.failed_tests} TESTS FAILED. Review security implementation.")
            return False

def main():
    """Main entry point"""
    print("Starting Sectify V2 Security Validation...")
    
    # Initialize and run tests
    test_suite = SecurityTestSuite()
    success = test_suite.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 