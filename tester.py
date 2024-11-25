import requests
import concurrent.futures
import time
import random
import string
import secrets
import json
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class SecurityTester:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
        self.legitimate_ips = ["127.0.0.1", "192.168.1.100"]
        self.attack_ips = ["10.0.0.1", "10.0.0.2"]
        self.test_results = []
        self.test_run_id = secrets.token_hex(4)  # Generate unique ID for this test run
    
    def generate_test_username(self, prefix):
        """Generate unique username for testing"""
        timestamp = int(time.time())
        return f"test_{prefix}_{self.test_run_id}_{timestamp}"
    
    def log_result(self, test_name, success, details):
        """Log test results for final report"""
        self.test_results.append({
            "test_name": test_name,
            "success": success,
            "details": details,
            "timestamp": datetime.now().isoformat()
        })

    def test_legitimate_traffic(self):
        """Test if legitimate IPs can access the service"""
        print("\nTesting legitimate traffic handling...")
        
        for ip in self.legitimate_ips:
            try:
                headers = {"X-Forwarded-For": ip}
                # Test registration with unique username
                test_username = self.generate_test_username(ip.replace('.', '_'))
                response = requests.get(
                    f"{self.base_url}/register",
                    params={"user": test_username, "pass": "Test123!@#"},
                    headers=headers,
                    verify=False
                )
                
                success = response.status_code == 201
                self.log_result(
                    f"Legitimate IP Access Test ({ip})",
                    success,
                    f"Status: {response.status_code}, Response: {response.text}"
                )
                
            except Exception as e:
                self.log_result(
                    f"Legitimate IP Access Test ({ip})",
                    False,
                    f"Error: {str(e)}"
                )

    def test_attack_ip_blocking(self):
        """Test if attack IPs are properly blocked"""
        print("\nTesting attack IP blocking...")
        
        for ip in self.attack_ips:
            try:
                headers = {"X-Forwarded-For": ip}
                # Make multiple rapid requests to trigger rate limiting
                responses = []
                for _ in range(150):  # Exceed the rate limit
                    response = requests.get(
                        f"{self.base_url}/login",
                        params={"user": "test", "pass": "test"},
                        headers=headers,
                        verify=False
                    )
                    responses.append(response.status_code)
                
                # Check if the IP was eventually blocked
                was_blocked = 403 in responses or 429 in responses
                self.log_result(
                    f"Attack IP Blocking Test ({ip})",
                    was_blocked,
                    f"IP was{' ' if was_blocked else ' not '}blocked after multiple requests"
                )
                
            except Exception as e:
                self.log_result(
                    f"Attack IP Blocking Test ({ip})",
                    False,
                    f"Error: {str(e)}"
                )

    def test_sql_injection(self):
        """Test SQL injection prevention"""
        print("\nTesting SQL injection prevention...")
        
        sql_injection_attempts = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users; --",
            "admin'--",
        ]
        
        for attempt in sql_injection_attempts:
            try:
                response = requests.get(
                    f"{self.base_url}/login",
                    params={"user": attempt, "pass": "anything"},
                    verify=False
                )
                
                success = response.status_code in [400, 401, 403]  # Should be blocked
                self.log_result(
                    f"SQL Injection Test ({attempt[:20]}...)",
                    success,
                    f"Status: {response.status_code}, Response: {response.text}"
                )
                
            except Exception as e:
                self.log_result(
                    f"SQL Injection Test ({attempt[:20]}...)",
                    False,
                    f"Error: {str(e)}"
                )

    def test_cookie_security(self):
        """Test cookie security and validation"""
        print("\nTesting cookie security...")
        
        try:
            test_username = self.generate_test_username('cookie')
            
            # Use a dictionary to track our test IPs
            test_ips = {
                'register': "192.168.1.200",
                'login': "192.168.1.201",
                'test1': "192.168.1.202",
                'test2': "192.168.1.203",
                'test3': "192.168.1.204",
                'test4': "192.168.1.205"
            }

            # Register a test user
            register_response = requests.get(
                f"{self.base_url}/register",
                params={"user": test_username, "pass": "Test123!@#"},
                headers={"X-Forwarded-For": test_ips['register']},
                verify=False
            )
            
            if register_response.status_code != 201:
                self.log_result(
                    "Cookie Security Test - Registration",
                    False,
                    f"Failed to register test user. Status: {register_response.status_code}, Response: {register_response.text}"
                )
                return

            # Short delay after registration
            time.sleep(1)

            # Login with different IP
            login_response = requests.get(
                f"{self.base_url}/login",
                params={"user": test_username, "pass": "Test123!@#"},
                headers={"X-Forwarded-For": test_ips['login']},
                verify=False
            )
            
            if login_response.status_code != 200:
                self.log_result(
                    "Cookie Security Test - Login",
                    False,
                    f"Failed to login test user. Status: {login_response.status_code}, Response: {login_response.text}"
                )
                return

            valid_cookie = login_response.cookies.get('session', '')
            
            # Test cookie manipulation attempts
            manipulated_cookies = [
                "' OR '1'='1",
                f"{valid_cookie}_modified" if valid_cookie else "modified",
                "fake_cookie_value",
                "../../../../etc/passwd"
            ]
            
            success_count = 0
            for i, cookie in enumerate(manipulated_cookies):
                # Use a different IP for each test
                test_ip = test_ips[f'test{i+1}']
                
                response = requests.get(
                    f"{self.base_url}/manage",
                    params={"action": "balance"},
                    cookies={"session": cookie},
                    headers={"X-Forwarded-For": test_ip},
                    verify=False
                )
                
                if response.status_code in [401, 403]:  # Should be unauthorized
                    success_count += 1
                
                # Small delay between requests
                time.sleep(0.5)
            
            success = success_count == len(manipulated_cookies)
            self.log_result(
                "Cookie Security Test",
                success,
                f"Blocked {success_count}/{len(manipulated_cookies)} invalid cookie attempts"
            )
                
        except Exception as e:
            self.log_result(
                "Cookie Security Test",
                False,
                f"Error: {str(e)}"
            )



    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        print("\nTesting rate limiting...")
        
        try:
            start_time = time.time()
            responses = []
            total_requests = 100  # Increased to ensure we hit rate limits
            
            # Make rapid requests to trigger rate limiting
            for _ in range(total_requests):
                response = requests.get(
                    f"{self.base_url}/login",
                    params={"user": "test", "pass": "test"},
                    verify=False
                )
                responses.append(response.status_code)
                
                # Small delay to prevent overwhelming the server
                time.sleep(0.01)
            
            time_taken = time.time() - start_time
            rate_limited_responses = sum(1 for code in responses if code in [429, 403])
            
            # Success if we got any rate limiting responses
            success = rate_limited_responses > 0
            
            self.log_result(
                "Rate Limiting Test",
                success,
                f"Time taken: {time_taken:.2f}s, Rate limited requests: {rate_limited_responses}/{total_requests}"
            )
                
        except Exception as e:
            self.log_result(
                "Rate Limiting Test",
                False,
                f"Error: {str(e)}"
            )



    def generate_report(self):
        """Generate a comprehensive security test report"""
        print("\n=== Security Test Report ===")
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result["success"])
        
        print(f"\nSummary:")
        print(f"Total Tests: {total_tests}")
        print(f"Passed Tests: {passed_tests}")
        print(f"Failed Tests: {total_tests - passed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.2f}%")
        
        print("\nDetailed Results:")
        for result in self.test_results:
            status = "✅ PASSED" if result["success"] else "❌ FAILED"
            print(f"\n{status} - {result['test_name']}")
            print(f"Details: {result['details']}")
            print(f"Timestamp: {result['timestamp']}")

    def run_all_tests(self):
        """Run all security tests"""
        print("Starting security tests...\n")
        
        test_functions = [
            self.test_legitimate_traffic,
            self.test_attack_ip_blocking,
            self.test_sql_injection,
            self.test_cookie_security,
            self.test_rate_limiting
        ]
        
        for test_func in test_functions:
            try:
                test_func()
            except Exception as e:
                self.log_result(
                    test_func.__name__,
                    False,
                    f"Test suite error: {str(e)}"
                )
        
        self.generate_report()

if __name__ == "__main__":
    tester = SecurityTester()
    tester.run_all_tests()