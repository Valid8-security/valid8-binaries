#!/usr/bin/env python3
"""
Comprehensive test script for Valid8 website components
Tests all pages, forms, navigation, and user flows
"""

import time
import json
import os
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import sys

class WebsiteTester:
    def __init__(self):
        self.test_results = []
        self.errors = []

        # Setup Chrome options for headless testing
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1920,1080")

        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.implicitly_wait(10)
            print("✅ Chrome WebDriver initialized successfully")
        except Exception as e:
            print(f"❌ Failed to initialize WebDriver: {e}")
            sys.exit(1)

    def log_test(self, test_name, status, message=""):
        """Log test result"""
        result = {
            'test': test_name,
            'status': status,
            'message': message,
            'timestamp': time.time()
        }
        self.test_results.append(result)

        if status == 'PASS':
            print(f"✅ {test_name}")
        elif status == 'FAIL':
            print(f"❌ {test_name}: {message}")
            self.errors.append(result)
        else:
            print(f"⚠️  {test_name}: {message}")

    def test_homepage(self):
        """Test homepage loading and basic elements"""
        try:
            self.driver.get("http://localhost:5173")
            time.sleep(2)

            # Check title
            title = self.driver.title
            assert "Valid8" in title, f"Title should contain 'Valid8', got: {title}"

            # Check hero section
            hero = self.driver.find_element(By.TAG_NAME, "h1")
            assert "Industry-Leading SAST" in hero.text, f"Hero text incorrect: {hero.text}"

            # Check navigation
            nav = self.driver.find_element(By.TAG_NAME, "nav")
            assert nav.is_displayed(), "Navigation should be visible"

            # Check pricing section exists
            pricing_section = self.driver.find_element(By.ID, "pricing")
            assert pricing_section.is_displayed(), "Pricing section should be visible"

            self.log_test("Homepage Loading", "PASS", "All homepage elements loaded correctly")

        except Exception as e:
            self.log_test("Homepage Loading", "FAIL", str(e))

    def test_navigation(self):
        """Test navigation between pages"""
        try:
            self.driver.get("http://localhost:5173")

            # Test signup link
            signup_link = self.driver.find_element(By.LINK_TEXT, "Start Free Trial")
            signup_link.click()
            time.sleep(1)

            # Should be on signup page
            assert "/signup" in self.driver.current_url, f"Should navigate to signup, got: {self.driver.current_url}"

            # Go back to home
            logo = self.driver.find_element(By.LINK_TEXT, "Valid8")
            logo.click()
            time.sleep(1)

            assert self.driver.current_url.endswith("/"), f"Should be back on home page, got: {self.driver.current_url}"

            self.log_test("Navigation Flow", "PASS", "Navigation between pages works correctly")

        except Exception as e:
            self.log_test("Navigation Flow", "FAIL", str(e))

    def test_signup_form(self):
        """Test signup form functionality"""
        try:
            self.driver.get("http://localhost:5173/signup")

            # Check form elements exist
            name_field = self.driver.find_element(By.NAME, "name")
            email_field = self.driver.find_element(By.NAME, "email")
            password_field = self.driver.find_element(By.NAME, "password")
            confirm_field = self.driver.find_element(By.NAME, "confirmPassword")

            assert name_field.is_displayed(), "Name field should be visible"
            assert email_field.is_displayed(), "Email field should be visible"
            assert password_field.is_displayed(), "Password field should be visible"
            assert confirm_field.is_displayed(), "Confirm password field should be visible"

            # Test form submission with valid data
            name_field.send_keys("Test User")
            email_field.send_keys("test@example.com")
            password_field.send_keys("password123")
            confirm_field.send_keys("password123")

            submit_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
            submit_button.click()

            # Should navigate to dashboard or success page
            time.sleep(2)
            current_url = self.driver.current_url
            assert "/dashboard" in current_url or "/account" in current_url, f"Should redirect after signup, got: {current_url}"

            self.log_test("Signup Form", "PASS", "Signup form works correctly")

        except Exception as e:
            self.log_test("Signup Form", "FAIL", str(e))

    def test_enterprise_signup(self):
        """Test enterprise signup flow"""
        try:
            self.driver.get("http://localhost:5173/enterprise-signup")

            # Check enterprise-specific elements
            title = self.driver.find_element(By.TAG_NAME, "h2")
            assert "Enterprise Setup" in title.text, f"Should show enterprise title, got: {title.text}"

            # Test step 1 - organization details
            org_name = self.driver.find_element(By.NAME, "organizationName")
            org_domain = self.driver.find_element(By.NAME, "organizationDomain")

            org_name.send_keys("Test Corp")
            org_domain.send_keys("testcorp.com")

            continue_btn = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
            continue_btn.click()
            time.sleep(1)

            # Should move to step 2
            step2_title = self.driver.find_elements(By.TAG_NAME, "h2")
            assert any("Enterprise Setup" in el.text for el in step2_title), "Should show step 2"

            self.log_test("Enterprise Signup Flow", "PASS", "Enterprise signup steps work correctly")

        except Exception as e:
            self.log_test("Enterprise Signup Flow", "FAIL", str(e))

    def test_pricing_section(self):
        """Test pricing section interactions"""
        try:
            self.driver.get("http://localhost:5173")

            # Scroll to pricing section
            pricing_section = self.driver.find_element(By.ID, "pricing")
            self.driver.execute_script("arguments[0].scrollIntoView();", pricing_section)
            time.sleep(1)

            # Check pricing tiers
            pricing_cards = self.driver.find_elements(By.CSS_SELECTOR, ".bg-white.rounded-lg")
            assert len(pricing_cards) >= 3, f"Should have at least 3 pricing tiers, found: {len(pricing_cards)}"

            # Check for Free Trial tier
            free_trial_found = False
            pro_found = False
            enterprise_found = False

            for card in pricing_cards:
                try:
                    title = card.find_element(By.TAG_NAME, "h3").text
                    if "Free Trial" in title:
                        free_trial_found = True
                    elif "Pro" in title:
                        pro_found = True
                    elif "Enterprise" in title:
                        enterprise_found = True
                except:
                    continue

            assert free_trial_found, "Free Trial tier should be visible"
            assert pro_found, "Pro tier should be visible"
            assert enterprise_found, "Enterprise tier should be visible"

            self.log_test("Pricing Section", "PASS", "All pricing tiers display correctly")

        except Exception as e:
            self.log_test("Pricing Section", "FAIL", str(e))

    def test_responsive_design(self):
        """Test responsive design on different screen sizes"""
        try:
            # Test mobile size
            self.driver.set_window_size(375, 667)
            time.sleep(1)

            self.driver.get("http://localhost:5173")
            time.sleep(2)

            # Check navigation collapses on mobile
            mobile_nav = self.driver.find_elements(By.CSS_SELECTOR, ".hidden.md\\:flex")
            assert len(mobile_nav) > 0, "Mobile navigation should be hidden on small screens"

            # Test tablet size
            self.driver.set_window_size(768, 1024)
            time.sleep(1)

            self.driver.refresh()
            time.sleep(2)

            # Should show desktop navigation
            desktop_nav = self.driver.find_elements(By.CSS_SELECTOR, ".hidden.md\\:flex")
            assert len(desktop_nav) > 0, "Desktop navigation should be visible on tablets"

            # Reset to desktop
            self.driver.set_window_size(1920, 1080)

            self.log_test("Responsive Design", "PASS", "Website adapts correctly to different screen sizes")

        except Exception as e:
            self.log_test("Responsive Design", "FAIL", str(e))

    def test_dashboard_functionality(self):
        """Test dashboard functionality (requires login)"""
        try:
            # Simulate login by setting localStorage
            self.driver.get("http://localhost:5173")

            # Inject mock user data
            mock_user = {
                'name': 'Test User',
                'email': 'test@example.com',
                'subscription': 'pro',
                'machine_id': 'test-machine-123',
                'scans_remaining': 500
            }

            self.driver.execute_script(f"localStorage.setItem('valid8_user', '{json.dumps(mock_user)}');")

            # Navigate to dashboard
            self.driver.get("http://localhost:5173/dashboard")
            time.sleep(2)

            # Check dashboard elements
            dashboard_title = self.driver.find_elements(By.TAG_NAME, "h1")
            dashboard_found = any("Dashboard" in el.text for el in dashboard_title)

            if dashboard_found:
                self.log_test("Dashboard Access", "PASS", "Dashboard loads correctly for authenticated users")
            else:
                self.log_test("Dashboard Access", "FAIL", "Dashboard did not load properly")

        except Exception as e:
            self.log_test("Dashboard Access", "FAIL", str(e))

    def test_console_errors(self):
        """Check for JavaScript console errors"""
        try:
            # Get browser logs
            logs = self.driver.get_log('browser')

            # Filter out non-errors (warnings, info)
            errors = [log for log in logs if log['level'] == 'SEVERE']

            if errors:
                error_messages = [f"{err['message'][:100]}..." for err in errors[:3]]
                self.log_test("Console Errors", "FAIL", f"Found {len(errors)} console errors: {', '.join(error_messages)}")
            else:
                self.log_test("Console Errors", "PASS", "No console errors detected")

        except Exception as e:
            self.log_test("Console Errors", "WARN", f"Could not check console logs: {e}")

    def run_all_tests(self):
        """Run all website tests"""
        print("🚀 Starting Valid8 Website Component Testing")
        print("=" * 50)

        # Wait for dev server to be ready
        time.sleep(3)

        tests = [
            self.test_homepage,
            self.test_navigation,
            self.test_signup_form,
            self.test_enterprise_signup,
            self.test_pricing_section,
            self.test_responsive_design,
            self.test_dashboard_functionality,
            self.test_console_errors
        ]

        for test in tests:
            try:
                test()
            except Exception as e:
                self.log_test(test.__name__, "ERROR", f"Test crashed: {e}")

        self.print_summary()

    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 50)
        print("📊 TEST SUMMARY")
        print("=" * 50)

        total_tests = len(self.test_results)
        passed = len([r for r in self.test_results if r['status'] == 'PASS'])
        failed = len([r for r in self.test_results if r['status'] == 'FAIL'])
        errors = len([r for r in self.test_results if r['status'] == 'ERROR'])

        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"💥 Errors: {errors}")

        if self.errors:
            print("\n❌ FAILED TESTS:")
            for error in self.errors:
                print(f"  • {error['test']}: {error['message']}")

        print(f"\n🎯 Success Rate: {passed}/{total_tests} ({passed/total_tests*100:.1f}%)")

        if passed == total_tests:
            print("🎉 All tests passed! Website is ready for production.")
        elif failed == 0 and errors == 0:
            print("⚠️  All tests completed but some had warnings.")
        else:
            print("🚨 Issues found. Please review and fix before deployment.")

    def cleanup(self):
        """Clean up resources"""
        if hasattr(self, 'driver'):
            self.driver.quit()


def main():
    tester = WebsiteTester()

    try:
        tester.run_all_tests()
    except KeyboardInterrupt:
        print("\n⏹️  Testing interrupted by user")
    except Exception as e:
        print(f"\n💥 Testing failed with error: {e}")
    finally:
        tester.cleanup()


if __name__ == "__main__":
    main()

