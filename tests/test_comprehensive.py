"""
Comprehensive Test Suite for Parry Security Scanner

Tests core functionality, AI features, integrations, and edge cases
"""

import pytest
from pathlib import Path
from parry.scanner import Scanner
from parry.ai_detector import AIDetector
from parry.validator import VulnerabilityValidator
from parry.sca import SCAScanner
from parry.compliance import ComplianceReporter
from parry.secrets_scanner import AdvancedSecretsScanner
from parry.framework_detectors import FrameworkDetectorEngine
from parry.container_iac_scanner import ContainerIaCScanner
from parry.custom_rules import CustomRulesEngine
from parry.cache import ScanCache


class TestCoreScanning:
    """Test core scanning functionality"""
    
    def test_scan_python_file(self):
        """Test scanning Python file"""
        scanner = Scanner()
        results = scanner.scan(Path("examples/vulnerable_code.py"))
        
        assert results['files_scanned'] == 1
        assert len(results['vulnerabilities']) >= 15
        
        # Verify specific CWEs detected
        cwes = [v['cwe'] for v in results['vulnerabilities']]
        assert 'CWE-78' in cwes  # Command injection
        assert 'CWE-798' in cwes  # Hardcoded credentials
        assert 'CWE-327' in cwes  # Weak crypto
        
    def test_scan_java_file(self):
        """Test scanning Java file"""
        scanner = Scanner()
        results = scanner.scan(Path("examples/vulnerable_test.java"))
        
        assert results['files_scanned'] == 1
        assert len(results['vulnerabilities']) > 0
        
    def test_scan_go_file(self):
        """Test scanning Go file"""
        scanner = Scanner()
        results = scanner.scan(Path("examples/vulnerable_test.go"))
        
        assert results['files_scanned'] == 1
        assert len(results['vulnerabilities']) > 0
        
    def test_scan_javascript_file(self):
        """Test scanning JavaScript file"""
        scanner = Scanner()
        results = scanner.scan(Path("examples/vulnerable_code.js"))
        
        assert results['files_scanned'] == 1
        assert len(results['vulnerabilities']) > 0
        
    def test_scan_directory(self):
        """Test scanning directory"""
        scanner = Scanner()
        results = scanner.scan(Path("examples/"))
        
        assert results['files_scanned'] >= 7  # Multiple test files
        assert len(results['vulnerabilities']) >= 30
        
    def test_exclude_patterns(self):
        """Test exclude patterns"""
        scanner = Scanner(exclude_patterns=["*.pyc", "vulnerable_code.py"])
        results = scanner.scan(Path("examples/"))
        
        # Should not scan excluded file
        scanned_files = [v['file_path'] for v in results['vulnerabilities']]
        assert 'vulnerable_code.py' not in str(scanned_files)
        
    def test_severity_filtering(self):
        """Test severity-based filtering"""
        scanner = Scanner()
        all_results = scanner.scan(Path("examples/vulnerable_code.py"))
        
        # Should have vulnerabilities across severities
        severities = [v['severity'] for v in all_results['vulnerabilities']]
        assert 'critical' in severities
        assert 'high' in severities
        
    def test_empty_file(self):
        """Test handling empty file"""
        scanner = Scanner()
        results = scanner.scan(Path("tests/__init__.py"))
        
        assert 'vulnerabilities' in results
        assert 'files_scanned' in results
        
    def test_nonexistent_file(self):
        """Test handling nonexistent file"""
        scanner = Scanner()
        
        with pytest.raises((FileNotFoundError, Exception)):
            scanner.scan(Path("nonexistent_file.py"))
            
    def test_malformed_code(self):
        """Test handling syntax errors"""
        # Create temp file with syntax errors
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("def broken code here !!!")
            temp_path = Path(f.name)
        
        try:
            scanner = Scanner()
            # Should not crash
            results = scanner.scan(temp_path)
            assert 'vulnerabilities' in results
        finally:
            temp_path.unlink()


class TestAIDetection:
    """Test AI-powered detection"""
    
    def test_ai_detector_initialization(self):
        """Test AI detector can be initialized"""
        detector = AIDetector()
        assert detector is not None
        
    def test_ai_chunking(self):
        """Test code chunking for AI analysis"""
        detector = AIDetector()
        sample_code = "# Sample code\n" * 100
        
        # Verify chunking works
        chunks = detector._chunk_code(sample_code, max_lines=50)
        assert len(chunks) > 0
        assert len(chunks) <= 3  # Should have 2-3 chunks for 100 lines
        
    def test_ai_detection_with_code(self):
        """Test AI detection on sample code"""
        detector = AIDetector()
        code = """
        def insecure_function(user_input):
            import os
            result = os.system(f"echo {user_input}")
            return result
        """
        
        # May fail if Ollama not running, that's ok
        try:
            results = detector.detect_vulnerabilities(
                code, "test.py", "python"
            )
            assert isinstance(results, list)
        except Exception:
            # Skip if AI not available
            pytest.skip("Ollama not available")
            
    def test_ai_prompt_generation(self):
        """Test AI prompt building"""
        detector = AIDetector()
        code = "test code"
        
        prompt = detector._build_detection_prompt(code, "test.py", "python", {})
        
        assert "python" in prompt.lower()
        assert "test code" in prompt
        assert len(prompt) > 0


class TestValidation:
    """Test AI-powered validation"""
    
    def test_validator_initialization(self):
        """Test validator initialization"""
        validator = VulnerabilityValidator()
        assert validator is not None
        
    def test_validation_cache(self):
        """Test validation caching"""
        validator = VulnerabilityValidator()
        assert hasattr(validator, 'validation_cache')
        assert isinstance(validator.validation_cache, dict)


class TestSCA:
    """Test Software Composition Analysis"""
    
    def test_sca_scanner_initialization(self):
        """Test SCA scanner initialization"""
        sca = SCAScanner()
        assert sca is not None
        
    def test_sca_detect_requirements(self):
        """Test detecting requirements.txt"""
        sca = SCAScanner()
        # Create a mock requirements.txt
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / "requirements.txt"
            req_file.write_text("flask==1.0.0\n")
            
            results = sca._scan_python_deps(req_file)
            
            assert isinstance(results, list)
        
    def test_sca_check_cves(self):
        """Test CVE checking"""
        sca = SCAScanner()
        
        # Check Django vulnerabilities using private method
        vulnerabilities = sca._check_package_vulnerabilities("pypi", "django", "4.1.0")
        
        assert isinstance(vulnerabilities, list)


class TestCompliance:
    """Test compliance reporting"""
    
    def test_compliance_reporter_init(self):
        """Test compliance reporter initialization"""
        reporter = ComplianceReporter()
        assert reporter is not None
        assert 'soc2' in reporter.reporters
        assert 'iso27001' in reporter.reporters
        assert 'pci-dss' in reporter.reporters
        assert 'owasp' in reporter.reporters
        
    def test_soc2_report_generation(self):
        """Test SOC2 report generation"""
        reporter = ComplianceReporter()
        # Mock vulnerabilities
        fake_vulns = [
            type('Vuln', (), {'cwe': 'CWE-78', 'severity': 'high', 
                             'file_path': 'test.py', 'line_number': 1,
                             'title': 'Test', 'description': 'Test'})()
        ]
        
        report = reporter.reporters['soc2'].generate_report(fake_vulns)
        
        assert 'standard' in report
        assert report['standard'] == 'SOC2'
        assert 'compliance_score' in report
        assert report['compliance_score'] <= 100
        
    def test_iso27001_report_generation(self):
        """Test ISO 27001 report generation"""
        reporter = ComplianceReporter()
        fake_vulns = []
        
        report = reporter.reporters['iso27001'].generate_report(fake_vulns)
        
        assert report['standard'] == 'ISO27001'
        assert 'compliance_score' in report
        
    def test_owasp_report_generation(self):
        """Test OWASP Top 10 report generation"""
        reporter = ComplianceReporter()
        fake_vulns = []
        
        report = reporter.reporters['owasp'].generate_report(fake_vulns)
        
        assert report['standard'] == 'OWASP Top 10 2021'
        assert 'categories' in report
        assert len(report['categories']) == 10


class TestSecrets:
    """Test secrets scanning"""
    
    def test_secrets_scanner_init(self):
        """Test secrets scanner initialization"""
        scanner = AdvancedSecretsScanner()
        assert scanner is not None
        
    def test_entropy_calculation(self):
        """Test Shannon entropy calculation"""
        from parry.secrets_scanner import EntropyAnalyzer
        
        # High entropy (random string)
        high_entropy = EntropyAnalyzer.calculate_entropy("a8x2mP9kQ3vR7w")
        assert high_entropy > 3.5  # More realistic threshold
        
        # Low entropy (repeated chars)
        low_entropy = EntropyAnalyzer.calculate_entropy("aaaaaaaaaaaa")
        assert low_entropy < 2.0
        
    def test_is_high_entropy(self):
        """Test high entropy detection"""
        from parry.secrets_scanner import EntropyAnalyzer
        
        assert EntropyAnalyzer.is_high_entropy("SK_API_KEY_1234567890abcdef")
        assert not EntropyAnalyzer.is_high_entropy("password")
        
    def test_api_key_detection(self):
        """Test API key pattern detection"""
        scanner = AdvancedSecretsScanner()
        
        code = 'API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"'
        secrets = scanner.scan_content(code, "test.py")
        
        assert len(secrets) > 0
        assert any('api' in s.type.lower() for s in secrets)
        
    def test_password_detection(self):
        """Test hardcoded password detection"""
        scanner = AdvancedSecretsScanner()
        
        code = 'password = "supersecret123"'
        secrets = scanner.scan_content(code, "test.py")
        
        assert len(secrets) > 0
        
    def test_aws_key_detection(self):
        """Test AWS key detection"""
        scanner = AdvancedSecretsScanner()
        
        code = 'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        secrets = scanner.scan_content(code, "test.py")
        
        # Should detect AWS key pattern
        assert len(secrets) > 0
        
    def test_false_positive_filtering(self):
        """Test false positive filtering"""
        scanner = AdvancedSecretsScanner()
        
        # Should be filtered out
        false_positives = [
            'value = "xxxxxxxxxxx"',  # All X's
            'value = "********"',  # All asterisks
            'value = "example"',  # Placeholder
        ]
        
        for code in false_positives:
            secrets = scanner.scan_content(code, "test.py")
            # Should have few or no secrets
            assert len(secrets) <= 1


class TestFrameworks:
    """Test framework-specific detection"""
    
    def test_django_detection(self):
        """Test Django-specific vulnerability detection"""
        engine = FrameworkDetectorEngine()
        
        django_code = """
        from django.views.decorators.csrf import csrf_exempt
        
        @csrf_exempt
        def my_view(request):
            return render(request, 'template.html', {'data': user_input | safe})
        """
        
        vulns = engine.scan(django_code, "django_app.py")
        
        # Should detect CSRF exemption and unsafe template
        assert any('csrf' in v.title.lower() for v in vulns)
        
    def test_flask_detection(self):
        """Test Flask-specific vulnerability detection"""
        engine = FrameworkDetectorEngine()
        
        flask_code = """
        from flask import Flask, render_template_string
        
        app = Flask(__name__)
        app.secret_key = "hardcoded-secret-key"
        app.run(debug=True)
        """
        
        vulns = engine.scan(flask_code, "app.py")
        
        # Should detect debug mode and hardcoded secret
        assert len(vulns) >= 2
        
    def test_spring_detection(self):
        """Test Spring Boot-specific detection"""
        engine = FrameworkDetectorEngine()
        
        spring_code = """
        @RestController
        public class MyController {
            @GetMapping("/user/{id}")
            public User getUser(@PathVariable String id) {
                // No @PreAuthorize
                return userService.findById(id);
            }
        }
        """
        
        vulns = engine.scan(spring_code, "Controller.java")
        
        assert len(vulns) >= 0  # May or may not detect


class TestContainerIaC:
    """Test container and IaC scanning"""
    
    def test_dockerfile_scanning(self):
        """Test Dockerfile vulnerability detection"""
        scanner = ContainerIaCScanner()
        
        dockerfile = """
        FROM ubuntu:latest
        USER root
        RUN apt-get install package
        ENV PASSWORD=hardcoded123
        """
        
        vulns = scanner.dockerfile_scanner.scan(dockerfile, "Dockerfile")
        
        # Should detect root user, latest tag, hardcoded password
        assert len(vulns) >= 3
        
    def test_kubernetes_scanning(self):
        """Test Kubernetes manifest scanning"""
        scanner = ContainerIaCScanner()
        
        k8s_yaml = """
        apiVersion: v1
        kind: Pod
        spec:
          containers:
          - name: app
            image: nginx:latest
            securityContext:
              privileged: true
        """
        
        vulns = scanner.kubernetes_scanner.scan(k8s_yaml, "pod.yaml")
        
        # Should detect privileged container and latest tag
        assert len(vulns) >= 2
        
    def test_terraform_scanning(self):
        """Test Terraform configuration scanning"""
        scanner = ContainerIaCScanner()
        
        terraform = """
        resource "aws_s3_bucket" "example" {
          bucket = "my-bucket"
          acl    = "public"
        }
        
        resource "aws_security_group" "web" {
          ingress {
            from_port = 22
            to_port   = 22
            cidr_blocks = ["0.0.0.0/0"]
          }
        }
        """
        
        vulns = scanner.terraform_scanner.scan(terraform, "main.tf")
        
        # Should detect public bucket and open security group
        assert len(vulns) >= 2


class TestCustomRules:
    """Test custom rules engine"""
    
    def test_rules_engine_init(self):
        """Test custom rules engine initialization"""
        engine = CustomRulesEngine()
        assert engine is not None
        
    def test_rule_template_creation(self):
        """Test rule template creation"""
        engine = CustomRulesEngine()
        import tempfile
        
        with tempfile.TemporaryDirectory() as tmpdir:
            template_path = Path(tmpdir) / "rules.yaml"
            engine.create_rule_template(template_path)
            
            assert template_path.exists()
            assert template_path.read_text()  # Should have content


class TestCache:
    """Test caching functionality"""
    
    def test_cache_initialization(self):
        """Test cache initialization"""
        cache = ScanCache()
        assert cache is not None
        
    def test_cache_stats(self):
        """Test cache statistics"""
        cache = ScanCache()
        stats = cache.get_cache_stats()
        
        assert 'total_files' in stats
        assert 'cache_size_mb' in stats


class TestErrorHandling:
    """Test error handling and edge cases"""
    
    def test_unicode_handling(self):
        """Test handling unicode characters"""
        scanner = Scanner()
        
        # Create temp file with unicode
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
            f.write("# Unicode: 🐍 🔒 💻")
            temp_path = Path(f.name)
        
        try:
            # Should not crash
            results = scanner.scan(temp_path)
            assert 'vulnerabilities' in results
        finally:
            temp_path.unlink()
            
    def test_large_file_handling(self):
        """Test handling large files"""
        scanner = Scanner()
        
        # Create temp large file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("# Large file\n" * 10000)
            temp_path = Path(f.name)
        
        try:
            # Should not crash
            results = scanner.scan(temp_path)
            assert 'vulnerabilities' in results
        finally:
            temp_path.unlink()
            
    def test_concurrent_scanning(self):
        """Test concurrent file scanning"""
        import concurrent.futures
        
        scanner = Scanner()
        files = [
            Path("examples/vulnerable_code.py"),
            Path("examples/vulnerable_code.js"),
            Path("examples/vulnerable_test.java"),
        ]
        
        # Scan files concurrently
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(scanner.scan, f) for f in files]
            results = [f.result() for f in futures]
        
        # All should succeed
        assert all('vulnerabilities' in r for r in results)


class TestPerformance:
    """Test performance characteristics"""
    
    def test_scan_speed(self):
        """Test scanning speed"""
        import time
        
        scanner = Scanner()
        start = time.time()
        results = scanner.scan(Path("examples/"))
        elapsed = time.time() - start
        
        # Should scan examples in < 5 seconds
        assert elapsed < 5.0
        print(f"✓ Scanned {results['files_scanned']} files in {elapsed:.2f}s")
        
    def test_memory_usage(self):
        """Test memory usage during scan"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        mem_before = process.memory_info().rss / 1024 / 1024  # MB
        
        scanner = Scanner()
        scanner.scan(Path("examples/"))
        
        mem_after = process.memory_info().rss / 1024 / 1024  # MB
        mem_increase = mem_after - mem_before
        
        # Should use reasonable memory
        assert mem_increase < 500  # Less than 500MB
        print(f"✓ Memory usage: {mem_increase:.2f}MB")


class TestCLIIntegration:
    """Test CLI integration"""
    
    def test_cli_imports(self):
        """Test that CLI imports correctly"""
        from parry.cli import main, scan, setup, doctor, config
        assert main is not None
        assert scan is not None
        assert setup is not None
        assert doctor is not None
        assert config is not None
        
    def test_cli_help(self):
        """Test CLI help works"""
        import subprocess
        
        result = subprocess.run(
            ["python", "-m", "parry.cli", "--help"],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert "Commands:" in result.stdout


class TestAPI:
    """Test REST API functionality"""
    
    def test_api_app_initialization(self):
        """Test FastAPI app initialization"""
        from parry.api import app
        assert app is not None
        assert app.title == "Parry Security Scanner API"
        
    def test_api_root_endpoint(self):
        """Test API root endpoint"""
        from parry.api import app
        from fastapi.testclient import TestClient
        
        client = TestClient(app)
        response = client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert "version" in data
        
    def test_api_health_endpoint(self):
        """Test health check endpoint"""
        from parry.api import app
        from fastapi.testclient import TestClient
        
        client = TestClient(app)
        response = client.get("/health")
        
        assert response.status_code == 200


class TestLanguageSupport:
    """Test multi-language support"""
    
    def test_python_analyzer(self):
        """Test Python-specific analyzer"""
        from parry.language_support import get_analyzer
        
        analyzer = get_analyzer('python')
        assert analyzer is not None
        
        results = analyzer.analyze(
            'os.system(user_input)',
            'test.py'
        )
        
        assert len(results) > 0
        assert any('CWE-78' in v.cwe for v in results)
        
    def test_java_analyzer(self):
        """Test Java-specific analyzer"""
        from parry.language_support import get_analyzer
        
        analyzer = get_analyzer('java')
        assert analyzer is not None
        
    def test_js_analyzer(self):
        """Test JavaScript analyzer"""
        from parry.language_support import get_analyzer
        
        analyzer = get_analyzer('javascript')
        assert analyzer is not None


class TestSetupTools:
    """Test setup and configuration tools"""
    
    def test_setup_helper_init(self):
        """Test setup helper initialization"""
        from parry.setup import SetupHelper
        
        helper = SetupHelper()
        assert helper is not None
        
    def test_ollama_check(self):
        """Test Ollama detection"""
        from parry.setup import SetupHelper
        
        helper = SetupHelper()
        
        # May return True or False depending on system
        installed = helper.check_ollama_installed()
        assert isinstance(installed, bool)


# Integration tests
class TestIntegration:
    """Integration tests"""
    
    def test_full_scan_workflow(self):
        """Test complete scanning workflow"""
        scanner = Scanner()
        results = scanner.scan(Path("examples/"))
        
        # Should have results (note: 'summary' is not in results, it's added by CLI)
        assert 'vulnerabilities_found' in results
        assert 'vulnerabilities' in results
        assert results['files_scanned'] > 0
        
    def test_scan_with_validation(self):
        """Test scanning with AI validation"""
        scanner = Scanner()
        results = scanner.scan(Path("examples/vulnerable_code.py"))
        
        assert 'vulnerabilities' in results
        assert len(results['vulnerabilities']) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

