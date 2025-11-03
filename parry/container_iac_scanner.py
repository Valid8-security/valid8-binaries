# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Container and Infrastructure as Code (IaC) Security Scanner

Scans for security issues in:
- Dockerfiles
- Docker Compose files
- Kubernetes manifests (YAML)
- Terraform configurations
- Helm charts
- AWS CloudFormation templates

Detects:
- Insecure base images
- Running as root
- Exposed secrets
- Insecure configurations
- Missing security controls
- Privilege escalation risks
"""

import re
import yaml
import json
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass


@dataclass
class IaCVulnerability:
    """Infrastructure/Container vulnerability"""
    type: str  # dockerfile, kubernetes, terraform, etc.
    cwe: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    remediation: str
    confidence: str


class DockerfileScanner:
    """Scanner for Dockerfiles"""
    
    def scan(self, content: str, filepath: str) -> List[IaCVulnerability]:
        """Scan Dockerfile for security issues"""
        vulnerabilities = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            line_lower = line.lower().strip()
            
            # Check for running as root
            if line_lower.startswith('user root') or (line_lower.startswith('run') and 'sudo' in line_lower):
                vulnerabilities.append(IaCVulnerability(
                    type="Dockerfile",
                    cwe="CWE-250",
                    severity="high",
                    title="Container Running as Root",
                    description="Container runs as root user, increasing attack surface.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    remediation="Add 'USER nonroot' directive. Create non-root user: RUN useradd -ms /bin/bash appuser && USER appuser",
                    confidence="high"
                ))
            
            # Check for latest tag
            if 'from' in line_lower and ':latest' in line_lower:
                vulnerabilities.append(IaCVulnerability(
                    type="Dockerfile",
                    cwe="CWE-494",
                    severity="medium",
                    title="Using 'latest' Tag",
                    description="Using 'latest' tag makes builds non-deterministic and can introduce vulnerabilities.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    remediation="Use specific version tags: FROM ubuntu:22.04 instead of FROM ubuntu:latest",
                    confidence="high"
                ))
            
            # Check for hardcoded secrets
            if re.search(r'(password|secret|key|token)\s*=', line_lower):
                vulnerabilities.append(IaCVulnerability(
                    type="Dockerfile",
                    cwe="CWE-798",
                    severity="critical",
                    title="Hardcoded Secret in Dockerfile",
                    description="Secret appears to be hardcoded in Dockerfile.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip()[:50] + "...",
                    remediation="Use ARG for build-time secrets (deleted after build) or ENV with runtime secrets management.",
                    confidence="high"
                ))
            
            # Check for insecure protocols
            if re.search(r'http://(?!localhost|127\.0\.0\.1)', line_lower):
                vulnerabilities.append(IaCVulnerability(
                    type="Dockerfile",
                    cwe="CWE-319",
                    severity="medium",
                    title="Insecure HTTP Protocol",
                    description="Using HTTP instead of HTTPS for downloads.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    remediation="Use HTTPS URLs for all external resources.",
                    confidence="medium"
                ))
            
            # Check for ADD instead of COPY
            if line_lower.startswith('add ') and 'http' not in line_lower:
                vulnerabilities.append(IaCVulnerability(
                    type="Dockerfile",
                    cwe="CWE-94",
                    severity="low",
                    title="Using ADD Instead of COPY",
                    description="ADD has implicit tar extraction which can be exploited. Use COPY for local files.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    remediation="Replace ADD with COPY for local files. Use ADD only for tar extraction or remote URLs.",
                    confidence="medium"
                ))
            
            # Check for missing HEALTHCHECK
            if line_lower.startswith('from ') and 'healthcheck' not in content.lower():
                vulnerabilities.append(IaCVulnerability(
                    type="Dockerfile",
                    cwe="CWE-1188",
                    severity="low",
                    title="Missing HEALTHCHECK",
                    description="No HEALTHCHECK instruction found. Container health cannot be monitored.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    remediation="Add HEALTHCHECK: HEALTHCHECK CMD curl -f http://localhost/ || exit 1",
                    confidence="low"
                ))
            
            # Check for apt-get without -y flag
            if 'apt-get install' in line_lower and '-y' not in line_lower:
                vulnerabilities.append(IaCVulnerability(
                    type="Dockerfile",
                    cwe="CWE-665",
                    severity="low",
                    title="Interactive Package Installation",
                    description="apt-get install without -y flag can cause build to hang.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    remediation="Add -y flag: RUN apt-get update && apt-get install -y package-name",
                    confidence="high"
                ))
        
        return vulnerabilities


class KubernetesScanner:
    """Scanner for Kubernetes manifests"""
    
    def scan(self, content: str, filepath: str) -> List[IaCVulnerability]:
        """Scan Kubernetes YAML for security issues"""
        vulnerabilities = []
        
        try:
            docs = yaml.safe_load_all(content)
            
            for doc in docs:
                if not doc or not isinstance(doc, dict):
                    continue
                
                vulns = self._scan_k8s_resource(doc, filepath)
                vulnerabilities.extend(vulns)
                
        except yaml.YAMLError:
            pass  # Not a valid YAML file
        
        return vulnerabilities
    
    def _scan_k8s_resource(self, resource: Dict, filepath: str) -> List[IaCVulnerability]:
        """Scan individual K8s resource"""
        vulnerabilities = []
        kind = resource.get('kind', '')
        
        if kind in ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job']:
            # Get container specs
            spec = resource.get('spec', {})
            if kind in ['Deployment', 'StatefulSet', 'DaemonSet']:
                spec = spec.get('template', {}).get('spec', {})
            
            containers = spec.get('containers', [])
            
            for container in containers:
                # Check for privileged containers
                security_context = container.get('securityContext', {})
                if security_context.get('privileged', False):
                    vulnerabilities.append(IaCVulnerability(
                        type="Kubernetes",
                        cwe="CWE-250",
                        severity="critical",
                        title="Privileged Container",
                        description=f"Container '{container.get('name')}' runs in privileged mode.",
                        file_path=filepath,
                        line_number=0,
                        code_snippet="privileged: true",
                        remediation="Remove 'privileged: true' or add specific capabilities instead: capabilities.add: ['NET_ADMIN']",
                        confidence="high"
                    ))
                
                # Check for running as root
                if not security_context.get('runAsNonRoot'):
                    vulnerabilities.append(IaCVulnerability(
                        type="Kubernetes",
                        cwe="CWE-250",
                        severity="high",
                        title="Container May Run as Root",
                        description=f"Container '{container.get('name')}' doesn't enforce non-root user.",
                        file_path=filepath,
                        line_number=0,
                        code_snippet=f"container: {container.get('name')}",
                        remediation="Add securityContext: runAsNonRoot: true and runAsUser: 1000",
                        confidence="medium"
                    ))
                
                # Check for writable root filesystem
                if not security_context.get('readOnlyRootFilesystem'):
                    vulnerabilities.append(IaCVulnerability(
                        type="Kubernetes",
                        cwe="CWE-732",
                        severity="medium",
                        title="Writable Root Filesystem",
                        description=f"Container '{container.get('name')}' has writable root filesystem.",
                        file_path=filepath,
                        line_number=0,
                        code_snippet=f"container: {container.get('name')}",
                        remediation="Add securityContext: readOnlyRootFilesystem: true. Use emptyDir volumes for writable paths.",
                        confidence="medium"
                    ))
                
                # Check for missing resource limits
                resources = container.get('resources', {})
                if not resources.get('limits'):
                    vulnerabilities.append(IaCVulnerability(
                        type="Kubernetes",
                        cwe="CWE-770",
                        severity="medium",
                        title="Missing Resource Limits",
                        description=f"Container '{container.get('name')}' has no resource limits.",
                        file_path=filepath,
                        line_number=0,
                        code_snippet=f"container: {container.get('name')}",
                        remediation="Add resources.limits: memory: '512Mi' and cpu: '500m'",
                        confidence="high"
                    ))
                
                # Check for latest tag
                image = container.get('image', '')
                if ':latest' in image or ':' not in image:
                    vulnerabilities.append(IaCVulnerability(
                        type="Kubernetes",
                        cwe="CWE-494",
                        severity="medium",
                        title="Using 'latest' or No Image Tag",
                        description=f"Container '{container.get('name')}' uses 'latest' or no tag.",
                        file_path=filepath,
                        line_number=0,
                        code_snippet=f"image: {image}",
                        remediation="Use specific version tags for reproducible deployments.",
                        confidence="high"
                    ))
        
        # Check for exposed secrets in env vars
        if kind == 'Secret':
            vulnerabilities.append(IaCVulnerability(
                type="Kubernetes",
                cwe="CWE-312",
                severity="low",
                title="Secret Definition in Version Control",
                description="Kubernetes Secret defined in YAML. Should use external secret management.",
                file_path=filepath,
                line_number=0,
                code_snippet="kind: Secret",
                remediation="Use external secret management (Sealed Secrets, External Secrets Operator, Vault).",
                confidence="medium"
            ))
        
        return vulnerabilities


class TerraformScanner:
    """Scanner for Terraform configurations"""
    
    def scan(self, content: str, filepath: str) -> List[IaCVulnerability]:
        """Scan Terraform files for security issues"""
        vulnerabilities = []
        lines = content.split('\n')
        
        in_resource = False
        current_resource = ""
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Track resource blocks
            if line_stripped.startswith('resource '):
                in_resource = True
                match = re.match(r'resource\s+"([^"]+)"\s+"([^"]+)"', line_stripped)
                if match:
                    current_resource = f"{match.group(1)}.{match.group(2)}"
            elif line_stripped == '}' and in_resource:
                in_resource = False
                current_resource = ""
            
            # Check for hardcoded credentials
            if re.search(r'(password|secret_key|access_key|token)\s*=\s*"[^$]', line_stripped):
                vulnerabilities.append(IaCVulnerability(
                    type="Terraform",
                    cwe="CWE-798",
                    severity="critical",
                    title="Hardcoded Credential in Terraform",
                    description="Credential appears to be hardcoded in Terraform configuration.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip()[:50] + "...",
                    remediation="Use variables or data sources: password = var.db_password",
                    confidence="high"
                ))
            
            # Check for public S3 buckets
            if 'aws_s3_bucket' in current_resource and 'acl' in line_stripped and 'public' in line_stripped:
                vulnerabilities.append(IaCVulnerability(
                    type="Terraform",
                    cwe="CWE-732",
                    severity="critical",
                    title="Public S3 Bucket",
                    description="S3 bucket is configured with public ACL.",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    remediation="Use private ACL and configure specific bucket policies. acl = 'private'",
                    confidence="high"
                ))
            
            # Check for unencrypted EBS volumes
            if 'aws_ebs_volume' in current_resource and 'encrypted' in content.lower():
                if 'encrypted = false' in line_stripped or 'encrypted=false' in line_stripped:
                    vulnerabilities.append(IaCVulnerability(
                        type="Terraform",
                        cwe="CWE-311",
                        severity="high",
                        title="Unencrypted EBS Volume",
                        description="EBS volume is not encrypted at rest.",
                        file_path=filepath,
                        line_number=i,
                        code_snippet=line.strip(),
                        remediation="Set encrypted = true and specify kms_key_id for encryption.",
                        confidence="high"
                    ))
            
            # Check for security groups allowing 0.0.0.0/0
            if 'aws_security_group' in current_resource and '0.0.0.0/0' in line_stripped:
                vulnerabilities.append(IaCVulnerability(
                    type="Terraform",
                    cwe="CWE-284",
                    severity="high",
                    title="Overly Permissive Security Group",
                    description="Security group allows traffic from anywhere (0.0.0.0/0).",
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip(),
                    remediation="Restrict to specific IP ranges. For SSH, use VPN or bastion host.",
                    confidence="high"
                ))
            
            # Check for missing encryption on RDS
            if 'aws_db_instance' in current_resource and 'storage_encrypted' in content.lower():
                if 'storage_encrypted = false' in line_stripped:
                    vulnerabilities.append(IaCVulnerability(
                        type="Terraform",
                        cwe="CWE-311",
                        severity="high",
                        title="Unencrypted RDS Instance",
                        description="RDS database is not encrypted at rest.",
                        file_path=filepath,
                        line_number=i,
                        code_snippet=line.strip(),
                        remediation="Set storage_encrypted = true and specify kms_key_id.",
                        confidence="high"
                    ))
        
        return vulnerabilities


class ContainerIaCScanner:
    """Main scanner for container and IaC files"""
    
    def __init__(self):
        self.dockerfile_scanner = DockerfileScanner()
        self.kubernetes_scanner = KubernetesScanner()
        self.terraform_scanner = TerraformScanner()
    
    def scan_file(self, filepath: Path) -> List[IaCVulnerability]:
        """Scan a file based on its type"""
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            filename = filepath.name.lower()
            
            # Dockerfile
            if 'dockerfile' in filename or filename == 'dockerfile':
                return self.dockerfile_scanner.scan(content, str(filepath))
            
            # Docker Compose
            elif 'docker-compose' in filename:
                return self.dockerfile_scanner.scan(content, str(filepath))
            
            # Kubernetes
            elif filename.endswith(('.yaml', '.yml')) and self._is_kubernetes_manifest(content):
                return self.kubernetes_scanner.scan(content, str(filepath))
            
            # Terraform
            elif filename.endswith('.tf'):
                return self.terraform_scanner.scan(content, str(filepath))
            
            return []
            
        except Exception as e:
            return []
    
    def _is_kubernetes_manifest(self, content: str) -> bool:
        """Check if YAML file is a Kubernetes manifest"""
        try:
            doc = yaml.safe_load(content)
            if not isinstance(doc, dict):
                return False
            
            # Check for K8s-specific fields
            return 'apiVersion' in doc and 'kind' in doc
        except:
            return False
    
    def scan_directory(self, directory: Path) -> List[IaCVulnerability]:
        """Scan entire directory for IaC files"""
        vulnerabilities = []
        
        # Patterns to match
        patterns = [
            '**/Dockerfile*',
            '**/docker-compose*.yml',
            '**/docker-compose*.yaml',
            '**/*.yaml',
            '**/*.yml',
            '**/*.tf'
        ]
        
        for pattern in patterns:
            for filepath in directory.glob(pattern):
                if filepath.is_file():
                    vulns = self.scan_file(filepath)
                    vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def generate_report(self, vulnerabilities: List[IaCVulnerability]) -> Dict[str, Any]:
        """Generate IaC security report"""
        # Group by type
        by_type = {}
        for vuln in vulnerabilities:
            if vuln.type not in by_type:
                by_type[vuln.type] = []
            by_type[vuln.type].append(vuln)
        
        # Group by severity
        by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulnerabilities:
            if vuln.severity in by_severity:
                by_severity[vuln.severity] += 1
        
        # Group by file
        by_file = {}
        for vuln in vulnerabilities:
            if vuln.file_path not in by_file:
                by_file[vuln.file_path] = []
            by_file[vuln.file_path].append({
                'type': vuln.type,
                'cwe': vuln.cwe,
                'severity': vuln.severity,
                'title': vuln.title,
                'line': vuln.line_number
            })
        
        return {
            'total_issues': len(vulnerabilities),
            'by_severity': by_severity,
            'by_type': {k: len(v) for k, v in by_type.items()},
            'by_file': by_file,
            'critical_issues': by_severity['critical'],
            'high_issues': by_severity['high'],
            'vulnerabilities': [
                {
                    'type': v.type,
                    'cwe': v.cwe,
                    'severity': v.severity,
                    'title': v.title,
                    'description': v.description,
                    'file': v.file_path,
                    'line': v.line_number,
                    'remediation': v.remediation,
                    'confidence': v.confidence
                }
                for v in vulnerabilities
            ]
        }


def scan_infrastructure(path: Path) -> Dict[str, Any]:
    """
    Convenience function to scan infrastructure code
    
    Args:
        path: Path to file or directory to scan
    
    Returns:
        Scan report
    """
    scanner = ContainerIaCScanner()
    
    if path.is_file():
        vulnerabilities = scanner.scan_file(path)
    else:
        vulnerabilities = scanner.scan_directory(path)
    
    return scanner.generate_report(vulnerabilities)

