# Amazon Q Developer Parity Implementation Plan

**Date**: November 3, 2025  
**Goal**: Achieve feature parity with Amazon Q Developer Security Scanner  
**Timeline**: 8 weeks (Q4 2025 - Q1 2026)

---

## Executive Summary

This document outlines the implementation plan to bring Parry Security Scanner to full feature parity with Amazon Q Developer, including:
- Expansion from 50+ to 150+ security detectors
- Real-time IDE scanning via VS Code extension
- Enhanced custom policy engine for enterprise use
- Cutting-edge 2024-2025 threat detection
- Superior benchmarking and documentation

---

## Current State vs Target State

### Security Detectors

| Category | Current | Target | Gap |
|----------|---------|--------|-----|
| **Total Detectors** | 50+ | 150+ | +100 |
| OWASP Top 10 | 78% | 95%+ | +17% |
| API Security | Partial | Full OWASP API Top 10 | +10 detectors |
| Cloud Native | Minimal | Comprehensive | +15 detectors |
| Supply Chain | Basic | Advanced | +8 detectors |
| AI/ML Security | None | Full | +12 detectors |
| Container/IaC | Basic | Enterprise | +15 detectors |
| Business Logic | Minimal | Advanced | +10 detectors |

### Feature Comparison

| Feature | Parry (Current) | Amazon Q | Parry (Target) |
|---------|-----------------|----------|----------------|
| **Detectors** | 50+ | Thousands | 150+ (focused) |
| **Languages** | 13 | 12+ | 15+ |
| **Real-time Scanning** | ❌ | ✅ | ✅ |
| **Auto-scan as you code** | ❌ | ✅ Pro | ✅ |
| **IDE Integration** | Planned | ✅ | ✅ VS Code |
| **Code Fix Previews** | Basic | ✅ | ✅ Enhanced |
| **Custom Rules** | ✅ | Limited | ✅ Advanced |
| **CWE Explanations** | Basic | ✅ | ✅ Enhanced |
| **Compliance Mapping** | ✅ | Limited | ✅ Enhanced |
| **Self-hosted** | ✅ | ❌ | ✅ |
| **Open Source** | ✅ | ❌ | ✅ |

---

## Phase 1: Advanced Security Detectors (Weeks 1-3)

### 1.1 AI/ML Security (12 detectors)

**New CWE Categories:**
- CWE-1295: Prompt Injection
- CWE-1296: Model Poisoning
- CWE-1297: Data Poisoning
- CWE-1298: Model Inversion Attacks
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes (AI context)

**Implementation:**
```python
# parry/security_domains/ai_ml_security.py
class AIMLSecurityDetector:
    """Detect AI/ML-specific vulnerabilities"""
    
    def detect_prompt_injection(code, language):
        """
        Detect unvalidated user input to LLM prompts
        - Direct prompt concatenation
        - Missing input sanitization
        - Lack of prompt templates
        """
    
    def detect_model_poisoning(code, language):
        """
        Detect untrusted model loading
        - pickle.load from untrusted sources
        - Unsigned model files
        - No integrity checks
        """
    
    def detect_data_poisoning(code, language):
        """
        Detect untrusted training data
        - No data validation
        - Missing data provenance
        - Lack of anomaly detection
        """
    
    def detect_model_inversion(code, language):
        """
        Detect model privacy leaks
        - Missing differential privacy
        - No output filtering
        - Excessive model confidence exposure
        """
```

### 1.2 API Security - OWASP API Top 10 (10 detectors)

**Implementation:**
```python
# parry/security_domains/api_security.py
class APISecurityDetector:
    """OWASP API Security Top 10 2023"""
    
    def detect_broken_object_auth(code, language):
        """
        API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
        - Missing authorization checks
        - Direct object references
        - No ownership validation
        """
    
    def detect_broken_authentication(code, language):
        """
        API2:2023 - Broken Authentication
        - Weak JWT secrets
        - Missing token expiration
        - No rate limiting on auth endpoints
        """
    
    def detect_broken_property_auth(code, language):
        """
        API3:2023 - Broken Object Property Level Authorization
        - Mass assignment vulnerabilities
        - Excessive data exposure
        - Missing field-level authorization
        """
    
    def detect_unrestricted_resource_consumption(code, language):
        """
        API4:2023 - Unrestricted Resource Consumption
        - No rate limiting
        - Missing pagination
        - Unbounded queries
        """
    
    def detect_broken_function_auth(code, language):
        """
        API5:2023 - Broken Function Level Authorization
        - Missing role checks
        - Privilege escalation paths
        - Admin endpoints without auth
        """
    
    def detect_unrestricted_access_to_sensitive_flows(code, language):
        """
        API6:2023 - Unrestricted Access to Sensitive Business Flows
        - No CAPTCHA on sensitive operations
        - Missing fraud detection
        - Bulk operation abuse
        """
    
    def detect_ssrf(code, language):
        """
        API7:2023 - Server Side Request Forgery
        - Unvalidated URL parameters
        - Missing allowlist checks
        - Cloud metadata access
        """
    
    def detect_security_misconfiguration(code, language):
        """
        API8:2023 - Security Misconfiguration
        - Debug mode in production
        - Verbose error messages
        - Missing security headers
        """
    
    def detect_improper_inventory_management(code, language):
        """
        API9:2023 - Improper Inventory Management
        - Outdated API versions
        - Undocumented endpoints
        - No API gateway
        """
    
    def detect_unsafe_api_consumption(code, language):
        """
        API10:2023 - Unsafe Consumption of APIs
        - No TLS verification
        - Missing response validation
        - Trusting third-party APIs
        """
```

### 1.3 Cloud Native Security (15 detectors)

**Implementation:**
```python
# parry/security_domains/cloud_security.py
class CloudSecurityDetector:
    """Cloud-native threat detection"""
    
    def detect_aws_iam_misconfig(code, language):
        """
        Detect overly permissive IAM policies
        - Wildcard permissions
        - Missing MFA requirements
        - Public S3 buckets
        """
    
    def detect_secrets_in_env(code, language):
        """
        Detect secrets in environment variables
        - AWS keys in .env
        - Database credentials
        - API tokens
        """
    
    def detect_ssrf_to_metadata(code, language):
        """
        Detect SSRF to cloud metadata services
        - 169.254.169.254 access
        - Metadata API calls
        - IMDSv1 usage
        """
    
    def detect_insecure_cloud_storage(code, language):
        """
        Detect insecure cloud storage config
        - Public read access
        - Missing encryption
        - No versioning
        """
```

### 1.4 Supply Chain Security (8 detectors)

**Implementation:**
```python
# parry/security_domains/supply_chain_security.py
class SupplyChainDetector:
    """Supply chain attack detection"""
    
    def detect_dependency_confusion(code, language):
        """
        Detect dependency confusion risks
        - Private package names matching public
        - Missing package scope
        - No registry authentication
        """
    
    def detect_typosquatting(code, language):
        """
        Detect typosquatting attempts
        - Similar package names
        - Suspicious new dependencies
        - No integrity checks
        """
    
    def detect_unsigned_artifacts(code, language):
        """
        Detect unsigned artifacts
        - No signature verification
        - Missing checksums
        - Untrusted sources
        """
    
    def detect_outdated_dependencies(code, language):
        """
        Detect known vulnerable dependencies
        - CVE databases check
        - Version comparison
        - Security advisories
        """
```

### 1.5 Container & IaC Security (15 detectors)

**Implementation:**
```python
# parry/security_domains/container_iac_security.py
class ContainerIaCDetector:
    """Container and Infrastructure as Code security"""
    
    def detect_privileged_containers(code, language):
        """
        Detect privileged container configurations
        - privileged: true in docker-compose
        - --privileged flag
        - CAP_SYS_ADMIN capability
        """
    
    def detect_root_user(code, language):
        """
        Detect containers running as root
        - Missing USER directive
        - UID 0 in Dockerfile
        - No runAsNonRoot in k8s
        """
    
    def detect_secrets_in_dockerfile(code, language):
        """
        Detect secrets in Dockerfile
        - ENV with secrets
        - ARG with passwords
        - COPY of .env files
        """
    
    def detect_insecure_base_images(code, language):
        """
        Detect insecure base images
        - latest tag usage
        - Unverified images
        - Known vulnerable images
        """
    
    def detect_exposed_ports(code, language):
        """
        Detect unnecessarily exposed ports
        - EXPOSE for internal services
        - Host network mode
        - NodePort services
        """
```

### 1.6 Modern Cryptography Issues (8 detectors)

**Implementation:**
```python
# parry/security_domains/modern_crypto.py
class ModernCryptoDetector:
    """2024-2025 cryptography standards"""
    
    def detect_tls_version(code, language):
        """
        Detect outdated TLS versions
        - TLS 1.0, 1.1 usage
        - SSLv3
        - Missing TLS 1.3
        """
    
    def detect_weak_rsa_keys(code, language):
        """
        Detect weak RSA key sizes
        - < 2048 bits
        - < 4096 for long-term
        - No key rotation
        """
    
    def detect_deprecated_crypto_libs(code, language):
        """
        Detect deprecated crypto libraries
        - pycrypto (deprecated)
        - OpenSSL < 1.1.1
        - Outdated crypto.js
        """
    
    def detect_insecure_random(code, language):
        """
        Detect insecure random sources
        - math.random() for crypto
        - time-based seeds
        - No CSPRNG usage
        """
```

---

## Phase 2: Enhanced Custom Rules Engine (Weeks 3-4)

### 2.1 Enterprise Policy Features

**File:** `parry/custom_rules_enhanced.py`

```python
class EnterpriseRulesEngine(CustomRulesEngine):
    """Enhanced custom rules for enterprise policies"""
    
    def __init__(self):
        super().__init__()
        self.policy_templates = {}
        self.compliance_mappings = {}
        self.rule_inheritance = {}
    
    def load_policy_template(self, template_name: str):
        """
        Load predefined policy templates
        - PCI-DSS baseline
        - HIPAA security rules
        - GDPR data protection
        - SOC2 controls
        - ISO 27001 controls
        """
    
    def apply_rule_inheritance(self, parent_rules: List[str], overrides: Dict):
        """
        Support rule inheritance and overrides
        - Base corporate policies
        - Department-specific rules
        - Project-level exceptions
        """
    
    def map_to_compliance_framework(self, framework: str):
        """
        Map custom rules to compliance requirements
        - Auto-generate compliance reports
        - Track control coverage
        - Identify gaps
        """
    
    def create_rule_from_incident(self, incident_data: Dict):
        """
        Generate custom rules from security incidents
        - Learn from past vulnerabilities
        - Create organization-specific detectors
        - Build institutional knowledge
        """
```

### 2.2 Rule Template Library

**File:** `parry/rule_templates/`

```yaml
# enterprise_baseline.yaml
rules:
  - id: org-no-hardcoded-internal-domains
    message: Internal domain names must not be hardcoded
    severity: HIGH
    languages: [python, javascript, java]
    patterns:
      - pattern: $URL = "*.internal.company.com"
    metadata:
      owner: security-team
      rationale: Prevents internal infrastructure exposure
  
  - id: org-require-encrypted-communications
    message: All external API calls must use HTTPS
    severity: CRITICAL
    languages: [python, javascript]
    patterns:
      - pattern: requests.get("http://$URL")
      - pattern: fetch("http://$URL")
    pattern-not:
      - pattern: requests.get("http://localhost*")
    metadata:
      compliance: [PCI-DSS-4.1, SOC2-CC6.6]
```

---

## Phase 3: VS Code Extension (Weeks 4-6)

### 3.1 Extension Architecture

**Directory Structure:**
```
integrations/vscode-parry/
├── package.json
├── src/
│   ├── extension.ts          # Main extension entry
│   ├── scanner.ts             # Scanner integration
│   ├── diagnostics.ts         # Problem reporting
│   ├── codeActions.ts         # Quick fixes
│   ├── statusBar.ts           # Status indicators
│   ├── webview/               # Security panel UI
│   │   ├── SecurityPanel.ts
│   │   └── views/
│   │       ├── vulnerabilities.html
│   │       └── settings.html
│   ├── commands/
│   │   ├── scanFile.ts
│   │   ├── scanWorkspace.ts
│   │   ├── applyFix.ts
│   │   └── explainVuln.ts
│   └── utils/
│       ├── config.ts
│       └── logger.ts
├── media/                     # Icons and assets
├── test/                      # Extension tests
└── README.md
```

### 3.2 Core Features

**1. Real-time Auto-Scanning**

```typescript
// src/scanner.ts
export class ParryScanner {
    private scanTimeout: NodeJS.Timeout | null = null;
    private readonly SCAN_DELAY = 2000; // 2 seconds after typing stops
    
    public setupAutoScan(context: vscode.ExtensionContext) {
        // Watch for file changes
        vscode.workspace.onDidChangeTextDocument(async (event) => {
            if (!this.isSupportedLanguage(event.document.languageId)) {
                return;
            }
            
            // Debounce scanning
            if (this.scanTimeout) {
                clearTimeout(this.scanTimeout);
            }
            
            this.scanTimeout = setTimeout(async () => {
                await this.scanDocument(event.document);
            }, this.SCAN_DELAY);
        });
        
        // Scan on file open
        vscode.workspace.onDidOpenTextDocument(async (document) => {
            if (this.isSupportedLanguage(document.languageId)) {
                await this.scanDocument(document);
            }
        });
    }
    
    private async scanDocument(document: vscode.TextDocument): Promise<void> {
        const filePath = document.fileName;
        const content = document.getText();
        
        // Call Parry scanner
        const vulnerabilities = await this.runParryScan(filePath, content);
        
        // Update diagnostics
        this.updateDiagnostics(document, vulnerabilities);
    }
    
    private async runParryScan(filePath: string, content: string): Promise<Vulnerability[]> {
        // Execute parry scan via CLI or Python API
        const result = await exec(`parry scan --file "${filePath}" --format json`);
        return JSON.parse(result.stdout);
    }
}
```

**2. Inline Diagnostics with Fixes**

```typescript
// src/diagnostics.ts
export class DiagnosticsManager {
    private diagnosticCollection: vscode.DiagnosticCollection;
    
    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('parry');
    }
    
    public updateDiagnostics(document: vscode.TextDocument, vulnerabilities: Vulnerability[]): void {
        const diagnostics: vscode.Diagnostic[] = [];
        
        for (const vuln of vulnerabilities) {
            const range = new vscode.Range(
                vuln.line - 1, 0,
                vuln.line - 1, 1000
            );
            
            const diagnostic = new vscode.Diagnostic(
                range,
                `[${vuln.cwe}] ${vuln.title}: ${vuln.description}`,
                this.getSeverity(vuln.severity)
            );
            
            diagnostic.code = {
                value: vuln.cwe,
                target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${vuln.cwe.replace('CWE-', '')}.html`)
            };
            
            diagnostic.source = 'Parry Security';
            
            // Attach fix information
            (diagnostic as any).fix = vuln.fix;
            
            diagnostics.push(diagnostic);
        }
        
        this.diagnosticCollection.set(document.uri, diagnostics);
    }
    
    private getSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity.toLowerCase()) {
            case 'critical': return vscode.DiagnosticSeverity.Error;
            case 'high': return vscode.DiagnosticSeverity.Error;
            case 'medium': return vscode.DiagnosticSeverity.Warning;
            case 'low': return vscode.DiagnosticSeverity.Information;
            default: return vscode.DiagnosticSeverity.Hint;
        }
    }
}
```

**3. Code Actions (Quick Fixes)**

```typescript
// src/codeActions.ts
export class ParryCodeActionProvider implements vscode.CodeActionProvider {
    public provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range,
        context: vscode.CodeActionContext
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];
        
        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== 'Parry Security') {
                continue;
            }
            
            // Quick fix action
            if ((diagnostic as any).fix) {
                const fixAction = new vscode.CodeAction(
                    `Fix: ${diagnostic.message}`,
                    vscode.CodeActionKind.QuickFix
                );
                fixAction.diagnostics = [diagnostic];
                fixAction.command = {
                    title: 'Apply Parry Fix',
                    command: 'parry.applyFix',
                    arguments: [document, diagnostic]
                };
                actions.push(fixAction);
            }
            
            // Explain action
            const explainAction = new vscode.CodeAction(
                'Explain this security issue',
                vscode.CodeActionKind.QuickFix
            );
            explainAction.command = {
                title: 'Explain Vulnerability',
                command: 'parry.explainVulnerability',
                arguments: [diagnostic]
            };
            actions.push(explainAction);
            
            // View CWE action
            const cweAction = new vscode.CodeAction(
                'View CWE details',
                vscode.CodeActionKind.QuickFix
            );
            cweAction.command = {
                title: 'View CWE',
                command: 'vscode.open',
                arguments: [diagnostic.code.target]
            };
            actions.push(cweAction);
        }
        
        return actions;
    }
}
```

**4. Security Panel View**

```typescript
// src/webview/SecurityPanel.ts
export class SecurityPanel {
    private panel: vscode.WebviewPanel | undefined;
    
    public show(context: vscode.ExtensionContext, vulnerabilities: Vulnerability[]): void {
        if (this.panel) {
            this.panel.reveal();
        } else {
            this.panel = vscode.window.createWebviewPanel(
                'parrySecurity',
                'Parry Security',
                vscode.ViewColumn.Two,
                {
                    enableScripts: true,
                    retainContextWhenHidden: true
                }
            );
            
            this.panel.webview.html = this.getWebviewContent(vulnerabilities);
            
            this.panel.onDidDispose(() => {
                this.panel = undefined;
            });
        }
    }
    
    private getWebviewContent(vulnerabilities: Vulnerability[]): string {
        return `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: var(--vscode-font-family); }
                .vulnerability { 
                    border-left: 4px solid var(--vscode-errorForeground);
                    padding: 10px;
                    margin: 10px 0;
                }
                .critical { border-left-color: #d73a49; }
                .high { border-left-color: #e36209; }
                .medium { border-left-color: #dbab09; }
                .low { border-left-color: #28a745; }
            </style>
        </head>
        <body>
            <h1>Security Issues Found: ${vulnerabilities.length}</h1>
            ${vulnerabilities.map(v => `
                <div class="vulnerability ${v.severity}">
                    <h3>[${v.cwe}] ${v.title}</h3>
                    <p><strong>File:</strong> ${v.file}:${v.line}</p>
                    <p><strong>Severity:</strong> ${v.severity}</p>
                    <p>${v.description}</p>
                    ${v.fix ? `<p><strong>Fix:</strong> ${v.fix}</p>` : ''}
                    <button onclick="applyFix('${v.id}')">Apply Fix</button>
                </div>
            `).join('')}
            <script>
                const vscode = acquireVsCodeApi();
                function applyFix(vulnId) {
                    vscode.postMessage({ command: 'applyFix', vulnId });
                }
            </script>
        </body>
        </html>
        `;
    }
}
```

### 3.3 Extension package.json

```json
{
  "name": "parry-security-scanner",
  "displayName": "Parry Security Scanner",
  "description": "AI-powered security vulnerability detection with real-time scanning",
  "version": "1.0.0",
  "publisher": "parry-ai",
  "engines": {
    "vscode": "^1.85.0"
  },
  "categories": [
    "Linters",
    "Programming Languages",
    "Other"
  ],
  "keywords": [
    "security",
    "vulnerability",
    "sast",
    "scanner",
    "ai"
  ],
  "activationEvents": [
    "onLanguage:python",
    "onLanguage:javascript",
    "onLanguage:typescript",
    "onLanguage:java",
    "onLanguage:go",
    "onLanguage:rust",
    "onLanguage:php",
    "onLanguage:ruby"
  ],
  "main": "./out/extension.js",
  "contributes": {
    "commands": [
      {
        "command": "parry.scanFile",
        "title": "Parry: Scan Current File"
      },
      {
        "command": "parry.scanWorkspace",
        "title": "Parry: Scan Workspace"
      },
      {
        "command": "parry.applyFix",
        "title": "Parry: Apply Security Fix"
      },
      {
        "command": "parry.explainVulnerability",
        "title": "Parry: Explain Vulnerability"
      },
      {
        "command": "parry.showSecurityPanel",
        "title": "Parry: Show Security Panel"
      }
    ],
    "configuration": {
      "title": "Parry Security Scanner",
      "properties": {
        "parry.autoScan": {
          "type": "boolean",
          "default": true,
          "description": "Automatically scan files as you type"
        },
        "parry.scanDelay": {
          "type": "number",
          "default": 2000,
          "description": "Delay in milliseconds before scanning after typing stops"
        },
        "parry.apiKey": {
          "type": "string",
          "default": "",
          "description": "API key for AI-powered fixes (Gemini or OpenAI)"
        },
        "parry.aiProvider": {
          "type": "string",
          "enum": ["gemini", "openai", "ollama"],
          "default": "ollama",
          "description": "AI provider for vulnerability fixes"
        },
        "parry.severity": {
          "type": "string",
          "enum": ["all", "critical", "high", "medium"],
          "default": "medium",
          "description": "Minimum severity level to report"
        },
        "parry.customRulesPath": {
          "type": "string",
          "default": "",
          "description": "Path to custom security rules directory"
        }
      }
    },
    "views": {
      "explorer": [
        {
          "id": "parrySecurityView",
          "name": "Parry Security",
          "when": "workspaceHasSecurityIssues"
        }
      ]
    },
    "menus": {
      "editor/context": [
        {
          "command": "parry.scanFile",
          "group": "parry",
          "when": "editorTextFocus"
        },
        {
          "command": "parry.applyFix",
          "group": "parry",
          "when": "editorTextFocus && parryHasFixes"
        }
      ],
      "editor/title": [
        {
          "command": "parry.scanFile",
          "group": "navigation",
          "when": "editorTextFocus"
        }
      ]
    }
  },
  "scripts": {
    "vscode:prepublish": "npm run compile",
    "compile": "tsc -p ./",
    "watch": "tsc -watch -p ./",
    "test": "npm run compile && node ./out/test/runTest.js"
  },
  "devDependencies": {
    "@types/vscode": "^1.85.0",
    "@types/node": "^18.x",
    "typescript": "^5.3.0"
  },
  "dependencies": {
    "execa": "^8.0.1"
  }
}
```

---

## Phase 4: Enhanced AI Fix Generation (Week 6)

### 4.1 Context-Aware Fix Generation

**File:** `parry/ai_fix_enhanced.py`

```python
class EnhancedPatchGenerator(PatchGenerator):
    """Enhanced AI-powered fix generation with context awareness"""
    
    def generate_fix_with_context(self, vulnerability: Vulnerability, file_context: FileContext) -> Patch:
        """
        Generate context-aware security fixes
        
        Context includes:
        - Surrounding code (5 lines before/after)
        - File imports and dependencies
        - Framework being used
        - Language version
        - Project conventions
        """
        prompt = self._build_contextual_prompt(vulnerability, file_context)
        
        # Get AI-generated fix
        fix_code = self.llm_client.generate(prompt)
        
        # Validate fix doesn't introduce new issues
        validation = self._validate_fix(fix_code, vulnerability)
        
        if not validation.is_safe:
            # Retry with stricter constraints
            fix_code = self._regenerate_with_constraints(prompt, validation.issues)
        
        return self._create_patch_with_diff(vulnerability, fix_code, file_context)
    
    def _build_contextual_prompt(self, vuln: Vulnerability, context: FileContext) -> str:
        """Build comprehensive prompt with full context"""
        return f"""
        Fix the following {vuln.cwe} vulnerability in {context.language}:
        
        **File:** {vuln.file}
        **Line:** {vuln.line}
        **Framework:** {context.framework or 'None'}
        **Language Version:** {context.language_version}
        
        **Vulnerable Code:**
        ```{context.language}
        {vuln.code}
        ```
        
        **Context (surrounding code):**
        ```{context.language}
        {context.before_code}
        >>> VULNERABLE LINE <<<
        {context.after_code}
        ```
        
        **Imports:**
        {context.imports}
        
        **Requirements:**
        1. Fix must address {vuln.cwe}
        2. Must maintain existing functionality
        3. Follow {context.language} best practices
        4. Use {context.framework} conventions if applicable
        5. Add inline comments explaining the fix
        
        Provide ONLY the fixed code, no explanations.
        """
    
    def _create_patch_with_diff(self, vuln: Vulnerability, fixed_code: str, context: FileContext) -> Patch:
        """Create patch with unified diff preview"""
        import difflib
        
        original_lines = context.original_code.splitlines(keepends=True)
        fixed_lines = fixed_code.splitlines(keepends=True)
        
        diff = difflib.unified_diff(
            original_lines,
            fixed_lines,
            fromfile=f'{vuln.file} (vulnerable)',
            tofile=f'{vuln.file} (fixed)',
            lineterm=''
        )
        
        return Patch(
            vulnerability=vuln,
            original_code=context.original_code,
            fixed_code=fixed_code,
            diff=''.join(diff),
            explanation=self._generate_fix_explanation(vuln, fixed_code),
            confidence=self._calculate_confidence(vuln, fixed_code)
        )
```

---

## Phase 5: Comprehensive Benchmarking (Week 7)

### 5.1 Benchmark Suite

**File:** `scripts/benchmark/comprehensive_benchmark.py`

```python
class ComprehensiveBenchmark:
    """Benchmark Parry against Amazon Q, Snyk, Semgrep"""
    
    BENCHMARKS = [
        'OWASP_Top_10',
        'WebGoat',
        'RailsGoat',
        'NodeGoat',
        'DVWA',
        'Juice_Shop',
        'CredData',
        'Custom_Test_Suite'
    ]
    
    COMPETITORS = [
        'amazon_q',
        'snyk',
        'semgrep',
        'codeql',
        'sonarqube'
    ]
    
    def run_comprehensive_benchmark(self):
        """Run all benchmarks against all tools"""
        results = {}
        
        for benchmark in self.BENCHMARKS:
            print(f"\n=== Running {benchmark} ===")
            benchmark_results = self.run_single_benchmark(benchmark)
            results[benchmark] = benchmark_results
        
        # Calculate aggregate metrics
        aggregate = self.calculate_aggregate_metrics(results)
        
        # Generate report
        self.generate_benchmark_report(results, aggregate)
        
        return results
    
    def run_single_benchmark(self, benchmark_name: str) -> Dict:
        """Run single benchmark across all tools"""
        test_cases = self.load_test_cases(benchmark_name)
        
        results = {
            'parry': self.run_parry(test_cases),
            'amazon_q': self.run_amazon_q(test_cases) if AMAZON_Q_AVAILABLE else None,
            'snyk': self.run_snyk(test_cases) if SNYK_AVAILABLE else None,
            'semgrep': self.run_semgrep(test_cases),
            'codeql': self.run_codeql(test_cases) if CODEQL_AVAILABLE else None
        }
        
        # Calculate precision and recall
        for tool, findings in results.items():
            if findings:
                results[f'{tool}_precision'] = self.calculate_precision(findings, test_cases)
                results[f'{tool}_recall'] = self.calculate_recall(findings, test_cases)
                results[f'{tool}_f1'] = self.calculate_f1(
                    results[f'{tool}_precision'],
                    results[f'{tool}_recall']
                )
        
        return results
    
    def calculate_precision(self, findings: List, ground_truth: List) -> float:
        """
        Precision = True Positives / (True Positives + False Positives)
        
        Measures how many reported vulnerabilities are actually vulnerabilities
        """
        true_positives = len([f for f in findings if f in ground_truth])
        false_positives = len([f for f in findings if f not in ground_truth])
        
        if true_positives + false_positives == 0:
            return 0.0
        
        return true_positives / (true_positives + false_positives)
    
    def calculate_recall(self, findings: List, ground_truth: List) -> float:
        """
        Recall = True Positives / (True Positives + False Negatives)
        
        Measures how many actual vulnerabilities were found
        """
        true_positives = len([f for f in findings if f in ground_truth])
        false_negatives = len([g for g in ground_truth if g not in findings])
        
        if true_positives + false_negatives == 0:
            return 0.0
        
        return true_positives / (true_positives + false_negatives)
```

---

## Phase 6: Documentation and Release (Week 8)

### 6.1 Updated README

```markdown
# 🛡️ Parry Security Scanner v3.0

**AI-Powered Security Scanning with Real-Time IDE Integration**

## ✨ New in v3.0

- 🎯 **150+ Security Detectors** - Comprehensive vulnerability coverage
- 🚀 **Real-Time IDE Scanning** - VS Code extension with auto-scan as you type
- 🏢 **Enterprise Custom Rules** - Advanced policy engine with compliance mapping
- 🔬 **Cutting-Edge Detectors** - AI/ML, API security, cloud-native, supply chain
- 📊 **Amazon Q Parity** - Feature parity with industry-leading tools
- 🎨 **Enhanced AI Fixes** - Context-aware code fixes with diff previews

## 🆚 Comparison with Amazon Q Developer

| Feature | Parry v3.0 | Amazon Q |
|---------|------------|----------|
| Security Detectors | 150+ | Thousands |
| Real-time Scanning | ✅ | ✅ (Pro) |
| IDE Integration | ✅ VS Code | ✅ Multiple |
| Custom Rules | ✅ Advanced | Limited |
| Self-hosted | ✅ | ❌ |
| Open Source | ✅ | ❌ |
| AI Providers | 3 (Gemini, OpenAI, Ollama) | Proprietary |

## 🚀 Quick Start

### VS Code Extension
```bash
# Install extension
code --install-extension parry-ai.parry-security-scanner

# Or search "Parry Security Scanner" in VS Code marketplace
```

### CLI Installation
```bash
pip install parry-scanner
parry scan . --deep
```

## 📚 Documentation

- [Installation Guide](docs/guides/SETUP_GUIDE.md)
- [VS Code Extension Guide](docs/guides/VSCODE_EXTENSION_GUIDE.md)
- [Custom Rules Documentation](docs/guides/CUSTOM_RULES.md)
- [API Reference](docs/api/API_REFERENCE.md)
- [Benchmark Results](docs/benchmarks/COMPREHENSIVE_BENCHMARK_RESULTS.md)
```

---

## Implementation Timeline

| Week | Phase | Deliverables |
|------|-------|--------------|
| 1-2 | Advanced Detectors | AI/ML, API Security, Cloud detectors |
| 3 | Advanced Detectors | Supply Chain, Container/IaC, Crypto |
| 3-4 | Custom Rules Enhancement | Enterprise features, templates |
| 4-6 | VS Code Extension | Real-time scanning, UI, fixes |
| 6 | Enhanced AI Fixes | Context-aware generation, validation |
| 7 | Benchmarking | Comprehensive testing, metrics |
| 8 | Documentation & Release | Docs, marketing, v3.0 release |

---

## Success Metrics

### Technical Metrics
- **Precision**: Target 85%+ (Amazon Q: 84.7% on OWASP)
- **Recall**: Target 90%+ (Amazon Q: 100% on OWASP)
- **False Positive Rate**: < 15%
- **Scan Performance**: < 5 seconds for 1000 LOC
- **IDE Extension**: < 2 second response time

### Business Metrics
- **GitHub Stars**: 5,000+ by Q2 2026
- **VS Code Extension Downloads**: 10,000+ in first quarter
- **Enterprise Adoption**: 50+ companies
- **Community Contributors**: 100+

---

## Risk Mitigation

### Technical Risks
1. **Performance**: Real-time scanning may slow IDE
   - *Mitigation*: Debouncing, incremental scans, caching
2. **False Positives**: Too many false alarms
   - *Mitigation*: Machine learning tuning, user feedback loop
3. **AI Fix Quality**: Generated fixes may be incorrect
   - *Mitigation*: Validation layer, confidence scoring, user review

### Business Risks
1. **Competition**: Amazon Q has more resources
   - *Mitigation*: Focus on open-source, customization, self-hosting
2. **Adoption**: Users may stick with existing tools
   - *Mitigation*: Superior UX, free tier, easy migration

---

## Conclusion

This implementation plan will bring Parry to full feature parity with Amazon Q Developer while maintaining our unique advantages: open-source, self-hosting, and advanced customization. The 8-week timeline is aggressive but achievable with focused execution.

**Next Steps:**
1. Review and approve this plan
2. Allocate resources (2-3 developers)
3. Begin Phase 1 implementation
4. Weekly progress reviews

---

*Document Version: 1.0*  
*Last Updated: November 3, 2025*  
*Owner: Parry Development Team*
