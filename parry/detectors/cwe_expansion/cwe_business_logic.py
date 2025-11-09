"""Business Logic Vulnerability Detectors - 10+ CWEs"""
import re
from pathlib import Path
from typing import List
from parry.scanner import Vulnerability, VulnerabilityDetector

class BehavioralWorkflowDetector(VulnerabilityDetector):
    """CWE-841: Improper Enforcement of Behavioral Workflow"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
            if re.search(r'if.*status.*==.*completed.*\n.*update.*status.*=', context, re.IGNORECASE | re.MULTILINE):
                vulnerabilities.append(Vulnerability(cwe="CWE-841", severity="medium", title="Improper Workflow Enforcement", description="Workflow state can be bypassed.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="business-logic"))
        return vulnerabilities

class ExcessiveTrustDetector(VulnerabilityDetector):
    """CWE-349: Acceptance of Extraneous Untrusted Data With Trusted Data"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'trust.*untrusted.*data', "CWE-349", "medium"),
            (r'merge.*trusted.*untrusted', "CWE-349", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Excessive Trust in Data",
                        description="Excessive trust placed in untrusted data mixed with trusted data.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="business-logic"
                    ))
        return vulnerabilities

class RaceConditionBusinessLogicDetector(VulnerabilityDetector):
    """CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'balance.*\+=.*amount', "CWE-362", "high"),
            (r'count.*\+=.*1', "CWE-362", "medium"),
            (r'inventory.*-=.*quantity', "CWE-362", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'lock|mutex|synchronized|atomic', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Race Condition in Business Logic",
                            description="Shared resource modification without proper synchronization.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="business-logic"
                        ))
        return vulnerabilities

class InsufficientProcessValidationDetector(VulnerabilityDetector):
    """CWE-573: Improper Following of Specification by Caller"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'process.*order.*without.*validation', "CWE-573", "medium"),
            (r'execute.*transaction.*bypass', "CWE-573", "high"),
            (r'skip.*verification.*step', "CWE-573", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Insufficient Process Validation",
                        description="Business process executed without proper validation steps.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="business-logic"
                    ))
        return vulnerabilities

class BusinessLogicFlawDetector(VulnerabilityDetector):
    """CWE-840: Business Logic Errors"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'discount.*>.*100', "CWE-840", "medium"),
            (r'quantity.*<.*0', "CWE-840", "medium"),
            (r'price.*=.*0', "CWE-840", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if re.search(r'if.*not.*|assert.*not', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Business Logic Flaw",
                            description="Potential business logic error allowing invalid states.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="business-logic"
                        ))
        return vulnerabilities

class IncorrectCalculationDetector(VulnerabilityDetector):
    """CWE-1339: Insufficient Precision or Accuracy of a Real Number"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'float.*calculation.*money', "CWE-1339", "medium"),
            (r'double.*price.*calculation', "CWE-1339", "medium"),
            (r'rounding.*error', "CWE-1339", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Incorrect Calculation",
                        description="Potential precision errors in financial calculations.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="business-logic"
                    ))
        return vulnerabilities

class StateTransitionDetector(VulnerabilityDetector):
    """CWE-374: Passing Mutable Objects to an Untrusted Method"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'pass.*mutable.*object', "CWE-374", "low"),
            (r'share.*state.*between.*threads', "CWE-374", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Unsafe State Transition",
                        description="Mutable objects passed between untrusted contexts.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="business-logic"
                    ))
        return vulnerabilities

class ConstraintViolationDetector(VulnerabilityDetector):
    """CWE-350: Reliance on Reverse DNS Resolution for a Security-Critical Action"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'access.*control.*dns', "CWE-350", "high"),
            (r'auth.*reverse.*dns', "CWE-350", "high"),
            (r'trust.*hostname.*resolution', "CWE-350", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Constraint Violation",
                        description="Security decisions based on unreliable reverse DNS.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="business-logic"
                    ))
        return vulnerabilities

class BusinessRuleBypassDetector(VulnerabilityDetector):
    """CWE-602: Client-Side Enforcement of Server-Side Security"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'client.*side.*validation.*only', "CWE-602", "high"),
            (r'browser.*enforce.*rule', "CWE-602", "high"),
            (r'javascript.*security', "CWE-602", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Business Rule Bypass",
                        description="Security rules enforced only on client-side.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="business-logic"
                    ))
        return vulnerabilities

class LogicBombDetector(VulnerabilityDetector):
    """CWE-511: Logic/Time Bomb"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'if.*date.*>.*explode', "CWE-511", "critical"),
            (r'time.*bomb', "CWE-511", "critical"),
            (r'logic.*bomb', "CWE-511", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Logic Bomb",
                        description="Malicious time or logic bomb detected.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="business-logic"
                    ))
        return vulnerabilities

class InfiniteLoopBusinessLogicDetector(VulnerabilityDetector):
    """CWE-835: Loop with Unreachable Exit Condition"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'while.*True.*\n.*continue', "CWE-835", "medium"),
            (r'for.*range.*1000000', "CWE-835", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'break|return|exit', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Infinite Loop Risk",
                            description="Potential infinite loop in business logic.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="business-logic"
                        ))
        return vulnerabilities

class PrivilegeEscalationBusinessLogicDetector(VulnerabilityDetector):
    """CWE-269: Improper Privilege Management - Business Logic"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'admin.*=.*user|role.*=.*admin', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'check.*permission|validate.*role|has.*admin', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-269", severity="critical", title="Privilege Escalation in Business Logic",
                        description="Business logic allows privilege escalation without proper authorization.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="business-logic"
                    ))
        return vulnerabilities

class BusinessLogicTimeBombDetector(VulnerabilityDetector):
    """CWE-511: Logic/Time Bomb"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'date.*>.*202|time.*>.*203|if.*Date.*after', line, re.IGNORECASE):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-511", severity="high", title="Logic Time Bomb",
                    description="Code contains time-based deactivation that may cause service disruption.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="medium", category="business-logic"
                ))
        return vulnerabilities

class InsufficientWorkflowValidationDetector(VulnerabilityDetector):
    """CWE-841: Improper Enforcement of Behavioral Workflow"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'status.*=.*complete|step.*=.*final', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if not re.search(r'validate.*step|check.*workflow|previous.*step', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-841", severity="medium", title="Insufficient Workflow Validation",
                        description="Workflow steps not properly validated, allowing out-of-order execution.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="business-logic"
                    ))
        return vulnerabilities

class BusinessLogicInjectionDetector(VulnerabilityDetector):
    """CWE-74: Injection - Business Logic"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'eval.*business|exec.*logic|Function.*input', line, re.IGNORECASE):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-74", severity="high", title="Business Logic Injection",
                    description="Business logic allows code injection through dynamic evaluation.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="high", category="business-logic"
                ))
        return vulnerabilities

class IncorrectBusinessRulePriorityDetector(VulnerabilityDetector):
    """CWE-841: Improper Enforcement of Behavioral Workflow"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'if.*priority|priority.*order', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-8):min(len(lines), i+8)])
                if not re.search(r'sort.*priority|order.*by.*priority', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-841", severity="low", title="Incorrect Business Rule Priority",
                        description="Business rules may be applied in incorrect priority order.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="business-logic"
                    ))
        return vulnerabilities

class BusinessLogicRaceConditionDetector(VulnerabilityDetector):
    """CWE-362: Race Condition - Business Logic"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'balance.*=|inventory.*=|stock.*=', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if re.search(r'concurrent|thread|async', context, re.IGNORECASE) and not re.search(r'lock|atomic|transaction', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-362", severity="high", title="Business Logic Race Condition",
                        description="Business logic operations on shared state without proper synchronization.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="business-logic"
                    ))
        return vulnerabilities

class InsufficientBusinessValidationDetector(VulnerabilityDetector):
    """CWE-20: Improper Input Validation - Business Logic"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'amount.*=|price.*=|quantity.*=', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'validate|check.*range|min.*max', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-20", severity="medium", title="Insufficient Business Validation",
                        description="Business values not properly validated for reasonable ranges.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="business-logic"
                    ))
        return vulnerabilities

class BusinessLogicBypassDetector(VulnerabilityDetector):
    """CWE-290: Authentication Bypass by Capture-replay"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'skip.*validation|bypass.*check|ignore.*rule', line, re.IGNORECASE):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-290", severity="high", title="Business Logic Bypass",
                    description="Business logic contains mechanisms to bypass validation rules.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="high", category="business-logic"
                ))
        return vulnerabilities

class IncorrectBusinessCalculationDetector(VulnerabilityDetector):
    """CWE-682: Incorrect Calculation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'total.*=.*price.*quantity|sum.*=.*\+', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'int.*float|float.*int', context) and not re.search(r'BigDecimal|Decimal|round', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-682", severity="medium", title="Incorrect Business Calculation",
                        description="Business calculations may suffer from precision errors.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="business-logic"
                    ))
        return vulnerabilities

class BusinessLogicStateCorruptionDetector(VulnerabilityDetector):
    """CWE-371: State Issues"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'state.*=.*|status.*=.*', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if re.search(r'exception|error', context, re.IGNORECASE) and not re.search(r'rollback|revert|restore', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-371", severity="medium", title="Business Logic State Corruption",
                        description="Business state may be corrupted during error conditions without rollback.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="business-logic"
                    ))
        return vulnerabilities

class InsufficientBusinessLoggingDetector(VulnerabilityDetector):
    """CWE-778: Insufficient Logging - Business Logic"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'withdraw|transfer|payment|transaction', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-15):min(len(lines), i+15)])
                if not re.search(r'log.*transaction|audit.*record|logger\.|log\.', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-778", severity="low", title="Insufficient Business Logging",
                        description="Critical business operations not properly logged for audit purposes.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="business-logic"
                    ))
        return vulnerabilities

class BusinessLogicEnumerationDetector(VulnerabilityDetector):
    """CWE-203: Observable Discrepancy - Business Logic Enumeration"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'if.*not.*found|user.*not.*exist', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'response\.|return.*message', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-203", severity="low", title="User Enumeration via Business Logic",
                        description="Different responses for existing vs non-existing users enables enumeration.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="business-logic"
                    ))
        return vulnerabilities

class BusinessLogicTimingAttackDetector(VulnerabilityDetector):
    """CWE-208: Observable Timing Discrepancy - Business Logic"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'password.*verify|check.*password|authenticate', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i):min(len(lines), i+10)])
                if not re.search(r'constant.*time|timing.*safe', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-208", severity="medium", title="Timing Attack in Business Logic",
                        description="Password verification may be vulnerable to timing attacks.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="business-logic"
                    ))
        return vulnerabilities

class BusinessLogicIntegerOverflowDetector(VulnerabilityDetector):
    """CWE-190: Integer Overflow - Business Logic"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'balance.*\+|amount.*\+|total.*\+', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if not re.search(r'check.*max|max.*value|overflow', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-190", severity="high", title="Integer Overflow in Business Logic",
                        description="Business calculations may overflow without proper bounds checking.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="business-logic"
                    ))
        return vulnerabilities

class BusinessLogicDenialOfServiceDetector(VulnerabilityDetector):
    """CWE-400: Uncontrolled Resource Consumption - Business Logic DoS"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'loop|while.*true|recursion', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if re.search(r'user.*input|request|param', context, re.IGNORECASE) and not re.search(r'limit|max.*iterations', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-400", severity="high", title="Business Logic Denial of Service",
                        description="User-controlled loops or recursion may cause DoS without limits.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="business-logic"
                    ))
        return vulnerabilities

class BusinessLogicAuthenticationBypassDetector(VulnerabilityDetector):
    """CWE-287: Improper Authentication - Business Logic Bypass"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'if.*admin|if.*role.*=|if.*permission', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-8):min(len(lines), i+8)])
                if re.search(r'param|request|input', context, re.IGNORECASE) and not re.search(r'check.*auth|verify.*session|validate.*token', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-287", severity="critical", title="Authentication Bypass via Business Logic",
                        description="Authentication checks bypassed through business logic manipulation.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="business-logic"
                    ))
        return vulnerabilities

class BusinessLogicDataTamperingDetector(VulnerabilityDetector):
    """CWE-471: Modification of Assumed-Immutable Data - Business Logic"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'const.*=.*|final.*=.*|readonly.*=', line, re.IGNORECASE):
                context = '\n'.join(lines[i:min(len(lines), i+10)])
                if re.search(r'Object\.defineProperty|modify|change', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-471", severity="high", title="Data Tampering via Business Logic",
                        description="Assumed-immutable data can be modified through business logic.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="business-logic"
                    ))
        return vulnerabilities

class BusinessLogicInsufficientValidationDetector(VulnerabilityDetector):
    """CWE-20: Improper Input Validation - Business Logic Flaw"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'business.*rule|workflow|process', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if not re.search(r'validate|check|sanitiz', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-20", severity="medium", title="Insufficient Business Logic Validation",
                        description="Business rules applied without proper input validation.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="business-logic"
                    ))
        return vulnerabilities

def get_business_logic_detectors():
    return [
        BehavioralWorkflowDetector(),
        ExcessiveTrustDetector(),
        RaceConditionBusinessLogicDetector(),
        InsufficientProcessValidationDetector(),
        BusinessLogicFlawDetector(),
        IncorrectCalculationDetector(),
        StateTransitionDetector(),
        ConstraintViolationDetector(),
        BusinessRuleBypassDetector(),
        LogicBombDetector(),
        InfiniteLoopBusinessLogicDetector(),
        PrivilegeEscalationBusinessLogicDetector(),
        BusinessLogicTimeBombDetector(),
        InsufficientWorkflowValidationDetector(),
        BusinessLogicInjectionDetector(),
        IncorrectBusinessRulePriorityDetector(),
        BusinessLogicRaceConditionDetector(),
        InsufficientBusinessValidationDetector(),
        BusinessLogicBypassDetector(),
        IncorrectBusinessCalculationDetector(),
        BusinessLogicStateCorruptionDetector(),
        InsufficientBusinessLoggingDetector(),
        BusinessLogicEnumerationDetector(),
        BusinessLogicTimingAttackDetector(),
        BusinessLogicIntegerOverflowDetector(),
        BusinessLogicDenialOfServiceDetector(),
        BusinessLogicAuthenticationBypassDetector(),
        BusinessLogicDataTamperingDetector(),
        BusinessLogicInsufficientValidationDetector(),
    ]
    return [BehavioralWorkflowDetector()]