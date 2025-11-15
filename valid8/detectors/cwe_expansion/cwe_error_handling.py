"""Error Handling Vulnerability Detectors - 10+ CWEs"""
import re
from pathlib import Path
from typing import List
from valid8.scanner import Vulnerability, VulnerabilityDetector

class UncheckedReturnValueDetector(VulnerabilityDetector):
    """CWE-252: Unchecked Return Value"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'\.(read|write|open)\(.*\)\s*(?!.*if.*!.*=|.*if.*==)', "CWE-252", "medium")]
        for i, line in enumerate(lines, 1):
            context = '\n'.join(lines[max(0, i-2):min(len(lines), i+2)])
            for pattern, cwe, severity in patterns:
                if re.search(pattern, context, re.IGNORECASE | re.MULTILINE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-252", severity=severity, title="Unchecked Return Value", description="Return value not checked.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="error-handling"))
        return vulnerabilities

class UncaughtExceptionDetector(VulnerabilityDetector):
    """CWE-248: Uncaught Exception"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'\.get\(|\[.*\]|\.read\(|\.write\(', line):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if not re.search(r'(try|catch|except|finally)', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-248", severity="low", title="Uncaught Exception", description="Potential uncaught exception.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="error-handling"))
        return vulnerabilities

class ErrorConditionWithoutActionDetector(VulnerabilityDetector):
    """CWE-390: Detection of Error Condition Without Action"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
            if re.search(r'except:.*\n.*pass|catch.*\{.*\}', context, re.IGNORECASE | re.MULTILINE):
                vulnerabilities.append(Vulnerability(cwe="CWE-390", severity="medium", title="Error Condition Without Action", description="Error caught but not handled.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="error-handling"))
        return vulnerabilities

class InformationLeakageThroughErrorDetector(VulnerabilityDetector):
    """CWE-209: Information Exposure Through an Error Message"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'except.*Exception.*as.*e.*print\(e', "CWE-209", "medium"),
            (r'catch.*Exception.*e.*printStackTrace', "CWE-209", "medium"),
            (r'error.*message.*stack.*trace', "CWE-209", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Information Leakage Through Error",
                        description="Error messages may expose sensitive information.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="error-handling"
                    ))
        return vulnerabilities

class ImproperErrorHandlingDetector(VulnerabilityDetector):
    """CWE-755: Improper Handling of Exceptional Conditions"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'except.*Exception.*pass', "CWE-755", "high"),
            (r'catch.*Throwable.*\{\s*\}', "CWE-755", "high"),
            (r'try.*finally.*no.*catch', "CWE-755", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Improper Error Handling",
                        description="Exceptional conditions not properly handled.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="error-handling"
                    ))
        return vulnerabilities

class InsufficientLoggingDetector(VulnerabilityDetector):
    """CWE-778: Insufficient Logging"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'except.*Exception.*no.*log', "CWE-778", "low"),
            (r'catch.*no.*logging', "CWE-778", "low"),
            (r'error.*not.*logged', "CWE-778", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Insufficient Logging",
                        description="Errors and exceptions not properly logged.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="error-handling"
                    ))
        return vulnerabilities

class IncompleteCleanupDetector(VulnerabilityDetector):
    """CWE-459: Incomplete Cleanup"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'open\(.*\).*no.*close', "CWE-459", "medium"),
            (r'connection.*no.*close', "CWE-459", "medium"),
            (r'resource.*no.*cleanup', "CWE-459", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+10)])
                    if not re.search(r'finally|with|using|close\(\)', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Incomplete Cleanup",
                            description="Resources not properly cleaned up in error conditions.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="error-handling"
                        ))
        return vulnerabilities

class OverlyBroadCatchDetector(VulnerabilityDetector):
    """CWE-396: Declaration of Catch for Generic Exception"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'except.*Exception:', "CWE-396", "medium"),
            (r'catch.*Exception', "CWE-396", "medium"),
            (r'catch.*Throwable', "CWE-396", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-2):min(len(lines), i+5)])
                    if not re.search(r'#.*specific|#.*narrow', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Overly Broad Catch",
                            description="Catching overly broad exception types.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="error-handling"
                        ))
        return vulnerabilities

class ErrorMessageInformationLeakDetector(VulnerabilityDetector):
    """CWE-535: Information Exposure Through Shell Error Message"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'system\(.*2>&1', "CWE-535", "medium"),
            (r'subprocess\..*stderr', "CWE-535", "medium"),
            (r'exec.*error.*message', "CWE-535", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if re.search(r'print|echo|return', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Error Message Information Leak",
                            description="Shell error messages may expose sensitive information.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="error-handling"
                        ))
        return vulnerabilities

class ImproperExceptionChainingDetector(VulnerabilityDetector):
    """CWE-835: Loop with Unreachable Exit Condition"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'except.*raise.*e', "CWE-835", "low"),
            (r'catch.*throw.*e', "CWE-835", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'from.*e|cause.*e', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Improper Exception Chaining",
                            description="Exceptions not properly chained, losing original context.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="error-handling"
                        ))
        return vulnerabilities

class UnhandledPromiseRejectionDetector(VulnerabilityDetector):
    """CWE-391: Unchecked Error Condition"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'\.then\(.*\)\.catch\(.*missing', "CWE-391", "medium"),
            (r'Promise\.all.*no.*catch', "CWE-391", "medium"),
            (r'async.*await.*no.*try', "CWE-391", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Unhandled Promise Rejection",
                        description="Asynchronous errors not properly handled.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="error-handling"
                    ))
        return vulnerabilities

class ResourceLeakInErrorPathDetector(VulnerabilityDetector):
    """CWE-775: Missing Release of File Descriptor or Handle after Effective Lifetime"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'open\(.*\).*except.*pass', "CWE-775", "high"),
            (r'connect\(.*\).*catch.*\{\s*\}', "CWE-775", "high"),
            (r'acquire.*resource.*error.*path', "CWE-775", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Resource Leak in Error Path",
                        description="Resources not released in error handling paths.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="error-handling"
                    ))
        return vulnerabilities

class SilentFailureDetector(VulnerabilityDetector):
    """CWE-544: Missing Standardized Error Handling Mechanism"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'if.*error.*continue', "CWE-544", "low"),
            (r'error.*=.*None', "CWE-544", "low"),
            (r'suppress.*error', "CWE-544", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Silent Failure",
                        description="Errors silently ignored without proper handling.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="error-handling"
                    ))
        return vulnerabilities

class GenericExceptionCatchingDetector(VulnerabilityDetector):
    """CWE-396: Declaration of Catch for Generic Exception"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'catch\s*\(\s*Exception|catch\s*\(\s*Error|except\s*Exception:|except\s*BaseException:', line):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-396", severity="low", title="Generic Exception Catching",
                    description="Catching generic exceptions may hide specific errors and make debugging difficult.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="medium", category="error-handling"
                ))
        return vulnerabilities

class MissingFinallyBlockDetector(VulnerabilityDetector):
    """CWE-584: Return Inside Finally Block"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'finally:', line):
                context = '\n'.join(lines[i:min(len(lines), i+10)])
                if re.search(r'return\s+|break\s+|continue\s+', context):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-584", severity="medium", title="Control Flow in Finally Block",
                        description="Control flow statements in finally blocks can suppress exceptions.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="error-handling"
                    ))
        return vulnerabilities

class NestedTryCatchDetector(VulnerabilityDetector):
    """CWE-705: Incorrect Control Flow Scoping"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        try_depth = 0
        for i, line in enumerate(lines, 1):
            if re.search(r'try\s*[:{]', line):
                try_depth += 1
                if try_depth > 2:
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-705", severity="low", title="Deeply Nested Try Blocks",
                        description="Deeply nested try blocks make error handling complex and error-prone.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="error-handling"
                    ))
            elif re.search(r'}\s*catch|except:|finally:', line):
                try_depth = max(0, try_depth - 1)
        return vulnerabilities

class ErrorWithoutLoggingDetector(VulnerabilityDetector):
    """CWE-778: Insufficient Logging"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'catch\s*\(|except\s+\w+:', line):
                context = '\n'.join(lines[i:min(len(lines), i+8)])
                if not re.search(r'logger\.|log\.|print.*error|console\.(error|warn)', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-778", severity="low", title="Error Without Logging",
                        description="Caught exceptions should be logged for debugging and monitoring.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="error-handling"
                    ))
        return vulnerabilities

class ExceptionSwallowingDetector(VulnerabilityDetector):
    """CWE-391: Unchecked Error Condition"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'catch\s*\([^)]*\)\s*{\s*}|except\s+\w+:\s*pass|catch\s*\([^)]*\)\s*=>\s*{\s*}', line):
                context = '\n'.join(lines[i:min(len(lines), i+3)])
                if re.search(r'pass\s*$|}\s*$', context) and not re.search(r'logger\.|log\.|throw|raise', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-391", severity="medium", title="Exception Swallowing",
                        description="Exceptions are caught but not handled or re-thrown, potentially hiding errors.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="error-handling"
                    ))
        return vulnerabilities

class InconsistentErrorHandlingDetector(VulnerabilityDetector):
    """CWE-390: Detection of Error Condition Without Action"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'if\s*\(.*error.*\)|if\s*\(.*Error.*\)', line, re.IGNORECASE):
                context = '\n'.join(lines[i:min(len(lines), i+5)])
                if not re.search(r'return|throw|raise|break|continue|logger\.|log\.', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-390", severity="low", title="Inconsistent Error Handling",
                        description="Error conditions are detected but not properly handled.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="error-handling"
                    ))
        return vulnerabilities

class ResourceLeakInExceptionPathDetector(VulnerabilityDetector):
    """CWE-772: Missing Release of Resource after Effective Lifetime"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'catch\s*\(|except\s+\w+:', line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+8)])
                # Look for resource allocation before try/catch
                alloc_pattern = r'open\(|fopen\(|new\s+\w+|malloc\(|connect\('
                if re.search(alloc_pattern, context) and not re.search(r'close\(|fclose\(|delete|free\(|disconnect\(', context):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-772", severity="high", title="Resource Leak in Exception Path",
                        description="Resources allocated before exception handling may not be released in error paths.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="error-handling"
                    ))
        return vulnerabilities

class AsynchronousErrorHandlingDetector(VulnerabilityDetector):
    """CWE-20: Improper Input Validation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'async|Promise|await', line):
                context = '\n'.join(lines[i:min(len(lines), i+10)])
                if re.search(r'Promise|async', context) and not re.search(r'\.catch\(|try\s*{\s*await|await.*catch', context):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-20", severity="medium", title="Missing Asynchronous Error Handling",
                        description="Asynchronous operations lack proper error handling.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="error-handling"
                    ))
        return vulnerabilities

class ErrorStatusCodeDetector(VulnerabilityDetector):
    """CWE-209: Information Exposure Through an Error Message"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'response\.status\s*=\s*5\d\d|res\.status\(5\d\d\)', line):
                context = '\n'.join(lines[i:min(len(lines), i+3)])
                if re.search(r'error\.message|err\.message|exception\.message', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-209", severity="medium", title="Error Information in HTTP Response",
                        description="Internal error details exposed in HTTP response status.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="error-handling"
                    ))
        return vulnerabilities

class IncompleteErrorRecoveryDetector(VulnerabilityDetector):
    """CWE-459: Incomplete Cleanup"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'catch\s*\(|except\s+\w+:', line):
                context = '\n'.join(lines[i:min(len(lines), i+15)])
                # Look for partial cleanup patterns
                if re.search(r'rollback|close|cleanup', context, re.IGNORECASE) and not re.search(r'finally:|complete.*cleanup|full.*recovery', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-459", severity="medium", title="Incomplete Error Recovery",
                        description="Error recovery is incomplete - some cleanup may be missing.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="error-handling"
                    ))
        return vulnerabilities

class UnreachableCatchBlockDetector(VulnerabilityDetector):
    """CWE-561: Dead Code"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'catch\s*\([^)]*Exception[^)]*\)|except\s+Exception:', line):
                # Check if this catch block is after a more specific exception
                context_before = '\n'.join(lines[max(0, i-10):i])
                if re.search(r'catch\s*\([^)]*\)|except\s+\w+:', context_before):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-561", severity="low", title="Unreachable Catch Block",
                        description="Catch block for generic exception may be unreachable due to more specific handlers.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="error-handling"
                    ))
        return vulnerabilities

class EmptyCatchBlockDetector(VulnerabilityDetector):
    """CWE-391: Unchecked Error Condition - Empty Catch Blocks"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'catch\s*\([^)]*\)\s*\{\s*\}|except\s+\w+:\s*pass', line):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-391", severity="low", title="Empty Catch Block",
                    description="Empty catch block silently ignores exceptions.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="high", category="error-handling"
                ))
        return vulnerabilities

class InsufficientErrorContextDetector(VulnerabilityDetector):
    """CWE-209: Information Exposure Through an Error Message - Insufficient Context"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'catch\s*\([^)]*\)|except\s+\w+', line):
                context = '\n'.join(lines[i:min(len(lines), i+5)])
                if not re.search(r'stackTrace|error\.message|err\.message|getMessage', context):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-209", severity="low", title="Insufficient Error Context",
                        description="Error handling without sufficient context information.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="error-handling"
                    ))
        return vulnerabilities

class ErrorMaskingDetector(VulnerabilityDetector):
    """CWE-397: Declaration of Throws for Generic Exception"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'throws\s+Exception|throws\s+Throwable|raise\s+Exception', line):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-397", severity="low", title="Generic Exception Declaration",
                    description="Method declares throwing generic exception, masking specific errors.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="medium", category="error-handling"
                ))
        return vulnerabilities

class UnhandledAsynchronousErrorDetector(VulnerabilityDetector):
    """CWE-20: Improper Input Validation - Unhandled Async Errors"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'Promise|async|await', line):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if not re.search(r'\.catch|try.*await|unhandledrejection', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-20", severity="medium", title="Unhandled Asynchronous Error",
                        description="Asynchronous operation without proper error handling.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="error-handling"
                    ))
        return vulnerabilities

def get_error_handling_detectors():
    return [
        UncheckedReturnValueDetector(),
        UncaughtExceptionDetector(),
        ErrorConditionWithoutActionDetector(),
        InformationLeakageThroughErrorDetector(),
        ImproperErrorHandlingDetector(),
        InsufficientLoggingDetector(),
        IncompleteCleanupDetector(),
        OverlyBroadCatchDetector(),
        ErrorMessageInformationLeakDetector(),
        ImproperExceptionChainingDetector(),
        UnhandledPromiseRejectionDetector(),
        ResourceLeakInErrorPathDetector(),
        SilentFailureDetector(),
        GenericExceptionCatchingDetector(),
        MissingFinallyBlockDetector(),
        NestedTryCatchDetector(),
        ErrorWithoutLoggingDetector(),
        ExceptionSwallowingDetector(),
        InconsistentErrorHandlingDetector(),
        ResourceLeakInExceptionPathDetector(),
        AsynchronousErrorHandlingDetector(),
        ErrorStatusCodeDetector(),
        IncompleteErrorRecoveryDetector(),
        UnreachableCatchBlockDetector(),
        EmptyCatchBlockDetector(),
        InsufficientErrorContextDetector(),
        ErrorMaskingDetector(),
        UnhandledAsynchronousErrorDetector(),
    ]
    return [UncheckedReturnValueDetector(), UncaughtExceptionDetector(), ErrorConditionWithoutActionDetector()]