"""Resource Management Vulnerability Detectors - 15+ CWEs"""
import re
from pathlib import Path
from typing import List
from parry.scanner import Vulnerability, VulnerabilityDetector

class UncontrolledResourceConsumptionDetector(VulnerabilityDetector):
    """CWE-400: Uncontrolled Resource Consumption"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'while\s*\(.*True|.*while\s*\(1\)', "CWE-400", "medium")]
        for i, line in enumerate(lines, 1):
            context = '\n'.join(lines[max(0, i-5):min(len(lines), i+10)])
            for pattern, cwe, severity in patterns:
                if re.search(pattern, context, re.IGNORECASE | re.MULTILINE):
                    if not re.search(r'(limit|max|timeout|break|return)', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-400", severity=severity, title="Uncontrolled Resource Consumption", description="Loop without limits may cause resource exhaustion.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="resource-management"))
        return vulnerabilities

class MissingFileCloseDetector(VulnerabilityDetector):
    """CWE-404: Improper Resource Shutdown"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'open\(|File\(|\.open\(', line, re.IGNORECASE):
                context = '\n'.join(lines[i:min(len(lines), i+20)])
                if not re.search(r'\.close\(|close\(|with\s+open|try.*finally.*close', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-404", severity="low", title="Missing File Close", description="File opened but may not be closed.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="resource-management"))
        return vulnerabilities

class UncontrolledRecursionDetector(VulnerabilityDetector):
    """CWE-674: Uncontrolled Recursion"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'def\s+(\w+).*:', line):
                func_match = re.search(r'def\s+(\w+)', line)
                if func_match:
                    func_name = func_match.group(1)
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+20)])
                    func_pattern = re.escape(func_name) + r'\('
                    if re.search(func_pattern, context) and not re.search(r'(depth|limit|count|max|recursion)', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-674", severity="medium", title="Uncontrolled Recursion", description="Recursive function without depth limit.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="resource-management"))
        return vulnerabilities

class MemoryLeakDetector(VulnerabilityDetector):
    """CWE-401: Missing Release of Memory after Effective Lifetime"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'malloc\(|new\s+\w+|alloc\(', "CWE-401", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-10):min(len(lines), i+20)])
                    if not re.search(r'free\(|delete|dealloc|release', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Memory Leak",
                            description="Memory allocated but may not be freed.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="resource-management"
                        ))
        return vulnerabilities

class ResourceExhaustionDetector(VulnerabilityDetector):
    """CWE-400: Uncontrolled Resource Consumption - CPU"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'while.*True|for.*;;|while\(1\)', "CWE-400", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+10)])
                    if not re.search(r'sleep|delay|limit|break|return|timeout', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Resource Exhaustion",
                            description="Infinite loop may exhaust CPU resources.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="resource-management"
                        ))
        return vulnerabilities

class DatabaseConnectionLeakDetector(VulnerabilityDetector):
    """CWE-404: Improper Resource Shutdown - Database"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'connect\(|createConnection\(|getConnection\(', "CWE-404", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[i:min(len(lines), i+25)])
                    if not re.search(r'close\(|disconnect\(|finally.*close', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Database Connection Leak",
                            description="Database connection opened but may not be closed.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="resource-management"
                        ))
        return vulnerabilities

class SocketLeakDetector(VulnerabilityDetector):
    """CWE-404: Improper Resource Shutdown - Sockets"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'socket\(|Socket\(|connect\(', "CWE-404", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[i:min(len(lines), i+20)])
                    if not re.search(r'close\(|shutdown\(|finally.*close', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Socket Leak",
                            description="Socket opened but may not be closed.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="resource-management"
                        ))
        return vulnerabilities

class ThreadLeakDetector(VulnerabilityDetector):
    """CWE-404: Improper Resource Shutdown - Threads"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'Thread\(|threading\.Thread\(|Thread\.start', "CWE-404", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[i:min(len(lines), i+15)])
                    if not re.search(r'join\(|daemon|finally.*join', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Thread Leak",
                            description="Thread started but may not be properly joined.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="resource-management"
                        ))
        return vulnerabilities

class BufferOverflowDetector(VulnerabilityDetector):
    """CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'strcpy\(|strcat\(|sprintf\(', "CWE-119", "high"),
            (r'gets\(|scanf.*%s|getchar', "CWE-119", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Buffer Overflow",
                        description="Unsafe string operation may cause buffer overflow.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="resource-management"
                    ))
        return vulnerabilities

class IntegerOverflowDetector(VulnerabilityDetector):
    """CWE-190: Integer Overflow or Wraparound"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'int.*\+.*=|count.*\+.*=|size.*\+.*=', "CWE-190", "medium"),
            (r'length.*\+.*=|index.*\+.*=', "CWE-190", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'check|limit|max|clamp|safe', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Integer Overflow",
                            description="Integer operation may overflow without bounds checking.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="resource-management"
                        ))
        return vulnerabilities

class UncheckedReturnValueDetector(VulnerabilityDetector):
    """CWE-252: Unchecked Return Value"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'malloc\(|fopen\(|connect\(', "CWE-252", "low"),
            (r'recv\(|send\(|read\(', "CWE-252", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-2):min(len(lines), i+3)])
                    if not re.search(r'if.*==.*NULL|if.*<.*0|if.*!.*|check|validate', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Unchecked Return Value",
                            description="Function return value not checked for errors.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="resource-management"
                        ))
        return vulnerabilities

class DoubleFreeDetector(VulnerabilityDetector):
    """CWE-415: Double Free"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'free\(|delete\s+', line):
                # Look for multiple frees of the same variable
                var_match = re.search(r'free\(([^)]+)\)|delete\s+([^;\s]+)', line)
                if var_match:
                    var = var_match.group(1) or var_match.group(2)
                    context = '\n'.join(lines[max(0, i-15):min(len(lines), i+15)])
                    free_count = context.count(f'free({var})') + context.count(f'delete {var}')
                    if free_count > 1:
                        vulnerabilities.append(Vulnerability(
                            cwe="CWE-415", severity="high", title="Double Free",
                            description="Variable may be freed multiple times.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="resource-management"
                        ))
        return vulnerabilities

class UseAfterFreeDetector(VulnerabilityDetector):
    """CWE-416: Use After Free"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        freed_vars = set()
        for i, line in enumerate(lines, 1):
            # Track frees
            if re.search(r'free\(|delete\s+', line):
                var_match = re.search(r'free\(([^)]+)\)|delete\s+([^;\s]+)', line)
                if var_match:
                    freed_vars.add(var_match.group(1) or var_match.group(2))
            # Check for use after free
            elif freed_vars:
                for var in freed_vars:
                    if re.search(rf'\b{re.escape(var)}\b', line) and not line.strip().startswith('//') and not line.strip().startswith('#'):
                        vulnerabilities.append(Vulnerability(
                            cwe="CWE-416", severity="critical", title="Use After Free",
                            description="Variable used after being freed.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="resource-management"
                        ))
                        break
        return vulnerabilities

class NullPointerDereferenceDetector(VulnerabilityDetector):
    """CWE-476: NULL Pointer Dereference"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            # Look for pointer dereferences without null checks
            if re.search(r'->|\.\s*\w+.*\(|\*.*\w+', line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+2)])
                if not re.search(r'if.*!=.*NULL|if.*==.*NULL|if.*null|assert.*!=.*NULL', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-476", severity="medium", title="Null Pointer Dereference",
                        description="Pointer dereferenced without null check.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="resource-management"
                    ))
        return vulnerabilities

class ResourceStarvationDetector(VulnerabilityDetector):
    """CWE-400: Uncontrolled Resource Consumption - Starvation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'fork\(\)|CreateProcess\(|system\(', "CWE-400", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                    if not re.search(r'limit|max|throttle|rate|semaphore', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Resource Starvation",
                            description="Process creation without resource limits.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="resource-management"
                        ))
        return vulnerabilities

class ImproperErrorHandlingDetector(VulnerabilityDetector):
    """CWE-391: Unchecked Error Condition"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'malloc\(|fopen\(|connect\(|socket\(', "CWE-391", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'if.*==.*NULL|if.*<.*0|if.*!.*|try|catch', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Improper Error Handling",
                            description="Function call result not checked for errors.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="resource-management"
                        ))
        return vulnerabilities

class MemoryExhaustionDetector(VulnerabilityDetector):
    """CWE-400: Uncontrolled Resource Consumption - Memory"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'new\s+\w+\[|malloc\(.*\*.*\)|realloc\(', "CWE-400", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'limit|max|size.*check|validate', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Memory Exhaustion",
                            description="Large memory allocation without size limits.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="resource-management"
                        ))
        return vulnerabilities

class UninitializedVariableDetector(VulnerabilityDetector):
    """CWE-457: Use of Uninitialized Variable"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        # Look for variable declarations without initialization
        for i, line in enumerate(lines, 1):
            if re.search(r'int\s+\w+;|char\s+\w+;|float\s+\w+;', line):
                var_match = re.search(r'(int|char|float)\s+(\w+);', line)
                if var_match:
                    var_name = var_match.group(2)
                    # Check if variable is used before initialization
                    for j in range(i, min(len(lines), i+20)):
                        if re.search(rf'\b{re.escape(var_name)}\b.*=', lines[j]) and not re.search(r'=', lines[j].split('=')[0]):
                            vulnerabilities.append(Vulnerability(
                                cwe="CWE-457", severity="medium", title="Uninitialized Variable",
                                description="Variable used before being initialized.",
                                file_path=str(file_path), line_number=j+1, code_snippet=lines[j].strip(),
                                confidence="medium", category="resource-management"
                            ))
                            break
        return vulnerabilities

class ImproperResourcePoolingDetector(VulnerabilityDetector):
    """CWE-410: Insufficient Resource Pool"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'connection.*pool|thread.*pool|resource.*pool', "CWE-410", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                    if not re.search(r'max.*size|max.*connections|limit|capacity', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Improper Resource Pooling",
                            description="Resource pool without size limits.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="resource-management"
                        ))
        return vulnerabilities

def get_resource_management_detectors():
    return [
        UncontrolledResourceConsumptionDetector(),
        MissingFileCloseDetector(),
        UncontrolledRecursionDetector(),
        MemoryLeakDetector(),
        ResourceExhaustionDetector(),
        DatabaseConnectionLeakDetector(),
        SocketLeakDetector(),
        ThreadLeakDetector(),
        BufferOverflowDetector(),
        IntegerOverflowDetector(),
        UncheckedReturnValueDetector(),
        DoubleFreeDetector(),
        UseAfterFreeDetector(),
        NullPointerDereferenceDetector(),
        ResourceStarvationDetector(),
        ImproperErrorHandlingDetector(),
        MemoryExhaustionDetector(),
        UninitializedVariableDetector(),
        ImproperResourcePoolingDetector(),
        ExcessiveResourceConsumptionDetector(),
        ResourcePoolingExhaustionDetector(),
        ImproperResourceShutdownDetector(),
        FileDescriptorExhaustionDetector(),
        MemoryPressureDetector(),
        ResourceContentionDetector(),
        DatabaseConnectionPoolingDetector(),
        ThreadPoolExhaustionDetector(),
        CachePoisoningDetector(),
        ResourceDeadlockDetector(),
        BufferUnderflowDetector(),
        ResourceInjectionDetector(),
        ImproperResourceInitializationDetector(),
        TemporaryFileRaceConditionDetector(),
        ResourceCleanupFailureDetector(),
    ]

class ExcessiveResourceConsumptionDetector(VulnerabilityDetector):
    """CWE-400: Uncontrolled Resource Consumption"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'while\s*\(\s*true\s*\)|for\s*\(\s*;;\s*\)', line):
                context = '\n'.join(lines[i:min(len(lines), i+5)])
                if not re.search(r'break|sleep|limit|count', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-400", severity="high", title="Excessive Resource Consumption",
                        description="Infinite loop may cause excessive resource consumption.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="resource-management"
                    ))
        return vulnerabilities

class ResourcePoolingExhaustionDetector(VulnerabilityDetector):
    """CWE-410: Insufficient Resource Pool"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'connection.*pool|getConnection|acquire.*resource', line, re.IGNORECASE):
                context = '\n'.join(lines[i:min(len(lines), i+10)])
                if not re.search(r'timeout|limit|max.*pool|pool.*size', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-410", severity="medium", title="Resource Pool Exhaustion",
                        description="Resource pool lacks proper limits and may be exhausted.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="resource-management"
                    ))
        return vulnerabilities

class ImproperResourceShutdownDetector(VulnerabilityDetector):
    """CWE-772: Missing Release of Resource after Effective Lifetime"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'server\.listen|app\.listen|createServer', line, re.IGNORECASE):
                context = '\n'.join(lines[i:min(len(lines), i+20)])
                if not re.search(r'server\.close|process\.on.*SIG|shutdown|cleanup', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-772", severity="medium", title="Improper Resource Shutdown",
                        description="Server or service not properly shut down, may leak resources.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="resource-management"
                    ))
        return vulnerabilities

class FileDescriptorExhaustionDetector(VulnerabilityDetector):
    """CWE-774: Allocation of File Descriptors or Handles Without Limits"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'open\(|fopen\(|fs\.open', line):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if not re.search(r'close\(|fclose\(|fs\.close|finally:|try:', context):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-774", severity="high", title="File Descriptor Exhaustion",
                        description="File descriptors opened without proper closure may exhaust system limits.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="resource-management"
                    ))
        return vulnerabilities

class MemoryPressureDetector(VulnerabilityDetector):
    """CWE-400: Uncontrolled Resource Consumption - Memory Pressure"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'malloc\(|new\s+\w+\[|alloc.*size', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'user.*input|request\.|params\[', context, re.IGNORECASE) and not re.search(r'check|limit|max|validate', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-400", severity="high", title="Memory Pressure Vulnerability",
                        description="Memory allocation based on user input without limits may cause memory exhaustion.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="resource-management"
                    ))
        return vulnerabilities

class ResourceContentionDetector(VulnerabilityDetector):
    """CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'global.*resource|shared.*variable|@staticmethod', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-15):min(len(lines), i+15)])
                if re.search(r'thread|concurrent|async', context, re.IGNORECASE) and not re.search(r'lock|mutex|semaphore|@synchronized|synchronized', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-362", severity="high", title="Resource Contention",
                        description="Shared resources accessed concurrently without proper synchronization.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="resource-management"
                    ))
        return vulnerabilities

class DatabaseConnectionPoolingDetector(VulnerabilityDetector):
    """CWE-405: Asymmetric Resource Consumption (Amplification)"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'connect\(|createConnection|getConnection', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if not re.search(r'pool|connection.*pool|close\(|disconnect', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-405", severity="medium", title="Database Connection Without Pooling",
                        description="Database connections not properly pooled may exhaust connection limits.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="resource-management"
                    ))
        return vulnerabilities

class ThreadPoolExhaustionDetector(VulnerabilityDetector):
    """CWE-410: Insufficient Resource Pool - Thread Pool"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'ThreadPoolExecutor|ExecutorService|thread.*pool', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'max.*thread|pool.*size|core.*pool', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-410", severity="medium", title="Thread Pool Exhaustion",
                        description="Thread pool without proper size limits may be exhausted.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="resource-management"
                    ))
        return vulnerabilities

class CachePoisoningDetector(VulnerabilityDetector):
    """CWE-349: Acceptance of Extraneous Untrusted Data With Trusted Data"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'cache\.set|redis\.set|memcache\.set', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'request\.|params\[|query\[', context, re.IGNORECASE) and not re.search(r'sanitiz|validat|escap', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-349", severity="high", title="Cache Poisoning",
                        description="Cache entries set with unsanitized user input may cause cache poisoning.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="resource-management"
                    ))
        return vulnerabilities

class ResourceDeadlockDetector(VulnerabilityDetector):
    """CWE-667: Improper Locking"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        locks = []
        for i, line in enumerate(lines, 1):
            if re.search(r'acquire\(|lock\.|synchronized', line):
                locks.append((i, line))
                if len(locks) > 3:  # Multiple locks without clear ordering
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-667", severity="medium", title="Potential Resource Deadlock",
                        description="Multiple locks acquired without clear ordering may cause deadlocks.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="resource-management"
                    ))
        return vulnerabilities

class BufferUnderflowDetector(VulnerabilityDetector):
    """CWE-124: Buffer Underwrite ('Buffer Underflow')"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'buffer\[.*\-\s*\d+\]|array\[.*\-\s*\d+\]', line):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-124", severity="high", title="Buffer Underflow",
                    description="Negative array indexing may cause buffer underflow.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="high", category="resource-management"
                ))
        return vulnerabilities

class ResourceInjectionDetector(VulnerabilityDetector):
    """CWE-99: Improper Control of Resource Identifiers"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'open\(|fopen\(|fs\.readFile', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'request\.|params\[|query\[', context, re.IGNORECASE) and not re.search(r'path\.join|resolve|basename|validat', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-99", severity="critical", title="Resource Injection",
                        description="User-controlled path used in file operations without validation.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="resource-management"
                    ))
        return vulnerabilities

class ImproperResourceInitializationDetector(VulnerabilityDetector):
    """CWE-909: Missing Initialization of Resource"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'var\s+\w+;\s*\w+\s*\.', line) or re.search(r'\w+\s*=\s*null;\s*\w+\s*\.', line):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-909", severity="medium", title="Improper Resource Initialization",
                    description="Resource used before proper initialization.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="medium", category="resource-management"
                ))
        return vulnerabilities

class TemporaryFileRaceConditionDetector(VulnerabilityDetector):
    """CWE-377: Insecure Temporary File"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'tempfile\.|tmpfile|mktemp', line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'secure|random|uuid|NamedTemporaryFile', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-377", severity="high", title="Insecure Temporary File",
                        description="Temporary file creation without secure random naming may be vulnerable to race conditions.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="resource-management"
                    ))
        return vulnerabilities

class ResourceCleanupFailureDetector(VulnerabilityDetector):
    """CWE-459: Incomplete Cleanup"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'try:|using\(|with\s+', line):
                context = '\n'.join(lines[i:min(len(lines), i+15)])
                if re.search(r'alloc|open|connect|new', context, re.IGNORECASE) and not re.search(r'finally:|dispose|close\(|__del__|destructor', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-459", severity="medium", title="Resource Cleanup Failure",
                        description="Resources allocated in try block without proper cleanup in finally/dispose.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="resource-management"
                    ))
        return vulnerabilities