"""Memory Safety Vulnerability Detectors - 20+ CWEs"""
import re
from pathlib import Path
from typing import List
from valid8.scanner import Vulnerability, VulnerabilityDetector

class OutOfBoundsWriteDetector(VulnerabilityDetector):
    """CWE-787: Out-of-bounds Write"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'\bstrcpy\s*\(', "CWE-787", "critical"), (r'\bstrcat\s*\(', "CWE-787", "critical"), (r'\bsprintf\s*\(', "CWE-787", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(cwe=cwe, severity=severity, title="Out-of-bounds Write", description="Potential out-of-bounds write.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="memory-safety"))
        return vulnerabilities

class OutOfBoundsReadDetector(VulnerabilityDetector):
    """CWE-125: Out-of-bounds Read"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'\bstrcpy\s*\([^)]*,\s*\w+\[', "CWE-125", "high"), (r'\w+\s*\[\s*\w+\s*\+\s*\w+\s*\]', "CWE-125", "medium")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'(if|assert|check).*(<|<=|length|size)', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe=cwe, severity=severity, title="Out-of-bounds Read", description="Potential out-of-bounds read.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="memory-safety"))
        return vulnerabilities

class StackBasedBufferOverflowDetector(VulnerabilityDetector):
    """CWE-121: Stack-based Buffer Overflow"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'char\s+\w+\[\s*\d+\s*\].*strcpy', "CWE-121", "critical"), (r'gets\s*\(', "CWE-121", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-121", severity=severity, title="Stack-based Buffer Overflow", description="Potential stack-based buffer overflow.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="memory-safety"))
        return vulnerabilities

class HeapBasedBufferOverflowDetector(VulnerabilityDetector):
    """CWE-122: Heap-based Buffer Overflow"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'strcpy\(.*malloc|.*calloc|.*strcat\(.*malloc', "CWE-122", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-122", severity=severity, title="Heap-based Buffer Overflow", description="Potential heap-based buffer overflow.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="memory-safety"))
        return vulnerabilities

class BufferUnderreadDetector(VulnerabilityDetector):
    """CWE-124: Buffer Underwrite"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'\w+\[.*-.*\]', "CWE-124", "medium")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'(if|assert|check).*(>=|>|length|size)', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-124", severity=severity, title="Buffer Underwrite", description="Potential buffer underwrite.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="memory-safety"))
        return vulnerabilities

class UseAfterFreeDetector(VulnerabilityDetector):
    """CWE-416: Use After Free"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'free\(.*\)|.*delete\s+.*;.*\n.*\w+\[', "CWE-416", "high")]
        for i, line in enumerate(lines, 1):
            context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
            for pattern, cwe, severity in patterns:
                if re.search(pattern, context, re.IGNORECASE | re.MULTILINE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-416", severity=severity, title="Use After Free", description="Potential use after free.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="memory-safety"))
        return vulnerabilities

class DoubleFreeDetector(VulnerabilityDetector):
    """CWE-415: Double Free"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        var_pattern = r'(free|delete)\s*\(?\s*(\w+)\s*\)?'
        vars_freed = {}
        for i, line in enumerate(lines, 1):
            match = re.search(var_pattern, line, re.IGNORECASE)
            if match:
                var = match.group(2)
                if var in vars_freed:
                    vulnerabilities.append(Vulnerability(cwe="CWE-415", severity="high", title="Double Free", description=f"Potential double free of '{var}'.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="memory-safety"))
                vars_freed[var] = i
        return vulnerabilities

class NullPointerDereferenceDetector(VulnerabilityDetector):
    """CWE-476: NULL Pointer Dereference"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'->.*\(|\.\w+\(.*\)\s*\n(?!.*if.*!=.*null)', "CWE-476", "medium")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'(if|assert|guard|check).*(null|None)', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-476", severity=severity, title="NULL Pointer Dereference", description="Potential NULL pointer dereference.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="memory-safety"))
        return vulnerabilities

class IntegerOverflowDetector(VulnerabilityDetector):
    """CWE-190: Integer Overflow"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'\w+\s*\*\s*\w+|.*\s*\+\s*\w+.*\[', "CWE-190", "low"), (r'malloc\([^)]*\*\s*\w+', "CWE-190", "medium")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'check|validate|overflow|safe', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-190", severity=severity, title="Integer Overflow", description="Potential integer overflow.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="memory-safety"))
        return vulnerabilities

class IntegerUnderflowDetector(VulnerabilityDetector):
    """CWE-191: Integer Underflow"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'\w+\s*-\s*\w+.*\[', "CWE-191", "low")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'check|validate|underflow|safe|>=', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-191", severity=severity, title="Integer Underflow", description="Potential integer underflow.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="memory-safety"))
        return vulnerabilities

class IntegerWraparoundDetector(VulnerabilityDetector):
    """CWE-128: Wrap-around Error"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'\w+\s*\*\s*\w+.*\w+\s*\+\s*\w+', "CWE-128", "low")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'check|validate|wraparound|safe', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-128", severity=severity, title="Integer Wraparound", description="Potential integer wraparound.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="memory-safety"))
        return vulnerabilities

class UninitializedMemoryDetector(VulnerabilityDetector):
    """CWE-457: Use of Uninitialized Variable"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'int\s+\w+;.*\w+\s*=.*\w+', "CWE-457", "medium"),
            (r'char\s+\w+;.*\w+\s*=.*\w+', "CWE-457", "medium"),
            (r'\w+\s+\w+;.*\w+\s*=.*\w+', "CWE-457", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'initialize|memset|memset_s|bzero', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Use of Uninitialized Variable",
                            description="Variable used before initialization.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="memory-safety"
                        ))
        return vulnerabilities

class MemoryLeakDetector(VulnerabilityDetector):
    """CWE-401: Memory Leak"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'malloc\(|calloc\(|realloc\(.*return|exit', "CWE-401", "medium"),
            (r'new\s+\w+.*return|exit', "CWE-401", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[i:min(len(lines), i+20)])
                    if not re.search(r'free\(|delete|delete\[\]', context):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Memory Leak",
                            description="Allocated memory not freed before function exit.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="memory-safety"
                        ))
        return vulnerabilities

class DanglingPointerDetector(VulnerabilityDetector):
    """CWE-416: Use After Free"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'free\(.*\).*;.*\*.*=', "CWE-416", "high"),
            (r'delete\s+.*;.*\*.*=', "CWE-416", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Dangling Pointer",
                        description="Pointer used after memory deallocation.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="memory-safety"
                    ))
        return vulnerabilities

class BufferOverrunDetector(VulnerabilityDetector):
    """CWE-119: Improper Restriction of Operations within Bounds of Memory Buffer"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'memcpy\([^,]+,\s*[^,]+,\s*[^)]+\)', "CWE-119", "high"),
            (r'memmove\([^,]+,\s*[^,]+,\s*[^)]+\)', "CWE-119", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Buffer Overrun",
                        description="Potential buffer overrun in memory operation.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="memory-safety"
                    ))
        return vulnerabilities

class StackOverflowDetector(VulnerabilityDetector):
    """CWE-121 variant: Stack Overflow"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'recursive.*function', "CWE-121", "medium"),
            (r'function.*calls.*itself', "CWE-121", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Stack Overflow",
                        description="Potential stack overflow from deep recursion.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="memory-safety"
                    ))
        return vulnerabilities

class HeapOverflowDetector(VulnerabilityDetector):
    """CWE-122 variant: Heap Overflow"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'malloc.*sizeof.*\*.*\+', "CWE-122", "medium"),
            (r'new\s*\[.*\+.*\]', "CWE-122", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Heap Overflow",
                        description="Potential heap overflow in allocation.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="memory-safety"
                    ))
        return vulnerabilities

class TypeConfusionDetector(VulnerabilityDetector):
    """CWE-843: Access of Resource Using Incompatible Type"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'\(struct\s+\w+\*\)\s*\w+', "CWE-843", "medium"),
            (r'\(class\s+\w+\*\)\s*\w+', "CWE-843", "medium"),
            (r'reinterpret_cast', "CWE-843", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Type Confusion",
                        description="Unsafe type casting that may cause memory corruption.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="memory-safety"
                    ))
        return vulnerabilities

class UncheckedReturnDetector(VulnerabilityDetector):
    """CWE-252: Unchecked Return Value"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'malloc\([^)]+\);', "CWE-252", "medium"),
            (r'fopen\([^)]+\);', "CWE-252", "medium"),
            (r'fread\([^)]+\);', "CWE-252", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-2):min(len(lines), i+2)])
                    if not re.search(r'if\s*\(|assert\s*\(|check\s*\(', context):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Unchecked Return Value",
                            description="Return value not checked for error conditions.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="memory-safety"
                        ))
        return vulnerabilities

class RaceConditionMemoryDetector(VulnerabilityDetector):
    """CWE-362 variant: Race Condition in Memory Access"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'thread.*shared.*memory', "CWE-362", "medium"),
            (r'concurrent.*access.*memory', "CWE-362", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'mutex|lock|semaphore|atomic', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Race Condition",
                            description="Potential race condition in memory access.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="memory-safety"
                        ))
        return vulnerabilities

class ImproperMemoryManagementDetector(VulnerabilityDetector):
    """CWE-401 variant: Improper Memory Management"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'free\(.*\).*free\(.*\)', "CWE-401", "high"),
            (r'delete.*delete', "CWE-401", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Improper Memory Management",
                        description="Double free or improper memory deallocation.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="memory-safety"
                    ))
        return vulnerabilities

class InvalidPointerDereferenceDetector(VulnerabilityDetector):
    """CWE-476: NULL Pointer Dereference"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'\*.*=.*NULL', "CWE-476", "high"),
            (r'->.*NULL', "CWE-476", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'if\s*\(|assert\s*\(', context):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Invalid Pointer Dereference",
                            description="Potential NULL pointer dereference.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="memory-safety"
                        ))
        return vulnerabilities

class MemoryCorruptionDetector(VulnerabilityDetector):
    """CWE-119 variant: Memory Corruption"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'memset.*sizeof', "CWE-119", "medium"),
            (r'memcpy.*sizeof', "CWE-119", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-2):min(len(lines), i+2)])
                    if 'sizeof' not in context or '*' in line:
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Memory Corruption",
                            description="Potential memory corruption in buffer operation.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="memory-safety"
                        ))
        return vulnerabilities

class UnboundedCopyDetector(VulnerabilityDetector):
    """CWE-119 variant: Unbounded Copy"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'strcpy\([^,]+,\s*[^)]+\)', "CWE-119", "high"),
            (r'strcat\([^,]+,\s*[^)]+\)', "CWE-119", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Unbounded Copy",
                        description="Unbounded string copy operation.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="memory-safety"
                    ))
        return vulnerabilities

class OffByOneErrorDetector(VulnerabilityDetector):
    """CWE-193: Off-by-one Error"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'for\s*\([^;]*;\s*\w+\s*<\s*\w+\s*\+\s*1\s*;.*\)', "CWE-193", "medium"),
            (r'for\s*\([^;]*;\s*\w+\s*!=\s*\w+\s*\+\s*1\s*;.*\)', "CWE-193", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Off-by-one Error",
                        description="Potential off-by-one error in loop bounds.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="memory-safety"
                    ))
        return vulnerabilities

class ImproperInputValidationDetector(VulnerabilityDetector):
    """CWE-20 variant: Improper Input Validation for Memory Operations"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'malloc\([^)]*user_input', "CWE-20", "high"),
            (r'new\s*\[.*user_input', "CWE-20", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'check|validate|limit|max', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Improper Input Validation",
                            description="User input used in memory allocation without validation.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="memory-safety"
                        ))
        return vulnerabilities

class UseOfUninitializedResourceDetector(VulnerabilityDetector):
    """CWE-908: Use of Uninitialized Resource"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'var\s+\w+;\s*\w+\s*\.', "CWE-908", "medium"),
            (r'\w+\s*=\s*null;\s*\w+\s*\.', "CWE-908", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Use of Uninitialized Resource",
                        description="Using uninitialized resource may cause undefined behavior.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="memory-safety"
                    ))
        return vulnerabilities

class IncorrectCalculationOfBufferSizeDetector(VulnerabilityDetector):
    """CWE-131: Incorrect Calculation of Buffer Size"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'malloc\(.*sizeof\(.*\)\s*\*\s*\w+\s*\+\s*\d+\)', "CWE-131", "high"),
            (r'new\s*\[.*sizeof\(.*\)\s*\*\s*\w+\s*\+\s*\d+\]', "CWE-131", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Incorrect Buffer Size Calculation",
                        description="Buffer size calculation may be incorrect, leading to overflow.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="memory-safety"
                    ))
        return vulnerabilities

class MemoryAllocationWithExcessiveSizeDetector(VulnerabilityDetector):
    """CWE-789: Memory Allocation with Excessive Size Value"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'malloc\(.*INT_MAX|new\s*\[.*MAX_INT', "CWE-789", "high"),
            (r'alloc.*0x7fffffff|alloc.*2147483647', "CWE-789", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Excessive Memory Allocation",
                        description="Memory allocation with excessive size may cause DoS.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="memory-safety"
                    ))
        return vulnerabilities

class InsufficientInformationDetector(VulnerabilityDetector):
    """CWE-201: Information Disclosure Through Sent Data"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'send\(.*password|write.*secret', "CWE-201", "high"),
            (r'response\.write.*key|output.*token', "CWE-201", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Information Disclosure",
                        description="Sensitive information may be disclosed in sent data.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="memory-safety"
                    ))
        return vulnerabilities

class ObservableDiscrepancyDetector(VulnerabilityDetector):
    """CWE-203: Observable Discrepancy"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'timing.*attack|side.*channel', "CWE-203", "low"),
            (r'different.*response.*time', "CWE-203", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Observable Discrepancy",
                        description="Observable timing or behavioral discrepancies may leak information.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="memory-safety"
                    ))
        return vulnerabilities

class ExposureOfDataElementToWrongSessionDetector(VulnerabilityDetector):
    """CWE-488: Exposure of Data Element to Wrong Session"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'session.*\[\s*["\']?\w+["\']?\s*\]\s*=.*user', "CWE-488", "medium"),
            (r'global.*session.*data', "CWE-488", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'check.*session|validate.*user', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Session Data Exposure",
                            description="Data may be exposed to wrong session due to improper validation.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="memory-safety"
                        ))
        return vulnerabilities

class IncorrectTypeConversionDetector(VulnerabilityDetector):
    """CWE-704: Incorrect Type Conversion or Cast"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'\(int\).*long|\(short\).*int', "CWE-704", "medium"),
            (r'cast.*truncat|narrow.*cast', "CWE-704", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Incorrect Type Conversion",
                        description="Type conversion may truncate or lose data.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="memory-safety"
                    ))
        return vulnerabilities

class OperationOnResourceInWrongPhaseOfLifetimeDetector(VulnerabilityDetector):
    """CWE-666: Operation on Resource in Wrong Phase of Lifetime"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'use.*after.*free|access.*freed', "CWE-666", "high"),
            (r'read.*closed.*file|write.*closed', "CWE-666", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Wrong Resource Lifetime Operation",
                        description="Operation performed on resource in wrong phase of lifetime.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="memory-safety"
                    ))
        return vulnerabilities

class MissingReferenceToActiveFileDescriptorDetector(VulnerabilityDetector):
    """CWE-775: Missing Reference to Active Allocated Resource"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'open\(.*\).*open\(.*\)', "CWE-775", "medium"),
            (r'fopen\(.*\).*fopen\(.*\)', "CWE-775", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                    if not re.search(r'close\(|fclose\(', context):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Missing File Descriptor Reference",
                            description="File descriptors opened but not properly tracked.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="memory-safety"
                        ))
        return vulnerabilities

class MissingReleaseOfResourceAfterEffectiveLifetimeDetector(VulnerabilityDetector):
    """CWE-772: Missing Release of Resource after Effective Lifetime"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'temp.*file.*unlink|temporary.*delete', "CWE-772", "medium"),
            (r'cache.*cleanup|temp.*cleanup', "CWE-772", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-15):min(len(lines), i+15)])
                    if not re.search(r'at_exit|finally:|destructor', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Missing Resource Release",
                            description="Resource not released after effective lifetime ends.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="low", category="memory-safety"
                        ))
        return vulnerabilities

class UncontrolledMemoryAllocationDetector(VulnerabilityDetector):
    """CWE-789: Uncontrolled Memory Allocation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'malloc\(.*user.*input|new\s*\[.*request', "CWE-789", "high"),
            (r'alloc.*param.*size|allocate.*input', "CWE-789", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'check.*size|validate.*limit|max.*size', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Uncontrolled Memory Allocation",
                            description="Memory allocation controlled by user input without limits.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="memory-safety"
                        ))
        return vulnerabilities

class ExternalControlOfAssumedImmutableWebParameterDetector(VulnerabilityDetector):
    """CWE-472: External Control of Assumed-Immutable Web Parameter"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'hidden.*field.*value|readonly.*input', "CWE-472", "medium"),
            (r'const.*param.*request|final.*param', "CWE-472", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if re.search(r'javascript|client.*side', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="External Control of Immutable Parameter",
                            description="Client-side immutable parameters can be modified.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="memory-safety"
                        ))
        return vulnerabilities

class IncorrectOwnershipAssignmentDetector(VulnerabilityDetector):
    """CWE-910: Incorrect Ownership Assignment"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'owner.*=.*user|assign.*owner', "CWE-910", "medium"),
            (r'setOwner\(.*input|changeOwner', "CWE-910", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'validate.*owner|check.*permission', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Incorrect Ownership Assignment",
                            description="Ownership assigned without proper validation.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="memory-safety"
                        ))
        return vulnerabilities

class IncorrectDefaultPermissionsDetector(VulnerabilityDetector):
    """CWE-276: Incorrect Default Permissions"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'default.*permission.*=.*777', "CWE-276", "high"),
            (r'DEFAULT_PERM.*=.*rwxrwxrwx', "CWE-276", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Incorrect Default Permissions",
                        description="Default permissions are too permissive.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="memory-safety"
                    ))
        return vulnerabilities

class InsufficientCompartmentalizationDetector(VulnerabilityDetector):
    """CWE-653: Insufficient Compartmentalization"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'global.*shared.*data|shared.*global', "CWE-653", "medium"),
            (r'compartment.*violation|bypass.*compartment', "CWE-653", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Insufficient Compartmentalization",
                        description="Insufficient compartmentalization allows data leakage between contexts.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="memory-safety"
                    ))
        return vulnerabilities

class MemoryLeakThroughClosuresDetector(VulnerabilityDetector):
    """CWE-401: Memory Leak - Closures"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'function.*\{.*\w+.*\}|=>.*\{.*\w+.*\}', line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if re.search(r'global|window|this\.|self\.', context) and not re.search(r'weak|dispose|cleanup', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-401", severity="medium", title="Memory Leak Through Closures",
                        description="Closures capturing large objects or DOM references may cause memory leaks.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="memory-safety"
                    ))
        return vulnerabilities

class UncheckedMemoryAllocationDetector(VulnerabilityDetector):
    """CWE-789: Uncontrolled Memory Allocation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'malloc\(|calloc\(|realloc\(|new\s+\w+\[', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'user.*input|request\.|params\[', context, re.IGNORECASE) and not re.search(r'check|limit|max', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-789", severity="high", title="Unchecked Memory Allocation",
                        description="Memory allocation based on user input without size limits.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="memory-safety"
                    ))
        return vulnerabilities

class DoubleFreeThroughExceptionPathsDetector(VulnerabilityDetector):
    """CWE-415: Double Free - Exception Paths"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'free\(|delete|delete\[\]', line):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if re.search(r'catch|except|finally', context) and re.search(r'throw|raise', context):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-415", severity="high", title="Double Free Through Exception Paths",
                        description="Memory deallocation in exception handling may cause double free if exceptions occur.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="memory-safety"
                    ))
        return vulnerabilities

class MemoryInitializationBypassDetector(VulnerabilityDetector):
    """CWE-456: Missing Initialization of a Variable"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'char\s+\w+\[\d+\]|byte\[\]|memset', line):
                context = '\n'.join(lines[max(0, i-2):min(len(lines), i+2)])
                if not re.search(r'memset|memset.*0|bzero|memset.*\\0', context):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-456", severity="medium", title="Memory Initialization Bypass",
                        description="Memory buffer not properly initialized before use.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="memory-safety"
                    ))
        return vulnerabilities

class StackExhaustionThroughRecursionDetector(VulnerabilityDetector):
    """CWE-674: Uncontrolled Recursion"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'function.*\{.*\w+\s*\(.*\).*\{', line) or re.search(r'def\s+\w+\s*\(.*\).*:', line):
                context = '\n'.join(lines[i:min(len(lines), i+15)])
                if re.search(r'\w+\s*\(', context) and not re.search(r'if.*depth|if.*count|limit|base.*case', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-674", severity="high", title="Stack Exhaustion Through Uncontrolled Recursion",
                        description="Recursive function without proper termination condition may cause stack overflow.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="memory-safety"
                    ))
        return vulnerabilities

def get_memory_safety_detectors():
    """Get all memory safety detectors"""
    return [
        OutOfBoundsWriteDetector(), OutOfBoundsReadDetector(), StackBasedBufferOverflowDetector(),
        HeapBasedBufferOverflowDetector(), BufferUnderreadDetector(), UseAfterFreeDetector(),
        DoubleFreeDetector(), NullPointerDereferenceDetector(), IntegerOverflowDetector(),
        IntegerUnderflowDetector(), IntegerWraparoundDetector(),
        UninitializedMemoryDetector(), MemoryLeakDetector(), DanglingPointerDetector(),
        BufferOverrunDetector(), StackOverflowDetector(), HeapOverflowDetector(),
        TypeConfusionDetector(), UncheckedReturnDetector(), RaceConditionMemoryDetector(),
        ImproperMemoryManagementDetector(), InvalidPointerDereferenceDetector(),
        MemoryCorruptionDetector(), UnboundedCopyDetector(), OffByOneErrorDetector(),
        ImproperInputValidationDetector(), UseOfUninitializedResourceDetector(),
        IncorrectCalculationOfBufferSizeDetector(), MemoryAllocationWithExcessiveSizeDetector(),
        InsufficientInformationDetector(), ObservableDiscrepancyDetector(),
        ExposureOfDataElementToWrongSessionDetector(), IncorrectTypeConversionDetector(),
        OperationOnResourceInWrongPhaseOfLifetimeDetector(), MissingReferenceToActiveFileDescriptorDetector(),
        MissingReleaseOfResourceAfterEffectiveLifetimeDetector(), UncontrolledMemoryAllocationDetector(),
        ExternalControlOfAssumedImmutableWebParameterDetector(), IncorrectOwnershipAssignmentDetector(),
        IncorrectDefaultPermissionsDetector(), InsufficientCompartmentalizationDetector(),
        MemoryLeakInLoopDetector(), BufferOverflowViaEnvironmentDetector(), UseAfterFreeInCallbackDetector(),
        StackExhaustionDetector(), HeapExhaustionDetector(), DoubleFreeDetector(), MemoryCorruptionViaIntegerOverflowDetector(),
        UninitializedMemoryAccessDetector(), BufferUnderflowDetector(), MemoryMappingFailureDetector(),
        MemoryLeakThroughClosuresDetector(), UncheckedMemoryAllocationDetector(),
        DoubleFreeThroughExceptionPathsDetector(), MemoryInitializationBypassDetector(),
        StackExhaustionThroughRecursionDetector(),
    ]

class MemoryLeakInLoopDetector(VulnerabilityDetector):
    """CWE-401: Missing Release of Memory after Effective Lifetime"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
            if re.search(r'for.*:|while.*:.*\n.*malloc\(|new ', context, re.IGNORECASE | re.MULTILINE):
                if not re.search(r'free\(|delete|close\(', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-401", severity="high", title="Memory Leak in Loop", description="Memory allocated in loop but not freed.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="memory-safety"))
        return vulnerabilities

class BufferOverflowViaEnvironmentDetector(VulnerabilityDetector):
    """CWE-120: Buffer Copy without Checking Size of Input"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'getenv\(.*\).*strcpy|strncpy.*getenv', "CWE-120", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-120", severity=severity, title="Buffer Overflow via Environment", description="Buffer overflow from environment variable.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="memory-safety"))
        return vulnerabilities

class UseAfterFreeInCallbackDetector(VulnerabilityDetector):
    """CWE-416: Use After Free"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'callback.*free.*\n.*use|use.*after.*free', "CWE-416", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-416", severity=severity, title="Use After Free in Callback", description="Use after free in callback function.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="memory-safety"))
        return vulnerabilities

class StackExhaustionDetector(VulnerabilityDetector):
    """CWE-674: Uncontrolled Recursion"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
            if re.search(r'def.*\w+.*:.*\n.*\w+\(', context, re.MULTILINE):
                if not re.search(r'depth|limit|count', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-674", severity="medium", title="Stack Exhaustion", description="Uncontrolled recursion may exhaust stack.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="memory-safety"))
        return vulnerabilities

class HeapExhaustionDetector(VulnerabilityDetector):
    """CWE-400: Uncontrolled Resource Consumption"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'malloc.*user.*input|new.*\[\].*input', "CWE-400", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'limit|max|check', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-400", severity=severity, title="Heap Exhaustion", description="Heap exhaustion from uncontrolled allocation.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="memory-safety"))
        return vulnerabilities

class DoubleFreeDetector(VulnerabilityDetector):
    """CWE-415: Double Free"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
            if re.search(r'free\(.*\)', line):
                var_match = re.search(r'free\(([^)]+)', line)
                if var_match:
                    var = var_match.group(1).strip()
                    if re.search(r'free\(' + re.escape(var) + r'\)', context):
                        vulnerabilities.append(Vulnerability(cwe="CWE-415", severity="critical", title="Double Free", description="Double free of memory.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="memory-safety"))
        return vulnerabilities

class MemoryCorruptionViaIntegerOverflowDetector(VulnerabilityDetector):
    """CWE-190: Integer Overflow or Wraparound"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'malloc\(.*\+.*\)|new.*\[.*\*.*\]', "CWE-190", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'check|limit|safe', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-190", severity=severity, title="Memory Corruption via Integer Overflow", description="Integer overflow leading to memory corruption.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="memory-safety"))
        return vulnerabilities

class UninitializedMemoryAccessDetector(VulnerabilityDetector):
    """CWE-457: Use of Uninitialized Variable"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'use.*uninitialized|access.*uninit', "CWE-457", "medium")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-457", severity=severity, title="Uninitialized Memory Access", description="Access to uninitialized memory.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="memory-safety"))
        return vulnerabilities

class BufferUnderflowDetector(VulnerabilityDetector):
    """CWE-124: Buffer Underwrite"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'buffer.*underflow|underwrite', "CWE-124", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-124", severity=severity, title="Buffer Underflow", description="Buffer underflow vulnerability.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="memory-safety"))
        return vulnerabilities

class MemoryMappingFailureDetector(VulnerabilityDetector):
    """CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'mmap.*failure|mapping.*failed', "CWE-119", "medium")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-119", severity=severity, title="Memory Mapping Failure", description="Memory mapping operation failed.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="memory-safety"))
        return vulnerabilities
