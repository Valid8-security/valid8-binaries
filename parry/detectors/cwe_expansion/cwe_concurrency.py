"""Concurrency Vulnerability Detectors - 10+ CWEs"""
import re
from pathlib import Path
from typing import List
from parry.scanner import Vulnerability, VulnerabilityDetector

class RaceConditionDetector(VulnerabilityDetector):
    """CWE-362: Race Condition"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
            if re.search(r'if\s*\(.*\).*\{.*\n.*\+\+.*\}', context, re.IGNORECASE | re.MULTILINE):
                if not re.search(r'(lock|mutex|synchronized|atomic)', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-362", severity="medium", title="Race Condition", description="Potential race condition.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="concurrency"))
        return vulnerabilities

class DeadlockDetector(VulnerabilityDetector):
    """CWE-833: Deadlock"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        lock_pattern = r'(lock|synchronized|mutex|acquire)\([^)]*\)'
        locks = []
        for i, line in enumerate(lines, 1):
            if re.search(lock_pattern, line, re.IGNORECASE):
                locks.append((i, line))
                if len(locks) >= 2:
                    vulnerabilities.append(Vulnerability(cwe="CWE-833", severity="medium", title="Potential Deadlock", description="Nested locks detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="concurrency"))
                    locks = []
        return vulnerabilities

class ThreadSafetyViolationDetector(VulnerabilityDetector):
    """CWE-366: Race Condition within a Thread"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'static.*shared.*variable', "CWE-366", "high"),
            (r'global.*variable.*thread', "CWE-366", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'volatile|synchronized|lock|atomic', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Thread Safety Violation",
                            description="Shared variable accessed without proper synchronization.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="concurrency"
                        ))
        return vulnerabilities

class ImproperLockingDetector(VulnerabilityDetector):
    """CWE-667: Improper Locking"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'lock\(\).*return', "CWE-667", "high"),
            (r'acquire\(\).*return', "CWE-667", "high"),
            (r'lock.*not.*released', "CWE-667", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Improper Locking",
                        description="Lock acquired but not properly released.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="concurrency"
                    ))
        return vulnerabilities

class ConcurrentModificationDetector(VulnerabilityDetector):
    """CWE-820: Missing Synchronization"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'list\.append\(.*\).*thread', "CWE-820", "medium"),
            (r'dict\[.*\].*=.*thread', "CWE-820", "medium"),
            (r'collection.*modify.*concurrent', "CWE-820", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'lock|synchronized|RLock|threading\.Lock', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Concurrent Modification",
                            description="Collection modified without synchronization in multithreaded context.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="concurrency"
                        ))
        return vulnerabilities

class ImproperSignalHandlingDetector(VulnerabilityDetector):
    """CWE-828: Signal Handler with Functionality that is not Asynchronous-Safe"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'signal.*malloc', "CWE-828", "high"),
            (r'signal.*printf', "CWE-828", "high"),
            (r'signal.*free', "CWE-828", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Unsafe Signal Handler",
                        description="Signal handler uses non-async-safe functions.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="concurrency"
                    ))
        return vulnerabilities

class DoubleCheckedLockingDetector(VulnerabilityDetector):
    """CWE-609: Double-Checked Locking"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            context = '\n'.join(lines[max(0, i-5):min(len(lines), i+10)])
            if re.search(r'if.*null.*\n.*synchronized.*\n.*if.*null', context, re.IGNORECASE | re.MULTILINE):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-609", severity="medium", title="Double-Checked Locking",
                    description="Double-checked locking pattern may be unsafe without volatile.",
                    file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                    confidence="medium", category="concurrency"
                ))
        return vulnerabilities

class SpinLockDetector(VulnerabilityDetector):
    """CWE-400: Uncontrolled Resource Consumption - Spin Lock"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'while.*!.*lock.*acquired', "CWE-400", "medium"),
            (r'spin.*lock.*busy.*wait', "CWE-400", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Spin Lock Resource Consumption",
                        description="Spin lock may consume excessive CPU resources.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="concurrency"
                    ))
        return vulnerabilities

class ThreadLocalStorageLeakDetector(VulnerabilityDetector):
    """CWE-533: Information Exposure Through Server Log Files"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'ThreadLocal.*not.*removed', "CWE-533", "medium"),
            (r'thread.*local.*leak', "CWE-533", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Thread Local Storage Leak",
                        description="ThreadLocal variables not properly cleaned up.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="concurrency"
                    ))
        return vulnerabilities

class PriorityInversionDetector(VulnerabilityDetector):
    """CWE-832: Unlock of a Resource that is not Locked"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'unlock\(\).*not.*locked', "CWE-832", "high"),
            (r'release\(\).*not.*acquired', "CWE-832", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Improper Unlock",
                        description="Attempting to unlock a resource that is not locked.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="concurrency"
                    ))
        return vulnerabilities

class LockOrderViolationDetector(VulnerabilityDetector):
    """CWE-764: Multiple Locks of Inconsistent Type"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'lock.*order.*different', "CWE-764", "high"),
            (r'inconsistent.*lock.*order', "CWE-764", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Lock Order Violation",
                        description="Locks acquired in different orders may cause deadlocks.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="concurrency"
                    ))
        return vulnerabilities

class ReentrantLockMisuseDetector(VulnerabilityDetector):
    """CWE-821: Incorrect Synchronization"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'ReentrantLock.*not.*fair', "CWE-821", "low"),
            (r'non.*fair.*lock.*starvation', "CWE-821", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Reentrant Lock Misuse",
                        description="Non-fair locking may cause thread starvation.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="concurrency"
                    ))
        return vulnerabilities

class AtomicityViolationDetector(VulnerabilityDetector):
    """CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization - Atomicity"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'counter.*\+\+|balance.*\+=|count.*\+=', line):
                context = '\n'.join(lines[max(0, i-8):min(len(lines), i+8)])
                if re.search(r'thread|concurrent|async', context, re.IGNORECASE) and not re.search(r'atomic|lock|synchronized|@Transactional', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-362", severity="high", title="Atomicity Violation",
                        description="Shared counter operations lack atomicity guarantees in concurrent environment.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="concurrency"
                    ))
        return vulnerabilities

class MemoryBarrierMissingDetector(VulnerabilityDetector):
    """CWE-667: Improper Locking - Memory Barriers"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'volatile|atomic', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'memory.*barrier|fence|__sync', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-667", severity="medium", title="Missing Memory Barrier",
                        description="Volatile/atomic operations may lack proper memory barriers.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="concurrency"
                    ))
        return vulnerabilities

class ThreadPoolStarvationDetector(VulnerabilityDetector):
    """CWE-400: Uncontrolled Resource Consumption - Thread Starvation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'executor\.submit|pool\.apply|threading\.Thread', line):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if re.search(r'while.*true|infinite|loop', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-400", severity="medium", title="Thread Pool Starvation",
                        description="Infinite or long-running tasks may starve thread pool resources.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="concurrency"
                    ))
        return vulnerabilities

class ConditionVariableMisuseDetector(VulnerabilityDetector):
    """CWE-667: Improper Locking - Condition Variables"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'condition.*wait|condition.*notify|Condition\.await', line):
                context = '\n'.join(lines[max(0, i-8):min(len(lines), i+8)])
                if not re.search(r'while.*condition|if.*condition', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-667", severity="high", title="Condition Variable Misuse",
                        description="Condition wait not protected by while loop - may cause spurious wakeups.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="concurrency"
                    ))
        return vulnerabilities

class SemaphoreLeakDetector(VulnerabilityDetector):
    """CWE-772: Missing Release of Resource after Effective Lifetime - Semaphore"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'semaphore\.acquire|sem\.wait', line):
                context = '\n'.join(lines[max(0, i):min(len(lines), i+15)])
                if not re.search(r'semaphore\.release|sem\.post', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-772", severity="high", title="Semaphore Leak",
                        description="Acquired semaphore not released in all code paths.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="concurrency"
                    ))
        return vulnerabilities

class ConcurrentDataStructureMisuseDetector(VulnerabilityDetector):
    """CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization - Data Structures"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'ArrayList|HashMap|HashSet|Vector', line):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if re.search(r'thread|concurrent|async', context, re.IGNORECASE) and not re.search(r'ConcurrentHashMap|CopyOnWriteArrayList|Collections\.synchronized', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-362", severity="high", title="Unsafe Concurrent Data Structure",
                        description="Non-thread-safe data structures used in concurrent context.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="concurrency"
                    ))
        return vulnerabilities

class LockGranularityIssueDetector(VulnerabilityDetector):
    """CWE-667: Improper Locking - Lock Granularity"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        lock_lines = []
        for i, line in enumerate(lines, 1):
            if re.search(r'synchronized|lock\.|with.*lock', line):
                lock_lines.append(i)

        for lock_line in lock_lines:
            context = '\n'.join(lines[max(0, lock_line):min(len(lines), lock_line+20)])
            if re.search(r'sleep\(|wait\(|io\.|database|network', context, re.IGNORECASE):
                vulnerabilities.append(Vulnerability(
                    cwe="CWE-667", severity="medium", title="Poor Lock Granularity",
                    description="Locks held during I/O or blocking operations reduce concurrency.",
                    file_path=str(file_path), line_number=lock_line, code_snippet=lines[lock_line-1].strip(),
                    confidence="medium", category="concurrency"
                ))
        return vulnerabilities

class InterruptHandlingInConcurrencyDetector(VulnerabilityDetector):
    """CWE-364: Signal Handler Race Condition"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'InterruptedException|Thread\.interrupt', line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'Thread\.currentThread\(\)\.isInterrupted\(\)', context):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-364", severity="low", title="Improper Interrupt Handling",
                        description="InterruptedException not properly handled in concurrent code.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="concurrency"
                    ))
        return vulnerabilities

class FutureTaskLeakDetector(VulnerabilityDetector):
    """CWE-772: Missing Release of Resource after Effective Lifetime - Future Tasks"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'Future|Promise|CompletableFuture', line):
                context = '\n'.join(lines[max(0, i):min(len(lines), i+20)])
                if not re.search(r'\.get\(|await|\.then\(', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-772", severity="medium", title="Future Task Leak",
                        description="Asynchronous tasks created but never consumed or awaited.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="concurrency"
                    ))
        return vulnerabilities

class ThreadLocalVariableLeakDetector(VulnerabilityDetector):
    """CWE-459: Incomplete Cleanup - ThreadLocal Variables"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'ThreadLocal|thread.*local', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i):min(len(lines), i+25)])
                if not re.search(r'remove\(|cleanup|finally:', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-459", severity="medium", title="ThreadLocal Variable Leak",
                        description="ThreadLocal variables not cleaned up may cause memory leaks.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="concurrency"
                    ))
        return vulnerabilities

def get_concurrency_detectors():
    return [
        RaceConditionDetector(),
        DeadlockDetector(),
        ThreadSafetyViolationDetector(),
        ImproperLockingDetector(),
        ConcurrentModificationDetector(),
        ImproperSignalHandlingDetector(),
        DoubleCheckedLockingDetector(),
        SpinLockDetector(),
        ThreadLocalStorageLeakDetector(),
        PriorityInversionDetector(),
        LockOrderViolationDetector(),
        ReentrantLockMisuseDetector(),
        AtomicityViolationDetector(),
        MemoryBarrierMissingDetector(),
        ThreadPoolStarvationDetector(),
        ConditionVariableMisuseDetector(),
        SemaphoreLeakDetector(),
        ConcurrentDataStructureMisuseDetector(),
        LockGranularityIssueDetector(),
        InterruptHandlingInConcurrencyDetector(),
        FutureTaskLeakDetector(),
        ThreadLocalVariableLeakDetector(),
    ]
    return [RaceConditionDetector(), DeadlockDetector()]