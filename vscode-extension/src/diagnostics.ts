import * as vscode from 'vscode';

interface Vulnerability {
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    cwe: string;
    file: string;
    line: number;
    description: string;
    code_snippet?: string;
}

interface ScanResult {
    summary: any;
    vulnerabilities: Vulnerability[];
}

export class DiagnosticManager {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private fileVulnerabilities: Map<string, Vulnerability[]> = new Map();

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('parry');
    }

    updateDiagnostics(scanResult: ScanResult): void {
        this.diagnosticCollection.clear();

        if (!scanResult.vulnerabilities) {
            return;
        }

        // Group vulnerabilities by file
        const fileGroups: { [filePath: string]: Vulnerability[] } = {};
        scanResult.vulnerabilities.forEach(vuln => {
            const filePath = vuln.file;
            if (!fileGroups[filePath]) {
                fileGroups[filePath] = [];
            }
            fileGroups[filePath].push(vuln);
        });

        // Create diagnostics for each file
        Object.entries(fileGroups).forEach(([filePath, vulnerabilities]) => {
            const uri = vscode.Uri.file(filePath);
            const diagnostics: vscode.Diagnostic[] = [];

            vulnerabilities.forEach(vuln => {
                const diagnostic = this.createDiagnostic(vuln);
                diagnostics.push(diagnostic);
            });

            this.diagnosticCollection.set(uri, diagnostics);
            this.fileVulnerabilities.set(uri.toString(), vulnerabilities);
        });
    }

    updateFileDiagnostics(uri: vscode.Uri, scanResult: ScanResult): void {
        const diagnostics: vscode.Diagnostic[] = [];

        if (scanResult.vulnerabilities) {
            scanResult.vulnerabilities.forEach(vuln => {
                const diagnostic = this.createDiagnostic(vuln);
                diagnostics.push(diagnostic);
            });
        }

        this.diagnosticCollection.set(uri, diagnostics);
        this.fileVulnerabilities.set(uri.toString(), scanResult.vulnerabilities || []);
    }

    private createDiagnostic(vulnerability: Vulnerability): vscode.Diagnostic {
        const line = Math.max(0, vulnerability.line - 1); // VS Code uses 0-based indexing
        const range = new vscode.Range(line, 0, line, 1000); // Full line

        let severity: vscode.DiagnosticSeverity;
        switch (vulnerability.severity) {
            case 'critical':
                severity = vscode.DiagnosticSeverity.Error;
                break;
            case 'high':
                severity = vscode.DiagnosticSeverity.Warning;
                break;
            case 'medium':
                severity = vscode.DiagnosticSeverity.Information;
                break;
            case 'low':
                severity = vscode.DiagnosticSeverity.Hint;
                break;
            default:
                severity = vscode.DiagnosticSeverity.Warning;
        }

        const diagnostic = new vscode.Diagnostic(
            range,
            `${vulnerability.title} (${vulnerability.cwe})`,
            severity
        );

        diagnostic.source = 'Parry Security Scanner';
        diagnostic.code = vulnerability.cwe;
        diagnostic.message = `${vulnerability.title}\n\n${vulnerability.description}\n\nCWE: ${vulnerability.cwe}\nSeverity: ${vulnerability.severity.toUpperCase()}`;

        if (vulnerability.code_snippet) {
            diagnostic.message += `\n\nCode: ${vulnerability.code_snippet}`;
        }

        // Add quick fix if available
        diagnostic.code = {
            value: vulnerability.cwe,
            target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${vulnerability.cwe.split('-')[1]}.html`)
        };

        return diagnostic;
    }

    getVulnerabilitiesForFile(uri: vscode.Uri): Vulnerability[] {
        return this.fileVulnerabilities.get(uri.toString()) || [];
    }

    clearDiagnostics(): void {
        this.diagnosticCollection.clear();
        this.fileVulnerabilities.clear();
    }

    dispose(): void {
        this.diagnosticCollection.dispose();
    }
}
    
    updateDiagnostics(uri: vscode.Uri, vulnerabilities: Vulnerability[]) {
        const diagnostics: vscode.Diagnostic[] = vulnerabilities.map(vuln => {
            const line = vuln.line;
            const range = new vscode.Range(
                new vscode.Position(line, vuln.column),
                new vscode.Position(line, vuln.column + vuln.code.length)
            );
            
            const diagnostic = new vscode.Diagnostic(
                range,
                `[${vuln.cwe}] ${vuln.title}: ${vuln.description}`,
                this.severityToVSCode(vuln.severity)
            );
            
            diagnostic.source = 'Parry';
            diagnostic.code = vuln.cwe;
            
            return diagnostic;
        });
        
        this.diagnosticCollection.set(uri, diagnostics);
    }
    
    clearForDocument(uri: vscode.Uri) {
        this.diagnosticCollection.delete(uri);
    }
    
    clear() {
        this.diagnosticCollection.clear();
    }
    
    private severityToVSCode(severity: string): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'critical':
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Hint;
        }
    }
}
