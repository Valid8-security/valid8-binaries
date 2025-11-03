// Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
/**
 * Diagnostics Manager - Handles VS Code diagnostics display
 */

import * as vscode from 'vscode';
import { Vulnerability } from './scanner';

export class DiagnosticsManager {
    private diagnosticCollection: vscode.DiagnosticCollection;
    
    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('parry');
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
