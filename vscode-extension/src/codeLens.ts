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

export class VulnerabilityCodeLensProvider implements vscode.CodeLensProvider {
    private fileVulnerabilities: Map<string, Vulnerability[]> = new Map();

    provideCodeLenses(document: vscode.TextDocument, token: vscode.CancellationToken): vscode.CodeLens[] {
        const vulnerabilities = this.fileVulnerabilities.get(document.uri.toString()) || [];
        const codeLenses: vscode.CodeLens[] = [];

        vulnerabilities.forEach(vuln => {
            const line = Math.max(0, vuln.line - 1); // Convert to 0-based
            const range = new vscode.Range(line, 0, line, 0);

            // Create code lens for fix suggestion
            const fixCommand = new vscode.CodeLens(range, {
                title: "$(tools) Fix Issue",
                tooltip: `Fix ${vuln.title} (${vuln.cwe})`,
                command: 'parry.applyFix',
                arguments: [vuln]
            });

            const infoCommand = new vscode.CodeLens(range, {
                title: "$(info) Learn More",
                tooltip: `View details for ${vuln.cwe}`,
                command: 'vscode.open',
                arguments: [vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${vuln.cwe.split('-')[1]}.html`)]
            });

            codeLenses.push(fixCommand, infoCommand);
        });

        return codeLenses;
    }

    updateCodeLenses(uri: vscode.Uri, vulnerabilities: Vulnerability[]): void {
        this.fileVulnerabilities.set(uri.toString(), vulnerabilities);

        // Trigger code lens update
        vscode.commands.executeCommand('vscode.executeCodeLensProvider', uri);
    }

    clearCodeLenses(uri: vscode.Uri): void {
        this.fileVulnerabilities.delete(uri.toString());
        vscode.commands.executeCommand('vscode.executeCodeLensProvider', uri);
    }
}
