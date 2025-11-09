
import * as vscode from 'vscode';
import * as path from 'path';
import axios from 'axios';

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext) {
    console.log('Parry Security Scanner is now active!');

    // Create diagnostic collection
    diagnosticCollection = vscode.languages.createDiagnosticCollection('parry');
    context.subscriptions.push(diagnosticCollection);

    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.text = "$(shield) Parry";
    statusBarItem.tooltip = "Parry Security Scanner";
    statusBarItem.command = 'parry.showReport';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('parry.scanFile', () => scanCurrentFile())
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('parry.scanWorkspace', () => scanWorkspace())
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('parry.quickFix', (uri: vscode.Uri, diagnostic: vscode.Diagnostic) => {
            applyAIFix(uri, diagnostic);
        })
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('parry.clearFindings', () => {
            diagnosticCollection.clear();
            vscode.window.showInformationMessage('Cleared all Parry findings');
        })
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('parry.showReport', () => showSecurityReport())
    );

    // Auto-scan on save
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(document => {
            const config = vscode.workspace.getConfiguration('parry');
            if (config.get('enableAutoScan')) {
                scanDocument(document);
            }
        })
    );

    // Scan active file on activation
    if (vscode.window.activeTextEditor) {
        scanDocument(vscode.window.activeTextEditor.document);
    }
}

async function scanCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showErrorMessage('No active file to scan');
        return;
    }
    
    await scanDocument(editor.document);
}

async function scanDocument(document: vscode.TextDocument) {
    // Only scan supported languages
    const supportedLanguages = ['python', 'javascript', 'typescript', 'java', 'go', 'rust', 'php', 'ruby'];
    if (!supportedLanguages.includes(document.languageId)) {
        return;
    }

    statusBarItem.text = "$(sync~spin) Scanning...";
    
    try {
        const config = vscode.workspace.getConfiguration('parry');
        const mode = config.get<string>('scanMode', 'fast');
        const validate = config.get<boolean>('enableAIValidation', false);
        
        // Call Parry CLI via terminal
        const filePath = document.uri.fsPath;
        const results = await runParryScan(filePath, mode, validate);
        
        // Convert results to diagnostics
        const diagnostics = convertToDiagnostics(results, document);
        diagnosticCollection.set(document.uri, diagnostics);
        
        // Update status bar
        const criticalCount = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Error).length;
        const highCount = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Warning).length;
        
        if (criticalCount > 0) {
            statusBarItem.text = `$(shield) Parry: ${criticalCount} critical`;
            statusBarItem.color = new vscode.ThemeColor('errorForeground');
        } else if (highCount > 0) {
            statusBarItem.text = `$(shield) Parry: ${highCount} high`;
            statusBarItem.color = new vscode.ThemeColor('warningForeground');
        } else {
            statusBarItem.text = "$(shield) Parry: ✓";
            statusBarItem.color = new vscode.ThemeColor('charts.green');
        }
        
    } catch (error) {
        console.error('Scan error:', error);
        statusBarItem.text = "$(shield) Parry: Error";
        vscode.window.showErrorMessage(`Parry scan failed: ${error}`);
    }
}

async function runParryScan(filePath: string, mode: string, validate: boolean): Promise<any> {
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);
    
    try {
        const validateFlag = validate ? '--validate' : '';
        const command = `parry scan "${filePath}" --mode ${mode} ${validateFlag} --format json`;
        
        const { stdout } = await execAsync(command, {
            timeout: 60000,  // 60 second timeout
            maxBuffer: 10 * 1024 * 1024  // 10MB buffer
        });
        
        return JSON.parse(stdout);
    } catch (error: any) {
        // Try to parse partial JSON from stdout
        if (error.stdout) {
            try {
                return JSON.parse(error.stdout);
            } catch {
                throw new Error(`Parry CLI error: ${error.message}`);
            }
        }
        throw error;
    }
}

function convertToDiagnostics(results: any, document: vscode.TextDocument): vscode.Diagnostic[] {
    const diagnostics: vscode.Diagnostic[] = [];
    const vulnerabilities = results.vulnerabilities || [];
    
    const config = vscode.workspace.getConfiguration('parry');
    const threshold = config.get<string>('severityThreshold', 'MEDIUM');
    const severityOrder = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const minSeverityIndex = severityOrder.indexOf(threshold);
    
    for (const vuln of vulnerabilities) {
        // Filter by severity threshold
        const vulnSeverityIndex = severityOrder.indexOf(vuln.severity);
        if (vulnSeverityIndex < minSeverityIndex) {
            continue;
        }
        
        const line = Math.max(0, vuln.line - 1);
        const range = new vscode.Range(
            new vscode.Position(line, 0),
            new vscode.Position(line, document.lineAt(line).text.length)
        );
        
        const severity = getSeverity(vuln.severity);
        const diagnostic = new vscode.Diagnostic(
            range,
            `${vuln.cwe_id}: ${vuln.description}`,
            severity
        );
        
        diagnostic.source = 'Parry Security';
        diagnostic.code = vuln.cwe_id;
        diagnostic.relatedInformation = [
            new vscode.DiagnosticRelatedInformation(
                new vscode.Location(document.uri, range),
                `Recommendation: ${vuln.recommendation || 'See Parry documentation'}`
            )
        ];
        
        diagnostics.push(diagnostic);
    }
    
    return diagnostics;
}

function getSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity.toUpperCase()) {
        case 'CRITICAL':
            return vscode.DiagnosticSeverity.Error;
        case 'HIGH':
            return vscode.DiagnosticSeverity.Warning;
        case 'MEDIUM':
            return vscode.DiagnosticSeverity.Information;
        case 'LOW':
            return vscode.DiagnosticSeverity.Hint;
        default:
            return vscode.DiagnosticSeverity.Information;
    }
}

async function scanWorkspace() {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        vscode.window.showErrorMessage('No workspace folder open');
        return;
    }
    
    const workspacePath = workspaceFolders[0].uri.fsPath;
    
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Parry: Scanning workspace...",
        cancellable: false
    }, async (progress) => {
        progress.report({ increment: 0 });
        
        try {
            const config = vscode.workspace.getConfiguration('parry');
            const mode = config.get<string>('scanMode', 'fast');
            
            const results = await runParryScan(workspacePath, mode, false);
            
            progress.report({ increment: 100 });
            
            // Show results in webview
            showResultsPanel(results);
            
            vscode.window.showInformationMessage(
                `Parry scan complete: ${results.vulnerabilities?.length || 0} issues found`
            );
        } catch (error) {
            vscode.window.showErrorMessage(`Workspace scan failed: ${error}`);
        }
    });
}

async function applyAIFix(uri: vscode.Uri, diagnostic: vscode.Diagnostic) {
    const document = await vscode.workspace.openTextDocument(uri);
    const editor = await vscode.window.showTextDocument(document);
    
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Parry: Generating AI fix...",
        cancellable: false
    }, async (progress) => {
        try {
            const { exec } = require('child_process');
            const { promisify } = require('util');
            const execAsync = promisify(exec);
            
            const filePath = uri.fsPath;
            const command = `parry patch "${filePath}" --line ${diagnostic.range.start.line + 1}`;
            
            const { stdout } = await execAsync(command, { timeout: 30000 });
            const fix = JSON.parse(stdout);
            
            if (fix.patched_code) {
                // Show diff and ask for confirmation
                const choice = await vscode.window.showInformationMessage(
                    'Apply AI-generated fix?',
                    'Apply',
                    'Show Diff',
                    'Cancel'
                );
                
                if (choice === 'Apply') {
                    await editor.edit(editBuilder => {
                        editBuilder.replace(diagnostic.range, fix.patched_code);
                    });
                    vscode.window.showInformationMessage('Fix applied successfully');
                } else if (choice === 'Show Diff') {
                    // Show diff in new editor
                    const diffDocument = await vscode.workspace.openTextDocument({
                        content: fix.patched_code,
                        language: document.languageId
                    });
                    await vscode.window.showTextDocument(diffDocument, vscode.ViewColumn.Beside);
                }
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to generate fix: ${error}`);
        }
    });
}

function showSecurityReport() {
    const panel = vscode.window.createWebviewPanel(
        'parryReport',
        'Parry Security Report',
        vscode.ViewColumn.Two,
        { enableScripts: true }
    );
    
    // Get all diagnostics
    const allDiagnostics: any[] = [];
    diagnosticCollection.forEach((uri, diagnostics) => {
        allDiagnostics.push({
            file: vscode.workspace.asRelativePath(uri),
            issues: diagnostics.length,
            critical: diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Error).length,
            high: diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Warning).length
        });
    });
    
    panel.webview.html = getReportHtml(allDiagnostics);
}

function showResultsPanel(results: any) {
    const panel = vscode.window.createWebviewPanel(
        'parryResults',
        'Parry Scan Results',
        vscode.ViewColumn.Two,
        { enableScripts: true }
    );
    
    const vulnerabilities = results.vulnerabilities || [];
    const critical = vulnerabilities.filter((v: any) => v.severity === 'CRITICAL').length;
    const high = vulnerabilities.filter((v: any) => v.severity === 'HIGH').length;
    const medium = vulnerabilities.filter((v: any) => v.severity === 'MEDIUM').length;
    
    panel.webview.html = `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: var(--vscode-font-family); padding: 20px; }
                .header { margin-bottom: 30px; }
                .stats { display: flex; gap: 20px; margin-bottom: 30px; }
                .stat-box { padding: 15px; border-radius: 5px; flex: 1; }
                .critical { background: #ff4444; color: white; }
                .high { background: #ff9900; color: white; }
                .medium { background: #ffcc00; color: black; }
                .vulnerability { border-left: 4px solid; padding: 10px; margin: 10px 0; }
                .vuln-critical { border-color: #ff4444; }
                .vuln-high { border-color: #ff9900; }
                .vuln-medium { border-color: #ffcc00; }
                h1 { color: var(--vscode-foreground); }
                pre { background: var(--vscode-textCodeBlock-background); padding: 10px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ Parry Security Scan Results</h1>
                <p>Files scanned: ${results.files_scanned || 0}</p>
            </div>
            
            <div class="stats">
                <div class="stat-box critical">
                    <h2>${critical}</h2>
                    <p>Critical</p>
                </div>
                <div class="stat-box high">
                    <h2>${high}</h2>
                    <p>High</p>
                </div>
                <div class="stat-box medium">
                    <h2>${medium}</h2>
                    <p>Medium</p>
                </div>
            </div>
            
            <h2>Vulnerabilities</h2>
            ${vulnerabilities.map((v: any) => `
                <div class="vulnerability vuln-${v.severity.toLowerCase()}">
                    <h3>${v.cwe_id} - ${v.severity}</h3>
                    <p><strong>File:</strong> ${v.file}:${v.line}</p>
                    <p><strong>Description:</strong> ${v.description}</p>
                    <p><strong>Recommendation:</strong> ${v.recommendation || 'N/A'}</p>
                    ${v.code_snippet ? `<pre>${v.code_snippet}</pre>` : ''}
                </div>
            `).join('')}
        </body>
        </html>
    `;
}

function getReportHtml(files: any[]): string {
    const totalIssues = files.reduce((sum, f) => sum + f.issues, 0);
    const totalCritical = files.reduce((sum, f) => sum + f.critical, 0);
    const totalHigh = files.reduce((sum, f) => sum + f.high, 0);
    
    return `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: var(--vscode-font-family); padding: 20px; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                th, td { padding: 10px; text-align: left; border-bottom: 1px solid var(--vscode-panel-border); }
                th { background: var(--vscode-editor-background); }
                .summary { display: flex; gap: 20px; margin-bottom: 30px; }
                .summary-box { padding: 15px; border-radius: 5px; flex: 1; text-align: center; }
            </style>
        </head>
        <body>
            <h1>🛡️ Parry Security Report</h1>
            
            <div class="summary">
                <div class="summary-box">
                    <h2>${files.length}</h2>
                    <p>Files with Issues</p>
                </div>
                <div class="summary-box">
                    <h2>${totalIssues}</h2>
                    <p>Total Issues</p>
                </div>
                <div class="summary-box">
                    <h2>${totalCritical}</h2>
                    <p>Critical</p>
                </div>
                <div class="summary-box">
                    <h2>${totalHigh}</h2>
                    <p>High</p>
                </div>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Issues</th>
                        <th>Critical</th>
                        <th>High</th>
                    </tr>
                </thead>
                <tbody>
                    ${files.map(f => `
                        <tr>
                            <td>${f.file}</td>
                            <td>${f.issues}</td>
                            <td>${f.critical}</td>
                            <td>${f.high}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </body>
        </html>
    `;
}

export function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
    if (statusBarItem) {
        statusBarItem.dispose();
    }
}


