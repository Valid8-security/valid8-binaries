import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { ParryScanner } from './scanner';
import { SecurityDashboard } from './dashboard';
import { VulnerabilityCodeLensProvider } from './codeLens';
import { DiagnosticManager } from './diagnostics';

let scanner: ParryScanner;
let dashboard: SecurityDashboard;
let diagnosticManager: DiagnosticManager;
let codeLensProvider: VulnerabilityCodeLensProvider;

export function activate(context: vscode.ExtensionContext) {
    console.log('🚀 Parry Security Scanner extension is now active!');

    // Initialize components
    scanner = new ParryScanner();
    dashboard = new SecurityDashboard(context);
    diagnosticManager = new DiagnosticManager();
    codeLensProvider = new VulnerabilityCodeLensProvider();

    // Register providers
    context.subscriptions.push(
        vscode.languages.registerCodeLensProvider('*', codeLensProvider)
    );

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('parry.scanWorkspace', scanWorkspace),
        vscode.commands.registerCommand('parry.scanFile', scanCurrentFile),
        vscode.commands.registerCommand('parry.showDashboard', showDashboard),
        vscode.commands.registerCommand('parry.applyFix', applyFix),
        vscode.commands.registerCommand('parry.configure', configureParry)
    );

    // Auto-scan on save if enabled
    if (vscode.workspace.getConfiguration('parry').get('scanOnSave', true)) {
        context.subscriptions.push(
            vscode.workspace.onDidSaveTextDocument((document) => {
                if (isSupportedFile(document)) {
                    scanFile(document);
                }
            })
        );
    }

    // File system watcher for real-time scanning
    const watcher = vscode.workspace.createFileSystemWatcher('**/*', false, false, false);
    context.subscriptions.push(watcher);

    watcher.onDidChange((uri) => {
        const document = vscode.workspace.textDocuments.find(doc => doc.uri.toString() === uri.toString());
        if (document && isSupportedFile(document)) {
            // Debounce rapid changes
            setTimeout(() => scanFile(document), 500);
        }
    });

    // Initialize dashboard
    dashboard.initialize();

    // Show welcome message
    showWelcomeMessage();
}

function isSupportedFile(document: vscode.TextDocument): boolean {
    const supportedExtensions = [
        '.js', '.ts', '.jsx', '.tsx',
        '.py', '.java', '.cs', '.go', '.rs', '.php',
        '.rb', '.cpp', '.c', '.h'
    ];

    const fileName = path.basename(document.fileName);
    const ext = path.extname(fileName);

    // Skip certain files
    if (fileName.startsWith('.') ||
        fileName.includes('test') ||
        fileName.includes('spec') ||
        document.uri.scheme !== 'file') {
        return false;
    }

    return supportedExtensions.includes(ext);
}

async function scanWorkspace(): Promise<void> {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
        vscode.window.showErrorMessage('No workspace folder open');
        return;
    }

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Parry Security Scan',
        cancellable: true
    }, async (progress, token) => {
        try {
            progress.report({ message: 'Scanning workspace...' });

            const config = vscode.workspace.getConfiguration('parry');
            const scanMode = config.get('scanMode', 'hybrid');
            const excludePatterns = config.get('excludePatterns', []);

            const results = await scanner.scanWorkspace(
                workspaceFolder.uri.fsPath,
                scanMode as string,
                excludePatterns as string[],
                (message: string) => progress.report({ message }),
                token
            );

            diagnosticManager.updateDiagnostics(results);
            dashboard.updateResults(results);

            const summary = getScanSummary(results);
            vscode.window.showInformationMessage(
                `Parry scan complete: ${summary.vulnerabilities} vulnerabilities found in ${summary.files} files`
            );

        } catch (error) {
            vscode.window.showErrorMessage(`Parry scan failed: ${error}`);
        }
    });
}

async function scanCurrentFile(): Promise<void> {
    const activeEditor = vscode.window.activeTextEditor;
    if (!activeEditor) {
        vscode.window.showErrorMessage('No active editor');
        return;
    }

    await scanFile(activeEditor.document);
}

async function scanFile(document: vscode.TextDocument): Promise<void> {
    try {
        const config = vscode.workspace.getConfiguration('parry');
        const scanMode = config.get('scanMode', 'hybrid');

        const results = await scanner.scanFile(
            document.fileName,
            document.getText(),
            scanMode as string
        );

        diagnosticManager.updateFileDiagnostics(document.uri, results);
        codeLensProvider.updateCodeLenses(document.uri, results);

        if (results.vulnerabilities && results.vulnerabilities.length > 0) {
            const severity = results.vulnerabilities[0].severity;
            const icon = severity === 'critical' ? '🚨' :
                        severity === 'high' ? '⚠️' :
                        severity === 'medium' ? 'ℹ️' : '💡';

            vscode.window.showWarningMessage(
                `${icon} ${results.vulnerabilities.length} security issue(s) found in ${path.basename(document.fileName)}`
            );
        }

    } catch (error) {
        console.error('Parry file scan error:', error);
        // Don't show error to user for background scans
    }
}

function showDashboard(): void {
    dashboard.show();
}

async function applyFix(): Promise<void> {
    const activeEditor = vscode.window.activeTextEditor;
    if (!activeEditor) {
        vscode.window.showErrorMessage('No active editor');
        return;
    }

    const document = activeEditor.document;
    const position = activeEditor.selection.active;

    // Find vulnerability at current position
    const vulnerabilities = diagnosticManager.getVulnerabilitiesForFile(document.uri);
    const vulnerability = vulnerabilities.find(vuln => {
        const range = vuln.range;
        return range.contains(position);
    });

    if (!vulnerability) {
        vscode.window.showInformationMessage('No security issue found at cursor position');
        return;
    }

    // Generate fix suggestion
    try {
        const fix = await scanner.generateFix(vulnerability, document.getText());

        if (fix) {
            // Apply the fix
            const edit = new vscode.WorkspaceEdit();
            edit.replace(document.uri, fix.range, fix.newText);
            await vscode.workspace.applyEdit(edit);

            vscode.window.showInformationMessage('✅ Security fix applied');
        } else {
            vscode.window.showWarningMessage('No automatic fix available for this issue');
        }
    } catch (error) {
        vscode.window.showErrorMessage(`Failed to apply fix: ${error}`);
    }
}

function configureParry(): void {
    vscode.commands.executeCommand('workbench.action.openSettings', '@ext:Parry-AI.parry-security-scanner');
}

function showWelcomeMessage(): void {
    const config = vscode.workspace.getConfiguration('parry');
    const hasShownWelcome = config.get('hasShownWelcome', false);

    if (!hasShownWelcome) {
        vscode.window.showInformationMessage(
            '🎉 Parry Security Scanner is now active! Click here to run your first scan.',
            'Scan Workspace'
        ).then(selection => {
            if (selection === 'Scan Workspace') {
                scanWorkspace();
            }
        });

        // Mark welcome as shown
        config.update('hasShownWelcome', true, vscode.ConfigurationTarget.Global);
    }
}

function getScanSummary(results: any): { files: number; vulnerabilities: number } {
    return {
        files: results.summary?.files_scanned || 0,
        vulnerabilities: results.summary?.vulnerabilities_found || 0
    };
}

export function deactivate() {
    console.log('👋 Parry Security Scanner extension deactivated');
}