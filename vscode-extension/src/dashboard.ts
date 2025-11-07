import * as vscode from 'vscode';
import * as path from 'path';

interface ScanResult {
    summary: {
        files_scanned: number;
        vulnerabilities_found: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        scan_time_seconds: number;
    };
    vulnerabilities: any[];
}

export class SecurityDashboard {
    private panel: vscode.WebviewPanel | undefined;
    private context: vscode.ExtensionContext;
    private currentResults: ScanResult | null = null;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
    }

    initialize(): void {
        // Register tree data provider for the explorer view
        const provider = new SecurityTreeDataProvider();
        vscode.window.registerTreeDataProvider('parryExplorer', provider);
    }

    show(): void {
        if (this.panel) {
            this.panel.reveal(vscode.ViewColumn.One);
        } else {
            this.panel = vscode.window.createWebviewPanel(
                'parryDashboard',
                'Parry Security Dashboard',
                vscode.ViewColumn.One,
                {
                    enableScripts: true,
                    localResourceRoots: [
                        vscode.Uri.file(path.join(this.context.extensionPath, 'media'))
                    ]
                }
            );

            this.panel.webview.html = this.getWebviewContent();

            this.panel.onDidDispose(() => {
                this.panel = undefined;
            });

            // Update content if we have results
            if (this.currentResults) {
                this.updateWebview();
            }
        }
    }

    updateResults(results: ScanResult): void {
        this.currentResults = results;
        if (this.panel) {
            this.updateWebview();
        }
    }

    private updateWebview(): void {
        if (this.panel && this.currentResults) {
            this.panel.webview.postMessage({
                type: 'updateResults',
                results: this.currentResults
            });
        }
    }

    private getWebviewContent(): string {
        const nonce = getNonce();

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Parry Security Dashboard</title>
    <style>
        body {
            font-family: var(--vscode-font-family);
            font-size: var(--vscode-font-size);
            background-color: var(--vscode-editor-background);
            color: var(--vscode-editor-foreground);
            margin: 0;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            margin-bottom: 30px;
        }

        .logo {
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
        }

        .subtitle {
            color: var(--vscode-descriptionForeground);
            font-size: 0.9rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: var(--vscode-editorWidget-background);
            border: 1px solid var(--vscode-widget-border);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .stat-critical { color: #dc3545; }
        .stat-high { color: #fd7e14; }
        .stat-medium { color: #ffc107; }
        .stat-low { color: #28a745; }
        .stat-total { color: #667eea; }

        .stat-label {
            color: var(--vscode-descriptionForeground);
            font-size: 0.9rem;
        }

        .chart-container {
            background: var(--vscode-editorWidget-background);
            border: 1px solid var(--vscode-widget-border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .chart-title {
            font-size: 1.2rem;
            font-weight: bold;
            margin-bottom: 15px;
        }

        .severity-chart {
            display: flex;
            justify-content: space-around;
            align-items: end;
            height: 200px;
            margin-bottom: 20px;
        }

        .severity-bar {
            display: flex;
            flex-direction: column;
            align-items: center;
            min-width: 60px;
        }

        .bar {
            width: 40px;
            background: #667eea;
            border-radius: 4px 4px 0 0;
            margin-bottom: 8px;
            transition: all 0.3s ease;
        }

        .bar-critical { background: #dc3545; }
        .bar-high { background: #fd7e14; }
        .bar-medium { background: #ffc107; }
        .bar-low { background: #28a745; }

        .bar-label {
            font-size: 0.8rem;
            color: var(--vscode-descriptionForeground);
            text-align: center;
        }

        .vulnerabilities-list {
            background: var(--vscode-editorWidget-background);
            border: 1px solid var(--vscode-widget-border);
            border-radius: 8px;
            overflow: hidden;
        }

        .vulnerability-item {
            padding: 15px;
            border-bottom: 1px solid var(--vscode-list-inactiveSelectionBackground);
            display: flex;
            align-items: center;
            cursor: pointer;
            transition: background-color 0.2s;
        }

        .vulnerability-item:hover {
            background: var(--vscode-list-hoverBackground);
        }

        .vulnerability-item:last-child {
            border-bottom: none;
        }

        .vulnerability-icon {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            font-weight: bold;
            margin-right: 15px;
            flex-shrink: 0;
        }

        .vulnerability-content {
            flex: 1;
        }

        .vulnerability-title {
            font-weight: bold;
            margin-bottom: 4px;
        }

        .vulnerability-meta {
            font-size: 0.8rem;
            color: var(--vscode-descriptionForeground);
        }

        .no-data {
            text-align: center;
            padding: 40px;
            color: var(--vscode-descriptionForeground);
        }

        .scan-button {
            background: #667eea;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            font-size: 1rem;
            cursor: pointer;
            margin: 20px 0;
            transition: background-color 0.2s;
        }

        .scan-button:hover {
            background: #5a67d8;
        }

        .scan-button:disabled {
            background: var(--vscode-disabledForeground);
            cursor: not-allowed;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️ Parry</div>
            <div class="subtitle">Security Dashboard - Real-time Vulnerability Monitoring</div>
        </div>

        <div id="content">
            <div class="no-data">
                <h3>Welcome to Parry Security Scanner</h3>
                <p>Click "Scan Workspace" to start your first security scan</p>
                <button class="scan-button" onclick="scanWorkspace()">🔍 Scan Workspace</button>
            </div>
        </div>
    </div>

    <script nonce="${nonce}">
        const vscode = acquireVsCodeApi();
        let currentResults = null;

        function scanWorkspace() {
            vscode.postMessage({ type: 'scanWorkspace' });
        }

        function updateUI(results) {
            currentResults = results;
            const content = document.getElementById('content');

            if (!results || !results.summary) {
                content.innerHTML = '<div class="no-data"><h3>No scan results available</h3><p>Run a security scan to see your results here.</p></div>';
                return;
            }

            const summary = results.summary;
            const vulnerabilities = results.vulnerabilities || [];

            content.innerHTML = \`
                <!-- Stats Grid -->
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value stat-total">\${summary.files_scanned}</div>
                        <div class="stat-label">Files Scanned</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value stat-critical">\${summary.critical || 0}</div>
                        <div class="stat-label">Critical Issues</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value stat-high">\${summary.high || 0}</div>
                        <div class="stat-label">High Severity</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value stat-medium">\${summary.medium || 0}</div>
                        <div class="stat-label">Medium Severity</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value stat-low">\${summary.low || 0}</div>
                        <div class="stat-label">Low Severity</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value stat-total">\${summary.scan_time_seconds}s</div>
                        <div class="stat-label">Scan Time</div>
                    </div>
                </div>

                <!-- Charts -->
                <div class="chart-container">
                    <div class="chart-title">Vulnerability Distribution by Severity</div>
                    <div class="severity-chart">
                        <div class="severity-bar">
                            <div class="bar bar-critical" style="height: \${Math.max((summary.critical || 0) * 20, 20)}px"></div>
                            <div class="bar-label">Critical<br/>\${summary.critical || 0}</div>
                        </div>
                        <div class="severity-bar">
                            <div class="bar bar-high" style="height: \${Math.max((summary.high || 0) * 20, 20)}px"></div>
                            <div class="bar-label">High<br/>\${summary.high || 0}</div>
                        </div>
                        <div class="severity-bar">
                            <div class="bar bar-medium" style="height: \${Math.max((summary.medium || 0) * 20, 20)}px"></div>
                            <div class="bar-label">Medium<br/>\${summary.medium || 0}</div>
                        </div>
                        <div class="severity-bar">
                            <div class="bar bar-low" style="height: \${Math.max((summary.low || 0) * 20, 20)}px"></div>
                            <div class="bar-label">Low<br/>\${summary.low || 0}</div>
                        </div>
                    </div>
                </div>

                <!-- Vulnerabilities List -->
                <div class="vulnerabilities-list">
                    \${vulnerabilities.length > 0 ? vulnerabilities.slice(0, 10).map(vuln => \`
                        <div class="vulnerability-item" onclick="showVulnerability('\${vuln.id}')">
                            <div class="vulnerability-icon \${getSeverityClass(vuln.severity)}">
                                \${getSeverityIcon(vuln.severity)}
                            </div>
                            <div class="vulnerability-content">
                                <div class="vulnerability-title">\${vuln.title}</div>
                                <div class="vulnerability-meta">
                                    \${vuln.file}:\${vuln.line} • \${vuln.cwe} • \${vuln.severity.toUpperCase()}
                                </div>
                            </div>
                        </div>
                    \`).join('') : '<div class="no-data"><h4>No vulnerabilities found! 🎉</h4><p>Your code looks secure.</p></div>'}
                </div>
            \`;
        }

        function getSeverityClass(severity) {
            return \`stat-\${severity}\`;
        }

        function getSeverityIcon(severity) {
            switch (severity) {
                case 'critical': return '🚨';
                case 'high': return '⚠️';
                case 'medium': return 'ℹ️';
                case 'low': return '💡';
                default: return '🔍';
            }
        }

        function showVulnerability(id) {
            vscode.postMessage({ type: 'showVulnerability', id: id });
        }

        // Handle messages from extension
        window.addEventListener('message', event => {
            const message = event.data;
            switch (message.type) {
                case 'updateResults':
                    updateUI(message.results);
                    break;
            }
        });
    </script>
</body>
</html>`;
    }
}

function getNonce(): string {
    let text = '';
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < 32; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}

class SecurityTreeDataProvider implements vscode.TreeDataProvider<SecurityItem> {
    onDidChangeTreeData?: vscode.Event<SecurityItem | null | undefined>;

    getTreeItem(element: SecurityItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: SecurityItem): Thenable<SecurityItem[]> {
        if (!element) {
            // Root level
            return Promise.resolve([
                new SecurityItem('Scan Status', 'Ready to scan', vscode.TreeItemCollapsibleState.None, 'status'),
                new SecurityItem('Recent Scans', 'View scan history', vscode.TreeItemCollapsibleState.Collapsed, 'history'),
                new SecurityItem('Configuration', 'Manage settings', vscode.TreeItemCollapsibleState.None, 'config')
            ]);
        }

        if (element.contextValue === 'history') {
            return Promise.resolve([
                new SecurityItem('Last Scan: 2 minutes ago', '15 vulnerabilities found', vscode.TreeItemCollapsibleState.None, 'scan'),
                new SecurityItem('Previous Scan: 1 hour ago', '8 vulnerabilities found', vscode.TreeItemCollapsibleState.None, 'scan')
            ]);
        }

        return Promise.resolve([]);
    }
}

class SecurityItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly tooltip: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly contextValue: string
    ) {
        super(label, collapsibleState);
        this.tooltip = tooltip;
        this.contextValue = contextValue;

        // Set icon based on type
        switch (contextValue) {
            case 'status':
                this.iconPath = new vscode.ThemeIcon('shield');
                break;
            case 'history':
                this.iconPath = new vscode.ThemeIcon('history');
                break;
            case 'config':
                this.iconPath = new vscode.ThemeIcon('settings-gear');
                break;
            case 'scan':
                this.iconPath = new vscode.ThemeIcon('search');
                break;
        }
    }
}
