#!/usr/bin/env python3
"""
Parry Webhook Server for Real-Time Security Scanning

Provides REST API endpoints for triggering security scans via webhooks.
Supports GitHub, GitLab, and generic webhook integrations.

Usage:
    python3 -m parry.webhook_server --port 8080 --host 0.0.0.0
"""

import json
import logging
import os
import tempfile
import subprocess
import time
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import git
import hmac
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Parry Webhook Server",
    description="Real-time security scanning via webhooks",
    version="1.0.0"
)

# In-memory storage for scan results (in production, use a database)
scan_results = {}
scan_status = {}

class WebhookConfig:
    """Webhook configuration and security"""
    def __init__(self):
        self.github_secret = os.getenv("GITHUB_WEBHOOK_SECRET")
        self.gitlab_secret = os.getenv("GITLAB_WEBHOOK_SECRET")
        self.allowed_repos = os.getenv("ALLOWED_REPOS", "").split(",")

webhook_config = WebhookConfig()

class ScanRequest(BaseModel):
    """Generic scan request model"""
    repository_url: str
    branch: str = "main"
    scan_mode: str = "hybrid"
    severity_threshold: str = "medium"
    webhook_type: str = "generic"

class ScanStatus(BaseModel):
    """Scan status response model"""
    scan_id: str
    status: str
    repository: str
    branch: str
    started_at: str
    completed_at: Optional[str] = None
    results_url: Optional[str] = None
    error_message: Optional[str] = None

def verify_github_signature(request: Request, body: bytes) -> bool:
    """Verify GitHub webhook signature"""
    if not webhook_config.github_secret:
        return True  # Skip verification if no secret configured

    signature = request.headers.get('X-Hub-Signature-256')
    if not signature:
        return False

    expected_signature = hmac.new(
        webhook_config.github_secret.encode(),
        body,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(f"sha256={expected_signature}", signature)

def verify_gitlab_signature(request: Request, body: bytes) -> bool:
    """Verify GitLab webhook signature"""
    if not webhook_config.gitlab_secret:
        return True  # Skip verification if no secret configured

    signature = request.headers.get('X-Gitlab-Token')
    if not signature:
        return False

    return signature == webhook_config.gitlab_secret

def clone_repository(repo_url: str, branch: str = "main") -> Path:
    """Clone repository to temporary directory"""
    temp_dir = Path(tempfile.mkdtemp(prefix="parry-scan-"))

    try:
        logger.info(f"Cloning repository: {repo_url} (branch: {branch})")
        repo = git.Repo.clone_from(repo_url, temp_dir, branch=branch, depth=1)
        logger.info(f"Repository cloned to: {temp_dir}")
        return temp_dir
    except Exception as e:
        logger.error(f"Failed to clone repository: {e}")
        raise

def run_parry_scan(scan_dir: Path, scan_mode: str, severity: str) -> Dict[str, Any]:
    """Run Parry security scan"""
    import sys
    sys.path.insert(0, str(Path(__file__).parent))

    from parry.scanner import Scanner

    try:
        logger.info(f"Starting Parry scan in {scan_mode} mode on {scan_dir}")

        # Initialize scanner
        scanner = Scanner()

        # Run scan
        results = scanner.scan(scan_dir)

        # Add scan metadata
        results['scan_metadata'] = {
            'timestamp': datetime.now().isoformat(),
            'scan_mode': scan_mode,
            'severity_threshold': severity,
            'scanner_version': '1.0.0'
        }

        logger.info(f"Scan completed: {len(results.get('vulnerabilities', []))} vulnerabilities found")
        return results

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise

@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "service": "Parry Webhook Server",
        "version": "1.0.0",
        "endpoints": {
            "/scan": "Trigger security scan",
            "/status/{scan_id}": "Get scan status",
            "/results/{scan_id}": "Get scan results",
            "/health": "Health check"
        }
    }

@app.post("/scan")
async def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks, req: Request):
    """Trigger a security scan"""
    scan_id = f"scan_{int(time.time())}_{hash(request.repository_url) % 10000}"

    # Initialize scan status
    scan_status[scan_id] = {
        "scan_id": scan_id,
        "status": "queued",
        "repository": request.repository_url,
        "branch": request.branch,
        "started_at": datetime.now().isoformat(),
        "scan_mode": request.scan_mode,
        "severity_threshold": request.severity_threshold
    }

    # Add background task
    background_tasks.add_task(
        perform_scan,
        scan_id,
        request.repository_url,
        request.branch,
        request.scan_mode,
        request.severity_threshold
    )

    return {
        "scan_id": scan_id,
        "status": "queued",
        "message": "Security scan queued successfully"
    }

@app.post("/webhooks/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """Handle GitHub webhook"""
    body = await request.body()

    # Verify signature
    if not verify_github_signature(request, body):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse payload
    payload = json.loads(body)
    repo_url = payload.get('repository', {}).get('clone_url')
    branch = payload.get('ref', 'refs/heads/main').replace('refs/heads/', '')

    if not repo_url:
        raise HTTPException(status_code=400, detail="No repository URL in payload")

    # Check if repo is allowed
    if webhook_config.allowed_repos and repo_url not in webhook_config.allowed_repos:
        raise HTTPException(status_code=403, detail="Repository not allowed")

    # Trigger scan
    scan_req = ScanRequest(
        repository_url=repo_url,
        branch=branch,
        webhook_type="github"
    )

    return await trigger_scan(scan_req, background_tasks, request)

@app.post("/webhooks/gitlab")
async def gitlab_webhook(request: Request, background_tasks: BackgroundTasks):
    """Handle GitLab webhook"""
    body = await request.body()

    # Verify signature
    if not verify_gitlab_signature(request, body):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse payload
    payload = json.loads(body)
    repo_url = payload.get('repository', {}).get('git_http_url')
    branch = payload.get('ref', 'refs/heads/main').replace('refs/heads/', '')

    if not repo_url:
        raise HTTPException(status_code=400, detail="No repository URL in payload")

    # Check if repo is allowed
    if webhook_config.allowed_repos and repo_url not in webhook_config.allowed_repos:
        raise HTTPException(status_code=403, detail="Repository not allowed")

    # Trigger scan
    scan_req = ScanRequest(
        repository_url=repo_url,
        branch=branch,
        webhook_type="gitlab"
    )

    return await trigger_scan(scan_req, background_tasks, request)

@app.get("/status/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get scan status"""
    if scan_id not in scan_status:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanStatus(**scan_status[scan_id])

@app.get("/results/{scan_id}")
async def get_scan_results(scan_id: str):
    """Get scan results"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan results not found")

    return scan_results[scan_id]

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "active_scans": len([s for s in scan_status.values() if s['status'] in ['running', 'queued']])
    }

async def perform_scan(scan_id: str, repo_url: str, branch: str, scan_mode: str, severity: str):
    """Perform the actual security scan"""
    try:
        # Update status to running
        scan_status[scan_id]["status"] = "running"

        # Clone repository
        repo_dir = clone_repository(repo_url, branch)

        # Run scan
        results = run_parry_scan(repo_dir, scan_mode, severity)

        # Store results
        scan_results[scan_id] = results

        # Update status
        scan_status[scan_id].update({
            "status": "completed",
            "completed_at": datetime.now().isoformat(),
            "results_url": f"/results/{scan_id}",
            "vulnerability_count": len(results.get('vulnerabilities', [])),
            "files_scanned": results.get('files_scanned', 0)
        })

        # Clean up
        import shutil
        shutil.rmtree(repo_dir, ignore_errors=True)

        logger.info(f"Scan {scan_id} completed successfully")

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        scan_status[scan_id].update({
            "status": "failed",
            "completed_at": datetime.now().isoformat(),
            "error_message": str(e)
        })

def main():
    """Main entry point for running the webhook server"""
    import argparse

    parser = argparse.ArgumentParser(description="Parry Webhook Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")

    args = parser.parse_args()

    print("🚀 Starting Parry Webhook Server...")
    print(f"📍 Host: {args.host}")
    print(f"🔌 Port: {args.port}")
    print(f"🔗 Webhooks: http://{args.host}:{args.port}/webhooks/github|gitlab")
    print(f"📊 API: http://{args.host}:{args.port}/docs")

    uvicorn.run(
        "parry.webhook_server:app",
        host=args.host,
        port=args.port,
        reload=args.reload
    )

if __name__ == "__main__":
    main()
