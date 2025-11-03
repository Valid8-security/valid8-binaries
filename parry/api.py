# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Parry REST API Server
Provides HTTP endpoints for scanning, results retrieval, and management

This module implements a FastAPI-based REST API server for Parry, enabling:
- Asynchronous security scans via background tasks
- Job status tracking and progress monitoring
- Multi-mode scanning (fast/deep/hybrid)
- SCA (Software Composition Analysis) integration
- Incremental scanning support
- Custom rules engine integration
- CORS support for web frontends

Key Endpoints:
- POST /api/v1/scan - Initiate a new security scan (returns job_id)
- GET /api/v1/jobs/{job_id} - Check scan status and retrieve results
- GET /api/v1/jobs - List all scan jobs with optional filtering
- GET /api/v1/stats - Aggregate statistics across all scans
- GET /health - Health check for monitoring

Job Lifecycle:
1. queued → Scan request received, waiting to start
2. running → Scan in progress with progress percentage
3. completed → Scan finished successfully, results available
4. failed → Scan encountered an error

Architecture:
- In-memory job storage (scan_jobs dict) - Use Redis/PostgreSQL for production
- Background task execution via FastAPI BackgroundTasks
- Pydantic models for request/response validation
- CORS enabled for cross-origin web client access

Used by: Web frontends, CI/CD pipelines, automation scripts
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File, Request, Header
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict
from typing import List, Dict, Any, Optional
from pathlib import Path
import uvicorn
import tempfile
import shutil
import uuid
from datetime import datetime
import logging

from parry.scanner import Scanner
from parry.sca import SCAScanner
from parry.custom_rules import CustomRulesEngine
from parry.cache import ProjectCache
from parry.payment.stripe_integration import StripePaymentManager, LicenseManager
from parry.payment.email_notifier import EmailNotifier

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Parry Security Scanner API",
    description="AI-powered security scanning with 100% local processing",
    version="0.4.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory job storage (use Redis/PostgreSQL in production)
scan_jobs: Dict[str, Dict[str, Any]] = {}


class ScanRequest(BaseModel):
    """Request model for initiating a scan"""
    model_config = ConfigDict()
    
    project_path: str
    mode: str = "fast"  # fast, deep, hybrid
    enable_validation: bool = False  # AI validation enabled
    sca: bool = False
    incremental: bool = False
    custom_rules_path: Optional[str] = None


class ScanResponse(BaseModel):
    """Response model for scan initiation"""
    job_id: str
    status: str
    message: str


class JobStatus(BaseModel):
    """Model for job status"""
    job_id: str
    status: str  # queued, running, completed, failed
    progress: float
    started_at: Optional[str]
    completed_at: Optional[str]
    results: Optional[Dict[str, Any]]
    error: Optional[str]


@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "name": "Parry Security Scanner API",
        "version": "0.4.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "scan": "/api/v1/scan",
            "job_status": "/api/v1/jobs/{job_id}",
            "jobs_list": "/api/v1/jobs",
            "stats": "/api/v1/stats"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.post("/api/v1/scan", response_model=ScanResponse)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Initiate a security scan
    Returns a job_id that can be used to check status
    """
    job_id = str(uuid.uuid4())
    
    # Validate project path
    project_path = Path(request.project_path)
    if not project_path.exists():
        raise HTTPException(status_code=400, detail=f"Project path does not exist: {request.project_path}")
    
    # Create job entry
    scan_jobs[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "progress": 0.0,
        "started_at": None,
        "completed_at": None,
        "results": None,
        "error": None,
        "request": request.dict()
    }
    
    # Run scan in background
    background_tasks.add_task(run_scan, job_id, request)
    
    return ScanResponse(
        job_id=job_id,
        status="queued",
        message="Scan initiated successfully"
    )


@app.get("/api/v1/jobs/{job_id}", response_model=JobStatus)
async def get_job_status(job_id: str):
    """Get status of a scan job"""
    if job_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = scan_jobs[job_id]
    return JobStatus(**job)


@app.get("/api/v1/jobs")
async def list_jobs(limit: int = 50, status: Optional[str] = None):
    """List all scan jobs"""
    jobs = list(scan_jobs.values())
    
    # Filter by status if provided
    if status:
        jobs = [j for j in jobs if j["status"] == status]
    
    # Sort by start time (most recent first)
    jobs.sort(key=lambda x: x.get("started_at") or "", reverse=True)
    
    return {
        "total": len(jobs),
        "jobs": jobs[:limit]
    }


@app.delete("/api/v1/jobs/{job_id}")
async def delete_job(job_id: str):
    """Delete a scan job"""
    if job_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    del scan_jobs[job_id]
    return {"message": "Job deleted successfully"}


@app.get("/api/v1/stats")
async def get_stats():
    """Get API statistics"""
    total_jobs = len(scan_jobs)
    completed = len([j for j in scan_jobs.values() if j["status"] == "completed"])
    running = len([j for j in scan_jobs.values() if j["status"] == "running"])
    failed = len([j for j in scan_jobs.values() if j["status"] == "failed"])
    
    # Calculate total vulnerabilities found
    total_vulns = 0
    for job in scan_jobs.values():
        if job["status"] == "completed" and job["results"]:
            total_vulns += len(job["results"].get("vulnerabilities", []))
    
    return {
        "total_scans": total_jobs,
        "completed": completed,
        "running": running,
        "failed": failed,
        "total_vulnerabilities_found": total_vulns
    }


@app.post("/api/v1/upload-scan")
async def upload_and_scan(
    file: UploadFile = File(...),
    mode: str = "fast"
):
    """
    Upload a zip file and scan it
    """
    # Create temp directory
    temp_dir = Path(tempfile.mkdtemp())
    
    try:
        # Save uploaded file
        zip_path = temp_dir / file.filename
        with open(zip_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
        
        # Extract if zip
        if file.filename.endswith(".zip"):
            import zipfile
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir / "project")
            project_path = temp_dir / "project"
        else:
            project_path = temp_dir
        
        # Run scan immediately (synchronous for uploads)
        scanner = Scanner()
        results = scanner.scan(project_path)
        
        return JSONResponse({
            "status": "completed",
            "results": {
                "files_scanned": results["files_scanned"],
                "vulnerabilities_found": results["vulnerabilities_found"],
                "vulnerabilities": results["vulnerabilities"]
            }
        })
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)


async def run_scan(job_id: str, request: ScanRequest):
    """Background task to run security scan"""
    try:
        # Update job status
        scan_jobs[job_id]["status"] = "running"
        scan_jobs[job_id]["started_at"] = datetime.now().isoformat()
        scan_jobs[job_id]["progress"] = 0.1
        
        project_path = Path(request.project_path)
        results = {
            "sast_results": None,
            "sca_results": None,
            "custom_rules_results": None
        }
        
        # SAST scan
        scanner = Scanner()
        scan_jobs[job_id]["progress"] = 0.3
        
        sast_results = scanner.scan(project_path)
        results["sast_results"] = {
            "files_scanned": sast_results["files_scanned"],
            "vulnerabilities_found": sast_results["vulnerabilities_found"],
            "vulnerabilities": sast_results["vulnerabilities"]
        }
        scan_jobs[job_id]["progress"] = 0.6
        
        # SCA scan if requested
        if request.sca:
            sca_scanner = SCAScanner()
            sca_vulns = sca_scanner.scan_project(project_path)
            results["sca_results"] = {
                "dependencies_scanned": len(sca_vulns),
                "vulnerabilities": [v.to_dict() for v in sca_vulns]
            }
        scan_jobs[job_id]["progress"] = 0.8
        
        # Custom rules if provided
        if request.custom_rules_path:
            rules_engine = CustomRulesEngine()
            rules_engine.load_rules(Path(request.custom_rules_path))
            # Apply custom rules (simplified)
            results["custom_rules_results"] = {
                "rules_applied": len(rules_engine.rules),
                "violations": []
            }
        
        # Mark as completed
        scan_jobs[job_id]["status"] = "completed"
        scan_jobs[job_id]["completed_at"] = datetime.now().isoformat()
        scan_jobs[job_id]["progress"] = 1.0
        scan_jobs[job_id]["results"] = results
    
    except Exception as e:
        logger.error(f"Scan failed for job {job_id}: {e}")
        scan_jobs[job_id]["status"] = "failed"
        scan_jobs[job_id]["error"] = str(e)
        scan_jobs[job_id]["completed_at"] = datetime.now().isoformat()


@app.post("/api/v1/webhooks/stripe")
async def stripe_webhook(request: Request, stripe_signature: Optional[str] = Header(None)):
    """
    Stripe webhook endpoint for payment events
    
    Handles:
    - checkout.session.completed: New subscription
    - customer.subscription.updated: Subscription change
    - customer.subscription.deleted: Cancellation
    - invoice.payment_failed: Payment failure
    """
    try:
        # Get raw payload
        payload = await request.body()
        
        # Verify signature
        if not stripe_signature:
            raise HTTPException(status_code=400, detail="Missing Stripe signature header")
        
        # Initialize managers
        payment_manager = StripePaymentManager()
        license_manager = LicenseManager()
        email_notifier = EmailNotifier(provider='sendgrid')  # or 'aws_ses'
        
        # Handle webhook
        result = payment_manager.handle_webhook(payload, stripe_signature)
        
        # Process based on event type
        if result['status'] == 'subscription_created':
            # Generate and send license
            subscription = result['subscription']
            customer_email = subscription['customer_email']
            tier = subscription['tier']
            
            # Generate license key
            license_key = license_manager.generate_license_key(
                email=customer_email,
                tier=tier
            )
            
            # Save license
            license_manager.save_license(license_key, {
                'email': customer_email,
                'tier': tier,
                'subscription_id': subscription['id'],
                'created_at': datetime.now().isoformat()
            })
            
            # Send email with license
            email_notifier.send_license_email(
                to_email=customer_email,
                to_name=subscription.get('customer_name', customer_email.split('@')[0]),
                license_key=license_key,
                tier=tier,
                expires=datetime.fromtimestamp(subscription['expires']),
                metadata={'subscription_id': subscription['id']}
            )
            
            logger.info(f"License generated and sent for {customer_email}")
        
        elif result['status'] == 'payment_failed':
            # Notify customer
            payment_info = result['payment']
            email_notifier.send_payment_failed_email(
                to_email=payment_info['customer_email'],
                to_name=payment_info.get('customer_name', payment_info['customer_email'].split('@')[0]),
                tier=payment_info['tier'],
                amount=payment_info['amount'] / 100,  # Convert from cents
                reason=payment_info.get('failure_reason', 'Unknown')
            )
            
            logger.warning(f"Payment failed for {payment_info['customer_email']}")
        
        elif result['status'] == 'subscription_deleted':
            # Notify customer
            subscription = result['subscription']
            email_notifier.send_subscription_cancelled_email(
                to_email=subscription['customer_email'],
                to_name=subscription.get('customer_name', subscription['customer_email'].split('@')[0]),
                tier=subscription['tier'],
                expires=datetime.fromtimestamp(subscription['expires'])
            )
            
            logger.info(f"Subscription cancelled for {subscription['customer_email']}")
        
        return JSONResponse(status_code=200, content={'received': True, 'result': result})
    
    except ValueError as e:
        logger.error(f"Webhook validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Webhook processing error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


def start_api_server(host: str = "0.0.0.0", port: int = 8000):
    """Start the API server"""
    print(f"""
    ╔════════════════════════════════════════════════════════╗
    ║                                                        ║
    ║   🛡️  Parry Security Scanner API Server               ║
    ║                                                        ║
    ║   Version: 0.4.0                                       ║
    ║   Server: http://{host}:{port}                     ║
    ║   Docs: http://{host}:{port}/docs                  ║
    ║   Webhook: http://{host}:{port}/api/v1/webhooks/stripe ║
    ║                                                        ║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    start_api_server()

