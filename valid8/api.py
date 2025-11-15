"""
Parry REST API Server
Provides HTTP endpoints for scanning, results retrieval, and management
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict
from typing import List, Dict, Any, Optional
from pathlib import Path
import uvicorn
import tempfile
import shutil
import uuid
import time
from datetime import datetime
import logging

from valid8.scanner import Scanner
from valid8.sca import SCAScanner
from valid8.custom_rules import CustomRulesEngine
from valid8.cache import ProjectCache

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
    Security: Only accepts .zip files, validates file size and content
    """
    # SECURITY: Validate file type and size
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    # SECURITY: Only allow .zip files
    if not file.filename.lower().endswith('.zip'):
        raise HTTPException(status_code=400, detail="Only .zip files are allowed")

    # SECURITY: Check file size (max 50MB)
    file_size = 0
    content = await file.read()
    file_size = len(content)

    if file_size > 50 * 1024 * 1024:  # 50MB limit
        raise HTTPException(status_code=400, detail="File too large (max 50MB)")

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    # Create temp directory
    temp_dir = Path(tempfile.mkdtemp())

    try:
        # Save uploaded file with safe filename
        safe_filename = f"upload_{int(time.time())}_{hash(file.filename) % 10000}.zip"
        zip_path = temp_dir / safe_filename
        with open(zip_path, "wb") as f:
            f.write(content)

        # Extract with security checks
        project_path = temp_dir / "project"
        project_path.mkdir(exist_ok=True)

        import zipfile
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # SECURITY: Check for zip bombs and malicious paths
            for member in zip_ref.namelist():
                # Prevent path traversal attacks
                if ".." in member or member.startswith("/"):
                    raise HTTPException(status_code=400, detail="Invalid file path in zip")

                # Prevent zip bombs (files that extract to very large sizes)
                if zip_ref.getinfo(member).file_size > 100 * 1024 * 1024:  # 100MB per file
                    raise HTTPException(status_code=400, detail="Zip contains file too large")

            # Extract safely
            zip_ref.extractall(project_path)
        
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
    ║                                                        ║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    start_api_server()

