from typing import List
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime

# Assuming these are in your project, adjust imports as needed
from analyzer.code_analyzer import CodeAnalyzer
from models.vulnerability import VulnerabilityReport
# from utils.file_handler import process_uploaded_file  # No longer needed, we read directly

app = FastAPI(
    title="Inspectify AI Agent",
    description="API for AI-powered security vulnerability detection and remediation",
    version="0.1.0"
)

# Configure CORS (restrict origins in production!)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins in development; restrict in production!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalysisRequest(BaseModel):
    repository_url: str
    branch: str = "main"
    scan_depth: int = 3

analyzer = CodeAnalyzer()  # Initialize the analyzer once

@app.post("/analyze/file", response_model=VulnerabilityReport)
async def analyze_file(files: List[UploadFile] = File(...)) -> VulnerabilityReport:
    """
    Analyze one or more files for security vulnerabilities.
    """
    print("--- Starting analyze_file (FastAPI) ---")
    try:
        reports = []
        for file in files:
            print(f"  Processing file: {file.filename}")
            file_content = await file.read()  # Read file content directly
            print(f"    File content read.  Size: {len(file_content)} bytes")
            report = await analyzer.analyze_code(file_content, file.filename)
            print(f"    Analysis complete for {file.filename}.")
            reports.append(report)

        if len(reports) > 1:
            # Combine reports
            combined_report = VulnerabilityReport(
                timestamp=datetime.now(),  # Use current time for combined report
                vulnerabilities=[vuln for r in reports for vuln in r.vulnerabilities],
                chained_vulnerabilities=[chain for r in reports for chain in r.chained_vulnerabilities]
            )
            combined_report.calculate_summary()
            combined_report.calculate_risk_score()
            print("    Combined report created.")
            return combined_report
        elif reports:
            print("    Returning single report.")
            return reports[0]
        else:
            print("    No files to analyze, returning empty report")
            return VulnerabilityReport(timestamp=datetime.now(), vulnerabilities=[], chained_vulnerabilities=[])

    except Exception as e:
        print(f"    Error during analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        print("--- Finishing analyze_file (FastAPI) ---")


@app.post("/analyze/repository", response_model=VulnerabilityReport)
async def analyze_repository(request: AnalysisRequest) -> VulnerabilityReport:
    """
    Analyze a git repository for security vulnerabilities.
    """
    print("--- Starting analyze_repository (FastAPI) ---") #Added print statement
    try:
        report = await analyzer.analyze_repository(
            request.repository_url,
            request.branch,
            request.scan_depth
        )
        print("--- Finishing analyze_repository (FastAPI) ---") #Added print statement
        return report
    except Exception as e:
        print(f"    Error during analysis: {e}") #Added print statement
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)