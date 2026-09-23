from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
import os
import sys

# Ensure root folder is in python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from reports.pdf_generator import generate_pdf_report

router = APIRouter()

@router.get("/api/report/pdf")
def download_pdf_report():
    try:
        pdf_path = generate_pdf_report()
        if not os.path.exists(pdf_path):
            raise HTTPException(status_code=404, detail="Generated PDF file not found.")
            
        return FileResponse(
            path=pdf_path, 
            filename=os.path.basename(pdf_path), 
            media_type="application/pdf"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF Generation failed: {str(e)}")