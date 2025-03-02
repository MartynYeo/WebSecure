# simple_api.py
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import JSONResponse

app = FastAPI()

@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """
    Simplified endpoint that just returns the filename and content size.
    """
    try:
        contents = await file.read()
        return JSONResponse({
            "filename": file.filename,
            "content_size": len(contents),
            "message": "File received successfully!"
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/health")
async def health_check():
    return {"status": "OK"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001) # Explicitly use 127.0.0.1