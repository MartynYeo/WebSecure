# Inspectify


## Setup

1. Create venv in folder ```python -m venv venv```
2. Activate venv ```call venv/Scripts/activate.bat```
3. Install modules ```pip install -r requirements.txt```
4. Create .env file with the contents:
```
OPENAI_API_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key
ZAP_API_KEY=your_ZAP_key
#OLLAMA_BASE_URL=http://localhost:11434  # Optional
```
5. Go to Terminal -> Run Tasks... -> Start OWASP ZAP (May need to change the cwd in tasks.json to where your ZAP is)
6. With venv activated ```uvicorn main:app --reload --port 8001```
7. With venv activated on another terminal ```streamlit run app.py```