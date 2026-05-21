FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for build
RUN apt-get update && apt-get install -y build-essential curl && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN python -m spacy download sv_core_news_sm

# Copy application files
COPY . .

# Expose Gateway and Dashboard ports
EXPOSE 8000 8502

# Run both the FastAPI gateway and Streamlit dashboard
CMD ["bash", "-c", "uvicorn gateway:app --host 0.0.0.0 --port 8000 & streamlit run dashboard.py --server.port 8502 --server.address 0.0.0.0"]
