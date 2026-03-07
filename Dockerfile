# arm64-native base image — runs natively on Apple Silicon M2
FROM --platform=linux/arm64 python:3.10-slim

# System deps
RUN apt-get update && apt-get install -y \
    git \
    curl \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY engine.py .

CMD ["python", "engine.py"]