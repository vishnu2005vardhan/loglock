FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -r requirements-blockchain.txt
COPY . .
ENV PYTHONUNBUFFERED=1
