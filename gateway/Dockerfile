FROM python:3.11-slim

LABEL maintainer="Politecnico di Torino - Audit Layer Thesis"
LABEL description="Audit Gateway - Immutable IoT Safety Audit Layer"

WORKDIR /audit-gateway

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Non-root user for security
RUN adduser --disabled-password --gecos "" audituser
USER audituser

EXPOSE 8080

# FABRIC_STUB_MODE=true for local dev without real Fabric
ENV FABRIC_STUB_MODE=true
ENV LOG_LEVEL=INFO

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
