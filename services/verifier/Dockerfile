FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir requests
COPY verify.py .
ENTRYPOINT ["python", "verify.py"]
CMD ["all-batches"]
