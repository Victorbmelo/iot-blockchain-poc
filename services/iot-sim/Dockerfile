FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir requests
COPY sim.py .
CMD ["python", "sim.py", "--scenario", "normal", "--eps", "1", "--duration", "3600"]
