FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY baseline_secure_coding_api.py .
EXPOSE 5001
CMD ["python", "baseline_secure_coding_api.py"]