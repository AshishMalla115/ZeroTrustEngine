FROM python:3.12-slim

WORKDIR /ml_pipeline

COPY requirements_freeze.txt .
RUN pip install --no-cache-dir -r requirements_freeze.txt

COPY . .

RUN mkdir -p models data notebooks

VOLUME ["/ml_pipeline/models"]

ENV DB_HOST=localhost
ENV DB_PORT=5432
ENV DB_NAME=zero_trust_db
ENV DB_USER=ztrust_readonly

CMD ["python", "retrain.py", "--csv"]