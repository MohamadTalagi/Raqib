FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

ENV PYTHONPATH=/app

EXPOSE 80 1900/udp

HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD python -c "\
import urllib.request; urllib.request.urlopen('http://localhost/health', timeout=2)"

ENTRYPOINT ["./entrypoint.sh"]
