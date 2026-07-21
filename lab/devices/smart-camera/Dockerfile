FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY docs ./docs
COPY entrypoint.sh .
COPY sitecustomize.py .
RUN chmod +x entrypoint.sh

ENV PYTHONPATH=/app

EXPOSE 80 443 23

HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD python -c "\
import os, ssl, urllib.request; \
ctx = ssl.create_default_context(); \
ctx.check_hostname = False; \
ctx.verify_mode = ssl.CERT_NONE; \
ctx.set_ciphers('DEFAULT@SECLEVEL=0'); \
scheme = 'https' if os.environ.get('TRANSPORT') == 'https' else 'http'; \
port = 443 if scheme == 'https' else 80; \
urllib.request.urlopen(f'{scheme}://localhost:{port}/health', context=ctx if scheme == 'https' else None, timeout=2)"

ENTRYPOINT ["./entrypoint.sh"]
