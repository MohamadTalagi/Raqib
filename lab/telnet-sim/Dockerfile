FROM python:3.12-alpine
WORKDIR /app
COPY banner_server.py .
EXPOSE 23
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD nc -z 127.0.0.1 23 || exit 1
CMD ["python", "banner_server.py"]
