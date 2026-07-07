#!/bin/sh
set -e

if [ "$TRANSPORT" = "https" ]; then
  exec uvicorn app.main:app --host 0.0.0.0 --port 443 \
    --ssl-keyfile "$TLS_KEYFILE" --ssl-certfile "$TLS_CERTFILE"
else
  exec uvicorn app.main:app --host 0.0.0.0 --port 80
fi
