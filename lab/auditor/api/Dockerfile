FROM python:3.12-slim
WORKDIR /app

# WeasyPrint 63.1 renders via pango + harfbuzz (pydyf/Pillow replaced the old
# cairo/gdk-pixbuf pipeline in WeasyPrint 53+). Package list matches what
# WeasyPrint's own docs specify for Debian/python:3.12-slim.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz-subset0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
