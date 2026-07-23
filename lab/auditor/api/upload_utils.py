from fastapi import HTTPException, UploadFile


async def read_capped(upload: UploadFile, max_bytes: int) -> bytes:
    """Read an upload in chunks, rejecting it the instant the real byte count
    exceeds max_bytes. Never trust Content-Length alone - it's a
    client-supplied header and can lie. Shared by main.py's firmware upload
    and nca_routes.py's compliance-document upload so the same defense isn't
    written twice."""
    chunks = []
    total = 0
    while True:
        chunk = await upload.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(status_code=413, detail=f"upload exceeds the {max_bytes // (1024 * 1024)}MB limit")
        chunks.append(chunk)
    return b"".join(chunks)
