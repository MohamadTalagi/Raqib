from fastapi import FastAPI

app = FastAPI(title="auditor-api")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
