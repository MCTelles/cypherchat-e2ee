def main() -> None:
    """Start the API locally with uvicorn (development defaults)."""
    import uvicorn

    uvicorn.run("seguranca_auditoria.main:app", host="127.0.0.1", port=8000)
