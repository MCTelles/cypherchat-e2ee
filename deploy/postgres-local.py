"""Manage an isolated development PostgreSQL cluster on Windows.

Run from the project root using .venv/Scripts/python.exe.
Download EDB binaries into .local/pgsql before the first setup.
"""

import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
DATA = LOCAL / "pgdata"
ENV_FILE = ROOT / ".env"
CREDENTIALS = LOCAL / "postgres-credentials.json"


def restrict(path):
    if os.name == "nt":
        sid = subprocess.check_output(
            ["whoami", "/user", "/fo", "csv", "/nh"], text=True
        ).strip().split(",")[-1].strip('"')
        rights = "(OI)(CI)F" if path.is_dir() else "F"
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:{rights}"],
            check=True, stdout=subprocess.DEVNULL,
        )
    else:
        path.chmod(0o700 if path.is_dir() else 0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["setup", "start", "stop", "status", "verify"])
    parser.add_argument("--bin", type=Path, default=LOCAL / "pgsql" / "bin")
    args = parser.parse_args()
    os.chdir(ROOT)
    binary = args.bin.resolve()

    def run(name, *arguments, **kwargs):
        return subprocess.run(
            [str(binary / (name + (".exe" if os.name == "nt" else ""))), *map(str, arguments)],
            check=True, text=True, **kwargs,
        )

    def start():
        state = subprocess.run(
            [str(binary / "pg_ctl"), "-D", str(DATA), "status"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if state.returncode != 0:
            run("pg_ctl", "-D", DATA, "-l", LOCAL / "postgres.log", "-w", "start")

    if args.action in {"start", "stop", "status"}:
        if not (DATA / "PG_VERSION").exists():
            raise SystemExit("Run setup first.")
        if args.action == "start":
            start()
        else:
            run("pg_ctl", "-D", DATA, *(["-m", "fast", "-w"] if args.action == "stop" else []), args.action)
        return

    if args.action == "setup":
        if ENV_FILE.exists() or DATA.exists() or CREDENTIALS.exists():
            raise SystemExit("Existing configuration preserved. Use start/verify; setup requires a new cluster and no .env.")
        if not (binary / "initdb.exe").exists():
            raise SystemExit("Extract PostgreSQL Windows binaries to .local/pgsql first, or pass --bin.")
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", 5432)) == 0:
                raise SystemExit("Port 5432 is occupied; existing server was not modified.")
        LOCAL.mkdir(exist_ok=True)
        restrict(LOCAL)
        credentials = {role: secrets.token_urlsafe(48) for role in ("postgres", "cypherchat_owner", "cypherchat_app")}
        CREDENTIALS.write_text(json.dumps(credentials, indent=2), encoding="utf-8")
        restrict(CREDENTIALS)
        password_file = LOCAL / "initdb-password"
        password_file.write_text(credentials["postgres"], encoding="utf-8")
        try:
            run("initdb", "-D", DATA, "-U", "postgres", "--encoding=UTF8", "--locale=C",
                "--auth=scram-sha-256", f"--pwfile={password_file}")
        finally:
            password_file.unlink(missing_ok=True)
        with (DATA / "postgresql.conf").open("a", encoding="utf-8") as config:
            config.write("\n" + (ROOT / "deploy/postgres-local.conf.example").read_text() + "\nport = 5432\n")
        hba = (ROOT / "deploy/pg_hba-local.conf.example").read_text()
        hba += "\nhost all postgres 127.0.0.1/32 scram-sha-256\nhost all postgres ::1/128 scram-sha-256\n"
        (DATA / "pg_hba.conf").write_text(hba, encoding="utf-8")
        start()

        def psql(role, database, sql):
            environment = dict(os.environ, PGPASSWORD=credentials[role])
            run("psql", "-X", "-h", "127.0.0.1", "-p", "5432", "-U", role,
                "-d", database, "-v", "ON_ERROR_STOP=1", input=sql, env=environment)

        setup = (ROOT / "deploy/postgres-setup.sql").read_text()
        for role in ("cypherchat_owner", "cypherchat_app"):
            setup = setup.replace(f"\\password {role}", f"ALTER ROLE {role} PASSWORD '{credentials[role]}';")
        psql("postgres", "postgres", setup)
        jwt_secret = secrets.token_urlsafe(48)
        from sqlalchemy import create_engine
        from sqlmodel import SQLModel
        import seguranca_auditoria.models  # noqa: F401

        owner = create_engine(f"postgresql+psycopg://cypherchat_owner:{credentials['cypherchat_owner']}@127.0.0.1:5432/cypherchat")
        try:
            SQLModel.metadata.create_all(owner)
        finally:
            owner.dispose()
        psql("cypherchat_owner", "cypherchat", (ROOT / "deploy/postgres-grants.sql").read_text())
        template = (ROOT / ".env.example").read_text(encoding="utf-8")
        template = template.replace("SENHA_DA_APLICACAO", credentials["cypherchat_app"])
        template = template.replace("SUBSTITUA_POR_UM_SEGREDO_ALEATORIO_DE_32_BYTES_OU_MAIS", jwt_secret)
        # Secure the empty file before writing any secrets.
        ENV_FILE.touch(exist_ok=False)
        restrict(ENV_FILE)
        ENV_FILE.write_text(template, encoding="utf-8")
    verify()


def verify():
    from sqlalchemy import create_engine, text
    from sqlalchemy.exc import ProgrammingError
    from seguranca_auditoria.config import Settings

    engine = create_engine(Settings().database_url)
    expected = {
        "users": {"SELECT", "INSERT", "UPDATE"},
        "public_keys": {"SELECT", "INSERT"},
        "encrypted_messages": {"SELECT", "INSERT", "UPDATE", "DELETE"},
        "audit_logs": {"SELECT", "INSERT"},
    }
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT current_user")) == "cypherchat_app"
        assert not connection.scalar(text("SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname = current_user"))
        assert not connection.scalar(text("SELECT has_schema_privilege(current_user, 'public', 'CREATE')"))
        for table, allowed in expected.items():
            for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
                actual = connection.scalar(text("SELECT has_table_privilege(current_user, :table, :privilege)"), {"table": table, "privilege": privilege})
                assert actual == (privilege in allowed), (table, privilege)
            connection.execute(text(f"SELECT 1 FROM {table} LIMIT 1"))
    for sql in ("DELETE FROM audit_logs WHERE false", "UPDATE audit_logs SET action = action WHERE false", "CREATE TABLE public.permission_probe (id integer)"):
        with engine.connect() as connection:
            try:
                connection.execute(text(sql))
            except ProgrammingError as exc:
                assert exc.orig.sqlstate == "42501"
            else:
                raise AssertionError("Application role has excessive privileges")
            finally:
                connection.rollback()
    engine.dispose()
    from fastapi.testclient import TestClient
    from seguranca_auditoria.main import app

    with TestClient(app) as client:
        response = client.get("/ready")
        assert response.status_code == 200 and response.json() == {"status": "ready"}
    print("OK: PostgreSQL at 127.0.0.1:5432, application role, table permissions and /ready.")


if __name__ == "__main__":
    main()
