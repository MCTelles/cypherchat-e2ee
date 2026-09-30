"""One-time local admin creation; never exposed as an HTTP endpoint."""

import getpass

from sqlmodel import Session, select

from seguranca_auditoria.audit import record
from seguranca_auditoria.database import get_engine
from seguranca_auditoria.models import AuditResult, User, UserRole
from seguranca_auditoria.security.auth import hash_password


def main():
    username = input("Nome do administrador: ").strip()
    email = input("Email do administrador: ").strip().lower()
    password = getpass.getpass("Senha (mínimo 12 caracteres): ")
    if not 3 <= len(username) <= 32 or not username.replace("_", "").isalnum() or len(password) < 12:
        raise SystemExit("Usuário ou senha inválidos")
    with Session(get_engine()) as session:
        if session.exec(select(User).where(User.role == UserRole.ADMIN)).first():
            raise SystemExit("Já existe um administrador. Use a API administrativa para promover usuários")
        if session.exec(select(User).where(User.username == username)).first():
            raise SystemExit("Usuário já existe")
        admin = User(username=username, email=email, password_hash=hash_password(password),
                     role=UserRole.ADMIN)
        session.add(admin)
        session.flush()
        record(session, who=admin.id, what="user.create", where="local_cli", why="admin_bootstrap",
               result=AuditResult.SUCCESS, resource_type="user", resource_id=str(admin.id))
        session.commit()
    print("Administrador criado")


if __name__ == "__main__":
    main()
