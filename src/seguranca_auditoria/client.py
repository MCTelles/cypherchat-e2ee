"""Terminal client. All encryption and decryption happens here."""

import argparse
import asyncio
import getpass
import json
import os
from pathlib import Path
from uuid import UUID

import httpx
import websockets

from seguranca_auditoria.security.e2ee import (
    ALGORITHM, Identity, b64, decrypt, encrypt, fingerprint, unb64,
)


def storage_dir() -> Path:
    path = Path(os.environ.get("CYPHERCHAT_DATA_DIR", Path.home() / ".cypherchat"))
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def key_path(username: str) -> Path:
    if not username.isidentifier():
        raise ValueError("Nome de usuário inválido")
    return storage_dir() / f"{username}.key"


def write_private_key(path: Path, identity: Identity, password: str):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(identity.protect(password))
    except Exception:
        path.unlink(missing_ok=True)
        raise


def load_private_key(username: str) -> Identity:
    password = getpass.getpass("Senha da chave local: ")
    return Identity.unprotect(key_path(username).read_bytes(), password)


def known_keys_path() -> Path:
    return storage_dir() / "known_keys.json"


def read_known_keys() -> dict[str, str]:
    path = known_keys_path()
    return json.loads(path.read_text()) if path.exists() else {}


def checked_public_keys(contact: dict) -> tuple[bytes, bytes]:
    """Never trust a fingerprint supplied alongside the key by the directory."""
    try:
        encryption = unb64(contact["public_key"])
        signing = unb64(contact["signing_public_key"])
        claimed = contact["fingerprint"]
        algorithm = contact["algorithm"]
    except (KeyError, ValueError, TypeError) as exc:
        raise RuntimeError("Resposta de chave inválida") from exc
    if (len(encryption) != 32 or len(signing) != 32 or algorithm != ALGORITHM
            or fingerprint(encryption, signing) != claimed):
        raise RuntimeError("A chave recebida não corresponde ao fingerprint anunciado")
    return encryption, signing


def trust_key(contact: dict, known: dict[str, str]):
    checked_public_keys(contact)
    identifier = contact["id"]
    current = known.get(identifier)
    if current and current != contact["fingerprint"]:
        raise RuntimeError(f"ALERTA: a chave de {contact['username']} mudou. Não envie mensagens.")
    if current:
        return
    print(f"Fingerprint de {contact['username']}: {contact['fingerprint']}")
    print("Confira este fingerprint por outro canal com a pessoa antes de confiar.")
    if input("Confirmado por outro canal? Digite SIM: ").strip() != "SIM":
        raise RuntimeError("Chave não confirmada")
    known[identifier] = contact["fingerprint"]
    path = known_keys_path()
    temporary = path.with_suffix(".tmp")
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as file:
        json.dump(known, file)
    temporary.replace(path)


def login(client: httpx.Client, username: str) -> str:
    password = getpass.getpass("Senha da conta: ")
    response = client.post("/auth/token", json={"username": username, "password": password})
    response.raise_for_status()
    return response.json()["access_token"]


def register(client: httpx.Client, username: str, email: str):
    path = key_path(username)
    if path.exists():
        raise RuntimeError("Já existe uma chave local para este usuário")
    account_password = getpass.getpass("Senha da conta (mínimo 12 caracteres): ")
    local_password = getpass.getpass("Senha para cifrar a chave local (mínimo 12 caracteres): ")
    identity = Identity.generate()
    write_private_key(path, identity, local_password)
    try:
        response = client.post("/auth/register", json={
            "username": username, "email": email, "password": account_password,
            "public_key": b64(identity.public_key),
            "signing_public_key": b64(identity.signing_public_key),
        })
        response.raise_for_status()
    except Exception:
        path.unlink(missing_ok=True)
        raise
    print(f"Conta criada. Seu fingerprint: {identity.fingerprint}")


async def chat(base_url: str, username: str, contact_name: str):
    with httpx.Client(base_url=base_url, timeout=10) as client:
        token = login(client, username)
        headers = {"Authorization": f"Bearer {token}"}
        me_response = client.get("/me", headers=headers)
        me_response.raise_for_status()
        me = me_response.json()
        key_response = client.get(f"/users/{me['id']}/key", headers=headers)
        key_response.raise_for_status()
        identity = load_private_key(username)
        own_encryption, own_signing = checked_public_keys(key_response.json())
        if (own_encryption != identity.public_key or own_signing != identity.signing_public_key):
            raise RuntimeError("A chave local difere da chave publicada no servidor")
        response = client.get("/users", headers=headers)
        response.raise_for_status()
        contact = next((item for item in response.json() if item["username"] == contact_name), None)
        if contact is None:
            raise RuntimeError("Contato não encontrado")
        known = read_known_keys()
        trust_key(contact, known)

    ws_url = base_url.replace("http://", "ws://", 1).replace("https://", "wss://", 1).rstrip("/") + "/ws"
    async with websockets.connect(ws_url, max_size=24000) as socket:
        await socket.send(json.dumps({"type": "auth", "token": token}))
        ready = json.loads(await socket.recv())
        if ready.get("type") != "ready":
            raise RuntimeError("WebSocket não autenticado")
        print(f"Conectado. Escreva para {contact_name}; /quit para sair.")

        async def receive():
            async with httpx.AsyncClient(base_url=base_url, timeout=10) as client:
                async for raw in socket:
                    event = json.loads(raw)
                    if event.get("type") == "message":
                        sender_id = event["sender_id"]
                        if sender_id not in known:
                            print(f"\nMensagem de chave não confirmada ({sender_id}); confirme-a antes de receber.")
                            continue
                        key_response = await client.get(f"/users/{sender_id}/key", headers=headers)
                        if key_response.status_code != 200:
                            print("\nNão foi possível obter a chave do remetente.")
                            continue
                        sender_key = key_response.json()
                        try:
                            _, sender_signing = checked_public_keys(sender_key)
                        except RuntimeError:
                            print("\nALERTA: resposta de chave inconsistente. Mensagem ignorada.")
                            continue
                        if sender_key["fingerprint"] != known[sender_id]:
                            print("\nALERTA: chave do remetente alterada. Mensagem ignorada.")
                            continue
                        try:
                            plaintext = decrypt(identity, sender_signing, event)
                        except Exception:
                            print("\nMensagem adulterada ou impossível de decifrar.")
                            continue
                        print(f"\n{sender_key['username']}: {plaintext}")
                        await socket.send(json.dumps({"type": "ack", "id": event["id"]}))
                    elif event.get("type") == "error":
                        print(f"\nErro: {event['detail']}")

        task = asyncio.create_task(receive())
        try:
            while not task.done():
                message = await asyncio.to_thread(input, "> ")
                if message.strip() == "/quit":
                    break
                if not message or len(message.encode()) > 8000:
                    print("Mensagem vazia ou longa demais")
                    continue
                recipient_encryption, _ = checked_public_keys(contact)
                envelope = encrypt(identity, recipient_encryption,
                                   UUID(me["id"]), UUID(contact["id"]), message)
                await socket.send(json.dumps({"type": "send", **{k: v for k, v in envelope.items() if k != "sender_id"}}))
        finally:
            task.cancel()


def main():
    parser = argparse.ArgumentParser(description="CypherChat E2EE terminal")
    parser.add_argument("--url", default=os.environ.get("CYPHERCHAT_URL", "http://127.0.0.1:8000"))
    commands = parser.add_subparsers(dest="command", required=True)
    register_cmd = commands.add_parser("register")
    register_cmd.add_argument("username")
    register_cmd.add_argument("email")
    chat_cmd = commands.add_parser("chat")
    chat_cmd.add_argument("username")
    chat_cmd.add_argument("contact")
    args = parser.parse_args()
    try:
        if args.command == "register":
            with httpx.Client(base_url=args.url, timeout=10) as client:
                register(client, args.username, args.email)
        else:
            asyncio.run(chat(args.url, args.username, args.contact))
    except (httpx.HTTPStatusError, httpx.ConnectError, RuntimeError, ValueError, OSError) as exc:
        print(f"Erro: {exc}")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
