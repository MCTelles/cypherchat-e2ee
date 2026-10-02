# PostgreSQL local no Windows

Execute os comandos na raiz `cypherchat-e2ee`, em PowerShell.
Requer Python e os binários Windows do PostgreSQL. Nesta instalação foram
utilizados Python 3.14 e PostgreSQL 17.11, com uma instância exclusiva do projeto.

## Preparar uma instalação nova

```powershell
py -m pip install uv
py -m uv sync
New-Item -ItemType Directory -Force .local
curl.exe -fL --retry 2 https://get.enterprisedb.com/postgresql/postgresql-17.11-3-windows-x64-binaries.zip -o .local/postgresql.zip
Expand-Archive .local/postgresql.zip -DestinationPath .local
.venv\Scripts\python.exe deploy/postgres-local.py setup
```

Os binários são distribuídos pela [EDB](https://www.enterprisedb.com/download-postgresql-binaries),
indicada pela [página de downloads do PostgreSQL](https://www.postgresql.org/download/windows/).
Também é possível usar binários já instalados com `--bin 'C:\caminho\bin'`.

O setup recusa sobrescrever `.env`, credenciais ou cluster existentes e recusa
usar uma porta 5432 já ocupada. Executa `postgres-setup.sql`, cria as tabelas
como `cypherchat_owner` e aplica `postgres-grants.sql`. Não é uma ferramenta de
migração de bancos existentes. Se houver falha parcial, preserve os arquivos e
investigue o log; repetir setup não apaga nem reinicializa dados.

## Uso diário

```powershell
.venv\Scripts\python.exe deploy/postgres-local.py start
.venv\Scripts\python.exe deploy/postgres-local.py verify
.venv\Scripts\uvicorn.exe seguranca_auditoria.main:app --host 127.0.0.1 --port 8000 --ws-max-size 24000 --ws-max-queue 16 --limit-concurrency 100
```

Em outro terminal: `Invoke-RestMethod http://127.0.0.1:8000/ready`.
Para criar a primeira conta administrativa, execute `.venv\Scripts\bootstrap-admin.exe`
e informe seus dados no terminal.

```powershell
.venv\Scripts\python.exe deploy/postgres-local.py status
.venv\Scripts\python.exe deploy/postgres-local.py stop
```

O banco roda como processo do usuário, sem serviço do Windows e sem início
automático após reiniciar o computador. Execute `start` novamente quando necessário.
O comando `verify` confere conexão, permissões por tabela, bloqueio de DDL e de
UPDATE/DELETE na auditoria, e chama `/ready` usando o cliente de teste da API.
Não cria registros de demonstração.

## Arquivos locais

- `.env`: configuração da API com senha de `cypherchat_app` e segredo JWT aleatório.
- `.local/postgres-credentials.json`: senhas administrativas e da aplicação;
  use somente para manutenção local.
- `.local/pgdata`: cluster PostgreSQL; não apague esta pasta para reiniciar o servidor.
- `.local/postgres.log`: log do servidor.
- `.local/pgsql`: binários PostgreSQL.

`.env` e `.local/` são ignorados pelo Git. O setup restringe as ACLs ao usuário
atual do Windows. A autenticação usa SCRAM-SHA-256 e o PostgreSQL escuta apenas
em loopback. A role da aplicação não cria tabelas, roles nem bancos e pode
apenas inserir/consultar registros de auditoria.

## Testes

```powershell
.venv\Scripts\python.exe -m pytest -q
```

Os testes existentes usam SQLite isolado. As chaves privadas do experimento
HPKE usam permissões POSIX `0600` em Unix e ACLs restritas ao usuário atual
no Windows. Os testes verificam leitura, proteção contra sobrescrita e rejeição
de acesso por outros usuários. Use `verify` para conferir as permissões reais
do banco configurado.
