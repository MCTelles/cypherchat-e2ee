# CypherChat E2EE

Aplicação local de mensagens em tempo real com criptografia ponta a ponta,
autenticação JWT e auditoria de segurança.

> **Estado atual:** apenas a estrutura base (configuração, modelos de banco e
> API com `/` e `/health`). Autenticação, E2EE, mensagens e auditoria ainda
> não foram implementadas.

## Pré-requisitos

- Python 3.14 (ver `.python-version`)
- [uv](https://docs.astral.sh/uv/) como gerenciador de dependências
- PostgreSQL local (12+), com um banco e um usuário de desenvolvimento

## Preparação do ambiente

```bash
uv sync --frozen
```

Cria o ambiente virtual `.venv` e instala as dependências travadas em `uv.lock`.

## Variáveis de ambiente

```bash
cp .env.example .env
```

Edite o `.env` (ele é ignorado pelo git):

| Variável | Descrição |
|---|---|
| `DATABASE_URL` | `postgresql+psycopg://USUARIO:SENHA@127.0.0.1:5432/NOME_DO_BANCO` |
| `JWT_SECRET_KEY` | Segredo longo e aleatório. Gere com `python3 -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `APP_ENV` | `development`, `test` ou `production` (em `development` o SQL é logado) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Validade do token (padrão 30) |

`DATABASE_URL` e `JWT_SECRET_KEY` são obrigatórios; a aplicação não inicia sem eles.

## Preparação do banco

Crie antes o banco e o usuário no PostgreSQL. Depois:

```bash
uv run init-db
```

Cria as tabelas `users`, `public_keys`, `encrypted_messages` e `audit_logs`
(`create_all`; é idempotente e não altera tabelas existentes). Migrações com
Alembic ainda não estão configuradas.

## Iniciar a API

```bash
uv run seguranca-auditoria
```

Sobe em `http://127.0.0.1:8000`. Alternativa com recarga automática:

```bash
uv run fastapi dev src/seguranca_auditoria/main.py
```

## Conferir o funcionamento

```bash
curl http://127.0.0.1:8000/          # {"Hello":"World"}
curl http://127.0.0.1:8000/health    # {"status":"ok"}
```

A documentação interativa fica em `http://127.0.0.1:8000/docs`.

Atenção: `/health` **não** verifica o banco; ele só indica que o processo da
API está no ar. Para checar o banco, rode `uv run init-db` (falha se não
conseguir conectar).
