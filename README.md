# CypherChat E2EE

Aplicação local de mensagens em tempo real com criptografia ponta a ponta,
autenticação JWT e auditoria de segurança.

> **Estado atual:** estrutura base, autenticação (cadastro, login e JWT) e
> gestão de chaves públicas X25519. Cifragem de mensagens, mensagens,
> WebSocket e auditoria ainda não foram implementadas.

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
| `JWT_SECRET_KEY` | Segredo aleatório com **no mínimo 32 bytes**. Gere com `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`. Valores vazios, curtos ou de exemplo (como o do `.env.example`) impedem a API de iniciar. Não troque a cada execução: tokens antigos deixam de valer |
| `APP_ENV` | `development`, `test` ou `production` (em `development` o SQL é logado) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Validade do token (padrão 30) |

`DATABASE_URL` e `JWT_SECRET_KEY` são obrigatórios; a aplicação não inicia sem eles.

## Preparação do banco

Crie antes o banco e o usuário no PostgreSQL. Depois:

```bash
uv run init-db
```

Cria as tabelas `users`, `public_keys`, `encrypted_messages` e `audit_logs`
(`create_all`; é idempotente e **não altera tabelas existentes**). Migrações com
Alembic ainda não estão configuradas.

**Banco criado antes da gestão de chaves:** aplique as atualizações de esquema
de `sql/` (uma vez; são idempotentes e não apagam dados):

```bash
psql 'postgresql://USUARIO:SENHA@127.0.0.1:5432/NOME_DO_BANCO' -v ON_ERROR_STOP=1 \
  -f sql/0001_public_keys_one_active_per_user.sql
```

O `0001` cria o índice único parcial que garante uma chave ativa por usuário.
Falha, sem alterar nada, se algum usuário já tiver 2 ou mais chaves ativas
(a consulta de verificação está no cabeçalho do arquivo).

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

## Autenticação

Cadastro, login e perfil usam JSON. Tokens JWT (HS256) têm `sub` (UUID do
usuário), `iat` e `exp` (UTC), e expiram em `ACCESS_TOKEN_EXPIRE_MINUTES`.
Cada requisição protegida relê o usuário no banco (papel e `is_active`).

### `POST /auth/register` → 201

```json
{"username": "maria", "email": "maria@example.com", "password": "senha-ficticia-123"}
```

Regras:
- `username`: 3 a 50 caracteres (`a-z`, `0-9`, `.`, `_`, `-`), começando por letra ou dígito. É convertido para minúsculas.
- `email`: válido; convertido para minúsculas.
- `password`: 12 a 128 caracteres, não pode ser só espaços.
- Campos extras (`role`, `is_active`, `password_hash`...) são rejeitados com 422. Todo cadastro público cria um usuário comum (`user`).
- `username` ou `email` já usados: 409.

Resposta: `{"id", "username", "email", "role", "created_at"}` (nunca senha ou hash).

### `POST /auth/login` → 200

```json
{"username": "maria", "password": "senha-ficticia-123"}
```

Resposta: `{"access_token": "...", "token_type": "bearer"}`. Usuário inexistente,
senha incorreta ou usuário inativo retornam o mesmo 401 (`Invalid credentials`).

### `GET /auth/me` → 200

Requer `Authorization: Bearer <token>`. Retorna o perfil público. Token ausente,
inválido, adulterado, expirado ou de usuário removido/inativo: 401 com
`WWW-Authenticate: Bearer`.

### Exemplo com curl (credenciais fictícias)

```bash
curl -X POST http://127.0.0.1:8000/auth/register -H 'Content-Type: application/json' \
  -d '{"username":"maria","email":"maria@example.com","password":"senha-ficticia-123"}'

TOKEN=$(curl -s -X POST http://127.0.0.1:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"maria","password":"senha-ficticia-123"}' \
  | python3 -c 'import sys, json; print(json.load(sys.stdin)["access_token"])')

curl http://127.0.0.1:8000/auth/me -H "Authorization: Bearer $TOKEN"
```

## Chaves públicas (X25519)

Todas as rotas exigem `Authorization: Bearer <token>`.

**Algoritmo e representação:** X25519 (troca de chaves). A chave pública é
enviada como **Base64 padrão (RFC 4648, com `=`) dos 32 bytes brutos** (formato
Raw). São rejeitados: Base64 inválido ou não canônico, tamanho diferente de 32
bytes e pontos de ordem pequena. Isso valida apenas o **formato**; o servidor
não tem como provar que o cliente possui a chave privada. Chaves privadas
nunca devem ser enviadas, e a API não as aceita.

**Fingerprint:** `SHA-256` dos 32 bytes brutos, em hexadecimal minúsculo (64
caracteres), calculado no servidor.

> **Verifique o fingerprint por um canal confiável** (pessoalmente, por
> telefone, por outro meio já autenticado). A rota `GET /users/{id}/keys/active`
> entrega a chave que o *servidor* tem. Sem comparar o fingerprint fora da
> API, um servidor comprometido, ou uma conta invadida, poderia substituir a
> chave de alguém sem que ninguém perceba. O cadastro autenticado sozinho não
> resolve isso.

### `POST /keys`

```json
{"algorithm": "X25519", "public_key": "<base64 de 32 bytes>"}
```

Só esses dois campos são aceitos (`user_id`, `fingerprint`, `is_active`,
`revoked_at` etc. resultam em 422). A chave é vinculada ao usuário do token.

| Situação | Resposta |
|---|---|
| Chave nova, sem outra chave ativa | 201 com o registro |
| Mesma chave ativa do próprio usuário reenviada | 200, mesmo registro (idempotente) |
| Já existe outra chave ativa do usuário | 409: revogue antes |
| Chave que o próprio usuário já revogou | 409: gere um novo par; não há reativação |
| Chave já cadastrada por outro usuário | 409 |
| Formato, tamanho ou algoritmo inválido | 422 |

Resposta: `{"id", "algorithm", "public_key", "fingerprint", "is_active", "created_at", "revoked_at"}`.
A unicidade da chave ativa por usuário é garantida pelo banco (índice único
parcial), inclusive sob requisições concorrentes.

### `GET /keys/me`

Lista todas as chaves do usuário (ativas e revogadas, mais recentes primeiro),
com os mesmos campos acima.

### `GET /users/{user_id}/keys/active`

Retorna `{"id", "user_id", "algorithm", "public_key", "fingerprint", "created_at"}`
da chave ativa. Usuário inexistente, usuário inativo ou sem chave ativa dão o
mesmo `404` (`Active key not found`). `user_id` que não seja UUID dá 422.

### `POST /keys/{key_id}/revoke`

Sem corpo. Só o dono revoga: chave inexistente ou de outro usuário dão `404`
(`Key not found`). Marca `is_active=false` e `revoked_at` (UTC); o registro é
mantido. Repetir a chamada retorna 200 com o mesmo registro (o `revoked_at`
original é preservado).

### Exemplo local

O par é gerado no cliente; só a pública é enviada. O script grava a privada em
um arquivo com permissão 0600 (não sobrescreve arquivos existentes):

```bash
uv run python examples/generate_keypair.py minha_chave_privada.bin | tee /tmp/par.txt
PUB=$(sed -n 's/^public_key : //p' /tmp/par.txt)

curl -X POST http://127.0.0.1:8000/keys -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"algorithm\":\"X25519\",\"public_key\":\"$PUB\"}"

curl http://127.0.0.1:8000/keys/me -H "Authorization: Bearer $TOKEN"
curl -X POST http://127.0.0.1:8000/keys/ID_DA_CHAVE/revoke -H "Authorization: Bearer $TOKEN"
```

(`$TOKEN` vem do login, veja a seção Autenticação.) Escolher X25519 não define o
protocolo E2EE: cifragem, derivação de chaves e autenticação das mensagens
ficam para a próxima etapa.

## Testes

Os testes de banco precisam de um PostgreSQL **exclusivo para testes**. O
esquema desse banco é apagado e recriado, e o nome do banco precisa conter
`test`. Exemplo com um container descartável:

```bash
docker run -d --rm --name cypherchat-test-pg -e POSTGRES_USER=cypher \
  -e POSTGRES_PASSWORD=troque-esta-senha -e POSTGRES_DB=cypherchat_test \
  -p 127.0.0.1:55432:5432 postgres:16-alpine

export TEST_DATABASE_URL='postgresql+psycopg://cypher:troque-esta-senha@127.0.0.1:55432/cypherchat_test'
uv run pytest
docker stop cypherchat-test-pg
```

Sem `TEST_DATABASE_URL`, apenas os testes de configuração rodam e os de banco
são ignorados (skipped).
