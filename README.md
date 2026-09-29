# CypherChat E2EE

Aplicação local de mensagens em tempo real com criptografia ponta a ponta,
autenticação JWT e auditoria de segurança.

> **Estado atual:** estrutura base, autenticação (cadastro, login e JWT) e
> gestão de chaves públicas X25519 e um módulo de cifragem de mensagens no
> cliente (apenas local: ainda não há API de mensagens, persistência, WebSocket
> ou auditoria). Não é um sistema pronto para produção.

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

## Criptografia de mensagens (cliente)

Módulo `seguranca_auditoria.client`, executado **no cliente**. Não depende de
FastAPI, banco, JWT nem da configuração do servidor (há um teste que verifica
isso). Nesta etapa nada é enviado nem guardado pelo servidor, e não existe
endpoint que receba chaves privadas ou texto original.

### Protocolo

HPKE ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)), **modo Auth**,
`DHKEM(X25519, HKDF-SHA256)` (0x0020), `HKDF-SHA256` (0x0001) e `AES-128-GCM`
(0x0001), pela biblioteca [PyHPKE](https://github.com/dajiaji/pyhpke) 0.6.5
(licença MIT, exige `cryptography>=42.0.1,<52` e Python >= 3.10, compatível com
o `cryptography` 50.x do projeto; passou nos vetores oficiais da RFC 9180 em
seus próprios testes, e o projeto informa que **não teve auditoria formal**).
O KEM, a derivação de chaves e os nonces são da biblioteca; este código só a usa.

- Cada mensagem cria uma **nova encapsulação** (`enc`) e um **novo contexto**
  HPKE, com **uma única** cifragem. Por isso não existe campo `nonce` externo.
- `info` = `CypherChat E2EE v1`.
- **AAD** = JSON determinístico dos metadados (`version`, `mode`, `suite`,
  `message_id`, `sender`, `recipient`; chaves ordenadas, sem espaços, ASCII).
- A remetente usa a **chave privada dela** e a **chave pública verificada** do
  destinatário. O destinatário usa a **chave privada dele** e a **chave pública
  verificada** do remetente.

### Envelope (versão 1)

```json
{
  "version": 1,
  "mode": "auth",
  "suite": "HPKE-Auth-X25519-SHA256-AES128GCM",
  "message_id": "<uuid>",
  "sender":    {"user_id": "<uuid>", "key_id": "<uuid>", "fingerprint": "<sha256 hex>"},
  "recipient": {"user_id": "<uuid>", "key_id": "<uuid>", "fingerprint": "<sha256 hex>"},
  "enc": "<base64 de 32 bytes>",
  "ciphertext": "<base64 do texto cifrado + tag GCM de 16 bytes>"
}
```

Base64 padrão canônico (com `=`). UUIDs em minúsculas com hífens. O `key_id` é o
`id` devolvido por `/keys`. **O envelope não contém chaves públicas**: o
cliente só usa chaves que ele mesmo confia (`TrustedKey`, que confere o
fingerprint contra os bytes da chave).

**Limites:** mensagem de 1 a 65.536 bytes em UTF-8 (`MAX_PLAINTEXT_BYTES`);
envelope de até 131.072 bytes (`MAX_ENVELOPE_BYTES`). Campos desconhecidos,
ausentes ou duplicados, Base64 não canônico, UUIDs mal formados, JSON com
`NaN`/aninhamento excessivo e tamanhos incorretos são rejeitados (`EnvelopeError`).
Versão, modo ou suíte diferentes dos acima são rejeitados sem *fallback*.

### API

```python
from seguranca_auditoria.client import TrustedKey, encrypt_message, decrypt_message

envelope = encrypt_message("texto", sender_private_key=..., sender=eu, recipient=ele)
envelope.to_json()  # string para enviar

resultado = decrypt_message(json_recebido, recipient_private_key=..., recipient=eu, sender=remetente_esperado)
resultado.plaintext, resultado.message_id
```

Na decifragem, remetente e destinatário do envelope são **comparados** com os
que o cliente espera (`ParticipantMismatchError` se diferirem); os valores do
envelope não provam identidade. Falhas de autenticação ou de decifragem levantam
`DecryptionError` com mensagem fixa e nenhum conteúdo parcial. O módulo não
registra plaintext, chaves nem segredos e usa apenas a aleatoriedade da biblioteca.

### Demonstração local

```bash
uv run python examples/e2ee_demo.py             # chaves temporárias
uv run python examples/e2ee_demo.py ./chaves    # grava/reusa chaves/alice.key e bob.key
```

Gera ou carrega duas chaves (arquivos 0600, nunca sobrescritos; arquivos legíveis
por outros usuários são recusados), cifra uma mensagem fictícia, mostra o
envelope, decifra como destinatário e demonstra a rejeição de um envelope adulterado.
Não coloque chaves privadas reais em repositórios.

### Mapeamento para o modelo `encrypted_messages` (sem alterar o banco agora)

| Envelope | Coluna |
|---|---|
| `message_id` | `id` |
| `sender.user_id` / `recipient.user_id` | `sender_id` / `recipient_id` |
| `ciphertext` (bytes) | `ciphertext` |
| `enc` (bytes) | `ephemeral_public_key` |
| `suite` (33 caracteres) | `algorithm` (limite de 50) |
| (não existe: o HPKE gerencia o nonce) | `nonce`, hoje `NOT NULL` |

Pendências para a etapa de mensagens: tornar `nonce` opcional (ou gravar valor
vazio de forma explícita), e guardar `version`, `mode`, os `key_id` e os
fingerprints, necessários para reconstruir o AAD (novas colunas ou o envelope
JSON completo). Isso exigirá uma atualização de esquema versionada.

### Limitações (leia antes de confiar)

- **A confiança depende da verificação das chaves públicas.** Se o cliente
  aceitar uma chave trocada pelo servidor, a proteção acaba. Compare
  fingerprints por outro canal.
- **HPKE Auth não é uma assinatura digital pública.** Só o destinatário
  consegue verificar o remetente, e ele próprio poderia forjar uma mensagem
  "vinda" do remetente para si mesmo: não há não repúdio perante terceiros.
- **Sem sigilo futuro em relação às chaves estáticas.** Se a chave privada do
  destinatário for comprometida, mensagens anteriores guardadas podem ser
  decifradas (e a do remetente permite forjar mensagens a esse destinatário).
- **Metadados visíveis:** `message_id`, identificadores de usuários e chaves,
  fingerprints, versão, modo, suíte e **tamanhos** aparecem no envelope.
- **Replay:** um envelope válido pode ser reapresentado. É preciso controle
  adicional, como registro de `message_id` já recebidos.
- **Chaves antigas:** para ler mensagens antigas o cliente precisa manter as
  chaves privadas antigas (revogar uma chave não descarta o segredo).
- **Leitura pelo próprio remetente:** a mensagem só é decifrável pelo
  destinatário; guardar uma cópia legível para quem enviou exige solução
  específica (por exemplo, cifrar uma segunda cópia para a própria chave).
- Não há ordem de mensagens, sessões ou *ratchet*. **Isto não equivale ao
  Signal** nem oferece proteção completa para produção; não houve auditoria.

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
