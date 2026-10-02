# CypherChat E2EE

Aplicação local de mensagens em tempo real para a G1. A interface é um cliente de terminal; o servidor FastAPI distribui chaves públicas e roteia envelopes cifrados por WebSocket. As chaves privadas são geradas e protegidas **no cliente** e nunca são enviadas ao servidor.

## Como funciona

1. O cliente gera uma chave X25519 para receber mensagens e uma chave Ed25519 para assinar mensagens. As duas chaves privadas são cifradas com AES-GCM e uma chave derivada da senha local por scrypt antes de serem salvas em `~/.cypherchat/` com permissões `0600`.
2. No cadastro, o servidor armazena apenas as duas chaves públicas, o fingerprint SHA-256 e o hash Argon2 da senha da conta.
3. O remetente consulta a chave pública do destinatário. Na primeira conversa, deve comparar o fingerprint por um **canal independente** e confirmar. O cliente fixa esse fingerprint e recusa mudanças posteriores.
4. Para cada mensagem, o remetente gera uma chave X25519 efêmera, deriva uma chave AES-256-GCM com HKDF e cifra o texto. O envelope inclui nonce, chave efêmera pública e assinatura Ed25519. O servidor verifica a assinatura e só armazena/roteia texto cifrado.
5. O destinatário compara a chave de assinatura com o fingerprint fixado, verifica a assinatura, deriva a mesma chave AES e decifra localmente. Ele confirma a entrega ao servidor.

Os identificadores de remetente/destinatário entram na assinatura e nos dados autenticados do AES-GCM. O servidor ainda vê **metadados** (usuários, horários, tamanho do texto cifrado). O primeiro contato depende da comparação do fingerprint fora da aplicação. O esquema usa chave efêmera do remetente, mas **não oferece sigilo retroativo completo** se a chave privada do destinatário for comprometida. Não é um protocolo auditado para uso em produção.

## Experimento HPKE

O projeto também contém um módulo cliente separado em `seguranca_auditoria.client` que implementa HPKE Auth (RFC 9180) com PyHPKE. Ele gera um envelope diferente do chat acima e inclui testes com vetores da RFC, adulteração e limites de entrada. Execute uma demonstração local sem servidor ou banco:

```sh
uv run python examples/e2ee_demo.py
```

O comando `cypherchat` usa `seguranca_auditoria.terminal_client` e o protocolo X25519/AES-GCM/Ed25519 descrito acima. **O WebSocket não aceita envelopes HPKE.** A integração exigiria uma versão de mensagem, mudanças no banco e no cliente. O experimento HPKE não substitui o fluxo da demonstração da G1. A revogação e troca de chaves públicas também precisam ser adaptadas ao par de chaves de criptografia e assinatura do chat antes de entrarem na API ativa.

## Execução local

### Windows: PostgreSQL isolado do projeto

O procedimento está em [deploy/README-windows.md](deploy/README-windows.md).
Ele cria `.env`, banco, tabelas e permissões automaticamente, com credenciais
aleatórias, usando os mesmos scripts SQL abaixo. A aplicação conecta como
`cypherchat_app`; a senha do proprietário não fica no `.env`.

### Configuração manual

Requer Python 3.14, `uv` e PostgreSQL. O caminho mais rápido para testes automatizados usa SQLite isolado; a instalação de demonstração deve usar PostgreSQL para cumprir os requisitos de roles e conexão local.

```sh
uv sync
# macOS/Homebrew: substitua pelo superusuário local se for diferente
psql -U "$(whoami)" -d postgres -f deploy/postgres-setup.sql
```

Configure PostgreSQL de acordo com [`deploy/postgres-local.conf.example`](deploy/postgres-local.conf.example) e [`deploy/pg_hba-local.conf.example`](deploy/pg_hba-local.conf.example): `listen_addresses = 'localhost'`, autenticação SCRAM e regras que só aceitam loopback. Verifique que não há regra mais ampla antes delas. O banco fica no mesmo computador do servidor FastAPI.

Crie `.env` a partir de `.env.example` e aplique `chmod 600 .env`, pois o arquivo contém a senha do banco e o segredo JWT. Para a etapa única de criação de tabelas, use a conexão de `cypherchat_owner` em `DATABASE_URL`. Em seguida, aplique as permissões por tabela com `postgres-grants.sql`, troque a URL para `cypherchat_app` e inicie o servidor. `init-db` prepara um banco novo; não migra tabelas antigas. Gere o segredo JWT com `python -c 'import secrets; print(secrets.token_urlsafe(48))'`.

```sh
uv run init-db
psql -h 127.0.0.1 -U cypherchat_owner -d cypherchat -f deploy/postgres-grants.sql
# Edite DATABASE_URL em .env para usar cypherchat_app antes dos comandos abaixo
uv run bootstrap-admin
uv run uvicorn seguranca_auditoria.main:app --host 127.0.0.1 --port 8000 --ws-max-size 24000 --ws-max-queue 16 --limit-concurrency 100
```

O comando `bootstrap-admin` cria a primeira conta administrativa somente no terminal local. Cadastro público só cria contas com role `user`. Para demonstrar o fluxo, abra dois outros terminais:

```sh
uv run cypherchat register alice alice@example.local
uv run cypherchat register bob bob@example.local
uv run cypherchat chat alice bob
uv run cypherchat chat bob alice
```

Cada lado deve informar a senha da conta e a senha da chave local. Antes do primeiro chat, confira os fingerprints impressos com a outra pessoa por um canal independente e digite `SIM`. O cliente mostra cada mensagem decifrada apenas no terminal de destino. Use `/quit` para sair. O servidor conserva até 100 mensagens cifradas pendentes por destinatário durante sete dias e as entrega quando ele se conecta. Após a confirmação, remove o ciphertext e mantém o evento de auditoria.

Para consultar a API administrativa, obtenha um token em `POST /auth/token` com o administrador e use `Authorization: Bearer <token>` nos endpoints `/admin/users` e `/admin/audit`. A documentação interativa fica em `/docs`.

Antes da apresentação, use `GET /ready` para verificar a conexão com o banco. O [roteiro de demonstração](presentation/ROTEIRO.md) traz a sequência dos terminais e o tempo previsto por slide.

## Controles de segurança

| Requisito | Implementação |
| --- | --- |
| Autenticação/autorização | Argon2 para senhas, JWT HS256 com expiração de 30 minutos; checagem de usuário ativo e role em cada requisição e mensagem WebSocket |
| Menor privilégio no banco | `cypherchat_owner` cria tabelas; `cypherchat_app` recebe apenas as operações necessárias por tabela, sem UPDATE/DELETE nos logs de auditoria; PostgreSQL em loopback |
| Auditoria 5W | Tabela `audit_logs` e log JSON com `when`, `who`, `what`, `where`, `why`, resultado e recurso; cadastro, login, atualização, remoção lógica, conexão e envio |
| BOLA | O remetente vem do JWT, não do payload; confirmação de entrega só pelo destinatário; consultas de chave exigem autenticação |
| Mass assignment | Modelos Pydantic com `extra="forbid"`; cadastro não aceita role e atualização de usuário não aceita role/estado |
| Injeção | SQLModel/SQLAlchemy geram consultas parametrizadas; limites, tipos e formatos de entrada são validados |
| Exaustão | Rate limit por IP/conta, limite por usuário e global de WebSockets, timeout de autenticação, tamanho máximo de mensagem, fila limitada, expiração de pendências, remoção após entrega, pool de banco limitado e flags do Uvicorn |
| Exceções | Erros 401/403/404/409/422/429 claros; erro de validação não ecoa entradas sensíveis |

Os limitadores de requisições são em memória e foram feitos para **um processo local**. Execute o Uvicorn com um worker. Para exposição em LAN, proteja HTTP/WebSocket com TLS e use firewall; sem TLS, senhas e JWT trafegariam em claro mesmo que o texto das mensagens seja E2EE.

## Testes

```sh
uv run pytest -q
```

Os testes exercitam criptografia do chat, adulteração, isolamento de roles, mass assignment, envio/recepção por WebSocket e restrição de confirmação ao destinatário. O módulo HPKE tem testes próprios, incluindo vetores da RFC 9180.

## Demonstração de 5–10 minutos

1. Mostrar o diagrama do fluxo e explicar por que o servidor só vê o envelope cifrado.
2. Criar Alice e Bob; mostrar fingerprints e confirmar chaves.
3. Abrir dois terminais de chat, enviar e receber uma mensagem; apontar que o banco registra ciphertext, nonce e chave efêmera, sem chave privada.
4. Tentar acessar `/admin/users` com token de usuário e mostrar 403; mostrar um evento de auditoria 5W com token administrativo.
5. Explicar os limites do protótipo: metadados expostos, confiança inicial no fingerprint e falta de sigilo retroativo completo.
