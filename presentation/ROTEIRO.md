# Roteiro da apresentação — 02/10/2026

Tempo previsto: **7 a 8 minutos**. Use os seis slides de `output/CypherChat_G1_v3.pptx`. As notas de cada slide trazem o texto de apoio.

## Antes da aula

1. Inicie o PostgreSQL local e confirme que `.env` contém `DATABASE_URL` da role `cypherchat_app`, além de um `JWT_SECRET_KEY` próprio.
2. Na raiz do projeto, execute `uv sync` e `uv run pytest -q`.
3. Inicie o servidor em um terminal:

   ```sh
   uv run uvicorn seguranca_auditoria.main:app --host 127.0.0.1 --port 8000 --ws-max-size 24000 --ws-max-queue 16 --limit-concurrency 100
   ```

4. Em outro terminal, verifique `curl -fsS http://127.0.0.1:8000/ready`. O retorno esperado é `{"status":"ready"}`. Se vier 503, confira o serviço PostgreSQL e a URL do banco antes de apresentar.
5. Separe dois terminais para Alice e Bob. Cadastre as contas antes da aula se quiser reservar mais tempo para a conversa. Guarde os fingerprints impressos no cadastro para conferir ao vivo.

## Durante a apresentação

| Tempo | Slide | Ação |
| --- | --- | --- |
| 0:00–0:40 | 1 | Apresentar o objetivo e os dois clientes de terminal. |
| 0:40–1:50 | 2 | Explicar geração efêmera, cifragem, assinatura, roteamento e descriptografia. |
| 1:50–2:50 | 3 | Mostrar onde ficam chaves privadas, chaves públicas e hashes de senha. |
| 2:50–3:50 | 4 | Destacar JWT, autorização, permissões por tabela e logs 5W. |
| 3:50–6:50 | 5 | Executar a conversa e a checagem de acesso administrativo. |
| 6:50–7:50 | 6 | Explicar metadados, confiança inicial e limite de sigilo retroativo. |

### Conversa ao vivo

Em dois terminais separados, se as contas ainda não existirem:

```sh
uv run cypherchat register alice alice@example.local
uv run cypherchat register bob bob@example.local
```

Depois, mantenha ambos os comandos abertos:

```sh
uv run cypherchat chat alice bob
uv run cypherchat chat bob alice
```

Confira o fingerprint exibido por cada cliente contra o que a outra pessoa anotou no cadastro antes de digitar `SIM`. Envie uma frase de Alice para Bob. No terminal do servidor, a auditoria mostra `message.send`, identificadores e horário; não registra o texto original.

### Autorização e auditoria na API

Abra `http://127.0.0.1:8000/docs`. Faça `POST /auth/token` com a conta Alice. Copie o `access_token`, use **Authorize** e execute `GET /admin/users`: retorno esperado **403**. Depois faça login com o administrador criado por `uv run bootstrap-admin`, autorize com esse token e execute `GET /admin/audit`: retorno esperado **200**, com campos `when`, `who`, `what`, `where` e `why`.

Se o tempo apertar, use as contas já cadastradas e comece diretamente pelos dois comandos `chat`.
