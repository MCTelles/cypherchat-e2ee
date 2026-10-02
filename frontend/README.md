# CypherChat Web

Frontend independente; nenhum arquivo do backend precisa ser alterado.

## Executar

Inicie o backend conforme o README da raiz, na porta 8000. Em outro terminal:

```powershell
cd frontend
npm install
npm run dev
```

Abra http://127.0.0.1:5173. O proxy do Vite encaminha `/api` e `/ws` para o FastAPI, sem exigir mudanças de CORS. Para outro endereço, defina `$env:CYPHERCHAT_API = "http://127.0.0.1:8001"` antes de iniciar o frontend.

```powershell
npm run build
npm test
```

O build fica em `dist`. Em produção, sirva os arquivos com HTTPS e configure o proxy reverso para `/api/*` (removendo `/api`) e `/ws` com upgrade WebSocket. `vite preview` serve apenas para conferir o build e não configura esse proxy de API.

## Fluxo

Crie duas contas, cada uma em um perfil de navegador distinto. Cada conta gera suas chaves localmente. Compare o fingerprint pela tela de verificação e confirme nos dois lados para conversar. O chat usa exatamente o envelope X25519/HKDF-SHA256/AES-256-GCM/Ed25519 do backend e confirma mensagens somente após verificar a assinatura e decifrar. Use um navegador moderno com suporte Web Crypto a X25519 e Ed25519, em localhost ou HTTPS.

As chaves privadas são armazenadas em um cofre AES-GCM no localStorage, protegido pela senha com PBKDF2-SHA256 (600.000 iterações). Exporte esse cofre nas configurações e guarde uma cópia: ele é necessário para acessar a identidade em outro navegador. O formato do cofre é próprio do frontend e não importa diretamente os arquivos scrypt do terminal. JWT, chaves abertas e histórico de mensagens permanecem somente em memória. Os fingerprints confirmados são persistidos por conta no navegador. Alterar a senha atualiza também o cofre; exporte uma nova cópia.

Para acessar administração, a conta precisa ter role `admin` no backend. A API não oferece promoção no cadastro público. O primeiro administrador continua sendo criado pelo comando existente `bootstrap-admin`; pode entrar no painel com usuário e senha, sem cofre, pois o bootstrap não cria chaves de mensagens. Um administrador já conectado pode promover outros usuários via tela administrativa.

## Interface e aparência

A navegação, a lista de contatos e a conversa ficam em painéis flutuantes. Em
celulares, a navegação vira uma barra inferior e o botão de voltar alterna entre
lista e conversa. Controles de funcionalidades indisponíveis não são exibidos.

Em **Ajustes → Aparência**, ou pelo botão de paleta, escolha tema claro, escuro ou
automático, quatro paletas ou cores principal e secundária personalizadas.
As preferências ficam neste navegador. A cor do texto dos botões se adapta ao
contraste. Animações podem ser desligadas e respeitam a preferência do sistema.

Botões têm estados de foco, pressão, seleção, carregamento e indisponibilidade.
Rascunhos ficam em memória por contato e são preservados durante atualizações.
Enter envia; Shift + Enter adiciona uma linha. O envio exige conexão e identidade
verificada. Confirme a comparação das chaves antes de liberar a conversa.

Os indicadores refletem dados reais; a presença online dos contatos não é
simulada. Use **Reconectar** se o WebSocket encerrar por inatividade. Se o JWT
expirar, entre novamente. O esquema do backend não oferece sigilo retroativo completo.
