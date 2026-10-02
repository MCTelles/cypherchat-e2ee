import { presets } from "./theme.js";

export function createViews(
  state,
  { icon, esc, avatar, button, badge, verified, pins },
) {
  const ib = (label, action, ico, cls = "") =>
    `<button type="button" class="icon-button ${cls}" data-action="${action}" aria-label="${label}" title="${label}">${icon(ico)}</button>`;
  const blocks = (value) =>
    `<div class="fingerprint-grid">${(value.match(/.{1,4}/g) || []).map((n) => `<code>${esc(n.toUpperCase())}</code>`).join("")}</div>`;
  function auth() {
    const register = state.page === "register";
    return `<div class="auth"><header class="auth-top"><div class="brand">${icon("shield")}<b>CypherChat</b></div>${button("Aparência", "appearance", "quiet", "palette")}</header><main class="auth-layout"><section class="auth-story"><span class="eyebrow">UM ESPAÇO SÓ SEU</span><h1>Boas conversas.<br><span>Em boas mãos.</span></h1><p>Mais perto de quem importa.<br>Com privacidade em cada mensagem.</p><div class="story-art" aria-hidden="true"><div class="art-orbit"></div><div class="art-message">Uma conversa só nossa. ${icon("lock")}</div><div class="art-message reply">Do começo ao fim. ${icon("check")}</div><div class="art-lock">${icon("shield")}</div></div><div class="story-caption">${icon("lock")} Cifrado no seu dispositivo. Lido só por vocês.</div></section>
    <section class="auth-card widget"><div class="auth-icon">${icon(register ? "users" : "shield")}</div><h2>${register ? "Seu espaço começa aqui." : "Que bom ter você aqui."}</h2><p>${register ? "Crie sua conta e suas chaves neste navegador." : "Entre para continuar suas conversas."}</p><form id="auth-form"><label for="username">Nome de usuário</label><input id="username" name="username" autocomplete="username" placeholder="seu_usuario" pattern="[a-zA-Z0-9_]{3,32}" minlength="3" maxlength="32" required>${register ? '<label for="email">E-mail</label><input id="email" name="email" type="email" autocomplete="email" placeholder="voce@exemplo.com" required>' : ""}<label for="password">Senha</label><div class="input-icon"><input id="password" name="password" type="password" autocomplete="${register ? "new-password" : "current-password"}" minlength="${register ? 12 : 1}" maxlength="128" placeholder="${register ? "Pelo menos 12 caracteres" : "Sua senha"}" required>${ib("Mostrar senha", "show-password", "eye")}</div>${register ? '<label for="confirm">Confirmar senha</label><input id="confirm" name="confirm" type="password" autocomplete="new-password" minlength="12" maxlength="128" placeholder="Repita sua senha" required><p class="field-help">Uma frase longa e única também protege suas chaves locais.</p>' : ""}<p class="form-error" role="alert" hidden></p><button class="primary wide" type="submit">${register ? "Criar minha conta" : "Entrar"} ${icon("send")}</button></form><p class="auth-switch">${register ? "Já tem uma conta?" : "Primeira vez aqui?"} ${button(register ? "Entrar" : "Criar conta", register ? "login" : "register", "link")}</p>${register ? '<p class="auth-footnote">Depois de entrar, exporte suas chaves em Ajustes para acessar a conta em outro navegador.</p>' : '<details class="import-details"><summary>Entrando em outro navegador?</summary><p>Importe o cofre exportado em Ajustes e use a senha da conta.</p><label for="import-vault">Importar cofre de chaves</label><input id="import-vault" type="file" accept="application/json,.json"></details>'}</section></main><footer class="auth-footer">${icon("shield")} Suas palavras, sua privacidade.<span>CypherChat · Mensagens de ponta a ponta</span></footer></div>`;
  }
  function shell(content) {
    const nav = [
      ["chat", "Conversas", "chat"],
      ["keys", "Segurança", "shield"],
      ["admin", "Administração", "users"],
      ["settings", "Ajustes", "settings"],
    ].filter(
      ([p]) =>
        (p !== "admin" || state.me.role === "admin") &&
        (state.identity || !["chat", "keys"].includes(p)),
    );
    return `<div class="shell"><nav class="rail widget" aria-label="Navegação principal"><div class="rail-brand" title="CypherChat">${icon("shield")}</div><div class="rail-links">${nav.map(([p, l, i]) => `<button type="button" data-action="${p}" class="nav-item ${state.page === p ? "active" : ""}" ${state.page === p ? 'aria-current="page"' : ""}>${icon(i)}<span>${l}</span></button>`).join("")}</div><div class="rail-bottom">${ib("Personalizar aparência", "appearance", "palette")}<span title="${esc(state.me.username)}">${avatar(state.me)}</span>${ib("Sair da conta", "logout", "logout")}</div></nav><div class="workspace"><header class="topbar"><div class="brand"><b>CypherChat</b><span class="separator">/</span><span>${{ chat: "Conversas", keys: "Segurança", settings: "Ajustes", admin: "Administração" }[state.page]}</span></div><div class="session-status">${state.identity ? `<span class="connection ${state.online ? "connected" : ""}"><i></i>${state.online ? "Conectado" : state.connecting ? "Conectando…" : "Desconectado"}</span>${!state.online ? `<button type="button" class="small" data-action="reconnect" ${state.connecting ? "disabled" : ""}>${icon("refresh")}Reconectar</button>` : ""}` : badge("Administrador")}<span class="session-name">${esc(state.me.username)}</span></div></header>${content}</div></div>`;
  }
  function chat() {
    const c = state.contacts.find((c) => c.id === state.selected);
    const contacts = state.contacts.filter(
      (c) =>
        c.username.toLowerCase().includes(state.search.toLowerCase()) &&
        (state.filter !== "unread" ||
          (state.messages[c.id] || []).some((m) => m.unread)),
    );
    const messages = c ? state.messages[c.id] || [] : [];
    const canSend = c && verified(c) && state.online;
    return `<main class="chat-layout ${state.mobileChat ? "show-conversation" : ""}"><aside class="conversations widget" aria-label="Lista de conversas"><div class="list-heading"><div><span class="eyebrow">SEU ESPAÇO</span><h1>Conversas<span class="count">${state.contacts.length}</span></h1></div>${ib("Atualizar contatos", "refresh", "refresh")}</div><div class="input-icon search">${icon("search")}<input id="contact-search" aria-label="Buscar contatos" placeholder="Buscar alguém" value="${esc(state.search)}" autocomplete="off"></div><div class="segmented filters" aria-label="Filtrar conversas">${[
      ["all", "Todas"],
      ["unread", "Não lidas"],
    ]
      .map(
        ([f, l]) =>
          `<button type="button" data-filter="${f}" aria-pressed="${state.filter === f}">${l}</button>`,
      )
      .join("")}</div><div class="contact-list">${
      contacts
        .map((u) => {
          const msgs = state.messages[u.id] || [],
            last = msgs.at(-1),
            unread = msgs.filter((m) => m.unread).length;
          return `<button type="button" class="contact ${state.selected === u.id ? "selected" : ""}" data-contact="${u.id}" aria-pressed="${state.selected === u.id}">${avatar(u)}<span class="contact-copy"><span class="contact-name">${esc(u.username)}${verified(u) ? icon("check") : ""}</span><small>${last ? `${last.own ? "Você: " : ""}${esc(last.text)}` : verified(u) ? "Tudo pronto para conversar" : "Verifique para começar"}</small></span><span class="contact-meta">${last ? `<time>${last.time}</time>` : ""}${unread ? `<span class="unread" aria-label="${unread} mensagens não lidas">${unread}</span>` : ""}</span></button>`;
        })
        .join("") ||
      `<div class="empty-small">${icon("search")}<h3>${state.search || state.filter === "unread" ? "Tudo tranquilo por aqui." : "Seu primeiro contato."}</h3><p>${state.search ? "Tente outro nome." : state.filter === "unread" ? "Nenhuma mensagem não lida." : "Crie outra conta em um segundo navegador e atualize a lista."}</p>${state.search || state.filter !== "all" ? button("Ver todos", "clear-search", "link") : button("Atualizar lista", "refresh", "quiet", "refresh")}</div>`
    }</div><div class="sidebar-footer">${icon("lock")} Um espaço para conversas privadas.</div></aside>
    <section class="conversation widget" aria-label="Conversa">${c ? `<header class="conversation-header">${ib("Voltar às conversas", "back-contacts", "back", "mobile-back")}${avatar(c)}<div class="conversation-person"><h2>${esc(c.username)}</h2><small>${verified(c) ? `${icon("shield")} Identidade verificada` : "Identidade ainda não verificada"}</small></div>${ib("Ver segurança da conversa", "keys", "shield")}</header>${!verified(c) ? `<div class="trust-banner">${icon("shield")}<span>Uma confirmação antes do primeiro olá.</span>${button("Verificar identidade", "keys", "small")}</div>` : ""}<div class="messages" role="log" aria-label="Mensagens" aria-live="polite">${messages.length ? `<div class="date-pill">Histórico desta conversa</div>${messages.map((m) => `<div class="message-row ${m.own ? "own" : ""}" data-message="${esc(m.localId || m.id)}"><div class="message-content"><div class="bubble">${esc(m.text)}</div><time>${m.time}${m.own ? `<span class="message-state">${esc(m.status || "Enviando…")}</span>` : ""}</time></div></div>`).join("")}` : `<div class="empty-chat"><div class="empty-icon">${icon(verified(c) ? "chat" : "lock")}</div><span class="eyebrow">SÓ ENTRE VOCÊS</span><h2>${verified(c) ? "Pode dizer olá." : "A confiança vem primeiro."}</h2><p>${verified(c) ? `Sua conversa com ${esc(c.username)} começa aqui.` : "Compare as chaves por outro canal para ter certeza de quem está do outro lado."}</p>${!verified(c) ? button("Conferir chaves", "keys", "primary", "key") : ""}</div>`}</div><div class="composer-area"><form id="send-form" class="composer"><textarea id="message" name="message" aria-label="Mensagem" rows="1" maxlength="4000" placeholder="${!verified(c) ? "Verifique a identidade para conversar" : !state.online ? "Reconecte para enviar" : "Escreva uma mensagem…"}" ${!canSend ? "disabled" : ""} required>${esc(state.drafts[c.id] || "")}</textarea><button class="primary send-button" type="submit" aria-label="Enviar mensagem" title="Enviar mensagem" ${!canSend || !state.drafts[c.id]?.trim() ? "disabled" : ""}>${icon("send")}</button></form><div class="composer-hint">${icon("lock")} Criptografia de ponta a ponta<span>Enter envia · Shift + Enter quebra a linha</span></div></div>` : `<div class="empty-chat"><div class="empty-icon">${icon("chat")}</div><span class="eyebrow">BEM-VINDO AO SEU ESPAÇO</span><h2>Menos ruído.<br>Mais conversa.</h2><p>Escolha alguém ao lado para começar.<br>Suas mensagens ficam só entre vocês.</p>${button("Encontrar contatos", "refresh", "primary", "users")}</div>`}</section></main>`;
  }
  function keys() {
    const c =
      state.contacts.find((c) => c.id === state.selected) || state.contacts[0];
    return `<main class="page"><div class="page-heading"><span class="eyebrow">CONFIANÇA, PESSOA A PESSOA</span><h1>Saiba com quem você fala.</h1><p>Compare a chave por ligação ou pessoalmente. É só uma vez por identidade.</p></div><div class="verification-layout"><section class="card widget">${c ? `<div class="person">${avatar(c)}<div><h2>${esc(c.username)}</h2><p>${verified(c) ? "Identidade confirmada neste navegador" : "Aguardando sua confirmação"}</p></div>${badge(verified(c) ? "Verificado" : "Pendente", verified(c) ? "success" : "warning")}</div>${pins()[c.id] && !verified(c) ? '<div class="alert">A chave deste contato mudou. Compare novamente antes de conversar.</div>' : ""}<div class="safety"><div class="section-heading"><h3>Chave de segurança</h3>${button("Copiar", "copy-fingerprint", "quiet small", "copy")}</div>${blocks(c.fingerprint)}<p class="field-help">Compare os 16 blocos com a chave que ${esc(c.username)} vê em Ajustes → Suas chaves.</p></div>${verified(c) ? `<div class="confirmed-note">${icon("check")} Tudo certo. Vocês já podem conversar.</div><div class="actions">${button("Ir para a conversa", "chat", "primary", "chat")}${button("Remover confiança", "unverify", "quiet danger")}</div>` : `<label class="check-row"><input id="trust-confirm" type="checkbox">Comparei todos os blocos com meu contato por outro canal.</label><div class="actions"><button type="button" class="primary" data-action="verify" disabled>${icon("shield")}Confirmar e conversar</button>${button("Agora não", "chat", "quiet")}</div>`}` : `<div class="empty-small">${icon("users")}<h2>Ainda não há contatos.</h2><p>Cadastre outra conta e atualize a lista.</p>${button("Atualizar contatos", "refresh", "primary")}</div>`}</section><aside class="card widget directory"><div class="section-heading"><h2>Contatos</h2>${ib("Atualizar contatos", "refresh", "refresh")}</div>${state.contacts.map((u) => `<button type="button" class="directory-contact ${u.id === c?.id ? "selected" : ""}" data-key-contact="${u.id}" aria-pressed="${u.id === c?.id}">${avatar(u)}<span><b>${esc(u.username)}</b><small>${verified(u) ? "Verificado" : "Pendente de verificação"}</small></span>${icon(verified(u) ? "check" : "key")}</button>`).join("")}<div class="note">${icon("shield")} Se uma chave mudar, o envio será bloqueado até você conferir novamente.</div></aside></div></main>`;
  }
  function appearance() {
    const t = state.theme;
    return `<div class="section-heading"><div><span class="eyebrow">DO SEU JEITO</span><h2>Aparência</h2></div>${icon("palette")}</div><p>Um espaço que combina com você. As mudanças são salvas neste navegador.</p><fieldset><legend>Tema</legend><div class="theme-modes">${[
      ["light", "Claro", "sun"],
      ["dark", "Escuro", "moon"],
      ["system", "Automático", "monitor"],
    ]
      .map(
        ([m, l, i]) =>
          `<button type="button" data-theme-mode="${m}" aria-pressed="${t.mode === m}"><span class="mode-preview ${m}"><i></i><i></i><i></i></span><span>${icon(i)}${l}</span></button>`,
      )
      .join(
        "",
      )}</div></fieldset><fieldset><legend>Paletas</legend><div class="palettes">${presets.map((p) => `<button type="button" data-palette="${p.name}" aria-pressed="${t.primary === p.primary && t.secondary === p.secondary}"><span class="swatch-pair" style="--swatch-a:${p.primary};--swatch-b:${p.secondary}"><i></i><i></i></span>${p.name}</button>`).join("")}</div></fieldset><div class="color-fields"><label>Cor principal<div><input type="color" data-color="primary" value="${t.primary}" aria-label="Cor principal"><output data-color-value="primary">${t.primary.toUpperCase()}</output></div></label><label>Cor secundária<div><input type="color" data-color="secondary" value="${t.secondary}" aria-label="Cor secundária"><output data-color-value="secondary">${t.secondary.toUpperCase()}</output></div></label></div><div class="theme-sample" aria-label="Prévia das cores"><span class="sample-avatar">C</span><div><b>Seu próximo olá.</b><small>Cores que acompanham suas conversas.</small></div><span class="sample-bubble">Olá! ${icon("check")}</span></div><label class="switch-row"><span><b>Animações suaves</b><small>Respeita a preferência de movimento do sistema.</small></span><input type="checkbox" role="switch" data-motion ${t.motion ? "checked" : ""}><span class="switch-track" aria-hidden="true"></span></label>${button("Restaurar aparência padrão", "reset-theme", "link")}`;
  }
  function settings() {
    return `<main class="page"><div class="page-heading"><span class="eyebrow">SEU ESPAÇO, SUAS ESCOLHAS</span><h1>Ajustes</h1><p>Cuide da sua conta e deixe tudo com a sua cara.</p></div><div class="settings-layout"><div><article class="card widget profile">${avatar(state.me)}<div><h2>${esc(state.me.username)}</h2><p>${esc(state.me.email)}</p>${badge(state.me.role === "admin" ? "Administrador" : "Sua conta", "neutral")}</div>${ib("Sair da conta", "logout", "logout")}</article><form id="profile-form" class="card widget"><h2>Conta</h2><label for="profile-email">E-mail</label><input id="profile-email" name="email" type="email" autocomplete="email" value="${esc(state.me.email)}" required><p class="field-help">Seu nome de usuário é permanente.</p><p class="form-error" role="alert" hidden></p><button type="submit" class="primary" disabled>Salvar alterações</button></form>${state.identity ? `<form id="password-form" class="card widget"><h2>Alterar senha</h2><label for="current-password">Senha atual</label><input id="current-password" name="current" type="password" autocomplete="current-password" required><label for="new-password">Nova senha</label><input id="new-password" name="password" type="password" minlength="12" maxlength="128" autocomplete="new-password" placeholder="Pelo menos 12 caracteres" required><label for="confirm-password">Confirmar nova senha</label><input id="confirm-password" name="confirm" type="password" autocomplete="new-password" required><p class="form-error" role="alert" hidden></p><button type="submit">Atualizar senha</button></form>` : ""}</div><div><article class="card widget appearance-panel">${appearance()}</article>${state.identity ? `<article class="card widget"><div class="section-heading"><h2>Suas chaves</h2>${icon("key")}</div><p>Esta é a chave que seus contatos devem comparar antes da primeira conversa.</p><div class="safety"><div id="my-fingerprint" class="fingerprint-grid"></div>${button("Copiar minha chave", "copy-mine", "quiet", "copy")}</div>${button("Exportar cofre cifrado", "export", "primary", "download")}<p class="field-help">Guarde uma cópia para entrar em outro navegador. Suas chaves privadas são protegidas pela sua senha.</p></article>` : ""}<article class="card widget"><h2>Privacidade por padrão</h2><div class="privacy-row">${icon("lock")}<div><b>Histórico cifrado neste navegador</b><p>As conversas ficam cifradas neste navegador e reaparecem ao entrar nesta conta. Elas não são sincronizadas com outros navegadores.</p></div></div><div class="privacy-row">${icon("shield")}<div><b>Identidades verificadas</b><p>Você confirma quem está do outro lado antes de conversar.</p></div></div></article></div></div></main>`;
  }
  function admin() {
    const users = state.users.filter((u) =>
      `${u.username} ${u.email}`
        .toLowerCase()
        .includes(state.adminSearch.toLowerCase()),
    );
    const audit = state.audit.filter((e) =>
      `${e.what} ${e.who} ${e.why}`
        .toLowerCase()
        .includes(state.adminSearch.toLowerCase()),
    );
    return `<main class="page"><div class="page-heading"><span class="eyebrow">VISÃO GERAL</span><h1>Administração</h1><p>Gerencie acessos e acompanhe a atividade da sua comunidade.</p></div><div class="stats">${[
      ["Contas", state.users.length],
      ["Ativas", state.users.filter((u) => u.is_active).length],
      ["Eventos registrados", state.audit.length],
    ]
      .map(
        ([l, n]) =>
          `<article class="card widget"><span>${l}</span><strong>${n}</strong></article>`,
      )
      .join(
        "",
      )}</div><section class="card widget admin-table"><div class="admin-toolbar"><div class="segmented">${button("Pessoas", "admin-users", state.adminTab === "users" ? "active" : "")}${button("Auditoria", "admin-audit", state.adminTab === "audit" ? "active" : "")}</div><div class="input-icon">${icon("search")}<input id="admin-search" aria-label="Buscar na administração" placeholder="Buscar" value="${esc(state.adminSearch)}"></div>${button("Atualizar", "load-admin", "quiet", "refresh")}</div><div class="table-wrap">${state.adminTab === "users" ? `<table><thead><tr><th>Pessoa</th><th>E-mail</th><th>Perfil</th><th>Estado</th><th>Ações</th></tr></thead><tbody>${users.map((u) => `<tr><td><div class="table-user">${avatar(u)}<b>${esc(u.username)}</b>${u.id === state.me.id ? badge("Você", "neutral") : ""}</div></td><td>${esc(u.email)}</td><td>${u.role === "admin" ? "Administrador" : "Usuário"}</td><td>${badge(u.is_active ? "Ativo" : "Suspenso", u.is_active ? "success" : "warning")}</td><td>${u.id !== state.me.id ? `<button type="button" data-toggle-user="${u.id}" class="small ${u.is_active ? "danger quiet" : ""}">${u.is_active ? "Suspender" : "Reativar"}</button><button type="button" data-role-user="${u.id}" class="small quiet">${u.role === "admin" ? "Tornar usuário" : "Tornar admin"}</button>` : "—"}</td></tr>`).join("") || '<tr><td colspan="5" class="empty-cell">Nenhuma pessoa encontrada.</td></tr>'}</tbody></table>` : `<table><thead><tr><th>Quando</th><th>Quem</th><th>Ação</th><th>Origem</th><th>Resultado</th></tr></thead><tbody>${audit.map((e) => `<tr><td>${esc(new Date(e.when).toLocaleString("pt-BR"))}</td><td>${esc(e.who || "Anônimo")}</td><td><b>${esc(e.what)}</b><small>${esc(e.why)}</small></td><td>${esc(e.where)}</td><td>${badge(esc(e.result), e.result === "success" ? "success" : "warning")}</td></tr>`).join("") || '<tr><td colspan="5" class="empty-cell">Nenhum evento encontrado.</td></tr>'}</tbody></table>`}</div></section></main>`;
  }
  return { auth, shell, chat, keys, settings, admin, appearance };
}
