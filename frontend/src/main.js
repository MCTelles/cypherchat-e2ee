import "./style.css";
import { createViews } from "./views.js";
import {
  defaults,
  presets,
  readTheme,
  normalizeTheme,
  applyTheme,
} from "./theme.js";
import {
  generateIdentity,
  protect,
  unlock,
  fingerprint,
  encrypt,
  decrypt,
} from "./crypto.js";
import { openHistory, sealHistory } from "./history.js";
import { clearSession, loadSession, saveSession } from "./session.js";
const app = document.querySelector("#app");
const state = {
  page: "login",
  me: null,
  token: null,
  identity: null,
  contacts: [],
  selected: null,
  messages: {},
  historyWritable: true,
  pending: [],
  incoming: [],
  socket: null,
  online: false,
  filter: "all",
  search: "",
  users: [],
  audit: [],
  adminTab: "users",
  notice: "",
  drafts: {},
  theme: readTheme(),
  busy: new Set(),
  mobileChat: false,
  connecting: false,
  adminSearch: "",
};
const icons = {
  shield:
    '<path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6Z"/><path d="m9 12 2 2 4-4"/>',
  chat: '<path d="M4 4h16v12H9l-5 4Z"/>',
  key: '<circle cx="8" cy="10" r="4"/><path d="m12 10 9 0m-3 0v4m-3-4v3"/>',
  settings:
    '<path d="m9 3-1 3-3 1v3l-2 2 2 2v3l3 1 1 3h6l1-3 3-1v-3l2-2-2-2V7l-3-1-1-3Z"/><circle cx="12" cy="12" r="3"/>',
  users:
    '<circle cx="9" cy="8" r="3"/><path d="M3 21v-4a6 6 0 0 1 12 0v4M16 4a3 3 0 0 1 0 6m2 4a5 5 0 0 1 3 5"/>',
  logout: '<path d="M10 4H4v16h6m4-12 4 4-4 4m-6-4h12"/>',
  search: '<circle cx="10" cy="10" r="6"/><path d="m15 15 5 5"/>',
  send: '<path d="m3 3 18 9-18 9 4-9Zm4 9h14"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8 10V6a4 4 0 0 1 8 0v4m-4 5v2"/>',
  copy: '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
  check: '<path d="m5 12 4 4 10-10"/>',
  download: '<path d="M12 3v12m-5-5 5 5 5-5M4 17v4h16v-4"/>',
  eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12"/><circle cx="12" cy="12" r="3"/>',
};
Object.assign(icons, {
  palette:
    '<circle cx="12" cy="12" r="9"/><circle cx="8" cy="9" r="1"/><circle cx="14" cy="8" r="1"/><path d="M12 21c-4-7 6-3 3-7"/>',
  refresh:
    '<path d="M20 7v5h-5M4 17v-5h5M6 7a7 7 0 0 1 12-1l2 6M4 12l2 6a7 7 0 0 0 12-1"/>',
  back: '<path d="m14 5-7 7 7 7"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2"/>',
  moon: '<path d="M20 14A9 9 0 0 1 10 3a9 9 0 1 0 10 11Z"/>',
  monitor:
    '<rect x="3" y="4" width="18" height="13" rx="3"/><path d="M12 17v4m-4 0h8"/>',
  send: '<path d="m5 12 7-7 7 7M12 5v15"/>',
});
const icon = (n) =>
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icons[n] || icons.shield}</svg>`;
const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const initials = (s) => esc(s.slice(0, 2).toUpperCase());
const avatar = (u) => `<span class="avatar">${initials(u.username)}</span>`;
const vaultName = (u) => `cypherchat.vault.${u}`;
const historyName = (userId) => `cypherchat.history.${userId}`;
let historyWrites = Promise.resolve();

async function restoreHistory() {
  try {
    const saved = localStorage.getItem(historyName(state.me.id));
    state.messages = saved
      ? await openHistory(state.identity, state.me.id, JSON.parse(saved))
      : {};
    for (const items of Object.values(state.messages))
      for (const message of items)
        if (message.own && message.status === "Enviando…")
          message.status = "Envio não confirmado";
    state.historyWritable = true;
    return null;
  } catch {
    state.messages = {};
    state.historyWritable = false;
    return "A sessão automática não conseguiu abrir este histórico. Saia e entre novamente com sua senha; o app tentará migrá-lo sem apagar os dados.";
  }
}

function saveHistory() {
  if (!state.me?.id || !state.identity) return Promise.resolve();
  if (!state.historyWritable)
    return Promise.reject(Error("Histórico local indisponível"));
  const userId = state.me.id;
  const identity = state.identity;
  const snapshot = structuredClone(state.messages);
  historyWrites = historyWrites.catch(() => {}).then(async () => {
    const sealed = await sealHistory(identity, userId, snapshot);
    localStorage.setItem(historyName(userId), JSON.stringify(sealed));
  });
  return historyWrites;
}
const pins = () => {
  try {
    return (
      JSON.parse(localStorage.getItem(`cypherchat.pins.${state.me?.id}`)) || {}
    );
  } catch {
    return {};
  }
};
const verified = (c) => pins()[c.id] === c.fingerprint;
const button = (label, action, cls = "", ico = "") =>
  `<button type="button" class="${cls}" data-action="${action}">${ico ? icon(ico) : ""}${label}</button>`;
const badge = (text, cls = "") => `<span class="badge ${cls}">${text}</span>`;
const { auth, shell, chat, keys, settings, admin, appearance } = createViews(
  state,
  { icon, esc, avatar, button, badge, verified, pins },
);
applyTheme(state.theme);
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () =>
  applyTheme(state.theme),
);
async function api(path, options = {}) {
  let r;
  try {
    r = await fetch("/api" + path, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}),
        ...options.headers,
      },
    });
  } catch {
    throw Error("Servidor indisponível. Inicie o backend na porta 8000.");
  }
  const data =
    r.status === 204
      ? null
      : await r
          .json()
          .catch(() => ({ detail: "Resposta inválida do servidor" }));
  if (!r.ok) {
    if (r.status === 401 && state.me) logout();
    const error = Error(
      typeof data.detail === "string"
        ? data.detail
        : "Não foi possível concluir a operação",
    );
    error.status = r.status;
    throw error;
  }
  return data;
}
async function directory() {
  state.contacts = await api("/users");
  for (const c of state.contacts) {
    if (
      (await fingerprint(c.public_key, c.signing_public_key)) !== c.fingerprint
    )
      throw Error("Fingerprint inválido no diretório");
  }
  if (state.selected && !state.contacts.some((c) => c.id === state.selected))
    state.selected = null;
}
async function receive(e) {
  const receivingSocket = state.socket;
  if (e.recipient_id !== state.me?.id) throw Error("Destinatário inválido");
  const c = await api(`/users/${e.sender_id}/key`);
  if ((await fingerprint(c.public_key, c.signing_public_key)) !== c.fingerprint)
    throw Error("Fingerprint inválido");
  const ci = state.contacts.findIndex((u) => u.id === c.id);
  if (ci < 0) state.contacts.push(c);
  else state.contacts[ci] = c;
  if (!verified(c)) {
    if (!state.incoming.some((m) => m.id === e.id)) state.incoming.push(e);
    notify(
      "Mensagem pendente: verifique a identidade do remetente em Segurança.",
      "info",
    );
    render();
    return;
  }
  const text = await decrypt(state.identity, c, e);
  if (receivingSocket !== state.socket) return;
  if (!(state.messages[c.id] || []).some((m) => m.id === e.id))
    (state.messages[c.id] ||= []).push({
      id: e.id,
      text,
      own: false,
      time: time(),
      unread: state.selected !== c.id || state.page !== "chat",
    });
  try {
    await saveHistory();
  } catch {
    notify(
      "Mensagem recebida, mas o histórico não foi salvo. Libere espaço no navegador antes de sair.",
      "error",
    );
    render();
    return;
  }
  if (receivingSocket?.readyState === WebSocket.OPEN)
    receivingSocket.send(JSON.stringify({ type: "ack", id: e.id }));
  render();
}
const time = () =>
  new Date().toLocaleTimeString("pt-BR", {
    hour: "2-digit",
    minute: "2-digit",
  });
function connect() {
  if (state.connecting || state.online || !state.identity) return;
  state.connecting = true;
  const socket = new WebSocket(
    `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/ws`,
  );
  state.socket = socket;
  socket.onopen = () =>
    socket.send(JSON.stringify({ type: "auth", token: state.token }));
  socket.onmessage = async (event) => {
    if (state.socket !== socket) return;
    try {
      const e = JSON.parse(event.data);
      if (e.type === "ready") {
        state.online = true;
        state.connecting = false;
        render();
      } else if (e.type === "message") await receive(e);
      else if (e.type === "sent") {
        const m = state.pending.shift();
        if (m) {
          m.id = e.id;
          m.status = "Enviada ✓";
          await saveHistory();
        }
        render();
      } else if (e.type === "error") {
        const m = state.pending.shift();
        if (m) m.status = "Falha no envio";
        if (m) await saveHistory();
        render();
        notify(e.detail, "error");
      }
    } catch (e) {
      notify("Mensagem não aceita: " + e.message);
    }
  };
  socket.onclose = () => {
    if (state.socket !== socket) return;
    state.online = false;
    state.connecting = false;
    for (const m of state.pending) m.status = "Envio não confirmado";
    state.pending = [];
    saveHistory().catch(() =>
      notify("Não foi possível atualizar o histórico local.", "error"),
    );
    render();
  };
  socket.onerror = () => {
    state.notice = "Não foi possível conectar o canal de mensagens.";
  };
}
async function logout() {
  try {
    await saveHistory();
  } catch {
    notify("Não foi possível salvar o histórico local antes de sair.", "error");
  }
  try {
    await clearSession();
  } catch {
    notify("Não foi possível encerrar a sessão local com segurança.", "error");
  }
  state.socket?.close();
  Object.assign(state, {
    me: null,
    token: null,
    identity: null,
    socket: null,
    online: false,
    page: "login",
    messages: {},
    historyWritable: true,
    drafts: {},
    connecting: false,
    pending: [],
    incoming: [],
    contacts: [],
    selected: null,
    notice: "",
    mobileChat: false,
    search: "",
    filter: "all",
  });
  document.querySelector(".toast")?.remove();
  render();
}
async function loadAdmin() {
  [state.users, state.audit] = await Promise.all([
    api("/admin/users"),
    api("/admin/audit"),
  ]);
  render();
}
function download(name, data) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
app.addEventListener("click", async (e) => {
  const target = e.target.closest("button");
  if (!target || target.disabled) return;
  const op = target.dataset.action;
  const pending = [
    "refresh",
    "verify",
    "copy-fingerprint",
    "copy-mine",
    "load-admin",
    "admin",
  ].includes(op);
  if (pending && state.busy.has(op)) return;
  if (pending) {
    state.busy.add(op);
    target.disabled = true;
    target.setAttribute("aria-busy", "true");
  }
  try {
    if (target.dataset.contact) {
      state.selected = target.dataset.contact;
      state.mobileChat = true;
      for (const m of state.messages[state.selected] || []) m.unread = false;
      render();
      return;
    }
    if (target.dataset.keyContact) {
      state.selected = target.dataset.keyContact;
      render();
      return;
    }
    if (target.dataset.filter) {
      state.filter = target.dataset.filter;
      render();
      return;
    }
    if (target.dataset.toggleUser || target.dataset.roleUser) {
      const id = target.dataset.toggleUser || target.dataset.roleUser,
        u = state.users.find((x) => x.id === id);
      confirmAction(
        "Alterar acesso?",
        `Alterar o acesso de ${esc(u.username)}? Administradores podem gerenciar usuários e consultar auditoria. Suspender impede o acesso à conta.`,
        "Confirmar",
        async () => {
          await api("/admin/users/" + id, {
            method: "PATCH",
            body: JSON.stringify(
              target.dataset.toggleUser
                ? { is_active: !u.is_active }
                : { role: u.role === "admin" ? "user" : "admin" },
            ),
          });
          await loadAdmin();
          notify("Acesso atualizado.");
        },
      );
      return;
    }
    const action = target.dataset.action;
    if (
      ["login", "register", "chat", "keys", "settings", "admin"].includes(
        action,
      )
    ) {
      if (!state.identity && ["chat", "keys"].includes(action)) {
        notify(
          "Esta conta administrativa não tem chaves de mensagens. Use o painel para gerenciar usuários.",
        );
        return;
      }
      state.page = action;
      state.notice = "";
      if (action === "keys" && !state.selected)
        state.selected = state.contacts[0]?.id;
      if (action === "chat") {
        state.mobileChat = !!state.selected;
        for (const m of state.messages[state.selected] || []) m.unread = false;
      }
      if (action === "admin") await loadAdmin();
      render();
    } else if (action === "logout")
      confirmAction(
        "Sair da conta?",
        "A sessão será encerrada. O histórico e o cofre de chaves continuam cifrados neste navegador.",
        "Sair",
        logout,
      );
    else if (action === "dismiss") {
      state.notice = "";
      render();
    } else if (action === "show-password") {
      const input = target.parentElement.querySelector("input");
      input.type = input.type === "password" ? "text" : "password";
      target.setAttribute(
        "aria-label",
        input.type === "password" ? "Mostrar senha" : "Ocultar senha",
      );
      target.setAttribute("aria-pressed", String(input.type === "text"));
    } else if (action === "refresh") {
      await directory();
      render();
      notify("Lista de contatos atualizada.");
    } else if (action === "verify" || action === "unverify") {
      const c =
        state.contacts.find((c) => c.id === state.selected) ||
        state.contacts[0];
      if (!c) return;
      const map = pins();
      if (action === "verify") {
        if (!app.querySelector("#trust-confirm")?.checked) return;
        const fresh = await api(`/users/${c.id}/key`);
        if (fresh.fingerprint !== c.fingerprint)
          throw Error(
            "A chave mudou. Atualize o diretório e compare novamente.",
          );
        map[c.id] = c.fingerprint;
      } else delete map[c.id];
      localStorage.setItem(
        `cypherchat.pins.${state.me.id}`,
        JSON.stringify(map),
      );
      render();
      if (action === "verify") {
        state.selected = c.id;
        state.page = "chat";
        state.mobileChat = true;
        render();
        notify("Identidade verificada. Pode conversar.");
        const queued = state.incoming.filter((m) => m.sender_id === c.id);
        for (const m of queued) {
          await receive(m);
          state.incoming = state.incoming.filter((x) => x.id !== m.id);
        }
      }
    } else if (action === "copy-fingerprint" || action === "copy-mine") {
      const f =
        action === "copy-mine"
          ? await fingerprint(
              state.identity.public_key,
              state.identity.signing_public_key,
            )
          : (
              state.contacts.find((c) => c.id === state.selected) ||
              state.contacts[0]
            )?.fingerprint;
      if (f) await navigator.clipboard.writeText(f);
      notify("Fingerprint copiado.");
    } else if (action === "export") {
      download(`cypherchat-${state.me.username}.json`, {
        username: state.me.username,
        vault: JSON.parse(localStorage.getItem(vaultName(state.me.username))),
      });
    } else if (action === "appearance")
      modal(
        "Personalize seu espaço",
        `<div class="appearance-panel">${appearance()}</div>`,
      );
    else if (action === "back-contacts") {
      state.mobileChat = false;
      render();
    } else if (action === "clear-search") {
      state.search = "";
      state.filter = "all";
      render();
    } else if (action === "reconnect") {
      connect();
      render();
    } else if (action === "load-admin") await loadAdmin();
    else if (action === "admin-users" || action === "admin-audit") {
      state.adminTab = action === "admin-users" ? "users" : "audit";
      state.adminSearch = "";
      render();
    }
  } catch (error) {
    notify(error.message, "error");
  } finally {
    if (pending) {
      state.busy.delete(op);
      target.disabled = false;
      target.removeAttribute("aria-busy");
      syncControls();
    }
  }
});
app.addEventListener("input", (e) => {
  if (e.target.id === "contact-search") {
    state.search = e.target.value;
    render();
  }
  if (e.target.id === "admin-search") {
    state.adminSearch = e.target.value;
    render();
  }
  if (e.target.id === "message") {
    state.drafts[state.selected] = e.target.value;
    e.target.style.height = "auto";
    e.target.style.height = Math.min(e.target.scrollHeight, 144) + "px";
  }
  const error = e.target.closest("form")?.querySelector(".form-error");
  if (error) error.hidden = true;
  syncControls();
});
app.addEventListener("keydown", (e) => {
  if (
    e.target.id === "message" &&
    e.key === "Enter" &&
    !e.shiftKey &&
    !e.isComposing
  ) {
    e.preventDefault();
    if (!app.querySelector("#send-form button").disabled)
      e.target.form.requestSubmit();
  }
});
app.addEventListener("change", async (e) => {
  syncControls();
  if (e.target.id !== "import-vault" || !e.target.files?.length) return;
  try {
    const data = JSON.parse(await e.target.files[0].text());
    if (
      !/^[a-zA-Z0-9_]{3,32}$/.test(data.username) ||
      data.vault?.version !== 1 ||
      !data.vault?.data ||
      !data.vault?.salt ||
      !data.vault?.nonce
    )
      throw Error("Cofre inválido");
    if (localStorage.getItem(vaultName(data.username)))
      throw Error("Já existe um cofre para esta conta neste navegador.");
    localStorage.setItem(vaultName(data.username), JSON.stringify(data.vault));
    notify("Cofre importado. Faça login com a conta correspondente.");
  } catch (error) {
    notify(error.message);
  }
});
app.addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  if (state.busy.has(form.id)) return;
  state.busy.add(form.id);
  const data = Object.fromEntries(new FormData(form));
  const submit = form.querySelector(
    'button[type="submit"],button.primary,button.wide',
  );
  const original = submit?.innerHTML;
  if (submit) {
    submit.disabled = true;
    submit.setAttribute("aria-busy", "true");
    if (form.id !== "send-form")
      submit.innerHTML = '<span class="spinner"></span> Só um instante…';
  }
  try {
    if (form.id === "auth-form") {
      let identity;
      if (state.page === "register") {
        if (data.password !== data.confirm)
          throw Error("As senhas não coincidem.");
        if (localStorage.getItem(vaultName(data.username)))
          throw Error("Já existe um cofre local com este identificador.");
        identity = await generateIdentity();
        const vault = await protect(identity, data.password);
        localStorage.setItem(vaultName(data.username), JSON.stringify(vault));
        try {
          await api("/auth/register", {
            method: "POST",
            body: JSON.stringify({
              username: data.username,
              email: data.email,
              password: data.password,
              public_key: identity.public_key,
              signing_public_key: identity.signing_public_key,
            }),
          });
        } catch (error) {
          if (error.status && error.status < 500)
            localStorage.removeItem(vaultName(data.username));
          else
            error.message +=
              " O cofre foi preservado; tente entrar se a conta foi criada.";
          throw error;
        }
      } else {
        const blob = localStorage.getItem(vaultName(data.username));
        if (blob) {
          try {
            identity = await unlock(JSON.parse(blob), data.password);
          } catch {
            throw Error("Não foi possível abrir o cofre. Confira a senha.");
          }
        }
      }
      const token = await api("/auth/token", {
        method: "POST",
        body: JSON.stringify({
          username: data.username,
          password: data.password,
        }),
      });
      state.token = token.access_token;
      const me = await api("/me");
      if (!identity) {
        if (me.role !== "admin") {
          state.token = null;
          throw Error(
            "Esta conta não tem cofre de chaves neste navegador. Importe um cofre exportado da interface web. Se a conta foi criada no terminal, use outra conta na web.",
          );
        }
        state.me = me;
        state.page = "admin";
        try {
          await saveSession(token.access_token, me, null);
        } catch {
          notify("A sessão não será restaurada automaticamente após recarregar esta aba.", "error");
        }
        await loadAdmin();
        render();
        return;
      }
      const own = await api(`/users/${me.id}/key`);
      if (
        own.public_key !== identity.public_key ||
        own.signing_public_key !== identity.signing_public_key
      ) {
        state.token = null;
        throw Error("O cofre local não corresponde às chaves desta conta.");
      }
      state.me = me;
      state.identity = identity;
      state.page = "chat";
      const historyWarning = await restoreHistory();
      if (!historyWarning) {
        try {
          state.identity = await saveSession(token.access_token, me, identity);
        } catch {
          notify("A sessão não será restaurada automaticamente após recarregar esta aba.", "error");
        }
      } else {
        try {
          await clearSession();
        } catch {
          sessionStorage.removeItem("cypherchat.active-session");
        }
      }
      await directory();
      if (!historyWarning) connect();
      render();
      if (historyWarning) notify(historyWarning, "error");
    } else if (form.id === "send-form") {
      const c = state.contacts.find((x) => x.id === state.selected),
        sendingSocket = state.socket;
      if (!c || !verified(c) || !state.online)
        throw Error("Verifique o contato e conecte o canal antes de enviar.");
      const text = data.message.trim();
      if (!text) return;
      if (new TextEncoder().encode(text).length > 8176)
        throw Error("Mensagem muito longa. Divida o texto em duas mensagens.");
      const fresh = await api(`/users/${c.id}/key`);
      if (fresh.fingerprint !== c.fingerprint) {
        await directory();
        throw Error("A chave do contato mudou. Faça uma nova verificação.");
      }
      const envelope = await encrypt(state.identity, fresh, state.me.id, text);
      delete envelope.sender_id;
      const m = {
        localId: crypto.randomUUID(),
        text,
        own: true,
        time: time(),
        status: "Enviando…",
      };
      if (
        state.socket !== sendingSocket ||
        sendingSocket.readyState !== WebSocket.OPEN
      )
        throw Error("Conexão interrompida. Seu rascunho foi mantido.");
      state.pending.push(m);
      (state.messages[c.id] ||= []).push(m);
      if (state.drafts[c.id] === data.message) state.drafts[c.id] = "";
      render();
      try {
        await saveHistory();
      } catch {
        state.pending = state.pending.filter((pending) => pending !== m);
        state.messages[c.id] = state.messages[c.id].filter(
          (message) => message !== m,
        );
        throw Error(
          "Não foi possível salvar o histórico local. Libere espaço no navegador e tente novamente.",
        );
      }
      if (
        state.socket !== sendingSocket ||
        sendingSocket.readyState !== WebSocket.OPEN
      ) {
        m.status = "Envio não confirmado";
        await saveHistory();
        throw Error("Conexão interrompida. Seu rascunho foi mantido.");
      }
      sendingSocket.send(JSON.stringify({ type: "send", ...envelope }));
    } else if (form.id === "profile-form") {
      state.me = await api("/me", {
        method: "PATCH",
        body: JSON.stringify({ email: data.email }),
      });
      notify("Informações atualizadas.");
    } else if (form.id === "password-form") {
      if (data.password !== data.confirm)
        throw Error("As senhas não coincidem.");
      await api("/auth/token", {
        method: "POST",
        body: JSON.stringify({
          username: state.me.username,
          password: data.current,
        }),
      });
      const unlockedIdentity = await unlock(
        JSON.parse(localStorage.getItem(vaultName(state.me.username))),
        data.current,
      );
      const vault = await protect(unlockedIdentity, data.password);
      await api("/me", {
        method: "PATCH",
        body: JSON.stringify({ password: data.password }),
      });
      localStorage.setItem(vaultName(state.me.username), JSON.stringify(vault));
      try {
        state.identity = await saveSession(state.token, state.me, unlockedIdentity);
      } catch {
        notify("Senha atualizada. Esta sessão pode pedir login após recarregar a aba.", "error");
      }
      form.reset();
      notify(
        "Senha da conta e do cofre atualizadas. Exporte novamente seu cofre.",
      );
    }
  } catch (error) {
    const el = document.getElementById(form.id)?.querySelector(".form-error");
    if (el) {
      el.textContent = error.message;
      el.hidden = false;
    } else notify(error.message, "error");
  } finally {
    state.busy.delete(form.id);
    const current = document
      .getElementById(form.id)
      ?.querySelector('button[type="submit"]');
    if (current) {
      current.innerHTML = original;
      current.disabled = false;
      current.removeAttribute("aria-busy");
    }
    syncControls();
  }
});
window.addEventListener("pagehide", () => state.socket?.close());
let renderedPage, renderedContact, toastTimer;
function notify(message, kind = "success") {
  document.querySelector(".toast")?.remove();
  clearTimeout(toastTimer);
  const toast = document.createElement("div");
  toast.className = "toast " + kind;
  toast.setAttribute("role", kind === "error" ? "alert" : "status");
  toast.innerHTML = `${icon(kind === "error" ? "shield" : "check")}<span>${esc(message)}</span><button type="button" class="icon-button" aria-label="Fechar aviso">${icon("close")}</button>`;
  toast.querySelector("button").onclick = () => toast.remove();
  document.body.append(toast);
  toastTimer = setTimeout(
    () => toast.remove(),
    kind === "error" ? 12000 : 5500,
  );
}
function syncControls() {
  const send = app.querySelector("#send-form button");
  const c = state.contacts.find((c) => c.id === state.selected);
  if (send)
    send.disabled =
      state.busy.has("send-form") ||
      !state.online ||
      !c ||
      !verified(c) ||
      !state.drafts[state.selected]?.trim();
  const profile = app.querySelector('#profile-form button[type="submit"]');
  if (profile)
    profile.disabled =
      state.busy.has("profile-form") ||
      app.querySelector("#profile-email").value === state.me.email;
  const verify = app.querySelector('[data-action="verify"]');
  if (verify)
    verify.disabled =
      state.busy.has("verify") || !app.querySelector("#trust-confirm")?.checked;
  for (const key of state.busy) {
    const el = document
      .getElementById(key)
      ?.querySelector('button[type="submit"]');
    if (el) {
      el.disabled = true;
      el.setAttribute("aria-busy", "true");
    }
  }
}
function render() {
  const same = renderedPage === state.page,
    sameContact = renderedContact === state.selected;
  const active = document.activeElement,
    focus = active?.id;
  const position = ["text", "password", "search", "textarea"].includes(
    active?.type,
  )
    ? active.selectionStart
    : null;
  const fields = same
    ? [...app.querySelectorAll("form:not(#send-form) input")].map((e) => ({
        id: e.id,
        value: e.value,
        checked: e.checked,
      }))
    : [];
  const previous = app.querySelector(".messages"),
    scroll = previous?.scrollTop || 0,
    bottom =
      !previous ||
      previous.scrollHeight - previous.scrollTop - previous.clientHeight < 90;
  app.innerHTML = state.me
    ? shell(({ chat, keys, settings, admin }[state.page] || chat)())
    : auth();
  for (const field of fields) {
    const el = document.getElementById(field.id);
    if (el) {
      el.value = field.value;
      el.checked = field.checked;
    }
  }
  if (same && focus && (focus !== "message" || sameContact)) {
    const el = document.getElementById(focus);
    el?.focus({ preventScroll: true });
    if (position !== null && el?.setSelectionRange)
      el.setSelectionRange(position, position);
  }
  const log = app.querySelector(".messages");
  if (log) log.scrollTop = !sameContact || bottom ? log.scrollHeight : scroll;
  if (!same) app.querySelector("main")?.classList.add("view-enter");
  renderedPage = state.page;
  renderedContact = state.selected;
  if (state.page === "settings" && state.identity)
    fingerprint(
      state.identity.public_key,
      state.identity.signing_public_key,
    ).then((f) => {
      const el = app.querySelector("#my-fingerprint");
      if (el)
        el.innerHTML = f
          .match(/.{1,4}/g)
          .map((x) => `<code>${x.toUpperCase()}</code>`)
          .join("");
    });
  syncControls();
}
function modal(title, body) {
  const focus = document.activeElement;
  const dialog = document.createElement("dialog");
  dialog.className = "floating-dialog";
  dialog.setAttribute("aria-label", title);
  dialog.innerHTML = `<header class="dialog-header"><h2>${title}</h2><button type="button" class="icon-button" data-close-dialog aria-label="Fechar janela">${icon("close")}</button></header>${body}`;
  document.body.append(dialog);
  dialog.querySelector("[data-close-dialog]").onclick = () => dialog.close();
  dialog.addEventListener("click", (e) => {
    if (e.target === dialog) {
      const r = dialog.getBoundingClientRect();
      if (
        e.clientX < r.left ||
        e.clientX > r.right ||
        e.clientY < r.top ||
        e.clientY > r.bottom
      )
        dialog.close();
    }
  });
  dialog.addEventListener(
    "close",
    () => {
      dialog.remove();
      if (focus?.isConnected) focus.focus();
    },
    { once: true },
  );
  dialog.showModal();
  return dialog;
}
function confirmAction(title, description, label, action) {
  const dialog = modal(
    title,
    `<p>${description}</p><p class="form-error" role="alert" hidden></p><div class="actions"><button type="button" data-cancel>Cancelar</button><button type="button" class="primary" data-confirm>${label}</button></div>`,
  );
  dialog.querySelector("[data-cancel]").onclick = () => dialog.close();
  dialog.querySelector("[data-cancel]").focus();
  dialog.querySelector("[data-confirm]").onclick = async (e) => {
    const b = e.currentTarget;
    b.disabled = true;
    b.setAttribute("aria-busy", "true");
    try {
      await action();
      dialog.close();
    } catch (error) {
      const el = dialog.querySelector(".form-error");
      el.textContent = error.message;
      el.hidden = false;
    } finally {
      b.disabled = false;
      b.removeAttribute("aria-busy");
    }
  };
}
function updateAppearance(patch, refresh = true) {
  const focused = document.activeElement;
  const panel = focused?.closest(".appearance-panel");
  const field = focused?.dataset;
  const theme = normalizeTheme({ ...state.theme, ...patch });
  try {
    localStorage.setItem("cypherchat.appearance", JSON.stringify(theme));
  } catch {
    notify("Não foi possível salvar sua aparência.", "error");
    return;
  }
  state.theme = theme;
  applyTheme(theme);
  if (refresh) {
    for (const el of document.querySelectorAll(".appearance-panel"))
      el.innerHTML = appearance();
    const selector = field?.themeMode
      ? '[data-theme-mode="' + field.themeMode + '"]'
      : field?.palette
        ? '[data-palette="' + field.palette + '"]'
        : field?.color
          ? '[data-color="' + field.color + '"]'
          : field?.action
            ? '[data-action="' + field.action + '"]'
            : null;
    if (panel && selector)
      panel.querySelector(selector)?.focus({ preventScroll: true });
  } else
    for (const key of ["primary", "secondary"])
      for (const el of document.querySelectorAll(`[data-color-value="${key}"]`))
        el.textContent = theme[key].toUpperCase();
}
document.addEventListener("click", (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  if (b.dataset.themeMode) updateAppearance({ mode: b.dataset.themeMode });
  if (b.dataset.palette) {
    const p = presets.find((p) => p.name === b.dataset.palette);
    updateAppearance({ primary: p.primary, secondary: p.secondary });
  }
  if (b.dataset.action === "reset-theme") {
    updateAppearance(defaults);
    notify("Aparência restaurada.");
  }
});
document.addEventListener("input", (e) => {
  if (e.target.dataset.color)
    updateAppearance({ [e.target.dataset.color]: e.target.value }, false);
});
document.addEventListener("change", (e) => {
  if (e.target.matches("[data-motion]"))
    updateAppearance({ motion: e.target.checked }, false);
  if (e.target.dataset.color)
    updateAppearance({ [e.target.dataset.color]: e.target.value });
});
window.addEventListener("storage", (e) => {
  if (e.key === "cypherchat.appearance") {
    state.theme = readTheme();
    applyTheme(state.theme);
  }
});

async function resumeSession() {
  let saved = null;
  try {
    saved = await loadSession();
    if (!saved) {
      render();
      return;
    }
    state.token = saved.token;
    const me = await api("/me");
    state.me = me;
    if (!saved.identity) {
      if (me.role !== "admin") throw Error("Sessão local sem chaves de usuário");
      state.page = "admin";
      await loadAdmin();
      return;
    }
    const own = await api(`/users/${me.id}/key`);
    if (
      own.public_key !== saved.identity.public_key ||
      own.signing_public_key !== saved.identity.signing_public_key
    )
      throw Error("Sessão local não corresponde às chaves da conta");
    state.identity = saved.identity;
    state.page = "chat";
    const historyWarning = await restoreHistory();
    if (historyWarning) {
      await clearSession();
      Object.assign(state, {
        me: null,
        token: null,
        identity: null,
        page: "login",
        messages: {},
        historyWritable: true,
      });
      render();
      notify(historyWarning, "error");
      return;
    }
    await directory();
    connect();
    render();
  } catch (error) {
    const sessionRejected =
      error.status === 401 || error.message?.startsWith("Sessão local");
    if (!saved || sessionRejected) {
      try {
        await clearSession();
      } catch {
        sessionStorage.removeItem("cypherchat.active-session");
      }
    }
    Object.assign(state, {
      me: null,
      token: null,
      identity: null,
      page: "login",
      messages: {},
      historyWritable: true,
    });
    render();
    if (saved && !sessionRejected)
      notify("Não consegui restaurar a sessão. Ela foi mantida; recarregue quando o servidor voltar.", "error");
  }
}

resumeSession();
