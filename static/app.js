const $ = (selector) => document.querySelector(selector);
const state = { user: null, notes: [] };

async function request(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  let data;
  try { data = await response.json(); } catch { data = { error: "Invalid server response" }; }
  return { status: response.status, data };
}

function setSession(user) {
  state.user = user;
  $("#loginPanel").classList.toggle("hidden", Boolean(user));
  $("#demoPanel").classList.toggle("hidden", !user);
  const badge = $("#sessionBadge");
  badge.textContent = user ? `SESSION: ${user.display_name || user.username}` : "SESSION: NONE";
  badge.className = `session-badge ${user ? "is-signed-in" : "is-signed-out"}`;
}

async function login(username, password) {
  $("#loginError").textContent = "";
  const result = await request("/api/login", { method: "POST", body: JSON.stringify({ username, password }) });
  if (result.status !== 200) { $("#loginError").textContent = result.data.error; return; }
  setSession(result.data);
  await loadNotes();
  chooseOther();
}

async function loadNotes() {
  const result = await request("/api/notes");
  if (result.status !== 200) return;
  state.notes = result.data;
  $("#noteList").replaceChildren(...state.notes.map((note) => {
    const item = document.createElement("div"); item.className = "note";
    const title = document.createElement("b"); title.textContent = note.title;
    const id = document.createElement("span"); id.textContent = `OBJECT ID ${note.id}`;
    item.append(title, id); return item;
  }));
}

function chooseOwn() { if (state.notes[0]) $("#noteId").value = state.notes[0].id; }
function chooseOther() { $("#noteId").value = state.user?.username === "aarav" ? 3 : 1; }

function renderResult(side, result) {
  const status = $(`#${side}Status`); status.textContent = `${result.status} ${statusName(result.status)}`;
  status.className = `http-status ${result.status === 200 ? "ok" : "denied"}`;
  const body = $(`#${side}Result`); body.replaceChildren();
  if (result.status !== 200) {
    const message = document.createElement("p");
    const strong = document.createElement("strong"); strong.textContent = result.data.error || "Request failed";
    message.append(strong, document.createTextNode(result.status === 404 ? "Ownership is not disclosed." : "No note data returned."));
    body.append(message); return;
  }
  const list = document.createElement("dl");
  [["ID", result.data.id], ["Owner", result.data.owner_name || result.data.owner], ["Title", result.data.title], ["Body", "[redacted in UI evidence]"]].forEach(([key, value]) => {
    const dt = document.createElement("dt"); dt.textContent = key;
    const dd = document.createElement("dd"); dd.textContent = value; if (key === "Body") dd.className = "redacted";
    list.append(dt, dd);
  });
  body.append(list);
}

function statusName(status) { return ({ 200: "OK", 401: "Unauthorized", 404: "Not Found" })[status] || "Response"; }

async function compare(unauthenticated = false) {
  const id = Number($("#noteId").value);
  if (!Number.isInteger(id) || id < 1) return;
  $("#compareButton").disabled = true;
  const options = unauthenticated ? { credentials: "omit" } : {};
  const [vulnerable, secure] = await Promise.all([
    request(`/api/vulnerable/notes/${id}`, options), request(`/api/secure/notes/${id}`, options),
  ]);
  renderResult("vulnerable", vulnerable); renderResult("secure", secure);
  const finding = $("#finding"); finding.classList.remove("hidden");
  if (unauthenticated) finding.innerHTML = `<strong>Authentication control:</strong> both endpoints return 401 without a session. Authentication alone does not prove object ownership.`;
  else if (vulnerable.status === 200 && secure.status === 404 && vulnerable.data.owner !== state.user.username) finding.innerHTML = `<strong>BOLA_REPRODUCED:</strong> the vulnerable endpoint returned ${escapeText(vulnerable.data.owner_name || vulnerable.data.owner)}'s object to ${escapeText(state.user.display_name || state.user.username)}. The secure endpoint concealed it with 404.`;
  else if (vulnerable.status === 200 && secure.status === 200) finding.innerHTML = `<strong>Expected owner access:</strong> both endpoints return the current user's note. The difference appears when the object belongs to someone else.`;
  else finding.innerHTML = `<strong>Comparison complete:</strong> inspect the two status codes and response shapes above.`;
  $("#compareButton").disabled = false;
}

function escapeText(value) { const node = document.createElement("span"); node.textContent = value; return node.innerHTML; }

document.querySelectorAll(".account-button").forEach((button) => button.addEventListener("click", () => login(button.dataset.user, button.dataset.password)));
$("#compareButton").addEventListener("click", () => compare(false));
$("#ownButton").addEventListener("click", () => { chooseOwn(); compare(false); });
$("#otherButton").addEventListener("click", () => { chooseOther(); compare(false); });
$("#unauthButton").addEventListener("click", () => compare(true));
$("#logoutButton").addEventListener("click", async () => { await request("/api/logout", { method: "POST" }); state.notes = []; setSession(null); });

(async () => { const me = await request("/api/me"); if (me.status === 200) { setSession(me.data); await loadNotes(); chooseOther(); } else setSession(null); })();
