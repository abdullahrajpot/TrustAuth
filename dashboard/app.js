(function () {
  "use strict";

  const STORAGE_DEVICE = "trustauth_device";
  const STORAGE_TOKEN = "trustauth_token";
  const STORAGE_API = "trustauth_api_base";
  const STORAGE_BRIDGE = "trustauth_tpm_bridge_base";

  function normalizeBaseUrl(raw, fallback) {
    const value = (raw || "").trim();
    if (!value) return fallback;
    try {
      const parsed = new URL(value);
      if (!/^https?:$/.test(parsed.protocol)) return fallback;
      return parsed.origin;
    } catch {
      return fallback;
    }
  }

  function apiBase() {
    const input = document.getElementById("apiBase");
    const v = (input && input.value) || "";
    return normalizeBaseUrl(v, window.location.origin);
  }

  function saveApiBase() {
    localStorage.setItem(STORAGE_API, apiBase());
  }

  function loadApiBase() {
    const input = document.getElementById("apiBase");
    const saved = localStorage.getItem(STORAGE_API);
    if (input) {
      input.value = normalizeBaseUrl(saved || "", window.location.origin);
    }
  }

  function tpmBridgeBase() {
    const input = document.getElementById("tpmBridgeBase");
    const v = (input && input.value) || "";
    return normalizeBaseUrl(v, "http://127.0.0.1:8740");
  }

  function saveBridgeBase() {
    localStorage.setItem(STORAGE_BRIDGE, tpmBridgeBase());
  }

  function loadBridgeBase() {
    const input = document.getElementById("tpmBridgeBase");
    const saved = localStorage.getItem(STORAGE_BRIDGE);
    if (input) {
      input.value = normalizeBaseUrl(saved || "", "http://127.0.0.1:8740");
    }
  }

  async function tpmBridgeFetch(path, options) {
    const opts = options || {};
    const url = tpmBridgeBase() + path;
    const headers = { ...(opts.headers || {}) };
    if (opts.body != null && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    const res = await fetch(url, { ...opts, headers });
    const text = await res.text();
    let data;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = { detail: text || res.statusText };
    }
    if (!res.ok) {
      const detail = data && data.detail;
      const msg = typeof detail === "string" ? detail : res.statusText;
      throw new Error(msg || "TPM bridge request failed");
    }
    return data;
  }

  async function isBridgeReachable() {
    try {
      const res = await fetch(tpmBridgeBase() + "/health", { method: "GET" });
      return res.ok;
    } catch {
      return false;
    }
  }

  function isLocalDashboardOrigin(origin) {
    if (!origin) return false;
    return (
      origin.includes("localhost") ||
      origin.includes("127.0.0.1") ||
      origin.includes("[::1]")
    );
  }

  function toast(msg, type) {
    const el = document.createElement("div");
    el.className = "toast " + (type === "error" ? "error" : "success");
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 4200);
  }

  function log(line) {
    const box = document.getElementById("activityLog");
    if (!box) return;
    const t = new Date().toLocaleTimeString();
    box.textContent += `[${t}] ${line}\n`;
    box.scrollTop = box.scrollHeight;
  }

  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function spkiToPem(spkiDer) {
    const b64 = arrayBufferToBase64(spkiDer);
    const lines = b64.match(/.{1,64}/g).join("\n");
    return "-----BEGIN PUBLIC KEY-----\n" + lines + "\n-----END PUBLIC KEY-----\n";
  }

  async function generateDeviceKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"]
    );
    const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const pem = spkiToPem(spki);
    const jwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    return { pem, jwk };
  }

  async function importPrivateKey(jwk) {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      true,
      ["sign"]
    );
  }

  async function signChallenge(privateKey, challengeText) {
    const enc = new TextEncoder();
    const sig = await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      privateKey,
      enc.encode(challengeText)
    );
    return arrayBufferToBase64(sig);
  }

  async function api(path, options) {
    const opts = options || {};
    const url = apiBase() + path;
    const headers = { ...(opts.headers || {}) };
    if (opts.body != null && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    const res = await fetch(url, { ...opts, headers });
    const text = await res.text();
    let data;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = { detail: text || res.statusText };
    }
    if (!res.ok) {
      const detail = data && data.detail;
      const msg =
        typeof detail === "string"
          ? detail
          : Array.isArray(detail)
            ? detail.map((d) => d.msg || d).join("; ")
            : res.statusText;
      throw new Error(msg || "Request failed");
    }
    return data;
  }

  function getToken() {
    return localStorage.getItem(STORAGE_TOKEN);
  }

  function setToken(t) {
    if (t) localStorage.setItem(STORAGE_TOKEN, t);
    else localStorage.removeItem(STORAGE_TOKEN);
    updateAuthUI();
  }

  function getDeviceStore() {
    try {
      const raw = localStorage.getItem(STORAGE_DEVICE);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  function setDeviceStore(obj) {
    if (obj) localStorage.setItem(STORAGE_DEVICE, JSON.stringify(obj));
    else localStorage.removeItem(STORAGE_DEVICE);
    updateAuthUI();
  }

  function updateAuthUI() {
    const token = getToken();
    const dev = getDeviceStore();
    const logged = document.getElementById("loggedSection");
    const guestA = document.getElementById("guestSection");
    const guestB = document.getElementById("guestSectionLogin");
    const userLabel = document.getElementById("userLabel");
    if (token) {
      if (logged) logged.hidden = false;
      if (guestA) guestA.hidden = true;
      if (guestB) guestB.hidden = true;
    } else {
      if (logged) logged.hidden = true;
      if (guestA) guestA.hidden = false;
      if (guestB) guestB.hidden = false;
    }
    if (userLabel) {
      userLabel.textContent = dev
        ? dev.username + " · device #" + dev.deviceId
        : "—";
    }
    const hint = document.getElementById("deviceHint");
    if (hint) {
      if (!dev) {
        hint.textContent =
          "Register first. If the TPM bridge is running, your platform TPM is used; otherwise Web Crypto keys stay in this browser.";
      } else if (dev.mode === "tpm-bridge") {
        hint.textContent =
          "This account uses the local TPM bridge (keep `python -m tpm_bridge.server` running). Device #" +
          dev.deviceId +
          ".";
      } else {
        hint.textContent =
          "This browser has a stored Web Crypto key for " +
          dev.username +
          " (device #" +
          dev.deviceId +
          ").";
      }
    }
  }

  async function checkBridgeHealth() {
    const dot = document.getElementById("bridgeDot");
    const label = document.getElementById("bridgeLabel");
    saveBridgeBase();
    try {
      const data = await tpmBridgeFetch("/health", { method: "GET" });
      if (dot) {
        dot.classList.add("ok");
        dot.classList.remove("err");
      }
      if (label) {
        label.textContent =
          "TPM bridge: online" + (data && data.tpm_mode ? " (" + data.tpm_mode + ")" : "");
      }
      log("TPM bridge OK");
    } catch (e) {
      if (dot) {
        dot.classList.add("err");
        dot.classList.remove("ok");
      }
      if (label) label.textContent = "TPM bridge: offline";
      log("TPM bridge: " + e.message);
    }
  }

  async function checkHealth() {
    await checkBridgeHealth();
    const dot = document.getElementById("healthDot");
    const label = document.getElementById("healthLabel");
    try {
      const data = await api("/api/health", { method: "GET" });
      if (dot) {
        dot.classList.add("ok");
        dot.classList.remove("err");
      }
      if (label) label.textContent = "API online · " + (data.time || "");
      log("Health OK");
    } catch (e) {
      if (dot) {
        dot.classList.add("err");
        dot.classList.remove("ok");
      }
      if (label) label.textContent = "API unreachable";
      log("Health failed: " + e.message);
    }
  }

  async function onRegister(e) {
    e.preventDefault();
    const username = document.getElementById("regUsername").value.trim();
    const password = document.getElementById("regPassword").value;
    const email = document.getElementById("regEmail").value.trim();
    const deviceName = document.getElementById("regDeviceName").value.trim() || "This browser";
    if (!username || password.length < 8) {
      toast("Username and password (8+ chars) required.", "error");
      return;
    }
    saveApiBase();
    saveBridgeBase();
    let pem;
    let jwk = null;
    let mode = "web-crypto";
    const canUseBridge = isLocalDashboardOrigin(window.location.origin);
    const useTpm = canUseBridge ? await isBridgeReachable() : false;
    try {
      if (useTpm) {
        log("Using local TPM bridge (platform TPM / helper)…");
        const pub = await tpmBridgeFetch("/public-pem", { method: "GET" });
        pem = pub.public_pem;
        mode = "tpm-bridge";
      } else {
        log("TPM bridge offline; generating Web Crypto key pair…");
        const kp = await generateDeviceKeyPair();
        pem = kp.pem;
        jwk = kp.jwk;
      }
    } catch (err) {
      toast(err.message || "Key setup failed", "error");
      return;
    }
    try {
      const body = {
        username,
        password,
        email: email || null,
        device_name: deviceName,
        device_type: useTpm ? "browser+tpm-bridge" : "browser",
        tpm_public_key: pem,
        pcr_values: [],
      };
      const res = await api("/api/register", { method: "POST", body: JSON.stringify(body) });
      setDeviceStore({ username, deviceId: res.device_id, privateJwk: jwk, mode: mode });
      toast(
        "Registered. Device #" + res.device_id + (useTpm ? " (TPM via bridge)." : " (Web Crypto)."),
        "success"
      );
      log("Registered user " + username + ", device id " + res.device_id);
      updateAuthUI();
    } catch (err) {
      toast(err.message, "error");
      log("Register error: " + err.message);
    }
  }

  async function onLogin(e) {
    e.preventDefault();
    const username = document.getElementById("loginUsername").value.trim();
    const password = document.getElementById("loginPassword").value;
    const dev = getDeviceStore();
    saveApiBase();
    saveBridgeBase();
    if (!dev || dev.username !== username) {
      toast("No device key for this user in this browser. Register first or use the same username.", "error");
      return;
    }
    if (dev.mode === "tpm-bridge") {
      if (!isLocalDashboardOrigin(window.location.origin)) {
        toast(
          "This device is registered using TPM bridge, but the dashboard is not running locally. Re-register using Web Crypto for online usage.",
          "error"
        );
        return;
      }
      if (!(await isBridgeReachable())) {
        toast("TPM bridge is offline. Start: python -m tpm_bridge.server", "error");
        return;
      }
    } else if (!dev.privateJwk) {
      toast("No Web Crypto key stored. Register again.", "error");
      return;
    }
    try {
      log("Requesting challenge…");
      const ch = await api("/api/challenge", {
        method: "POST",
        body: JSON.stringify({ device_id: dev.deviceId }),
      });
      const challenge = ch.challenge;
      let signature;
      if (dev.mode === "tpm-bridge") {
        log("Signing with TPM bridge…");
        const sigRes = await tpmBridgeFetch("/sign", {
          method: "POST",
          body: JSON.stringify({ challenge: challenge }),
        });
        signature = sigRes.signature;
      } else {
        const privateKey = await importPrivateKey(dev.privateJwk);
        signature = await signChallenge(privateKey, challenge);
      }
      log("Sending login…");
      const res = await api("/api/login", {
        method: "POST",
        body: JSON.stringify({
          username,
          password,
          device_id: dev.deviceId,
          challenge_nonce: challenge,
          signature,
        }),
      });
      setToken(res.token);
      toast("Welcome, " + (res.user && res.user.username) + ".", "success");
      log("Login successful.");
      await refreshDashboard();
    } catch (err) {
      toast(err.message, "error");
      log("Login error: " + err.message);
    }
  }

  async function refreshDashboard() {
    const token = getToken();
    if (!token) return;
    saveApiBase();
    try {
      const [devicesRes, sessionsRes] = await Promise.all([
        api("/api/devices", { method: "GET", headers: { Authorization: "Bearer " + token } }),
        api("/api/sessions", { method: "GET", headers: { Authorization: "Bearer " + token } }),
      ]);
      renderDevices(devicesRes.devices || []);
      renderSessions(sessionsRes.sessions || []);
      log("Dashboard refreshed.");
    } catch (err) {
      toast(err.message, "error");
      log("Refresh error: " + err.message);
    }
  }

  function renderDevices(list) {
    const root = document.getElementById("deviceList");
    if (!root) return;
    root.innerHTML = "";
    if (!list.length) {
      root.innerHTML = "<p class=\"help\">No devices yet.</p>";
      return;
    }
    list.forEach((d) => {
      const row = document.createElement("div");
      row.className = "device-row";
      const active = d.is_active;
      row.innerHTML =
        "<div>" +
        "<div class=\"name\">" +
        escapeHtml(d.name) +
        " <span class=\"tag " +
        (active ? "tag-active" : "tag-revoked") +
        "\">" +
        (active ? "Active" : "Revoked") +
        "</span></div>" +
        "<div class=\"meta\">ID " +
        d.id +
        " · " +
        escapeHtml(d.type) +
        " · last used " +
        (d.last_used || "never") +
        "</div></div>";
      const actions = document.createElement("div");
      actions.className = "btn-row";
      if (active) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "btn btn-danger";
        btn.textContent = "Revoke";
        btn.addEventListener("click", () => revokeDevice(d.id));
        actions.appendChild(btn);
      }
      row.appendChild(actions);
      root.appendChild(row);
    });
  }

  function renderSessions(list) {
    const root = document.getElementById("sessionList");
    if (!root) return;
    root.innerHTML = "";
    if (!list.length) {
      root.innerHTML = "<p class=\"help\">No active sessions.</p>";
      return;
    }
    list.forEach((s) => {
      const row = document.createElement("div");
      row.className = "device-row";
      row.innerHTML =
        "<div><div class=\"name\">" +
        escapeHtml(s.device_name) +
        "</div>" +
        "<div class=\"meta\">Session #" +
        s.session_id +
        " · device " +
        s.device_id +
        " · expires " +
        s.expires_at +
        "</div></div>";
      root.appendChild(row);
    });
  }

  function escapeHtml(s) {
    if (!s) return "";
    const div = document.createElement("div");
    div.textContent = s;
    return div.innerHTML;
  }

  async function revokeDevice(deviceId) {
    const token = getToken();
    if (!token) return;
    if (!confirm("Revoke device #" + deviceId + "? Logins from that device will stop working.")) return;
    try {
      await api("/api/devices/" + deviceId, {
        method: "DELETE",
        headers: { Authorization: "Bearer " + token },
      });
      toast("Device revoked.", "success");
      log("Revoked device " + deviceId);
      await refreshDashboard();
    } catch (err) {
      toast(err.message, "error");
    }
  }

  async function onLogout() {
    const token = getToken();
    if (!token) {
      setToken(null);
      return;
    }
    try {
      await api("/api/logout", {
        method: "POST",
        headers: { Authorization: "Bearer " + token },
      });
    } catch {
      /* ignore */
    }
    setToken(null);
    toast("Logged out.", "success");
    log("Logged out.");
    const dl = document.getElementById("deviceList");
    const sl = document.getElementById("sessionList");
    if (dl) dl.innerHTML = "";
    if (sl) sl.innerHTML = "";
    updateAuthUI();
  }

  function onClearDevice() {
    if (!confirm("Remove stored device key from this browser? You will need to register again to log in here.")) return;
    setDeviceStore(null);
    toast("Device key cleared.", "success");
    log("Cleared local device key.");
    updateAuthUI();
  }

  document.addEventListener("DOMContentLoaded", () => {
    loadApiBase();
    loadBridgeBase();
    updateAuthUI();

    const regForm = document.getElementById("registerForm");
    const loginForm = document.getElementById("loginForm");
    if (regForm) regForm.addEventListener("submit", onRegister);
    if (loginForm) loginForm.addEventListener("submit", onLogin);

    const btnHealth = document.getElementById("btnHealth");
    if (btnHealth) btnHealth.addEventListener("click", checkHealth);

    const btnRefresh = document.getElementById("btnRefresh");
    if (btnRefresh) btnRefresh.addEventListener("click", refreshDashboard);

    const btnLogout = document.getElementById("btnLogout");
    if (btnLogout) btnLogout.addEventListener("click", onLogout);

    const btnClearDevice = document.getElementById("btnClearDevice");
    if (btnClearDevice) btnClearDevice.addEventListener("click", onClearDevice);

    const apiInput = document.getElementById("apiBase");
    if (apiInput) apiInput.addEventListener("change", saveApiBase);

    const bridgeInput = document.getElementById("tpmBridgeBase");
    if (bridgeInput) bridgeInput.addEventListener("change", saveBridgeBase);

    checkHealth();
    if (getToken()) {
      refreshDashboard();
    }
  });
})();
