(() => {
  const params = new URLSearchParams(window.location.search);
  const tokenFromUrl = params.get("token") || "";
  let sessionToken = tokenFromUrl;
  if (tokenFromUrl) {
    try {
      sessionStorage.setItem("mesh_gui_token", tokenFromUrl);
      window.history.replaceState({}, document.title, "/");
    } catch (_) {}
  } else {
    try {
      sessionToken = sessionStorage.getItem("mesh_gui_token") || "";
    } catch (_) {}
  }

  let selectedPeer = "";
  let lastActionBanner = "";
  let currentStatusEndpoint = "";
  let currentPin = "";
  let currentNodeName = "";
  let pendingConfirmAction = null;

  const byId = (id) => document.getElementById(id);

  async function apiFetch(path, options = {}) {
    const headers = Object.assign({}, options.headers || {}, {
      "X-Mesh-Session-Token": sessionToken,
    });
    if (options.body && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    const resp = await fetch(path, Object.assign({}, options, { headers }));
    if (path.startsWith("/api/bugreport")) {
      return resp;
    }
    const data = await resp.json();
    if (!resp.ok || data.ok === false) {
      throw new Error(data.error || ("HTTP " + resp.status));
    }
    return data;
  }

  function addBanner(container, cls, text) {
    if (!text) return;
    const div = document.createElement("div");
    div.className = "banner " + cls;
    div.textContent = text;
    container.appendChild(div);
  }

  function renderState(st) {
    byId("state-badge").textContent = st.state_label;
    byId("status-headline").textContent = st.headline;
    byId("tray-summary").textContent = st.tray_summary;
    byId("chk-autostart").checked = Boolean(st.autostart_enabled);
    byId("self-network-panel").textContent = st.self_network_text || "";

    const dot = byId("state-dot");
    dot.className = "dot " + st.tone;

    if (st.server_endpoint) {
      currentStatusEndpoint = st.server_endpoint;
      if (!byId("inp-endpoint").value) {
        byId("inp-endpoint").value = st.server_endpoint;
      }
    }
    if (st.active_pin) {
      currentPin = st.active_pin;
      if (!byId("inp-pin").value) {
        byId("inp-pin").value = st.active_pin;
      }
    }
    if (st.node_name) {
      currentNodeName = st.node_name;
    }

    const banners = byId("banners");
    banners.textContent = "";
    addBanner(banners, "warn", st.legacy_banner);
    addBanner(banners, "warn", st.version_mismatch_banner);
    addBanner(banners, "error", st.recoverable_error);
    addBanner(banners, "info", lastActionBanner);

    const peerList = byId("peer-list");
    peerList.textContent = "";
    for (const p of st.peers || []) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "peer-item" + (p.node_id === selectedPeer ? " selected" : "");
      btn.textContent = p.line;
      btn.addEventListener("click", () => {
        selectedPeer = p.node_id;
        byId("detail-panel").textContent = p.detail;
        refreshState();
      });
      peerList.appendChild(btn);
      if (p.node_id === selectedPeer) {
        byId("detail-panel").textContent = p.detail;
      }
    }
  }

  async function refreshState() {
    try {
      const q = encodeURIComponent(byId("inp-peer-filter").value || "");
      const sel = encodeURIComponent(selectedPeer || "");
      const st = await apiFetch("/api/state?q=" + q + "&selected=" + sel);
      renderState(st);
    } catch (err) {
      const banners = byId("banners");
      banners.textContent = "";
      addBanner(banners, "error", err.message);
    }
  }

  async function updateEndpointLock() {
    const ep = byId("inp-endpoint").value.trim();
    if (!ep) {
      byId("rad-ca").disabled = false;
      byId("ca-lock-hint").textContent = "";
      return;
    }
    try {
      const res = await apiFetch("/api/validate-endpoint?endpoint=" + encodeURIComponent(ep));
      byId("rad-ca").disabled = Boolean(res.lock_system_ca);
      if (res.lock_system_ca) {
        byId("rad-spki").checked = true;
        byId("ca-lock-hint").textContent = "IP literal requires Pinned SPKI (Zero-TOFU).";
      } else {
        byId("ca-lock-hint").textContent = "";
      }
    } catch (_) {}
  }

  function showConfirm(summaryText, actionFn) {
    pendingConfirmAction = actionFn;
    byId("confirm-summary").textContent = summaryText;
    byId("confirm-modal").classList.remove("hidden");
  }

  function hideConfirm() {
    pendingConfirmAction = null;
    byId("confirm-modal").classList.add("hidden");
  }

  async function runAction(label, fn) {
    try {
      lastActionBanner = label + "...";
      await fn();
      lastActionBanner = label + " completed.";
    } catch (err) {
      lastActionBanner = label + " failed: " + err.message;
    }
    await refreshState();
  }

  byId("inp-endpoint").addEventListener("input", updateEndpointLock);
  byId("inp-peer-filter").addEventListener("input", refreshState);

  byId("btn-preview-uri").addEventListener("click", async () => {
    const rawUri = byId("inp-join-uri").value;
    byId("inp-join-uri").value = "";
    await runAction("URI preview", async () => {
      const res = await apiFetch("/api/enroll/preview", {
        method: "POST",
        body: JSON.stringify({
          join_uri: rawUri,
          node_name: byId("inp-nodename").value,
        }),
      });
      byId("inp-endpoint").value = res.form_endpoint;
      byId("inp-pin").value = res.form_spki_pin || "";
      byId(res.form_tls_mode === "system_ca" ? "rad-ca" : "rad-spki").checked = true;
      await updateEndpointLock();
      showConfirm(res.confirmation_summary, async () => {
        await apiFetch("/api/enroll/confirm", { method: "POST", body: "{}" });
      });
    });
  });

  byId("btn-preview-manual").addEventListener("click", async () => {
    const preauth = byId("inp-preauth").value;
    byId("inp-preauth").value = "";
    await runAction("Enrollment preview", async () => {
      const res = await apiFetch("/api/enroll/preview", {
        method: "POST",
        body: JSON.stringify({
          endpoint: byId("inp-endpoint").value,
          tls_mode: byId("rad-ca").checked ? "system_ca" : "spki_pin",
          spki_pin: byId("inp-pin").value,
          preauth_key: preauth,
          node_name: byId("inp-nodename").value,
        }),
      });
      showConfirm(res.confirmation_summary, async () => {
        await apiFetch("/api/enroll/confirm", { method: "POST", body: "{}" });
      });
    });
  });

  byId("btn-confirm-ok").addEventListener("click", async () => {
    const fn = pendingConfirmAction;
    hideConfirm();
    if (!fn) return;
    await runAction("Execute operation", fn);
  });

  byId("btn-confirm-cancel").addEventListener("click", async () => {
    hideConfirm();
    try {
      await apiFetch("/api/enroll/cancel", { method: "POST", body: "{}" });
    } catch (_) {}
  });

  byId("btn-connect").addEventListener("click", () =>
    runAction("Connect tunnel", () =>
      apiFetch("/api/connect", {
        method: "POST",
        body: JSON.stringify({
          endpoint: byId("inp-endpoint").value || currentStatusEndpoint,
          spki_pin: byId("inp-pin").value || currentPin,
          node_name: byId("inp-nodename").value || currentNodeName,
        }),
      }),
    ),
  );

  byId("btn-disconnect").addEventListener("click", () =>
    runAction("Disconnect tunnel", () => apiFetch("/api/disconnect", { method: "POST", body: "{}" })),
  );

  byId("btn-service-start").addEventListener("click", () =>
    runAction("Start/repair meshd.service", () =>
      apiFetch("/api/service/start", { method: "POST", body: "{}" }),
    ),
  );

  byId("btn-cleanup").addEventListener("click", () =>
    runAction("Cleanup OS routes", () => apiFetch("/api/cleanup", { method: "POST", body: "{}" })),
  );

  byId("btn-update-server").addEventListener("click", () =>
    runAction("Update Control server", () =>
      apiFetch("/api/server/update", {
        method: "POST",
        body: JSON.stringify({
          endpoint: byId("inp-endpoint").value,
          tls_mode: byId("rad-ca").checked ? "system_ca" : "spki_pin",
          spki_pin: byId("inp-pin").value,
        }),
      }),
    ),
  );

  byId("btn-rotate-key").addEventListener("click", async () => {
    const preauth = byId("inp-preauth").value;
    byId("inp-preauth").value = "";
    await runAction("Rotate identity key", () =>
      apiFetch("/api/rotate-key", {
        method: "POST",
        body: JSON.stringify({
          endpoint: byId("inp-endpoint").value || currentStatusEndpoint,
          tls_mode: byId("rad-ca").checked ? "system_ca" : "spki_pin",
          spki_pin: byId("inp-pin").value || currentPin,
          preauth_key: preauth,
        }),
      }),
    );
  });

  byId("btn-reset-id").addEventListener("click", () => {
    showConfirm(
      "Reset local node identity?\n\nDeletes local enrollment keys on this machine cleanly.",
      () => apiFetch("/api/reset-identity", { method: "POST", body: "{}" }),
    );
  });

  async function runPing(forceDirect) {
    if (!selectedPeer) {
      lastActionBanner = "Select a peer first.";
      await refreshState();
      return;
    }
    await runAction("Ping", async () => {
      const res = await apiFetch("/api/ping", {
        method: "POST",
        body: JSON.stringify({ target: selectedPeer, force_direct: forceDirect }),
      });
      byId("detail-panel").textContent = res.report;
    });
  }

  byId("btn-ping").addEventListener("click", () => runPing(false));
  byId("btn-ping-direct").addEventListener("click", () => runPing(true));

  byId("btn-netcheck").addEventListener("click", () =>
    runAction("Netcheck", async () => {
      const res = await apiFetch("/api/netcheck", { method: "POST", body: "{}" });
      byId("detail-panel").textContent = res.report;
    }),
  );

  byId("btn-bugreport").addEventListener("click", () =>
    runAction("Export bugreport", async () => {
      const resp = await apiFetch("/api/bugreport");
      if (!resp.ok) {
        const msg = await resp.text();
        throw new Error(msg || "Export failed");
      }
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "meshvpn-bugreport.tar";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }),
  );

  byId("chk-autostart").addEventListener("change", (ev) =>
    runAction("Update autostart", () =>
      apiFetch("/api/autostart", {
        method: "POST",
        body: JSON.stringify({ enabled: Boolean(ev.target.checked) }),
      }),
    ),
  );

  byId("btn-quit").addEventListener("click", async () => {
    try {
      await apiFetch("/api/quit", { method: "POST", body: "{}" });
    } catch (_) {}
    window.close();
  });

  refreshState();
  setInterval(refreshState, 2500);
})();
