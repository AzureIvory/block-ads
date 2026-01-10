// 禁止进入调试模式
function banDev() {
  document.addEventListener(
    "contextmenu",
    function (e) {
      e.preventDefault();
    },
    true
  );
  document.addEventListener(
    "keydown",
    function (e) {
      if (e.key === "F12") {
        e.preventDefault();
        return;
      }
      if (e.ctrlKey && e.shiftKey) {
        const k = e.key.toUpperCase();
        if (k === "I" || k === "J" || k === "C" || k === "K") {
          e.preventDefault();
        }
      }
    },
    true
  );
}

const st = {
  dat: { sign: [], folder: [], whitelist: [], signWhite: [] },
  note: {},
  log: [],
  key: "sign",
  sel: -1,
  filt: "",
  adm: false,
  run: false,
  boot: false,
  ctxp: "",
  ctx: null,
};

async function callMaybe(fn, ...args) {
  try {
    if (typeof window[fn] !== "function") return null;
    return await window[fn](...args);
  } catch (e) {
    throw e;
  }
}

function lsGet(k, def) {
  try {
    const v = localStorage.getItem(k);
    return v == null ? def : v;
  } catch (_) {
    return def;
  }
}
function lsSet(k, v) {
  try { localStorage.setItem(k, v); } catch (_) {}
}

function modalShow(id) {
  const m = document.getElementById(id);
  if (!m) return;
  m.classList.add("show");
  m.setAttribute("aria-hidden", "false");
}
function modalHide(id) {
  const m = document.getElementById(id);
  if (!m) return;
  m.classList.remove("show");
  m.setAttribute("aria-hidden", "true");
}


// 全局等待弹窗
let __waitTok = 0;
let __waitCur = 0;
let __updWait = 0;
let __syncWait = 0;

function waitShow(text, mode) {
  const w = document.getElementById("waitOverlay");
  if (!w) return;
  const box = document.getElementById("waitBox");
  const gif = document.getElementById("waitGif");
  const txt = document.getElementById("waitText");

  if (txt) txt.textContent = text || "";
  const isErr = mode === "error";
  const isLoading = mode === "loading";

  if (gif) {
    gif.style.display = isLoading ? "block" : "none";
    // gif未就绪时隐藏
    gif.style.visibility = (__waitGifReady || !isLoading) ? "visible" : "hidden";
  }
  if (box) box.classList.toggle("err", isErr);

  w.classList.add("show");
  w.setAttribute("aria-hidden", "false");
}

function waitHide() {
  const w = document.getElementById("waitOverlay");
  if (!w) return;
  w.classList.remove("show");
  w.setAttribute("aria-hidden", "true");
}

function waitStart(text) {
  __waitCur = ++__waitTok;
  waitShow(text, "loading");
  return __waitCur;
}

function waitDone(tok, text, isErr) {
  if (!tok || tok !== __waitCur) return;
  waitShow(text, isErr ? "error" : "info");
  if (!isErr) {
    setTimeout(function () {
      if (tok === __waitCur) waitHide();
    }, 1100);
  }
}

// 仅关闭弹窗，不中断后台任务
function waitDismiss() {
  __waitCur = 0;
  __updWait = 0;
  __syncWait = 0;
  waitHide();
}

function initWaitOverlay() {
  const w = document.getElementById("waitOverlay");
  if (!w) return;

  w.addEventListener("click", function (e) {
    const t = e.target;
    if (t === w || (t && t.classList && t.classList.contains("wait-mask"))) {
      waitDismiss();
    }
  });

  const btn = document.getElementById("waitClose");
  if (btn) {
    btn.addEventListener("click", function (e) {
      e.preventDefault();
      e.stopPropagation();
      waitDismiss();
    });
  }
}

function esc(s) {
  return (s || "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
}

function fmtSizeTextFromKB(kb) {
  const n = Number(kb || 0);
  if (!isFinite(n) || n <= 0) return "-";
  if (n > 1024) return (n / 1024).toFixed(2) + " MB";
  return Math.round(n) + " KB";
}

let __waitGifReady = false;

function preloadWaitGif() {
  try {
    const img = new Image();
    img.decoding = "async";
    img.onload = function () {
      __waitGifReady = true;
      const el = document.getElementById("waitGif");
      if (el) el.style.visibility = "visible";
    };
    img.onerror = function () {
      // gif加载失败时只显示文字
      __waitGifReady = false;
      const el = document.getElementById("waitGif");
      if (el) el.style.display = "none";
    };
    img.src = "wait.gif";
  } catch (e) {
    console.warn("preloadWaitGif failed:", e);
  }
}

function nextFrame() {
  return new Promise((resolve) => requestAnimationFrame(() => resolve()));
}

function isWaitShowing() {
  const w = document.getElementById("waitOverlay");
  return !!(w && w.classList.contains("show"));
}

let lastUpdInfo = null;
let lastSyncInfo = null;

let pendingUpdShowMsg = false;
let pendingSyncShowMsg = false;

let upBusy = false;

window.__onDoUpd = function (res) {
  const ok = !!(res && res.ok);
  if (ok) {
    const started = !!(res && res.started);
    const txt = started ? "已启动更新流程，界面将关闭并更新。" : "未执行更新。";
    if (__updWait) waitDone(__updWait, txt, false);
    setMsg(txt, false);
  } else {
    const txt = "更新失败: " + (res && res.err ? res.err : "unknown");
    if (__updWait) waitDone(__updWait, txt, true);
    setMsg(txt, true);
  }
  __updWait = 0;
};

window.__onChkSync = function (res) {
  const ok = !!(res && res.ok);
  if (ok) {
    renderSync(res.info);

    let txt = "已检查同步。";
    const items = res && res.info && Array.isArray(res.info.items) ? res.info.items : [];
    if (items.length) {
      const need = items.some((it) => it && it.need);
      txt = need ? "检查完成：有需要同步的项目。" : "无需同步，均已同步。";
    }
    if (__syncWait) waitDone(__syncWait, txt, false);
    if (pendingSyncShowMsg) setMsg(txt, false);
  } else {
    const txt = "检查同步失败: " + (res && res.err ? res.err : "unknown");
    if (__syncWait) waitDone(__syncWait, txt, true);
    if (pendingSyncShowMsg) setMsg(txt, true);
  }
  pendingSyncShowMsg = false;
  __syncWait = 0;
};


// 上传回调
window.__onUp = function (res) {
  upBusy = false;
  const btn = document.getElementById("btnUploadGo");
  if (btn) btn.disabled = false;

  const ok = !!(res && res.ok);
  if (ok) {
    const u = res && res.url ? ("\n" + res.url) : "";
    setMsg("上传成功。" + u, false);
  } else {
    setMsg("上传失败: " + (res && res.err ? res.err : "unknown"), true);
  }
};

function renderUpd(info) {
  lastUpdInfo = info || null;
  const ver = document.getElementById("updVer");
  const at = document.getElementById("updAt");
  const notes = document.getElementById("updNotes");
  const list = document.getElementById("updList");
  const mand = document.getElementById("updMandatory");
  const sub = document.getElementById("updSub");

  if (!info) {
    if (ver) ver.textContent = "v-";
    if (at) at.textContent = "未检测";
    if (notes) notes.textContent = "";
    if (list) list.innerHTML = "";
    if (mand) mand.style.display = "none";
    if (sub) sub.textContent = "检测新版本并更新程序文件";
    return;
  }

  const sv = info.server_version || "-";
  const lv = info.local_version || "-";
  if (ver) ver.textContent = "v" + sv;
  if (at) at.textContent = (info.updated_at ? ("更新日期：" + info.updated_at) : "") + (info.has_update ? " · 有新版本" : " · 已是最新");
  if (sub) sub.textContent = "本地 v" + lv + " → 在线 v" + sv;
  if (mand) {
    mand.style.display = info.mandatory ? "inline-flex" : "none";
  }
  if (notes) {
    const nt = info.notes || "";
    notes.textContent = nt ? ("更新说明：\n" + nt) : "更新说明：无";
  }
  if (list) {
    const items = Array.isArray(info.items) ? info.items : [];
    if (!items.length) {
      list.innerHTML = `<div class="u-notes">暂无文件列表</div>`;
    } else {
      list.innerHTML = items
        .map((it) => {
          const need = !!it.need;
          const sz = it.size_text || fmtSizeTextFromKB(it.size_kb);
          const run = it.run ? "更新后执行" : "";
          const tag = need ? `<span class="u-chip bad">需要更新</span>` : `<span class="u-chip good">已是最新</span>`;
          const p = it.path || it.name || "";
          return `
            <div class="u-item ${need ? "" : "locked"}">
              <input class="u-check" type="checkbox" ${need ? "checked" : ""} disabled />
              <div class="u-main">
                <p class="u-name">${esc(it.name || p)}</p>
                <p class="u-desc">路径：${esc(p)} · 大小：${esc(sz)}${run ? " · " + run : ""}</p>
              </div>
              <div class="u-meta">
                ${tag}
              </div>
            </div>`;
        })
        .join("");
    }
  }
}

function renderSync(info) {
  lastSyncInfo = info || null;
  const at = document.getElementById("syncAt");
  const notes = document.getElementById("syncNotes");
  const list = document.getElementById("syncList");
  if (!info) {
    if (at) at.textContent = "未检查";
    if (notes) notes.textContent = "";
    if (list) list.innerHTML = "";
    return;
  }
  if (at) at.textContent = info.updated_at ? ("同步日期：" + info.updated_at) : "";
  if (notes) notes.textContent = (info.notes ? ("同步说明：\n" + info.notes) : "同步说明：无");
  if (list) {
    const items = Array.isArray(info.items) ? info.items : [];
    const selected = new Set(JSON.parse(lsGet("syncSelected", "[]") || "[]"));
    list.innerHTML = items
      .map((it) => {
        const need = !!it.need;
        const id = it.name || "";
        const checked = selected.has(id);
        const sz = it.size_text || fmtSizeTextFromKB(it.size_kb);
        const cnt = it.count ? (" · 行数：" + it.count) : "";
        const tag = need ? `<span class="u-chip bad">需同步</span>` : `<span class="u-chip good">已同步</span>`;
        return `
          <label class="u-item">
            <input class="u-check sync-item" type="checkbox" data-id="${esc(id)}" ${checked ? "checked" : ""} />
            <div class="u-main">
              <p class="u-name">${esc(it.name || "")}</p>
              <p class="u-desc">大小：${esc(sz)}${cnt}</p>
            </div>
            <div class="u-meta">${tag}</div>
          </label>`;
      })
      .join("");
  }

  applySyncPolicyUI();
}

function syncFilterApply() {
  const inp = document.getElementById("syncFilter");
  const q = ((inp && inp.value) || "").trim().toLowerCase();
  document.querySelectorAll("#syncList .u-item").forEach((el) => {
    const txt = el.innerText.toLowerCase();
    el.style.display = !q || txt.includes(q) ? "" : "none";
  });
}

function syncSelectedCacheFromUI() {
  const ids = Array.from(document.querySelectorAll(".sync-item"))
    .filter((cb) => cb.checked)
    .map((cb) => cb.dataset.id)
    .filter(Boolean);
  lsSet("syncSelected", JSON.stringify(ids));
}

function getUpdPolicy() {
  return lsGet("updPolicy", "prompt");
}
function setUpdPolicy(v) {
  lsSet("updPolicy", v);
  document.querySelectorAll('input[name="updPolicy"]').forEach((r) => {
    r.checked = r.value === v;
  });
}
function getSyncPolicy() {
  return lsGet("syncPolicy", "auto_selected");
}
function setSyncPolicy(v) {
  lsSet("syncPolicy", v);
  document.querySelectorAll('input[name="syncPolicy"]').forEach((r) => {
    r.checked = r.value === v;
  });
}

function getSyncSelectedSet() {
  try {
    const raw = lsGet("syncSelected", "[]");
    const arr = JSON.parse(raw);
    const s = new Set();
    (Array.isArray(arr) ? arr : []).forEach((x) => s.add(String(x)));
    return s;
  } catch (_) {
    return new Set();
  }
}

function restoreSyncSelectedToUI() {
  const set = getSyncSelectedSet();
  document.querySelectorAll(".sync-item").forEach((cb) => {
    const id = cb.dataset.id;
    if (id) cb.checked = set.has(id);
  });
}

function applySyncPolicyUI() {
  const p = getSyncPolicy();
  const cbs = Array.from(document.querySelectorAll(".sync-item"));

  if (p === "never") {
    cbs.forEach((cb) => {
      cb.checked = false;
      cb.disabled = true;
    });
    return;
  }

  if (p === "auto_all") {
    cbs.forEach((cb) => {
      cb.checked = true;
      cb.disabled = true;
    });
    syncSelectedCacheFromUI();
    return;
  }

  // auto_selected
  cbs.forEach((cb) => (cb.disabled = false));
  restoreSyncSelectedToUI();
}

async function checkUpdate(showMsg) {
  const p = getUpdPolicy();

  const mdl = document.getElementById("mdlUpdate");
  const shouldPopup = !!(showMsg || (mdl && mdl.classList.contains("show")));

  if (p === "never") {
    renderUpd({ local_version: "-", server_version: "-", has_update: false, notes: "已关闭更新。", items: [] });
    if (shouldPopup) {
      __updWait = waitStart("检测更新");
      await nextFrame();
      waitDone(__updWait, "已关闭更新。", false);
      __updWait = 0;
    }
    if (showMsg) setMsg("已关闭更新。", true);
    return null;
  }

  if (shouldPopup) __updWait = waitStart("检测更新中...");
      await nextFrame();

  try {
    // 异步
    if (typeof window.chkUpdAsync === "function") {
      pendingUpdShowMsg = !!showMsg;
      if (shouldPopup) {
        __updWait = waitStart("检测更新");
        await nextFrame();
      }
      if (showMsg) setMsg("检测更新中...", false);
      callMaybe("chkUpdAsync");
      return null;
    }

    // 同步
    const info = await callMaybe("chkUpd");
    renderUpd(info);

    const txt = info && info.has_update ? "发现新版本。" : "已是最新版本。";
    if (__updWait) waitDone(__updWait, txt, false);
    __updWait = 0;

    if (showMsg) setMsg(txt, false);
    return info;
  } catch (e) {
    console.error(e);
    const txt = "检测更新失败: " + (e && e.message ? e.message : String(e));
    if (__updWait) waitDone(__updWait, txt, true);
    __updWait = 0;

    if (showMsg) setMsg(txt, true);
    return null;
  }
}

async function doUpdateNow(force) {
  const p = getUpdPolicy();
  if (p === "never") {
    setMsg("已关闭更新。", true);
    return;
  }
  if (!lastUpdInfo || !lastUpdInfo.has_update) {
    setMsg("未发现可更新内容。", false);
    return;
  }
  if (!force) {
    if (!confirm("确认开始更新吗？更新过程中可能会短暂关闭界面。")) return;
  }
  try {
    const __tok = waitStart("更新中...");
    __updWait = __tok;
    await nextFrame();
    setMsg("更新中...", false);
    await callMaybe("doUpdAsync");
  } catch (e) {
    console.error(e);
    const txt = "更新失败: " + (e && e.message ? e.message : String(e));
    setMsg(txt, true);
    if (__updWait) waitDone(__updWait, txt, true);
    __updWait = 0;
  }
}

async function checkSync(showMsg) {
  const p = getSyncPolicy();

  const mdl = document.getElementById("mdlSync");
  const shouldPopup = !!(showMsg || (mdl && mdl.classList.contains("show")));

  if (p === "never") {
    renderSync({ updated_at: "-", notes: "已关闭同步。", items: [] });
    if (shouldPopup) {
      __syncWait = waitStart("检查同步");
      await nextFrame();
      waitDone(__syncWait, "已关闭同步。", false);
      __syncWait = 0;
    }
    if (showMsg) setMsg("已关闭同步。", true);
    return null;
  }

  if (shouldPopup) __syncWait = waitStart("检查同步中...");
      await nextFrame();

  try {
    // 异步
    if (typeof window.chkSyncAsync === "function") {
      pendingSyncShowMsg = !!showMsg;
      if (shouldPopup) {
        __syncWait = waitStart("检查同步");
        await nextFrame();
      }
      if (showMsg) setMsg("检查同步中...", false);
      callMaybe("chkSyncAsync");
      return null;
    }

    // 同步
    const info = await callMaybe("chkSync");
    renderSync(info);

    let txt = "已检查同步。";
    const items = info && Array.isArray(info.items) ? info.items : [];
    if (items.length) {
      const need = items.some((it) => it && it.need);
      txt = need ? "检查完成：有需要同步的项目。" : "无需同步，均已同步。";
    }

    if (__syncWait) waitDone(__syncWait, txt, false);
    __syncWait = 0;

    if (showMsg) setMsg(txt, false);
    return info;
  } catch (e) {
    console.error(e);
    const txt = "检查同步失败: " + (e && e.message ? e.message : String(e));
    if (__syncWait) waitDone(__syncWait, txt, true);
    __syncWait = 0;

    if (showMsg) setMsg(txt, true);
    return null;
  }
}

async function doSyncNow() {
  const p = getSyncPolicy();
  if (p === "never") {
    setMsg("已关闭同步。", true);
    return;
  }
  syncSelectedCacheFromUI();
  const selected = JSON.parse(lsGet("syncSelected", "[]") || "[]");
  const payload = {
    policy: p,
    selected: selected,
  };
  try {
    const __tok = waitStart("同步中...");
    await nextFrame();
    setMsg("同步中...", false);
    const ok = await callMaybe("doSync", payload);
    setMsg(ok ? "同步完成。" : "未执行同步。", !ok);
    await checkSync(false);
    if (__tok === __waitCur) waitHide();
  } catch (e) {
    console.error(e);
    setMsg("同步失败: " + e, true);
    if (__tok === __waitCur) waitShow("同步失败: " + (e && e.message ? e.message : String(e)), "error");
  }
}

function setMsg(t, err) {
  const el = document.getElementById("msg");
  if (!el) return;
  el.textContent = t || "";
  el.style.color = err ? "#b91c1c" : "#6b7280";
}

// 侧边栏计数
function updCounts() {
  const ids = [
    ["sign", "cnt-sign"],
    ["folder", "cnt-folder"],
    ["whitelist", "cnt-whitelist"],
    ["signWhite", "cnt-signWhite"],
  ];
  ids.forEach(function (it) {
    const k = it[0];
    const id = it[1];
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = String((st.dat[k] || []).length);
  });
}

// 当前列表数量
function updListHead() {
  const el = document.getElementById("lstCnt");
  if (!el) return;
  const n = (st.dat[st.key] || []).length;
  el.textContent = "(" + n + ")";
}

// 更新状态
function updSta(s) {
  if (!s) return;
  st.adm = !!s.adm;
  st.run = !!s.run;
  st.boot = !!s.boot;

  const chkBoot = document.getElementById("chkBoot");
  if (chkBoot) chkBoot.checked = !!st.boot;

  const admEl = document.getElementById("admTxt");
  if (admEl) {
    admEl.textContent = st.adm ? "管理员" : "非管理员";
    admEl.style.color = st.adm ? "#16a34a" : "#b91c1c";
  }

  const runEl = document.getElementById("runTxt");
  if (runEl) {
    runEl.textContent = st.run ? "已运行" : "未运行";
    runEl.style.color = st.run ? "#16a34a" : "#6b7280";
  }

  const svc = document.getElementById("svcSta");
  if (svc) {
    svc.textContent = st.run ? "运行中" : "未运行";
  }
  const mode = document.getElementById("modeTxt");
  if (mode) {
    mode.textContent = st.adm ? "Admin Mode" : "User Mode";
  }

  // 顶部主按钮
  const btn = document.getElementById("btnRun");
  if (btn) {
    if (st.run) {
      btn.classList.remove("btn-primary");
      btn.classList.add("btn-danger");
      btn.innerHTML = `<span class="ico-play">■</span>停止`;
    } else {
      btn.classList.remove("btn-danger");
      btn.classList.add("btn-primary");
      btn.innerHTML = `<span class="ico-play">▶</span>启动`;
    }
  }

  const btnStop = document.getElementById("btnStop");
  if (btnStop) {
    btnStop.disabled = !st.run;
  }
}

// 渲染规则列表
function rend() {
  const ul = document.getElementById("lst");
  if (!ul) return;
  ul.innerHTML = "";

  const list = st.dat[st.key] || [];
  const f = (st.filt || "").toLowerCase();

  updCounts();
  updListHead();

  list.forEach(function (line, idx) {
    const note = st.note[line] || "";
    const t1 = (line || "").toLowerCase();
    const t2 = (note || "").toLowerCase();
    if (f && t1.indexOf(f) === -1 && t2.indexOf(f) === -1) return;

    const li = document.createElement("li");
    li.className = "rule-row";
    li.dataset.idx = String(idx);

    const cb = document.createElement("label");
    cb.className = "cb";
    const cbi = document.createElement("input");
    cbi.type = "checkbox";
    cbi.checked = idx === st.sel;
    cbi.addEventListener("click", function (e) {
      e.stopPropagation();
      selIdx(idx);
    });
    const cbs = document.createElement("span");
    cb.appendChild(cbi);
    cb.appendChild(cbs);

    const main = document.createElement("div");
    main.className = "rule-main";
    const title = document.createElement("div");
    title.className = "rule-title";
    title.textContent = line;
    const sub = document.createElement("div");
    sub.className = "rule-sub";
    
    if (st.key === "sign" || st.key === "signWhite") {
      sub.textContent = "Sign";
    } else {
      sub.textContent = "Path";
    }
    main.appendChild(title);
    main.appendChild(sub);

    const noteEl = document.createElement("div");
    noteEl.className = "rule-note" + (note ? "" : " muted");
    noteEl.textContent = note || "无注释";

    li.appendChild(cb);
    li.appendChild(main);
    li.appendChild(noteEl);

    if (idx === st.sel) {
      li.classList.add("sel");
      cb.classList.add("cb-on");
    }
    li.addEventListener("click", function () {
      selIdx(idx);
    });
    ul.appendChild(li);
  });
}

function selIdx(idx) {
  st.sel = idx;
  document.querySelectorAll("#lst li").forEach(function (li) {
    const v = parseInt(li.dataset.idx, 10);
    const cb = li.querySelector(".cb");
    const cbi = li.querySelector("input[type=checkbox]");
    if (v === idx) {
      li.classList.add("sel");
      if (cb) cb.classList.add("cb-on");
      if (cbi) cbi.checked = true;
    } else {
      li.classList.remove("sel");
      if (cb) cb.classList.remove("cb-on");
      if (cbi) cbi.checked = false;
    }
  });
}

// 解析日志
function pLog(line) {
  const ps = (line || "").split("--");
  if (ps.length < 5) return null;
  return {
    t: ps[0],
    k: ps[1],
    v: ps[2],
    m: ps[3],
    p: ps.slice(4).join("--"),
  };
}

// 定位文件
function logOpen(p) {
  if (!p) return;
  if (typeof opSel !== "function") {
    setMsg("未绑定文件打开函数。", true);
    return;
  }
  opSel(p).catch(function (e) {
    console.error(e);
    setMsg("打开失败: " + e, true);
  });
}

// 右键菜单
function hideCtx() {
  const m = document.getElementById("logMenu");
  if (!m) return;
  m.style.display = "none";
}
function showCtx(x, y) {
  const m = document.getElementById("logMenu");
  if (!m) return;
  m.style.display = "block";

  const w = m.offsetWidth;
  const h = m.offsetHeight;
  const vw = window.innerWidth;
  const vh = window.innerHeight;

  let lx = x;
  let ly = y;
  if (lx + w > vw) lx = vw - w - 4;
  if (ly + h > vh) ly = vh - h - 4;

  m.style.left = lx + "px";
  m.style.top = ly + "px";
}

// 渲染拦截列表
function rendLog() {
  const ul = document.getElementById("logLst");
  const info = document.getElementById("logInfo");
  if (!ul) return;
  ul.innerHTML = "";
  const list = st.log || [];

  if (!list.length) {
    if (info) info.textContent = "今日暂无记录";
    return;
  }
  if (info) info.textContent = "共 " + list.length + " 条";

  list.forEach(function (line) {
    const it = pLog(line);
    const li = document.createElement("li");
    li.className = "log-row";
    li.title = line;

    if (!it) {
      li.textContent = line;
      ul.appendChild(li);
      return;
    }

    li.dataset.path = it.p || "";
    li.dataset.kind = it.k || "";
    li.dataset.val = it.v || "";

    // 判断状态
    let status = "放行";
    let dotCls = "dot-amber";
    const kind = (it.k || "").toLowerCase();
    const val = it.v || "";

    if (kind === "sign") {
      if ((st.dat.sign || []).indexOf(val) !== -1) {
        status = "黑名单命中";
        dotCls = "dot-red";
      } else if ((st.dat.signWhite || []).indexOf(val) !== -1) {
        status = "白名单放行";
        dotCls = "dot-green";
      }
    } else if (kind === "folder") {
      if ((st.dat.folder || []).indexOf(val) !== -1) {
        status = "黑名单命中";
        dotCls = "dot-red";
      } else if ((st.dat.whitelist || []).indexOf(val) !== -1) {
        status = "白名单放行";
        dotCls = "dot-green";
      }
    }

    const dot = document.createElement("div");
    dot.className = "dot " + dotCls;

    const tm = document.createElement("div");
    tm.className = "log-time";
    tm.textContent = "[" + (it.t || "") + "]";

    const proc = document.createElement("div");
    proc.className = "log-proc";
    proc.textContent = it.m || (it.k || "");

    const path = document.createElement("div");
    path.className = "log-path";
    path.textContent = it.p || it.v || "";

    const stx = document.createElement("div");
    stx.className = "log-status";
    stx.textContent = "- " + status;

    li.appendChild(dot);
    li.appendChild(tm);
    li.appendChild(proc);
    li.appendChild(path);
    li.appendChild(stx);

    li.addEventListener("dblclick", function () {
      const p = this.dataset.path || "";
      if (p) logOpen(p);
    });
    li.addEventListener("contextmenu", function (e) {
      e.preventDefault();
      const p = this.dataset.path || "";
      if (!p) return;
      st.ctxp = p;
      st.ctx = {
        k: this.dataset.kind || "",
        v: this.dataset.val || "",
        p: p,
      };
      showCtx(e.clientX, e.clientY);
    });

    ul.appendChild(li);
  });
}

function openAddModal() {
  const m = document.getElementById("mdlAdd");
  if (!m) return;
  m.classList.add("show");
  m.setAttribute("aria-hidden", "false");
  const hint = document.getElementById("addHint");
  if (hint) {
    const map = {
      sign: "签名黑名单",
      folder: "目录黑名单",
      whitelist: "目录白名单",
      signWhite: "签名白名单",
    };
    hint.textContent = "当前：" + (map[st.key] || st.key);
  }
  const inp = document.getElementById("newL");
  if (inp) {
    inp.value = "";
    setTimeout(function () {
      inp.focus();
    }, 0);
  }
}

function closeAddModal() {
  const m = document.getElementById("mdlAdd");
  if (!m) return;
  m.classList.remove("show");
  m.setAttribute("aria-hidden", "true");
}

async function onAdd() {
  const inp = document.getElementById("newL");
  const txt = ((inp && inp.value) || "").trim();
  if (!txt) {
    setMsg("内容为空。", true);
    return;
  }
  try {
    const v = await addLn(st.key, txt);
    st.dat[st.key] = v || [];
    st.sel = st.dat[st.key].length - 1;
    st.filt = "";
    const sr = document.getElementById("srch");
    if (sr) sr.value = "";
    if (inp) inp.value = "";
    closeAddModal();
    rend();
    setMsg("已添加。", false);
  } catch (e) {
    console.error(e);
    setMsg("添加失败: " + e, true);
  }
}

async function onDel() {
  if (st.sel < 0) {
    setMsg("请先选择一行。", true);
    return;
  }
  if (!confirm("确定删除当前选中行吗？")) {
    return;
  }
  try {
    const v = await delLn(st.key, st.sel);
    st.dat[st.key] = v || [];
    st.sel = -1;
    rend();
    setMsg("已删除。", false);
  } catch (e) {
    console.error(e);
    setMsg("删除失败: " + e, true);
  }
}

let runBusy = false;

async function onToggleRun() {
  if (runBusy) return;
  runBusy = true;
  try {
    if (!st.run) {
      setMsg("启动中...", false);
      await doRun();
      const s = await stChk();
      updSta(s);
      setMsg(st.run ? "启动成功。" : "已尝试启动。", !st.run);
    } else {
      if (!confirm("是否停止拦截进程？")) {
        return;
      }
      setMsg("停止中...", false);
      await doStop();
      const s = await stChk();
      updSta(s);
      setMsg(!st.run ? "已停止。" : "停止可能未成功。", st.run);
    }
  } catch (e) {
    console.error(e);
    setMsg("操作失败: " + e, true);
  } finally {
    runBusy = false;
  }
}

async function onStop() {
  if (!st.run) return;
  if (!confirm("是否停止拦截进程？")) return;
  setMsg("停止中...", false);
  try {
    await doStop();
    const s = await stChk();
    updSta(s);
    setMsg("已尝试停止。", false);
  } catch (e) {
    console.error(e);
    setMsg("停止失败: " + e, true);
  }
}

async function onBoot(ev) {
  const on = ev.target.checked;
  setMsg("更新启动项...", false);
  try {
    const v = await setAut(on);
    st.boot = !!v;
    const chk = document.getElementById("chkBoot");
    if (chk) chk.checked = st.boot;
    setMsg("", false);
  } catch (e) {
    console.error(e);
    ev.target.checked = !on;
    setMsg("设置失败: " + e, true);
  }
}

async function onHel() {
  try {
    await doHel();
    setMsg("", false);
  } catch (e) {
    console.error(e);
    setMsg("无法打开使用指南: " + e, true);
  }
}

async function onFak() {
  setMsg("伪装中...", false);
  try {
    const ok = await doFak();
    if (ok) setMsg("一键伪装已执行。", false);
    else setMsg("伪装未完全成功。", true);
  } catch (e) {
    console.error(e);
    setMsg("伪装失败: " + e, true);
  }
}

async function onGit() {
  try {
    await doGit();
    setMsg("", false);
  } catch (e) {
    console.error(e);
    setMsg("无法打开 GitHub: " + e, true);
  }
}

// 刷新日志
async function refLog() {
  try {
    const lg = await getLog();
    if (lg) {
      st.log = lg;
      rendLog();
    }
  } catch (e) {
    console.error(e);
  }
}

// 从日志加入白名单
async function AddWhite() {
  const ctx = st.ctx || {};
  const kind = (ctx.k || "").toLowerCase();
  const val = ctx.v || "";
  const p = ctx.p || "";

  if (!kind) {
    setMsg("无法识别当前记录类型。", true);
    return;
  }

  try {
    const ok = await addWht(kind, val, p);
    if (ok) {
      setMsg("已加入白名单。", false);
      const all = await getAll();
      if (all) {
        st.dat = all;
        rend();
      }
    } else {
      setMsg("未添加，可能已经在白名单中。", false);
    }
  } catch (e) {
    console.error(e);
    setMsg("加入白名单失败: " + e, true);
  }
}

// 初始化
function initUI() {
  initWaitOverlay();
  preloadWaitGif();
  document.querySelectorAll(".tab").forEach(function (btn) {
    btn.addEventListener("click", function () {
      swTab(btn.dataset.key);
    });
  });

  const sr = document.getElementById("srch");
  if (sr) {
    sr.addEventListener("input", function (e) {
      st.filt = e.target.value || "";
      rend();
    });
  }

  const btnAdd = document.getElementById("btnAdd");
  if (btnAdd) btnAdd.addEventListener("click", openAddModal);

  const btnDel = document.getElementById("btnDel");
  if (btnDel) btnDel.addEventListener("click", onDel);

  const btnRun = document.getElementById("btnRun");
  if (btnRun) btnRun.addEventListener("click", onToggleRun);

  const btnStop = document.getElementById("btnStop");
  if (btnStop) btnStop.addEventListener("click", onStop);

  const chkBoot = document.getElementById("chkBoot");
  if (chkBoot) chkBoot.addEventListener("change", onBoot);

  const btnHelp = document.getElementById("btnHelp");
  if (btnHelp) btnHelp.addEventListener("click", onHel);

  const btnFake = document.getElementById("btnFake");
  if (btnFake) btnFake.addEventListener("click", onFak);

  const btnGit = document.getElementById("btnGit");
  if (btnGit) btnGit.addEventListener("click", onGit);

  const btnAbout = document.getElementById("btnAbout");
  if (btnAbout) {
    btnAbout.addEventListener("click", function () {
      modalShow("mdlAbout");
    });
  }
  // 关于弹窗
  const mdlAbout = document.getElementById("mdlAbout");
  if (mdlAbout) {
    mdlAbout.addEventListener("click", function (e) {
      if (e.target && e.target.dataset && e.target.dataset.act === "close-about") {
        modalHide("mdlAbout");
      }
    });
  }
  const btnAboutClose = document.getElementById("btnAboutClose");
  if (btnAboutClose) btnAboutClose.addEventListener("click", () => modalHide("mdlAbout"));
  
  const btnAboutOk = document.getElementById("btnAboutOk");
  if (btnAboutOk) btnAboutOk.addEventListener("click", () => modalHide("mdlAbout"));

  const btnAboutGit = document.getElementById("btnAboutGit");
  if (btnAboutGit) btnAboutGit.addEventListener("click", onGit);

  // 上传功能
  const btnUpload = document.getElementById("btnUpload");
  if (btnUpload) {
      btnUpload.addEventListener("click", function() {
          const chkAll = document.getElementById("chkUpAll");
          if(chkAll) chkAll.checked = false;
          modalShow("mdlUpload");
      });
  }
  
  // 全选
  const chkUpAll = document.getElementById("chkUpAll");
  if (chkUpAll) {
    chkUpAll.addEventListener("change", function(e) {
      const checked = e.target.checked;
      document.querySelectorAll(".chk-upload").forEach(function(el) {
        el.checked = checked;
      });
    });
  }
  
  const uploadChecks = document.querySelectorAll(".chk-upload");
  uploadChecks.forEach(function(ck){
      ck.addEventListener("change", function(){
          if(!this.checked && chkUpAll) chkUpAll.checked = false;
          // 如果全都勾上了，把全选也勾上
          if(this.checked && chkUpAll) {
              const allChecked = Array.from(uploadChecks).every(c => c.checked);
              if(allChecked) chkUpAll.checked = true;
          }
      })
  });
  const btnUploadClose = document.getElementById("btnUploadClose");
  if (btnUploadClose) btnUploadClose.addEventListener("click", () => modalHide("mdlUpload"));
  const btnUploadCancel = document.getElementById("btnUploadCancel");
  if (btnUploadCancel) btnUploadCancel.addEventListener("click", () => modalHide("mdlUpload"));
  const btnUploadGo = document.getElementById("btnUploadGo");
  if (btnUploadGo) {
    btnUploadGo.addEventListener("click", function() {
      if (upBusy) return;
      const sel = Array.from(document.querySelectorAll(".chk-upload:checked")).map((x) => x.value);
      if (!sel.length) {
        setMsg("请选择需要上传的项。", true);
        return;
      }
      upBusy = true;
      btnUploadGo.disabled = true;
      setMsg("开始上传...", false);
      callMaybe("doUp", { sel }).then((r) => {
        if (r == null) {
          upBusy = false;
          btnUploadGo.disabled = false;
          setMsg("上传不可用。", true);
        } else {
          modalHide("mdlUpload");
        }
      }).catch((e) => {
        upBusy = false;
        btnUploadGo.disabled = false;
        setMsg("上传失败: " + (e && e.message ? e.message : String(e)), true);
      });
    }); 
  }
  
  // 关闭上传弹窗
  const mdlUpload = document.getElementById("mdlUpload");
  if(mdlUpload){
    mdlUpload.addEventListener("click", function(e){
        if(e.target && e.target.dataset && e.target.dataset.act === 'close-upload'){
            modalHide("mdlUpload");
        }
    })
  }


  // 同步 / 更新
  const btnSync = document.getElementById("btnSync");
  if (btnSync) {
    btnSync.addEventListener("click", async function () {
      setSyncPolicy(getSyncPolicy());
      modalShow("mdlSync");
      await checkSync(false);
    });
  }
  const btnUpdate = document.getElementById("btnUpdate");
  if (btnUpdate) {
    btnUpdate.addEventListener("click", async function () {
      setUpdPolicy(getUpdPolicy());
      modalShow("mdlUpdate");
      await checkUpdate(false);
    });
  }

  // 同步弹窗事件
  const mdlSync = document.getElementById("mdlSync");
  if (mdlSync) {
    mdlSync.addEventListener("click", function (e) {
      const t = e.target;
      if (t && t.dataset && t.dataset.act === "close-sync") modalHide("mdlSync");
    });
  }
  const btnSyncClose = document.getElementById("btnSyncClose");
  if (btnSyncClose) btnSyncClose.addEventListener("click", () => modalHide("mdlSync"));
  const btnSyncCancel = document.getElementById("btnSyncCancel");
  if (btnSyncCancel) btnSyncCancel.addEventListener("click", () => modalHide("mdlSync"));
  const btnSyncCheck = document.getElementById("btnSyncCheck");
  if (btnSyncCheck) btnSyncCheck.addEventListener("click", () => checkSync(true));
  const btnSyncGo = document.getElementById("btnSyncGo");
  if (btnSyncGo) btnSyncGo.addEventListener("click", doSyncNow);
  const syncFilter = document.getElementById("syncFilter");
  if (syncFilter) syncFilter.addEventListener("input", syncFilterApply);
  document.addEventListener("change", function (e) {
    const t = e.target;
    if (t && t.name === "syncPolicy") {
      setSyncPolicy(t.value);
      applySyncPolicyUI();
    }
    if (t && t.classList && t.classList.contains("sync-item")) {
      syncSelectedCacheFromUI();
    }
  });

  // 更新弹窗事件
  const mdlUpdate = document.getElementById("mdlUpdate");
  if (mdlUpdate) {
    mdlUpdate.addEventListener("click", function (e) {
      const t = e.target;
      if (t && t.dataset && t.dataset.act === "close-update") modalHide("mdlUpdate");
    });
  }
  const btnUpdClose = document.getElementById("btnUpdClose");
  if (btnUpdClose) btnUpdClose.addEventListener("click", () => modalHide("mdlUpdate"));
  const btnUpdCancel = document.getElementById("btnUpdCancel");
  if (btnUpdCancel) btnUpdCancel.addEventListener("click", () => modalHide("mdlUpdate"));
  const btnUpdCheck = document.getElementById("btnUpdCheck");
  if (btnUpdCheck) btnUpdCheck.addEventListener("click", () => checkUpdate(true));
  const btnUpdGo = document.getElementById("btnUpdGo");
  if (btnUpdGo) btnUpdGo.addEventListener("click", () => doUpdateNow(false));
  document.addEventListener("change", function (e) {
    const t = e.target;
    if (t && t.name === "updPolicy") {
      setUpdPolicy(t.value);
    }
  });

  const mdl = document.getElementById("mdlAdd");
  if (mdl) {
    mdl.addEventListener("click", function (e) {
      const t = e.target;
      if (t && t.dataset && t.dataset.act === "close") {
        closeAddModal();
      }
    });
  }
  const btnAddOk = document.getElementById("btnAddOk");
  if (btnAddOk) btnAddOk.addEventListener("click", onAdd);
  const btnAddCancel = document.getElementById("btnAddCancel");
  if (btnAddCancel) btnAddCancel.addEventListener("click", closeAddModal);
  const btnAddClose = document.getElementById("btnAddClose");
  if (btnAddClose) btnAddClose.addEventListener("click", closeAddModal);

  const newL = document.getElementById("newL");
  if (newL) {
    newL.addEventListener("keydown", function (e) {
      if (e.key === "Enter") {
        e.preventDefault();
        onAdd();
      } else if (e.key === "Escape") {
        e.preventDefault();
        closeAddModal();
      }
    });
  }

  // 右键菜单
  const menu = document.getElementById("logMenu");
  if (menu) {
    menu.addEventListener("click", function (e) {
      e.stopPropagation();
      const t = e.target;
      if (!t || !t.dataset || !t.dataset.act) {
        hideCtx();
        return;
      }
      const p = st.ctxp || "";
      hideCtx();
      if (!p && t.dataset.act !== "addWhite") return;

      if (t.dataset.act === "rm") {
        tryrm(p)
          .then(function () {
            setMsg("已尝试卸载: " + p, false);
          })
          .catch(function (err) {
            console.error("tryrm err:", err);
            setMsg("尝试卸载失败: " + err, true);
          });
      } else if (t.dataset.act === "del") {
        trydel(p);
      } else if (t.dataset.act === "addWhite") {
        AddWhite();
      }
    });
  }

  document.addEventListener("click", function () {
    hideCtx();
  });
  document.addEventListener(
    "scroll",
    function () {
      hideCtx();
    },
    true
  );
}

// 切换 tab
function swTab(key) {
  if (!st.dat[key]) st.dat[key] = [];
  st.key = key;
  st.filt = "";
  st.sel = -1;
  const sr = document.getElementById("srch");
  if (sr) sr.value = "";

  document.querySelectorAll(".tab").forEach(function (btn) {
    if (btn.dataset.key === key) btn.classList.add("act");
    else btn.classList.remove("act");
  });

  rend();
}

// 定时刷新运行状态
async function refSta() {
  try {
    const s = await stChk();
    updSta(s);
  } catch (e) {
    console.error("状态检查失败", e);
  }
}

// 启动流程
async function boot() {
  banDev();
  initUI();
  setMsg("加载中...", false);
  try {
    const all = await getAll();
    const note = await getNot();
    const lg = await getLog();
    const s = await stChk();
    if (all) st.dat = all;
    if (note) st.note = note;
    if (lg) st.log = lg;

    updSta(s);
    swTab("sign");
    rendLog();
    updCounts();
    updListHead();

    setMsg("", false);
    setInterval(refLog, 5000);
    setInterval(refSta, 4000);

    // 默认有更新时自动打开更新窗口
    setUpdPolicy(getUpdPolicy());
    setSyncPolicy(getSyncPolicy());
    try {
      const info = await checkUpdate(false);
      if (info && info.has_update) {
        const p = getUpdPolicy();
        if (p === "prompt") {
          modalShow("mdlUpdate");
        } else if (p === "auto") {
          // 自动更新
          doUpdateNow(true);
        }
      }
    } catch (_) {}
  } catch (e) {
    console.error(e);
    setMsg("加载失败: " + e, true);
  }
}

window.onload = boot;