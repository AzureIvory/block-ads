// 禁止进入调试模式
function banDev() {
  document.addEventListener("contextmenu", function (e) {
    e.preventDefault();
  }, true);
  document.addEventListener("keydown", function (e) {
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
  }, true);
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

function setMsg(t, err) {
  const el = document.getElementById("msg");
  el.textContent = t || "";
  el.style.color = err ? "#b91c1c" : "#6b7280";
}

// 更新状态
function updSta(s) {
  if (!s) return;
  st.adm = !!s.adm;
  st.run = !!s.run;
  st.boot = !!s.boot;

  const admEl = document.getElementById("admTxt");
  const runEl = document.getElementById("runTxt");
  const btnRun = document.getElementById("btnRun");
  const btnStop = document.getElementById("btnStop");
  const chkBoot = document.getElementById("chkBoot");

  admEl.textContent = st.adm ? "管理员" : "非管理员";
  admEl.style.color = st.adm ? "#16a34a" : "#b91c1c";

  runEl.textContent = st.run ? "已运行" : "未运行";
  runEl.style.color = st.run ? "#16a34a" : "#6b7280";

  // 只根据运行状态控制按钮，不再限制非管理员
  btnRun.disabled = st.run;
  btnStop.disabled = !st.run;

  chkBoot.checked = !!st.boot;
}

// 渲染列表
function rend() {
  const ul = document.getElementById("lst");
  ul.innerHTML = "";
  const list = st.dat[st.key] || [];
  const f = (st.filt || "").toLowerCase();

  list.forEach((line, idx) => {
    const note = st.note[line] || "";
    const t1 = (line || "").toLowerCase();
    const t2 = (note || "").toLowerCase();

    if (f && t1.indexOf(f) === -1 && t2.indexOf(f) === -1) {
      return;
    }

    const li = document.createElement("li");
    li.dataset.idx = idx;

    const d1 = document.createElement("div");
    d1.className = "ln-txt";
    d1.textContent = line;

    const d2 = document.createElement("div");
    d2.className = "ln-note";
    d2.textContent = note || "无注释";

    li.appendChild(d1);
    li.appendChild(d2);

    if (idx === st.sel) {
      li.classList.add("sel");
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
    if (v === idx) {
      li.classList.add("sel");
    } else {
      li.classList.remove("sel");
    }
  });
}

// 解析日志
function pLog(line) {
  const ps = (line || "").split("--");
  if (ps.length < 5) {
    return null;
  }
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

// 隐藏右键菜单
function hideCtx() {
  const m = document.getElementById("logMenu");
  if (!m) return;
  m.style.display = "none";
}

// 显示右键菜单
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
  ul.innerHTML = "";
  const list = st.log || [];

  if (!list.length) {
    info.textContent = "今日暂无记录";
    return;
  }
  info.textContent = "共 " + list.length + " 条";

  list.forEach(function (line) {
    const it = pLog(line);
    const li = document.createElement("li");
    li.title = line;

    if (!it) {
      li.textContent = line;
      ul.appendChild(li);
      return;
    }

    const nt = st.note[it.v] || "";
    li.dataset.path = it.p || "";
    // 保存类型与值
    li.dataset.kind = it.k || "";
    li.dataset.val = it.v || "";

    const top = document.createElement("div");
    top.className = "log-top";
    top.textContent = it.t + "  " + it.k + " / " + it.m;

    const mid = document.createElement("div");
    mid.className = "log-mid";

    const sk = document.createElement("span");
    sk.className = "log-key";
    sk.textContent = it.v;
    mid.appendChild(sk);

    if (nt) {
      const sn = document.createElement("span");
      sn.className = "log-note";
      sn.textContent = "「" + nt + "」";
      mid.appendChild(sn);
    }

    const bot = document.createElement("div");
    bot.className = "log-path";
    bot.textContent = it.p;

    li.appendChild(top);
    li.appendChild(mid);
    li.appendChild(bot);

    // 双击定位文件
    li.addEventListener("dblclick", function () {
      const p = this.dataset.path || "";
      if (!p) return;
      logOpen(p);
    });

    // 右键弹出菜单
    li.addEventListener("contextmenu", function (e) {
      e.preventDefault();
      const p = this.dataset.path || "";
      if (!p) return;
      st.ctxp = p;
      // 记录当前行上下文
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
async function onAdd() {
  const inp = document.getElementById("newL");
  const txt = (inp.value || "").trim();
  if (!txt) {
    setMsg("内容为空。", true);
    return;
  }
  try {
    const v = await addLn(st.key, txt);
    st.dat[st.key] = v || [];
    st.sel = st.dat[st.key].length - 1;
    st.filt = "";
    document.getElementById("srch").value = "";
    inp.value = "";
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
async function onRun() {
  if (st.run) return;
  setMsg("启动中...", false);
  try {
    const ok = await doRun();
    if (!ok) {
      setMsg("启动失败。", true);
    }
    const s = await stChk();
    updSta(s);
    setMsg("已尝试启动。", false);
  } catch (e) {
    console.error(e);
    setMsg("启动失败: " + e, true);
  }
}
async function onStop() {
  if (!st.run) return;
  const msg = "是否停止拦截进程？";
  if (!confirm(msg)) {
    return;
  }
  setMsg("停止中...", false);
  try {
    const ok = await doStop();
    if (!ok) {
      // ignore
    }
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
    document.getElementById("chkBoot").checked = st.boot;
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
    if (ok) {
      setMsg("一键伪装已执行。", false);
    } else {
      setMsg("伪装未完全成功。", true);
    }
  } catch (e) {
    console.error(e);
    setMsg("伪装失败: " + e, true);
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
    // 调用Go的addWht
    const ok = await addWht(kind, val, p);
    if (ok) {
      setMsg("已加入白名单。", false);
      // 再取一次名单
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
async function onGit() {
  try {
    await doGit();
    setMsg("", false);
  } catch (e) {
    console.error(e);
    setMsg("无法打开 GitHub: " + e, true);
  }
}

// 初始化
function initUI() {
  document.querySelectorAll(".tab").forEach(function (btn) {
    btn.addEventListener("click", function () {
      swTab(btn.dataset.key);
    });
  });

  document.getElementById("srch").addEventListener("input", function (e) {
    st.filt = e.target.value || "";
    rend();
  });

  document.getElementById("newL").addEventListener("keydown", function (e) {
    if (e.key === "Enter") {
      e.preventDefault();
      onAdd();
    }
  });

  document.getElementById("btnAdd").addEventListener("click", onAdd);
  document.getElementById("btnDel").addEventListener("click", onDel);

  document.getElementById("btnRun").addEventListener("click", onRun);
  document.getElementById("btnStop").addEventListener("click", onStop);
  document.getElementById("chkBoot").addEventListener("change", onBoot);
  document.getElementById("btnHelp").addEventListener("click", onHel);
  document.getElementById("btnFake").addEventListener("click", onFak);
  document.getElementById("btnGit").addEventListener("click", onGit);

  // 右键菜单
  const menu = document.getElementById("logMenu");
  if (menu) {
    menu.addEventListener("click", function (e) {
      e.stopPropagation();
      const t = e.target;
      if (!t || !t.dataset.act) {
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
        // 加入白名单
        AddWhite();
      }
    });
  }

  document.addEventListener("click", function () {
    hideCtx();
  });
  document.addEventListener("scroll", function () {
    hideCtx();
  }, true);
}

// 切换 tab
function swTab(key) {
  if (!st.dat[key]) {
    st.dat[key] = [];
  }
  st.key = key;
  st.filt = "";
  st.sel = -1;
  document.getElementById("srch").value = "";

  document.querySelectorAll(".tab").forEach(function (btn) {
    if (btn.dataset.key === key) {
      btn.classList.add("act");
    } else {
      btn.classList.remove("act");
    }
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
    setMsg("", false);
    // 定时刷新日志
    setInterval(refLog, 5000);
    // 定时刷新运行状态
    setInterval(refSta, 4000);
  } catch (e) {
    console.error(e);
    setMsg("加载失败: " + e, true);
  }
}

window.onload = boot;
