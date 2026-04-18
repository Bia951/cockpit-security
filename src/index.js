const AUTO_REFRESH_MS = 15000;

const state = {
    activeTab: "firewall",
    firewallBackend: "ufw",
    currentJail: "",
    autoRefreshTimer: null,
    refreshLocks: {
        firewall: null,
        fail2ban: null,
    },
    lastRefreshed: {
        firewall: 0,
        fail2ban: 0,
    },
    superuserAllowed: null,
    superuserConfigured: null,
    superuserProxy: null,
    superuserPermission: null,
};

const SERVICE_LINKS = {
    ufw: [
        {
            unit: "ufw.service",
            label: "ufw.service",
        },
    ],
    iptables: [
        {
            unit: "netfilter-persistent.service",
            label: "netfilter-persistent.service",
        },
        {
            unit: "iptables.service",
            label: "iptables.service",
        },
    ],
    fail2ban: [
        {
            unit: "fail2ban.service",
            label: "fail2ban.service",
        },
    ],
};

function getElement(id) {
    return document.getElementById(id);
}

function setHidden(id, hidden) {
    const element = getElement(id);
    if (element)
        element.hidden = hidden;
}

function formatTime(timestamp) {
    return new Date(timestamp).toLocaleTimeString("zh-CN", {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
    });
}

function updateRefreshCopy(section, options = {}) {
    const id = section === "firewall" ? "firewall-refresh-copy" : "fail2ban-refresh-copy";
    if (options.loading) {
        setText(id, `正在刷新... 页面可见时每 ${AUTO_REFRESH_MS / 1000} 秒自动刷新。`);
        return;
    }

    const lastRefreshed = state.lastRefreshed[section];
    if (!lastRefreshed) {
        setText(id, `页面可见时每 ${AUTO_REFRESH_MS / 1000} 秒自动刷新。`);
        return;
    }

    setText(id, `最近刷新：${formatTime(lastRefreshed)} · 页面可见时每 ${AUTO_REFRESH_MS / 1000} 秒自动刷新。`);
}

function withRefreshLock(key, callback) {
    if (state.refreshLocks[key])
        return state.refreshLocks[key];

    const task = Promise.resolve()
        .then(callback)
        .finally(() => {
            state.refreshLocks[key] = null;
        });

    state.refreshLocks[key] = task;
    return task;
}

function stopAutoRefresh() {
    if (state.autoRefreshTimer) {
        window.clearInterval(state.autoRefreshTimer);
        state.autoRefreshTimer = null;
    }
}

function refreshVisibleTab() {
    if (state.superuserAllowed !== true)
        return Promise.resolve();

    if (state.activeTab === "fail2ban")
        return refreshFail2BanStatus();

    return refreshFirewallStatus();
}

function startAutoRefresh() {
    stopAutoRefresh();

    if (state.superuserAllowed !== true || document.hidden)
        return;

    state.autoRefreshTimer = window.setInterval(() => {
        refreshVisibleTab();
    }, AUTO_REFRESH_MS);
}

function applyDarkMode(styleOverride) {
    const style = styleOverride || window.localStorage.getItem("shell:style") || "auto";
    const prefersDark = window.matchMedia?.("(prefers-color-scheme: dark)").matches;
    const darkMode = style === "dark" || (style === "auto" && prefersDark);
    document.documentElement.classList.toggle("pf-v6-theme-dark", darkMode);
}

function bindDarkMode() {
    applyDarkMode();

    window.addEventListener("storage", event => {
        if (event.key === "shell:style")
            applyDarkMode();
    });

    window.addEventListener("cockpit-style", event => {
        if (event instanceof CustomEvent)
            applyDarkMode(event.detail?.style);
    });

    const media = window.matchMedia?.("(prefers-color-scheme: dark)");
    media?.addEventListener?.("change", () => applyDarkMode());
}

function computeSuperuserAllowed() {
    if (!state.superuserProxy?.valid || state.superuserProxy.Current === "init")
        return null;

    return state.superuserProxy.Current !== "none";
}

function computeSuperuserConfigured() {
    if (!state.superuserProxy)
        return null;

    if (state.superuserProxy.Current === "init")
        return null;

    return (state.superuserProxy.Bridges?.length ?? 0) > 0;
}

function renderAccessState() {
    const pageContent = document.querySelector(".page-content");
    const title = getElement("security-access-title");
    const copy = getElement("security-access-copy");

    if (state.superuserAllowed === true) {
        setHidden("security-access-panel", true);
        if (pageContent)
            pageContent.hidden = false;
        startAutoRefresh();
        return;
    }

    stopAutoRefresh();
    setHidden("security-access-panel", false);
    if (pageContent)
        pageContent.hidden = true;

    if (!title || !copy)
        return;

    if (state.superuserAllowed === null) {
        title.textContent = "正在检查管理员访问...";
        copy.textContent = "页面会在确认权限状态后自动加载。";
        return;
    }

    title.textContent = "需要管理员权限";
    if (state.superuserConfigured === false) {
        copy.textContent = "当前 Web 控制台处于受限访问模式，且这台主机没有可用的管理员提权方式。请使用具备管理员权限的会话重新进入后再查看安全状态。";
        return;
    }

    copy.textContent = "当前 Web 控制台正以受限访问模式运行。请先使用 Cockpit 统一的管理员访问入口完成认证，然后返回此页面查看和管理防火墙与 Fail2Ban。";
}

function handleSuperuserStateChange(nextAllowed, configured = computeSuperuserConfigured()) {
    const previous = state.superuserAllowed;
    state.superuserAllowed = nextAllowed;
    state.superuserConfigured = configured;
    renderAccessState();

    if (previous !== nextAllowed && nextAllowed === true)
        refreshVisibleTab();
}

function initSuperuser() {
    state.superuserProxy = cockpit.dbus(null, { bus: "internal" }).proxy("cockpit.Superuser", "/superuser");
    state.superuserProxy.addEventListener("changed", () => {
        handleSuperuserStateChange(computeSuperuserAllowed());
    });

    state.superuserProxy.wait(() => {
        if (!state.superuserProxy.valid) {
            state.superuserPermission = cockpit.permission({ admin: true });
            state.superuserConfigured = false;
            const updatePermission = () => {
                handleSuperuserStateChange(state.superuserPermission.allowed, false);
            };
            state.superuserPermission.addEventListener("changed", updatePermission);
            updatePermission();
            return;
        }

        handleSuperuserStateChange(computeSuperuserAllowed());
    });
}

function run(args) {
    return cockpit.spawn(args, {
        superuser: "require",
        err: "out",
    }).then(output => output.trim());
}

function runShell(script) {
    return run(["sh", "-lc", script]);
}

function capture(argsOrScript, options = {}) {
    const runner = options.shell ? runShell : run;
    return runner(argsOrScript)
        .then(output => ({ ok: true, output }))
        .catch(error => ({ ok: false, output: formatError(error) }));
}

function formatError(error) {
    if (typeof error === "string")
        return error;

    if (error?.message)
        return error.message;

    if (error?.problem)
        return `${error.problem}${error.exit_status ? ` (exit ${error.exit_status})` : ""}`;

    try {
        return JSON.stringify(error, null, 2);
    } catch (_error) {
        return "命令执行失败，且无法解析错误对象。";
    }
}

function setText(id, text) {
    const element = document.getElementById(id);
    if (element)
        element.textContent = text;
}

function setBadge(id, text, tone = "neutral") {
    const element = document.getElementById(id);
    if (!element)
        return;

    element.textContent = text;
    element.classList.remove("tone-success", "tone-warning", "tone-danger");
    if (tone === "success")
        element.classList.add("tone-success");
    else if (tone === "warning")
        element.classList.add("tone-warning");
    else if (tone === "danger")
        element.classList.add("tone-danger");
}

function setCallout(id, text, tone = "neutral") {
    const element = document.getElementById(id);
    if (!element)
        return;

    element.textContent = text;
    element.classList.remove("tone-success", "tone-warning", "tone-danger");
    if (tone === "success")
        element.classList.add("tone-success");
    else if (tone === "warning")
        element.classList.add("tone-warning");
    else if (tone === "danger")
        element.classList.add("tone-danger");
}

function summarizeOutput(text, ok = true) {
    const lines = String(text || "")
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(Boolean);

    if (!lines.length)
        return ok ? "命令执行完成，没有额外输出。" : "命令执行失败。";

    const combined = lines.join(" ");
    if (/permission denied to socket/i.test(combined))
        return "需要管理员权限才能访问 Fail2Ban 套接字。";

    if (/you must be root/i.test(combined))
        return "当前命令需要 root 权限。";

    if (/not found|command not found|No such file/i.test(combined))
        return "命令或对应组件不存在，请先确认目标主机已安装。";

    return lines[0];
}

function renderServiceLinks(containerId, services) {
    const container = document.getElementById(containerId);
    if (!container)
        return;

    container.replaceChildren();

    services.forEach(service => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "service-link";
        button.textContent = service.label;
        button.addEventListener("click", () => {
            cockpit.jump(`/system/services#/?name=${encodeURIComponent(service.unit)}`);
        });
        container.append(button);
    });
}

function renderDetailList(id, items, emptyText = "暂无详情。") {
    const list = document.getElementById(id);
    if (!list)
        return;

    list.replaceChildren();

    if (!items.length) {
        const dt = document.createElement("dt");
        dt.textContent = "状态";
        const dd = document.createElement("dd");
        dd.textContent = emptyText;
        list.append(dt, dd);
        return;
    }

    items.forEach(([label, value]) => {
        const dt = document.createElement("dt");
        dt.textContent = label;
        const dd = document.createElement("dd");
        dd.textContent = value;
        list.append(dt, dd);
    });
}

function renderTable(headId, bodyId, emptyId, columns, rows, emptyText) {
    const head = document.getElementById(headId);
    const body = document.getElementById(bodyId);
    const empty = document.getElementById(emptyId);

    if (!head || !body || !empty)
        return;

    const headRow = document.createElement("tr");
    columns.forEach(column => {
        const th = document.createElement("th");
        th.scope = "col";
        th.textContent = column;
        headRow.append(th);
    });

    head.replaceChildren(headRow);
    body.replaceChildren();

    if (!rows.length) {
        empty.hidden = false;
        empty.textContent = emptyText;
        return;
    }

    empty.hidden = true;
    rows.forEach(row => {
        const tr = document.createElement("tr");
        row.forEach(cell => {
            const td = document.createElement("td");
            td.textContent = cell;
            tr.append(td);
        });
        body.append(tr);
    });
}

function renderMetricCards(id, metrics) {
    const container = document.getElementById(id);
    if (!container)
        return;

    container.replaceChildren();

    if (!metrics.length) {
        const card = document.createElement("div");
        card.className = "metric-card";
        const label = document.createElement("span");
        label.textContent = "Jail";
        const value = document.createElement("strong");
        value.textContent = "暂无数据";
        card.append(label, value);
        container.append(card);
        return;
    }

    metrics.forEach(metric => {
        const card = document.createElement("div");
        card.className = "metric-card";
        const label = document.createElement("span");
        label.textContent = metric.label;
        const value = document.createElement("strong");
        value.textContent = metric.value;
        card.append(label, value);
        container.append(card);
    });
}

function renderTokenRow(id, items, options = {}) {
    const container = document.getElementById(id);
    if (!container)
        return;

    container.replaceChildren();

    if (!items.length && options.emptyText) {
        const token = document.createElement("span");
        token.className = "token";
        token.textContent = options.emptyText;
        container.append(token);
        return;
    }

    items.forEach(item => {
        if (options.clickable) {
            const button = document.createElement("button");
            button.type = "button";
            button.className = "token-button";
            button.textContent = item;
            button.addEventListener("click", () => options.onClick(item));
            container.append(button);
            return;
        }

        const token = document.createElement("span");
        token.className = "token";
        token.textContent = item;
        container.append(token);
    });
}

function normalizeStatus(value) {
    const normalized = String(value || "").trim().toLowerCase();
    const mapping = {
        active: "运行中",
        inactive: "未运行",
        running: "运行中",
        failed: "失败",
        enabled: "已启用",
        disabled: "已禁用",
        loaded: "已加载",
        masked: "已屏蔽",
    };
    return mapping[normalized] || value || "未知";
}

function normalizeWhitespace(value) {
    return String(value || "").replace(/\s+/g, " ").trim();
}

function parseSystemdShow(output) {
    const values = {};
    String(output || "").split(/\r?\n/).forEach(line => {
        const index = line.indexOf("=");
        if (index <= 0)
            return;

        values[line.slice(0, index)] = line.slice(index + 1).trim();
    });
    return values;
}

function parseUfwStatus(numberedOutput, verboseOutput) {
    const rules = [];
    String(numberedOutput || "").split(/\r?\n/).forEach(line => {
        const match = line.match(/^\[\s*(\d+)\]\s+(.+?)\s{2,}(\S+)\s+(\S+)\s+(.+)$/);
        if (!match)
            return;

        rules.push({
            number: match[1],
            to: match[2].trim(),
            action: match[3],
            direction: match[4],
            from: match[5].trim(),
        });
    });

    const sourceText = verboseOutput || numberedOutput;
    const status = sourceText.match(/Status:\s*(.+)/i)?.[1]?.trim() || "unknown";
    const defaults = sourceText.match(/Default:\s*(.+)/i)?.[1]?.trim() || "";
    const logging = sourceText.match(/Logging:\s*(.+)/i)?.[1]?.trim() || "";
    const isActive = status.toLowerCase() === "active";

    return {
        summary: isActive
            ? `UFW 已启用，解析到 ${rules.length} 条规则。`
            : "UFW 当前未启用。",
        statusLabel: isActive ? "运行中" : normalizeStatus(status),
        tone: isActive ? "success" : "warning",
        ruleCount: String(rules.length),
        policySummary: defaults ? `默认策略：${defaults}` : "未解析到默认策略。",
        details: [
            ["状态", normalizeStatus(status)],
            defaults ? ["默认策略", defaults] : null,
            logging ? ["日志", logging] : null,
            ["规则数", String(rules.length)],
        ].filter(Boolean),
        columns: ["编号", "目标", "动作", "方向", "来源"],
        rows: rules.map(rule => [rule.number, rule.to, rule.action, rule.direction, rule.from]),
        emptyText: isActive ? "当前没有 UFW 规则。" : "UFW 未启用，暂无规则可显示。",
    };
}

function parseIptablesStatus(listOutput) {
    const lines = String(listOutput || "").split(/\r?\n/);
    const chainLine = lines.find(line => /^Chain\s+INPUT/i.test(line));
    const policy = chainLine?.match(/\(policy\s+([A-Z]+)/)?.[1] || "未知";
    const rules = [];
    let tableStarted = false;

    lines.forEach(line => {
        const trimmed = line.trim();
        if (!trimmed)
            return;

        if (/^num\s+pkts\s+bytes/i.test(trimmed)) {
            tableStarted = true;
            return;
        }

        if (!tableStarted)
            return;

        const parts = trimmed.split(/\s+/);
        if (parts.length < 10)
            return;

        const [num, pkts, bytes, target, protocol, opt, inputIf, outputIf, source, destination, ...rest] = parts;
        rules.push({
            num,
            pkts,
            bytes,
            target,
            protocol,
            inputIf,
            outputIf,
            source,
            destination,
            detail: rest.join(" "),
            opt,
        });
    });

    return {
        summary: `INPUT 链默认策略为 ${policy}，解析到 ${rules.length} 条规则。`,
        statusLabel: `策略 ${policy}`,
        tone: policy === "DROP" ? "warning" : "success",
        ruleCount: String(rules.length),
        policySummary: `默认策略：${policy}`,
        details: [
            ["链", "INPUT"],
            ["默认策略", policy],
            ["规则数", String(rules.length)],
        ],
        columns: ["行号", "目标", "协议", "来源", "目的地", "匹配"],
        rows: rules.map(rule => [
            rule.num,
            rule.target,
            rule.protocol,
            rule.source,
            rule.destination,
            normalizeWhitespace(rule.detail || rule.opt),
        ]),
        emptyText: "当前没有 iptables INPUT 规则。",
    };
}

function parseFail2BanOverview(serviceOutput, statusOutput, serviceOk, statusOk) {
    const service = parseSystemdShow(serviceOutput);
    const jailCountMatch = statusOutput.match(/Number of jail:\s*(\d+)/i);
    const jailListMatch = statusOutput.match(/Jail list:\s*(.+)/i);
    const jailCount = jailCountMatch ? Number(jailCountMatch[1]) : 0;
    const jails = jailListMatch
        ? jailListMatch[1].split(",").map(item => item.trim()).filter(Boolean)
        : [];
    const activeState = service.ActiveState || "";
    const serviceState = activeState ? `${normalizeStatus(activeState)} / ${service.SubState || "unknown"}` : "未知";

    let summary = "未拿到 Fail2Ban 状态。";
    let tone = "warning";

    if (serviceOk && statusOk) {
        summary = jails.length
            ? `当前共有 ${jails.length} 个 jail：${jails.join("、")}。`
            : "当前没有已启用的 jail。";
        tone = activeState === "active" ? "success" : "warning";
    } else if (/permission denied|must be root/i.test(statusOutput)) {
        summary = "Fail2Ban 套接字需要管理员权限，当前会话未拿到。";
    } else if (!statusOk) {
        summary = summarizeOutput(statusOutput, false);
        tone = "danger";
    }

    return {
        jailCount,
        jails,
        serviceState,
        summary,
        tone,
        details: [
            ["服务", service.Id || "fail2ban.service"],
            service.Description ? ["说明", service.Description] : null,
            service.ActiveState ? ["运行状态", normalizeStatus(service.ActiveState)] : null,
            service.SubState ? ["子状态", service.SubState] : null,
            service.UnitFileState ? ["开机策略", normalizeStatus(service.UnitFileState)] : null,
            service.LoadState ? ["加载状态", normalizeStatus(service.LoadState)] : null,
            ["Jail 数量", String(jailCount)],
            jails.length ? ["Jail 列表", jails.join("、")] : null,
        ].filter(Boolean),
    };
}

function parseFail2BanJail(output, jailName) {
    const detailMap = {};
    String(output || "").split(/\r?\n/).forEach(line => {
        const cleaned = line.replace(/^[\s|`-]+/, "").trim();
        if (!cleaned.includes(":"))
            return;

        const index = cleaned.indexOf(":");
        const key = cleaned.slice(0, index).trim();
        const value = cleaned.slice(index + 1).trim();
        if (key)
            detailMap[key] = value;
    });

    const bannedIps = (detailMap["Banned IP list"] || "")
        .split(/\s+/)
        .map(item => item.trim())
        .filter(Boolean);

    return {
        name: output.match(/Status for the jail:\s*(.+)/i)?.[1]?.trim() || jailName,
        metrics: [
            { label: "当前失败", value: detailMap["Currently failed"] || "0" },
            { label: "当前封禁", value: detailMap["Currently banned"] || "0" },
            { label: "累计封禁", value: detailMap["Total banned"] || "0" },
        ],
        details: [
            ["累计失败", detailMap["Total failed"] || "0"],
            detailMap["File list"] ? ["日志文件", detailMap["File list"]] : null,
            detailMap["Banned IP list"] ? ["封禁 IP", detailMap["Banned IP list"]] : null,
        ].filter(Boolean),
        bannedIps,
        summary: `已加载 jail ${jailName}，当前封禁 ${detailMap["Currently banned"] || "0"} 个 IP。`,
    };
}

function updateFirewallServices() {
    const services = SERVICE_LINKS[state.firewallBackend];
    renderServiceLinks("firewall-service-links", services);
    setText(
        "firewall-service-copy",
        state.firewallBackend === "ufw"
            ? "UFW 对应的 systemd unit。"
            : "iptables 没有统一的单一服务，这里给出常见的持久化/兼容 unit。"
    );
}

function renderFirewallStatus(parsed, rawOutput) {
    setText("firewall-backend-label", state.firewallBackend.toUpperCase());
    setText("firewall-summary-copy", parsed.summary);
    setText("firewall-rule-count", parsed.ruleCount);
    setText("firewall-policy-summary", parsed.policySummary);
    setBadge("firewall-status-pill", parsed.statusLabel, parsed.tone);
    setBadge("firewall-detail-pill", parsed.statusLabel, parsed.tone);
    renderDetailList("firewall-details", parsed.details, "没有解析到防火墙详情。");
    renderTable("firewall-rules-head", "firewall-rules-body", "firewall-rules-empty", parsed.columns, parsed.rows, parsed.emptyText);
    setText("firewall-status", rawOutput || "没有拿到原始防火墙输出。");
}

function renderFirewallError(message, rawOutput) {
    setText("firewall-summary-copy", summarizeOutput(message, false));
    setText("firewall-rule-count", "--");
    setText("firewall-policy-summary", "状态刷新失败。");
    setBadge("firewall-status-pill", "刷新失败", "danger");
    setBadge("firewall-detail-pill", "刷新失败", "danger");
    renderDetailList("firewall-details", [["错误", summarizeOutput(message, false)]], "状态刷新失败。");
    renderTable("firewall-rules-head", "firewall-rules-body", "firewall-rules-empty", ["状态"], [], "无法读取规则列表。");
    setText("firewall-status", rawOutput || message);
}

function renderFail2BanStatus(parsed, rawOutput) {
    setText("fail2ban-service-state", parsed.serviceState);
    setText("fail2ban-service-copy", parsed.summary);
    setText("fail2ban-jail-count", String(parsed.jailCount));
    setBadge("fail2ban-service-pill", parsed.serviceState, parsed.tone);
    renderDetailList("fail2ban-details", parsed.details, "没有解析到 Fail2Ban 总体状态。");
    renderTokenRow("fail2ban-jail-list", parsed.jails, {
        clickable: true,
        emptyText: "没有 jail",
        onClick: jail => {
            fillJailInputs(jail);
            loadFail2BanJail(jail);
        },
    });
    setText("fail2ban-status", rawOutput || "没有拿到原始 Fail2Ban 状态输出。");
}

function renderFail2BanJail(parsed, rawOutput, tone = "success") {
    state.currentJail = parsed.name;
    setText("fail2ban-current-jail", parsed.name);
    setText("fail2ban-current-jail-copy", parsed.summary);
    setBadge("fail2ban-jail-pill", parsed.name, tone);
    renderMetricCards("fail2ban-jail-metrics", parsed.metrics);
    renderDetailList("fail2ban-jail-details", parsed.details, "没有解析到 jail 详情。");
    renderTokenRow("fail2ban-banned-ips", parsed.bannedIps, {
        emptyText: "当前没有封禁 IP",
    });
    setText("fail2ban-jail-output", rawOutput || "没有拿到原始 jail 输出。");
    fillJailInputs(parsed.name);
}

function clearFail2BanJail(message) {
    state.currentJail = "";
    setText("fail2ban-current-jail", "未选择");
    setText("fail2ban-current-jail-copy", message);
    setBadge("fail2ban-jail-pill", "未选择");
    renderMetricCards("fail2ban-jail-metrics", []);
    renderDetailList("fail2ban-jail-details", [], message);
    renderTokenRow("fail2ban-banned-ips", [], {
        emptyText: "当前没有封禁 IP",
    });
    setText("fail2ban-jail-output", "选择一个 jail 后，这里会保留完整输出。");
}

function showCommandResult(prefix, label, text, ok = true, summaryOverride = "") {
    setBadge(`${prefix}-command-label`, label, ok ? "success" : "danger");
    setCallout(`${prefix}-result-summary`, summaryOverride || summarizeOutput(text, ok), ok ? "success" : "danger");
    setText(`${prefix}-result`, text || "命令执行完成，没有额外输出。");
}

async function execute(prefix, label, argsOrScript, options = {}) {
    const commandLabel = Array.isArray(argsOrScript) ? argsOrScript.join(" ") : argsOrScript;
    const shouldUpdateResult = options.updateResult !== false;

    if (shouldUpdateResult)
        showCommandResult(prefix, label, `执行中...\n\n${commandLabel}`, true, "正在执行命令...");

    const result = await capture(argsOrScript, options);
    if (shouldUpdateResult)
        showCommandResult(prefix, result.ok ? label : `${label} 失败`, result.output, result.ok, options.summary);

    return result;
}

async function refreshFirewallStatus() {
    return withRefreshLock("firewall", async () => {
        if (state.superuserAllowed !== true)
            return;

        updateFirewallServices();
        updateRefreshCopy("firewall", { loading: true });
        setText("firewall-summary-copy", "正在刷新防火墙状态...");
        setBadge("firewall-status-pill", "加载中");
        setBadge("firewall-detail-pill", "加载中");
        setText("firewall-status", "正在刷新防火墙状态...");

        try {
            if (state.firewallBackend === "ufw") {
                const [verboseResult, numberedResult] = await Promise.all([
                    capture(["ufw", "status", "verbose"]),
                    capture(["ufw", "status", "numbered"]),
                ]);

                const rawOutput = [
                    "== ufw status verbose ==",
                    verboseResult.output,
                    "",
                    "== ufw status numbered ==",
                    numberedResult.output,
                ].join("\n");

                if (!verboseResult.ok && !numberedResult.ok) {
                    renderFirewallError(numberedResult.output || verboseResult.output, rawOutput);
                    return;
                }

                renderFirewallStatus(parseUfwStatus(numberedResult.output, verboseResult.output), rawOutput);
                return;
            }

            const [listResult, specResult] = await Promise.all([
                capture(["iptables", "-L", "INPUT", "-n", "--line-numbers", "-v"]),
                capture(["iptables", "-S", "INPUT"]),
            ]);

            const rawOutput = [
                "== iptables -L INPUT -n --line-numbers -v ==",
                listResult.output,
                "",
                "== iptables -S INPUT ==",
                specResult.output,
            ].join("\n");

            if (!listResult.ok) {
                renderFirewallError(listResult.output, rawOutput);
                return;
            }

            renderFirewallStatus(parseIptablesStatus(listResult.output), rawOutput);
        } finally {
            state.lastRefreshed.firewall = Date.now();
            updateRefreshCopy("firewall");
        }
    });
}

async function refreshFail2BanStatus() {
    return withRefreshLock("fail2ban", async () => {
        if (state.superuserAllowed !== true)
            return;

        updateRefreshCopy("fail2ban", { loading: true });
        setText("fail2ban-service-copy", "正在刷新 Fail2Ban 状态...");
        setBadge("fail2ban-service-pill", "加载中");
        setText("fail2ban-status", "正在刷新 Fail2Ban 状态...");

        try {
            const [serviceResult, statusResult] = await Promise.all([
                capture([
                    "systemctl",
                    "show",
                    "fail2ban",
                    "--property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,FragmentPath",
                ]),
                capture(["fail2ban-client", "status"]),
            ]);

            const rawOutput = [
                "== systemctl show fail2ban ==",
                serviceResult.output,
                "",
                "== fail2ban-client status ==",
                statusResult.output,
            ].join("\n");

            renderFail2BanStatus(
                parseFail2BanOverview(serviceResult.output, statusResult.output, serviceResult.ok, statusResult.ok),
                rawOutput
            );

            if (state.currentJail) {
                const parsed = parseFail2BanOverview(serviceResult.output, statusResult.output, serviceResult.ok, statusResult.ok);
                if (parsed.jails.includes(state.currentJail))
                    await loadFail2BanJail(state.currentJail, { quiet: true });
                else
                    clearFail2BanJail("当前 jail 已不在总列表中，请重新选择。");
            }
        } finally {
            state.lastRefreshed.fail2ban = Date.now();
            updateRefreshCopy("fail2ban");
        }
    });
}

async function loadFail2BanJail(jail, options = {}) {
    if (state.superuserAllowed !== true)
        return;

    const jailName = jail.trim();
    if (!jailName) {
        showCommandResult("fail2ban", "jail 查询失败", "jail 名称不能为空。", false);
        return;
    }

    setBadge("fail2ban-jail-pill", "加载中");
    setText("fail2ban-current-jail", jailName);
    setText("fail2ban-current-jail-copy", "正在加载 jail 详情...");
    setText("fail2ban-jail-output", "正在加载 jail 详情...");

    const result = await capture(["fail2ban-client", "status", jailName]);
    if (!result.ok) {
        const summary = summarizeOutput(result.output, false);
        setText("fail2ban-current-jail", jailName);
        setText("fail2ban-current-jail-copy", summary);
        setBadge("fail2ban-jail-pill", "加载失败", "danger");
        renderMetricCards("fail2ban-jail-metrics", []);
        renderDetailList("fail2ban-jail-details", [["错误", summary]], "jail 查询失败。");
        renderTokenRow("fail2ban-banned-ips", [], {
            emptyText: "当前没有封禁 IP",
        });
        setText("fail2ban-jail-output", result.output);
        if (!options.quiet)
            showCommandResult("fail2ban", `jail: ${jailName} 失败`, result.output, false, summary);
        return;
    }

    const parsed = parseFail2BanJail(result.output, jailName);
    renderFail2BanJail(parsed, result.output);
    if (!options.quiet)
        showCommandResult("fail2ban", `jail: ${jailName}`, result.output, true, parsed.summary);
}

function switchTab(tab) {
    state.activeTab = tab;

    document.querySelectorAll(".tab-button").forEach(button => {
        button.classList.toggle("active", button.dataset.tab === tab);
    });

    document.querySelectorAll(".tab-panel").forEach(panel => {
        panel.classList.toggle("active", panel.dataset.panel === tab);
    });

    if (state.superuserAllowed === true)
        refreshVisibleTab();
}

function switchFirewallBackend(backend, options = {}) {
    state.firewallBackend = backend;

    document.querySelectorAll(".backend-button").forEach(button => {
        button.classList.toggle("active", button.dataset.backend === backend);
    });

    document.querySelectorAll(".backend-panel").forEach(panel => {
        panel.classList.toggle("active", panel.dataset.backendPanel === backend);
    });

    updateFirewallServices();
    if (options.refresh !== false)
        refreshFirewallStatus();
}

function getFormValue(form, name) {
    const field = form.elements.namedItem(name);
    return typeof field?.value === "string" ? field.value.trim() : "";
}

function fillJailInputs(jail) {
    const jailInput = document.getElementById("fail2ban-jail-input");
    const unbanInput = document.getElementById("fail2ban-unban-jail-input");
    if (jailInput)
        jailInput.value = jail;
    if (unbanInput)
        unbanInput.value = jail;
}

async function handleQuickAction(action) {
    const actions = {
        "ufw-enable": () => execute("firewall", "UFW 启用", ["ufw", "--force", "enable"]),
        "ufw-disable": () => execute("firewall", "UFW 禁用", ["ufw", "disable"]),
        "ufw-reload": () => execute("firewall", "UFW 重新加载", ["ufw", "reload"]),
        "fail2ban-start": () => execute("fail2ban", "启动 Fail2Ban", ["systemctl", "start", "fail2ban"]),
        "fail2ban-stop": () => execute("fail2ban", "停止 Fail2Ban", ["systemctl", "stop", "fail2ban"]),
        "fail2ban-restart": () => execute("fail2ban", "重启 Fail2Ban", ["systemctl", "restart", "fail2ban"]),
        "fail2ban-reload": () => execute("fail2ban", "重新加载 Fail2Ban", ["fail2ban-client", "reload"]),
    };

    const handler = actions[action];
    if (!handler)
        return;

    await handler();

    if (action.startsWith("ufw") || action.startsWith("iptables"))
        await refreshFirewallStatus();

    if (action.startsWith("fail2ban"))
        await refreshFail2BanStatus();
}

async function handleUfwAdd(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const action = getFormValue(form, "action");
    const port = getFormValue(form, "port");
    const protocol = getFormValue(form, "protocol");
    const source = getFormValue(form, "source");

    if (!port) {
        showCommandResult("firewall", "UFW 添加失败", "端口不能为空。", false);
        return;
    }

    const args = source
        ? ["ufw", action, "from", source, "to", "any", "port", port, "proto", protocol]
        : ["ufw", action, `${port}/${protocol}`];

    await execute("firewall", "UFW 添加规则", args);
    form.reset();
    await refreshFirewallStatus();
}

async function handleUfwDelete(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const number = getFormValue(form, "number");

    if (!number) {
        showCommandResult("firewall", "UFW 删除失败", "规则编号不能为空。", false);
        return;
    }

    await execute("firewall", "UFW 删除规则", ["ufw", "--force", "delete", number]);
    form.reset();
    await refreshFirewallStatus();
}

async function handleIptablesAdd(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const action = getFormValue(form, "action");
    const port = getFormValue(form, "port");
    const protocol = getFormValue(form, "protocol");
    const source = getFormValue(form, "source");

    if (!port) {
        showCommandResult("firewall", "iptables 添加失败", "端口不能为空。", false);
        return;
    }

    const args = ["iptables", "-I", "INPUT", "-p", protocol];
    if (source)
        args.push("-s", source);
    args.push("--dport", port, "-j", action);

    await execute("firewall", "iptables 插入规则", args);
    form.reset();
    await refreshFirewallStatus();
}

async function handleIptablesDelete(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const line = getFormValue(form, "line");

    if (!line) {
        showCommandResult("firewall", "iptables 删除失败", "行号不能为空。", false);
        return;
    }

    await execute("firewall", "iptables 删除规则", ["iptables", "-D", "INPUT", line]);
    form.reset();
    await refreshFirewallStatus();
}

async function handleFail2BanJail(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const jail = getFormValue(form, "jail");
    await loadFail2BanJail(jail);
}

async function handleFail2BanUnban(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const jail = getFormValue(form, "jail");
    const ip = getFormValue(form, "ip");

    if (!jail || !ip) {
        showCommandResult("fail2ban", "解封失败", "jail 和 IP 都不能为空。", false);
        return;
    }

    fillJailInputs(jail);
    await execute("fail2ban", "Fail2Ban 解封 IP", ["fail2ban-client", "set", jail, "unbanip", ip]);
    form.reset();
    fillJailInputs(jail);
    await refreshFail2BanStatus();
    await loadFail2BanJail(jail, { quiet: true });
}

function bindEvents() {
    document.querySelectorAll(".tab-button").forEach(button => {
        button.addEventListener("click", () => switchTab(button.dataset.tab));
    });

    document.querySelectorAll(".backend-button").forEach(button => {
        button.addEventListener("click", () => switchFirewallBackend(button.dataset.backend));
    });

    document.querySelectorAll("[data-action]").forEach(button => {
        button.addEventListener("click", () => handleQuickAction(button.dataset.action));
    });

    document.getElementById("ufw-add-form")?.addEventListener("submit", handleUfwAdd);
    document.getElementById("ufw-delete-form")?.addEventListener("submit", handleUfwDelete);
    document.getElementById("iptables-add-form")?.addEventListener("submit", handleIptablesAdd);
    document.getElementById("iptables-delete-form")?.addEventListener("submit", handleIptablesDelete);
    document.getElementById("fail2ban-jail-form")?.addEventListener("submit", handleFail2BanJail);
    document.getElementById("fail2ban-unban-form")?.addEventListener("submit", handleFail2BanUnban);

    document.addEventListener("visibilitychange", () => {
        if (document.hidden) {
            stopAutoRefresh();
            return;
        }

        if (state.superuserAllowed === true) {
            refreshVisibleTab();
            startAutoRefresh();
        }
    });
}

document.addEventListener("DOMContentLoaded", async () => {
    bindEvents();
    bindDarkMode();
    initSuperuser();
    updateRefreshCopy("firewall");
    updateRefreshCopy("fail2ban");
    renderServiceLinks("fail2ban-service-links", SERVICE_LINKS.fail2ban);
    clearFail2BanJail("可从 jail 列表快速打开，也可以手动输入名称查看。");
    switchTab(state.activeTab);
    switchFirewallBackend(state.firewallBackend, { refresh: false });
    renderAccessState();
});
