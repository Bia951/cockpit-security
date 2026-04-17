const state = {
    activeTab: "firewall",
    firewallBackend: "ufw",
};

function run(args) {
    return cockpit.spawn(args, {
        superuser: "require",
        err: "out",
    }).then(output => output.trim());
}

function runShell(script) {
    return run(["sh", "-lc", script]);
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

function setBadge(id, text) {
    setText(id, text);
}

function showCommandResult(prefix, label, text) {
    setBadge(`${prefix}-command-label`, label);
    setText(`${prefix}-result`, text || "命令执行完成，没有额外输出。");
}

async function execute(prefix, label, argsOrScript, options = {}) {
    const runner = options.shell ? runShell : run;
    const commandLabel = Array.isArray(argsOrScript) ? argsOrScript.join(" ") : argsOrScript;
    const shouldUpdateResult = options.updateResult !== false;

    if (shouldUpdateResult)
        showCommandResult(prefix, label, `执行中...\n\n${commandLabel}`);

    try {
        const output = await runner(argsOrScript);
        if (shouldUpdateResult)
            showCommandResult(prefix, label, output || "命令执行完成，没有额外输出。");
        return { ok: true, output };
    } catch (error) {
        const message = formatError(error);
        if (shouldUpdateResult)
            showCommandResult(prefix, `${label} 失败`, message);
        return { ok: false, output: message };
    }
}

async function refreshFirewallStatus() {
    setBadge("firewall-backend-label", state.firewallBackend.toUpperCase());
    setText("firewall-status", "正在刷新防火墙状态...");

    if (state.firewallBackend === "ufw") {
        const result = await execute("firewall", "UFW 状态", ["ufw", "status", "numbered"], { updateResult: false });
        setText("firewall-status", result.output || "没有拿到 UFW 状态输出。");
        return;
    }

    const result = await execute(
        "firewall",
        "iptables 状态",
        "iptables -L INPUT -n --line-numbers -v && printf '\\n-----\\n' && iptables -S INPUT",
        { shell: true, updateResult: false }
    );
    setText("firewall-status", result.output || "没有拿到 iptables 状态输出。");
}

async function refreshFail2BanStatus() {
    setText("fail2ban-status", "正在刷新 Fail2Ban 状态...");
    const result = await execute(
        "fail2ban",
        "Fail2Ban 状态",
        "systemctl status fail2ban --no-pager || true; printf '\\n=====\\n'; fail2ban-client status",
        { shell: true, updateResult: false }
    );
    setText("fail2ban-status", result.output || "没有拿到 Fail2Ban 状态输出。");
}

function switchTab(tab) {
    state.activeTab = tab;

    document.querySelectorAll(".tab-button").forEach(button => {
        button.classList.toggle("active", button.dataset.tab === tab);
    });

    document.querySelectorAll(".tab-panel").forEach(panel => {
        panel.classList.toggle("active", panel.dataset.panel === tab);
    });
}

function switchFirewallBackend(backend) {
    state.firewallBackend = backend;

    document.querySelectorAll(".backend-button").forEach(button => {
        button.classList.toggle("active", button.dataset.backend === backend);
    });

    document.querySelectorAll(".backend-panel").forEach(panel => {
        panel.classList.toggle("active", panel.dataset.backendPanel === backend);
    });

    refreshFirewallStatus();
}

function getFormValue(form, name) {
    const field = form.elements.namedItem(name);
    return typeof field?.value === "string" ? field.value.trim() : "";
}

async function handleQuickAction(action) {
    const actions = {
        "ufw-status": () => refreshFirewallStatus(),
        "ufw-enable": () => execute("firewall", "UFW 启用", ["ufw", "--force", "enable"]),
        "ufw-disable": () => execute("firewall", "UFW 禁用", ["ufw", "disable"]),
        "ufw-reload": () => execute("firewall", "UFW 重新加载", ["ufw", "reload"]),
        "iptables-status": () => refreshFirewallStatus(),
        "fail2ban-status": () => refreshFail2BanStatus(),
        "fail2ban-start": () => execute("fail2ban", "启动 Fail2Ban", ["systemctl", "start", "fail2ban"]),
        "fail2ban-stop": () => execute("fail2ban", "停止 Fail2Ban", ["systemctl", "stop", "fail2ban"]),
        "fail2ban-restart": () => execute("fail2ban", "重启 Fail2Ban", ["systemctl", "restart", "fail2ban"]),
        "fail2ban-reload": () => execute("fail2ban", "重新加载 Fail2Ban", ["fail2ban-client", "reload"]),
    };

    const handler = actions[action];
    if (!handler)
        return;

    await handler();

    if (action !== "ufw-status" && action !== "iptables-status" && (action.startsWith("ufw") || action.startsWith("iptables")))
        refreshFirewallStatus();

    if (action.startsWith("fail2ban") && action !== "fail2ban-status")
        refreshFail2BanStatus();
}

async function handleUfwAdd(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const action = getFormValue(form, "action");
    const port = getFormValue(form, "port");
    const protocol = getFormValue(form, "protocol");
    const source = getFormValue(form, "source");

    if (!port) {
        showCommandResult("firewall", "UFW 添加失败", "端口不能为空。");
        return;
    }

    const args = source
        ? ["ufw", action, "from", source, "to", "any", "port", port, "proto", protocol]
        : ["ufw", action, `${port}/${protocol}`];

    await execute("firewall", "UFW 添加规则", args);
    form.reset();
    refreshFirewallStatus();
}

async function handleUfwDelete(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const number = getFormValue(form, "number");

    if (!number) {
        showCommandResult("firewall", "UFW 删除失败", "规则编号不能为空。");
        return;
    }

    await execute("firewall", "UFW 删除规则", ["ufw", "--force", "delete", number]);
    form.reset();
    refreshFirewallStatus();
}

async function handleIptablesAdd(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const action = getFormValue(form, "action");
    const port = getFormValue(form, "port");
    const protocol = getFormValue(form, "protocol");
    const source = getFormValue(form, "source");

    if (!port) {
        showCommandResult("firewall", "iptables 添加失败", "端口不能为空。");
        return;
    }

    const args = ["iptables", "-I", "INPUT", "-p", protocol];
    if (source)
        args.push("-s", source);
    args.push("--dport", port, "-j", action);

    await execute("firewall", "iptables 插入规则", args);
    form.reset();
    refreshFirewallStatus();
}

async function handleIptablesDelete(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const line = getFormValue(form, "line");

    if (!line) {
        showCommandResult("firewall", "iptables 删除失败", "行号不能为空。");
        return;
    }

    await execute("firewall", "iptables 删除规则", ["iptables", "-D", "INPUT", line]);
    form.reset();
    refreshFirewallStatus();
}

async function handleFail2BanJail(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const jail = getFormValue(form, "jail");

    if (!jail) {
        showCommandResult("fail2ban", "jail 查询失败", "jail 名称不能为空。");
        return;
    }

    await execute("fail2ban", `jail: ${jail}`, ["fail2ban-client", "status", jail]);
}

async function handleFail2BanUnban(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const jail = getFormValue(form, "jail");
    const ip = getFormValue(form, "ip");

    if (!jail || !ip) {
        showCommandResult("fail2ban", "解封失败", "jail 和 IP 都不能为空。");
        return;
    }

    await execute("fail2ban", "Fail2Ban 解封 IP", ["fail2ban-client", "set", jail, "unbanip", ip]);
    form.reset();
    refreshFail2BanStatus();
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

    document.getElementById("refresh-all")?.addEventListener("click", async () => {
        await refreshFirewallStatus();
        await refreshFail2BanStatus();
    });

    document.getElementById("firewall-refresh")?.addEventListener("click", refreshFirewallStatus);
    document.getElementById("fail2ban-refresh")?.addEventListener("click", refreshFail2BanStatus);

    document.getElementById("ufw-add-form")?.addEventListener("submit", handleUfwAdd);
    document.getElementById("ufw-delete-form")?.addEventListener("submit", handleUfwDelete);
    document.getElementById("iptables-add-form")?.addEventListener("submit", handleIptablesAdd);
    document.getElementById("iptables-delete-form")?.addEventListener("submit", handleIptablesDelete);
    document.getElementById("fail2ban-jail-form")?.addEventListener("submit", handleFail2BanJail);
    document.getElementById("fail2ban-unban-form")?.addEventListener("submit", handleFail2BanUnban);
}

document.addEventListener("DOMContentLoaded", async () => {
    bindEvents();
    switchTab(state.activeTab);
    switchFirewallBackend(state.firewallBackend);
    await refreshFail2BanStatus();
});
