const AUTO_REFRESH_MS = 15000;

const state = {
    firewallBackend: "ufw",
    firewallBackends: [],
    firewallBackendsReady: false,
    firewallChains: [],
    firewallPersist: null,
    firewallNotices: [],
    firewallReadOnly: false,
    firewallManager: "",
    securityLogSource: "all",
    firewallRules: {
        columns: [],
        rows: [],
        emptyText: "暂无规则数据。",
        page: 1,
        pageSize: 10,
    },
    firewallDialog: {
        open: false,
        mode: "",
        busy: false,
        error: "",
    },
    currentJail: "",
    fail2banService: "fail2ban.service",
    autoRefreshTimer: null,
    refreshLocks: {
        firewall: null,
        fail2ban: null,
        logs: null,
    },
    securityLogsRefreshPending: false,
    toolInstalled: {
        ufw: null,
        iptables: null,
        nftables: null,
        firewalld: null,
        fail2ban: null,
    },
    toolCommand: {
        ufw: "ufw",
        iptables: "iptables",
        nftables: "nft",
        firewalld: "firewall-cmd",
        fail2ban: "fail2ban-client",
    },
    installDialog: {
        open: false,
        toolId: "",
        packageNames: [],
        data: null,
        checking: false,
        busy: false,
        progressMessage: "",
        error: "",
        cancel: null,
    },
    superuserAllowed: null,
    superuserError: "",
    superuserProxy: null,
    superuserPermission: null,
    superuserDialog: {
        open: false,
        methods: [],
        selectedMethod: "",
        message: "",
        prompt: "",
        value: "",
        echo: false,
        error: "",
        errorTone: "warning",
        inProgress: false,
        promptSeen: false,
        cleanup: null,
        closeAfterSuccess: false,
    },
};

const SECURITY_LOG_FETCH_LIMIT = 200;
const SECURITY_LOG_DISPLAY_LIMIT = 10;

const SECURITY_LOG_SOURCES = [
    {
        id: "all",
        label: "全部服务",
        units: ["ufw.service", "iptables.service", "ip6tables.service", "netfilter-persistent.service", "nftables.service", "firewalld.service", "fail2ban.service"],
        kernelScope: "firewall",
    },
    {
        id: "ufw",
        label: "UFW",
        units: ["ufw.service"],
        kernelScope: "ufw",
    },
    {
        id: "iptables",
        label: "iptables / nftables",
        units: ["iptables.service", "ip6tables.service", "netfilter-persistent.service", "nftables.service"],
        kernelScope: "iptables",
    },
    {
        id: "firewalld",
        label: "firewalld",
        units: ["firewalld.service"],
    },
    {
        id: "fail2ban",
        label: "Fail2Ban",
        units: ["fail2ban.service"],
    },
];

const REQUIRED_TOOLS = {
    ufw: {
        id: "ufw",
        label: "UFW",
        command: "ufw",
        commands: ["ufw"],
        paths: ["/usr/sbin/ufw", "/sbin/ufw"],
        packages: ["ufw"],
        installTitle: "安装 UFW",
        installCopy: "需要安装 UFW 才能管理 UFW 防火墙规则。",
    },
    iptables: {
        id: "iptables",
        label: "iptables",
        command: "iptables",
        commands: ["iptables", "iptables-nft", "iptables-legacy"],
        paths: ["/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables", "/usr/sbin/iptables-nft", "/usr/sbin/iptables-legacy"],
        packages: ["iptables"],
        packageCandidates: [["iptables"], ["iptables-nft"], ["iptables-services"]],
        installTitle: "安装 iptables",
        installCopy: "需要安装 iptables 才能管理 iptables INPUT 规则。",
    },
    nftables: {
        id: "nftables",
        label: "nftables",
        command: "nft",
        commands: ["nft"],
        paths: ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"],
        packages: ["nftables"],
        packageCandidates: [["nftables"]],
        installTitle: "安装 nftables",
        installCopy: "需要安装 nftables 才能查看和管理 nftables 规则。",
    },
    firewalld: {
        id: "firewalld",
        label: "firewalld",
        command: "firewall-cmd",
        commands: ["firewall-cmd"],
        paths: ["/usr/bin/firewall-cmd", "/usr/sbin/firewall-cmd", "/bin/firewall-cmd", "/sbin/firewall-cmd"],
        packages: ["firewalld"],
        packageCandidates: [["firewalld"]],
        installTitle: "安装 firewalld",
        installCopy: "需要安装 firewalld 才能查看和管理防火墙区域配置。",
    },
    fail2ban: {
        id: "fail2ban",
        label: "Fail2Ban",
        command: "fail2ban-client",
        commands: ["fail2ban-client"],
        paths: ["/usr/bin/fail2ban-client", "/usr/sbin/fail2ban-client"],
        packages: ["fail2ban"],
        packageCandidates: [["fail2ban"], ["fail2ban-server"]],
        installTitle: "安装 Fail2Ban",
        installCopy: "需要安装 Fail2Ban 才能查看 jail 状态和管理封禁 IP。",
    },
};

const INSTALL_PROGRESS_TYPE = {
    DOWNLOADING: 0,
    UPDATING: 1,
    INSTALLING: 2,
    REMOVING: 3,
    REINSTALLING: 4,
    DOWNGRADING: 5,
};

const PACKAGEKIT_ENUM = {
    EXIT_SUCCESS: 1,
    EXIT_CANCELLED: 3,
    INFO_DOWNLOADING: 10,
    INFO_UPDATING: 11,
    INFO_INSTALLING: 12,
    INFO_REMOVING: 13,
    INFO_REINSTALLING: 19,
    INFO_DOWNGRADING: 20,
    STATUS_WAIT: 1,
    STATUS_WAITING_FOR_LOCK: 30,
    FILTER_NEWEST: (1 << 16),
    FILTER_ARCH: (1 << 18),
    FILTER_NOT_SOURCE: (1 << 21),
    TRANSACTION_FLAG_SIMULATE: (1 << 2),
};

const PACKAGEKIT_INSTALL_PROGRESS_MAP = {
    [PACKAGEKIT_ENUM.INFO_DOWNLOADING]: INSTALL_PROGRESS_TYPE.DOWNLOADING,
    [PACKAGEKIT_ENUM.INFO_UPDATING]: INSTALL_PROGRESS_TYPE.UPDATING,
    [PACKAGEKIT_ENUM.INFO_INSTALLING]: INSTALL_PROGRESS_TYPE.INSTALLING,
    [PACKAGEKIT_ENUM.INFO_REMOVING]: INSTALL_PROGRESS_TYPE.REMOVING,
    [PACKAGEKIT_ENUM.INFO_REINSTALLING]: INSTALL_PROGRESS_TYPE.REINSTALLING,
    [PACKAGEKIT_ENUM.INFO_DOWNGRADING]: INSTALL_PROGRESS_TYPE.DOWNGRADING,
};

const PACKAGEKIT_TRANSACTION_INTERFACE = "org.freedesktop.PackageKit.Transaction";
const SYSTEM_COMMAND_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const FAIL2BAN_SERVICE_CANDIDATES = ["fail2ban.service", "fail2ban-server.service"];
let packageManager = null;
let packageKitClient = null;
let dnf5Client = null;

function getElement(id) {
    return document.getElementById(id);
}

function setHidden(id, hidden) {
    const element = getElement(id);
    if (element)
        element.hidden = hidden;
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

function refreshSecurityPage() {
    if (state.superuserAllowed === null)
        return Promise.resolve();

    return Promise.all([
        refreshFirewallStatus(),
        refreshFail2BanStatus(),
        refreshSecurityLogs(),
    ]);
}

function startAutoRefresh() {
    stopAutoRefresh();

    if (state.superuserAllowed === null || document.hidden)
        return;

    state.autoRefreshTimer = window.setInterval(() => {
        if (document.hidden || state.superuserAllowed === null)
            return;
        refreshSecurityPage();
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

function renderSuperuserDialog() {
    const dialog = getElement("security-auth-dialog");
    const alert = getElement("security-auth-alert");
    const title = getElement("security-auth-title");
    const message = getElement("security-auth-message");
    const methodField = getElement("security-auth-method-field");
    const methodSelect = getElement("security-auth-method");
    const promptField = getElement("security-auth-prompt-field");
    const promptLabel = getElement("security-auth-prompt-label");
    const promptInput = getElement("security-auth-input");
    const submit = getElement("security-auth-submit");
    const cancel = getElement("security-auth-cancel");

    if (!dialog || !alert || !title || !message || !methodField || !methodSelect || !promptField || !promptLabel || !promptInput || !submit || !cancel)
        return;

    const current = state.superuserDialog;
    dialog.hidden = !current.open;

    if (!current.open)
        return;

    title.textContent = "切换到管理员访问";

    alert.hidden = !current.error;
    alert.textContent = current.error;
    alert.classList.toggle("tone-danger", current.errorTone === "danger");

    methodField.hidden = current.methods.length <= 1 || Boolean(current.prompt);
    methodSelect.replaceChildren();
    current.methods.forEach(method => {
        const option = document.createElement("option");
        option.value = method.id;
        option.textContent = method.label;
        option.selected = method.id === current.selectedMethod;
        methodSelect.append(option);
    });
    methodSelect.disabled = current.inProgress;

    message.hidden = !current.message;
    message.textContent = current.message;

    promptField.hidden = !current.prompt;
    promptLabel.textContent = current.prompt || "密码";
    promptInput.type = current.echo ? "text" : "password";
    promptInput.value = current.value;
    promptInput.disabled = current.inProgress;

    submit.disabled = current.inProgress;
    cancel.disabled = current.inProgress;

    if (current.prompt)
        submit.textContent = current.inProgress ? "验证中..." : "验证";
    else
        submit.textContent = current.inProgress ? "验证中..." : "验证";

    window.setTimeout(() => {
        if (!state.superuserDialog.open)
            return;
        if (!promptField.hidden)
            promptInput.focus();
        else if (!methodField.hidden)
            methodSelect.focus();
        else
            submit.focus();
    }, 0);
}

function closeSuperuserDialog(options = {}) {
    if (options.stop !== false && state.superuserProxy?.valid)
        state.superuserProxy.Stop().catch(() => {});

    resetSuperuserDialog();
    renderSuperuserDialog();
}

function getPreferredSuperuserMethod(methods) {
    if (!methods.length)
        return "sudo";

    const sudo = methods.find(method => method.id === "sudo");
    return (sudo || methods[0]).id;
}

function updateSuperuserDialog(patch) {
    state.superuserDialog = {
        ...state.superuserDialog,
        ...patch,
    };
    renderSuperuserDialog();
}

async function invokeSuperuserStart(method) {
    try {
        return await state.superuserProxy.Start(method);
    } catch (error) {
        const message = formatError(error);
        if (/argument|signature|type/i.test(message))
            return state.superuserProxy.Start();
        throw error;
    }
}

async function startSuperuserAuthentication(method) {
    if (!state.superuserProxy?.valid || typeof state.superuserProxy.Start !== "function")
        throw new Error("当前环境不支持从此页面直接开启管理员权限。");

    const promptListener = (_event, message, prompt, value, _unused, echo, hintError) => {
        updateSuperuserDialog({
            message: normalizePromptText(message, "请验证以获取管理员权限"),
            prompt: normalizePromptText(prompt, "密码"),
            value: String(unwrapVariant(value) || ""),
            echo: Boolean(unwrapVariant(echo)),
            inProgress: false,
            error: hintError ? normalizePromptText(hintError) : "",
            errorTone: state.superuserDialog.promptSeen ? "danger" : "warning",
            promptSeen: true,
        });
    };

    updateSuperuserDialog({
        open: true,
        message: "请验证以获取管理员权限",
        prompt: "",
        value: "",
        echo: false,
        error: "",
        errorTone: "warning",
        inProgress: true,
        promptSeen: false,
    });

    state.superuserProxy.addEventListener("Prompt", promptListener);
    updateSuperuserDialog({
        cleanup: () => state.superuserProxy?.removeEventListener("Prompt", promptListener),
    });

    try {
        await invokeSuperuserStart(method);
        closeSuperuserDialog({ stop: false });
    } catch (error) {
        const message = formatError(error);
        if (message !== "cancelled") {
            updateSuperuserDialog({
                inProgress: false,
                prompt: "",
                message: "",
                error: normalizePromptText(message, "切换为管理员访问时出现问题"),
                errorTone: "danger",
            });
        } else {
            closeSuperuserDialog();
        }
    }
}

async function handleSuperuserDialogSubmit(event) {
    event.preventDefault();
    const current = state.superuserDialog;
    if (!current.open || current.inProgress)
        return;

    if (current.prompt) {
        updateSuperuserDialog({
            inProgress: true,
            error: "",
        });
        state.superuserProxy?.Answer(current.value);
        return;
    }

    const methodSelect = getElement("security-auth-method");
    const selectedMethod = typeof methodSelect?.value === "string" && methodSelect.value
        ? methodSelect.value
        : getPreferredSuperuserMethod(current.methods);

    updateSuperuserDialog({
        selectedMethod,
    });
    await startSuperuserAuthentication(selectedMethod);
}

function handleSuperuserDialogInput(event) {
    if (event.target?.id === "security-auth-input") {
        updateSuperuserDialog({
            value: event.target.value,
        });
        return;
    }

    if (event.target?.id === "security-auth-method") {
        updateSuperuserDialog({
            selectedMethod: event.target.value,
        });
    }
}

async function requestSuperuserAccess() {
    if (state.superuserAllowed === true || state.superuserDialog.open)
        return;

    state.superuserError = "";
    renderAccessState();

    if (!state.superuserProxy?.valid || typeof state.superuserProxy.Start !== "function") {
        state.superuserError = " 当前环境不支持从此页面直接开启管理员权限。";
        renderAccessState();
        return;
    }

    const methods = getSuperuserMethods();
    updateSuperuserDialog({
        open: true,
        methods,
        selectedMethod: getPreferredSuperuserMethod(methods),
        message: methods.length > 1 ? "" : "请验证以获取管理员权限",
        prompt: "",
        value: "",
        echo: false,
        error: "",
        errorTone: "warning",
        inProgress: false,
        promptSeen: false,
        cleanup: null,
    });

    await state.superuserProxy.Stop().catch(() => {});
    if (!state.superuserDialog.open)
        return;

    if (methods.length <= 1)
        await startSuperuserAuthentication(getPreferredSuperuserMethod(methods));
    else
        renderSuperuserDialog();
}

function updateWritableElements() {
    const writable = isWritable();
    document.querySelectorAll("[data-requires-admin]").forEach(element => {
        element.hidden = !writable;
    });
    updateFirewallActionBar();
}

function renderAccessState() {
    const pageContent = document.querySelector(".page-content");
    const panel = getElement("security-access-panel");
    const copy = getElement("security-access-copy");
    const spinner = getElement("security-access-spinner");
    const pending = state.superuserAllowed === null;
    const writable = isWritable();

    // The page itself is never gated on admin rights: unprivileged sessions get
    // the read-only view and only the mutating controls are withheld.
    if (pageContent)
        pageContent.hidden = pending;
    setHidden("security-access-panel", !pending);

    if (pending) {
        if (panel)
            panel.classList.add("is-loading");
        if (spinner)
            spinner.hidden = false;
        if (copy)
            copy.textContent = "正在检查当前会话的管理员访问权限。";
        stopAutoRefresh();
    } else {
        if (panel)
            panel.classList.remove("is-loading");
        if (spinner)
            spinner.hidden = true;
        startAutoRefresh();
    }

    const banner = getElement("security-readonly-panel");
    const bannerCopy = getElement("security-readonly-copy");
    const bannerAction = getElement("security-readonly-action");

    if (banner)
        banner.hidden = pending || writable;

    if (bannerCopy) {
        bannerCopy.textContent = state.superuserError
            ? `当前会话没有管理员权限，只能查看状态。${state.superuserError}`
            : "当前会话没有管理员权限，只能查看状态；修改防火墙、Fail2Ban 或安装软件前请先开启管理员访问。";
    }

    if (bannerAction)
        bannerAction.hidden = Boolean(state.superuserError);

    updateWritableElements();
}

function handleSuperuserStateChange(nextAllowed) {
    const previous = state.superuserAllowed;
    state.superuserAllowed = nextAllowed;
    if (previous !== nextAllowed)
        resetDnf5Connection();
    if (nextAllowed !== false)
        state.superuserError = "";
    if (nextAllowed === true && state.superuserDialog.open)
        closeSuperuserDialog({ stop: false });
    renderAccessState();

    // Re-read on every transition: the session may have gained or lost the
    // ability to see privileged state, and the buttons follow it. Backend
    // detection triggers its own read once the preferred backend is known.
    if (previous !== nextAllowed && nextAllowed !== null && state.firewallBackendsReady)
        refreshSecurityPage();
}

function initSuperuser() {
    state.superuserProxy = cockpit.dbus(null, { bus: "internal" }).proxy("cockpit.Superuser", "/superuser");
    state.superuserProxy.addEventListener("changed", () => {
        handleSuperuserStateChange(computeSuperuserAllowed());
    });

    state.superuserProxy.wait(() => {
        if (!state.superuserProxy.valid) {
            state.superuserPermission = cockpit.permission({ admin: true });
            const updatePermission = () => {
                handleSuperuserStateChange(state.superuserPermission.allowed);
            };
            state.superuserPermission.addEventListener("changed", updatePermission);
            updatePermission();
            return;
        }

        handleSuperuserStateChange(computeSuperuserAllowed());
    });
}

function spawnCommand(args, superuser) {
    return cockpit.spawn(args, {
        superuser,
        err: "out",
        environ: [`PATH=${SYSTEM_COMMAND_PATH}`, "LC_ALL=C"],
    }).then(output => output.trim());
}

// Writes need the superuser bridge; failing loudly is the right behaviour there.
function run(args) {
    return spawnCommand(args, "require");
}

function capture(argsOrScript) {
    return run(argsOrScript)
        .then(output => ({ ok: true, output }))
        .catch(error => ({ ok: false, output: formatError(error) }));
}

// Reads use the superuser bridge when the session already holds it and fall back
// to the unprivileged session otherwise. That fallback is what lets a plain user
// see whatever the host allows without being locked out of the whole page.
function captureRead(argsOrScript) {
    return spawnCommand(argsOrScript, "try")
        .then(output => ({ ok: true, output }))
        .catch(error => ({ ok: false, output: formatError(error) }));
}

const PERMISSION_ERROR_PATTERN = /permission denied|must be root|not permitted|access denied|authentication is required|you must be root|operation not permitted/i;

function isPermissionError(text) {
    return PERMISSION_ERROR_PATTERN.test(String(text || ""));
}

function isWritable() {
    return state.superuserAllowed === true;
}

function runUnprivileged(args) {
    return cockpit.spawn(args, {
        err: "out",
        environ: [`PATH=${SYSTEM_COMMAND_PATH}`, "LC_ALL=C"],
    }).then(output => output.trim());
}

function captureUnprivileged(args) {
    return runUnprivileged(args)
        .then(output => ({ ok: true, output }))
        .catch(error => ({ ok: false, output: formatError(error) }));
}

function getToolCommand(toolId) {
    return state.toolCommand[toolId] || REQUIRED_TOOLS[toolId]?.command || toolId;
}

async function checkToolInstalled(toolId, options = {}) {
    const tool = REQUIRED_TOOLS[toolId];
    if (!tool)
        return false;

    if (options.force !== true && state.toolInstalled[toolId] !== null)
        return state.toolInstalled[toolId];

    const commands = tool.commands || [tool.command];
    const paths = tool.paths || [];
    // Decide by the path we print, not by the script's exit status. cockpit.spawn's
    // resolve/reject behaviour around non-zero exits proved unreliable here (a missing
    // tool was still being treated as installed), and a login shell (-lc) can leak
    // /etc/profile output into stdout. Use a plain `sh -c` that always exits 0 and only
    // prints a path when the tool is actually found.
    const script = [
        `PATH=${SYSTEM_COMMAND_PATH}`,
        ...commands.map(command => `command -v ${command} 2>/dev/null && exit 0`),
        ...paths.map(path => `[ -x ${path} ] && echo ${path} && exit 0`),
        "exit 0",
    ].join("\n");
    const result = await captureUnprivileged(["sh", "-c", script]);
    const found = result.ok
        ? (result.output.split(/\r?\n/).map(line => line.trim()).find(Boolean) || "")
        : "";
    state.toolInstalled[toolId] = Boolean(found);
    if (found)
        state.toolCommand[toolId] = found;
    return Boolean(found);
}

function createPackageManagerError(name, message) {
    const error = new Error(message);
    error.name = name;
    return error;
}

async function isImmutableOS() {
    try {
        const options = await runUnprivileged(["findmnt", "-T", "/usr", "-n", "-o", "VFS-OPTIONS"]);
        return options.split(",").includes("ro");
    } catch (error) {
        console.debug("Unable to detect immutable OS", error);
        return false;
    }
}

async function detectDnf5Daemon() {
    const client = cockpit.dbus("org.rpm.dnf.v0", { superuser: "try" });
    let detected = false;

    try {
        await client.call("/org/rpm/dnf/v0", "org.freedesktop.DBus.Peer", "Ping", []);
        detected = true;
    } catch (error) {
        console.debug("dnf5daemon not supported", error);
    } finally {
        client.close();
    }

    return detected;
}

async function detectPackageKit() {
    const client = cockpit.dbus("org.freedesktop.PackageKit", { superuser: "try" });
    let detected = false;

    try {
        await client.call("/org/freedesktop/PackageKit", "org.freedesktop.DBus.Properties", "Get", ["org.freedesktop.PackageKit", "VersionMajor"]);
        detected = true;
    } catch (error) {
        console.debug("PackageKit not supported", error);
    } finally {
        client.close();
    }

    return detected;
}

async function getPackageManager(forcePackageKit = false) {
    if (packageManager !== null)
        return packageManager;

    const [unsupported, hasDnf5Daemon, hasPackageKit] = await Promise.all([
        isImmutableOS(),
        detectDnf5Daemon(),
        detectPackageKit(),
    ]);

    if (unsupported)
        throw createPackageManagerError("UnsupportedError", "Cockpit does not support installing additional packages on immutable operating systems");

    if (hasDnf5Daemon && !forcePackageKit) {
        packageManager = createDnf5DaemonManager();
        return packageManager;
    }

    if (hasPackageKit) {
        packageManager = createPackageKitManager();
        return packageManager;
    }

    throw createPackageManagerError("NotFoundError", "No package manager found");
}

function resetDnf5Connection() {
    if (dnf5Client)
        dnf5Client.close();
    dnf5Client = null;
}

function packageKitDbusClient() {
    if (!packageKitClient) {
        packageKitClient = cockpit.dbus("org.freedesktop.PackageKit", { superuser: "try", track: true });
        packageKitClient.addEventListener("close", () => {
            packageKitClient = null;
        });
    }

    return packageKitClient;
}

function packageKitCall(objectPath, iface, method, args, options) {
    return packageKitDbusClient().call(objectPath, iface, method, args, options);
}

function watchPackageKitTransaction(transactionPath, signalHandlers, notifyHandler) {
    const subscriptions = [];
    const client = packageKitDbusClient();

    function onClose(_event, error) {
        if (signalHandlers.ErrorCode)
            signalHandlers.ErrorCode("close", formatError(error) || "PackageKit 已断开连接。");
        if (signalHandlers.Finished)
            signalHandlers.Finished(PACKAGEKIT_ENUM.EXIT_CANCELLED);
    }

    function onNotify(reply) {
        const iface = reply?.detail?.[transactionPath]?.[PACKAGEKIT_TRANSACTION_INTERFACE];
        if (iface)
            notifyHandler(iface, transactionPath);
    }

    client.addEventListener("close", onClose);

    if (signalHandlers) {
        Object.keys(signalHandlers).forEach(handler => {
            subscriptions.push(client.subscribe({
                interface: PACKAGEKIT_TRANSACTION_INTERFACE,
                path: transactionPath,
                member: handler,
            }, (_path, _iface, _signal, args) => signalHandlers[handler](...args)));
        });
    }

    if (notifyHandler) {
        subscriptions.push(client.watch(transactionPath));
        client.addEventListener("notify", onNotify);
    }

    subscriptions.push(client.subscribe({
        interface: PACKAGEKIT_TRANSACTION_INTERFACE,
        path: transactionPath,
        member: "Finished",
    }, () => {
        subscriptions.forEach(subscription => subscription.remove());
        client.removeEventListener("close", onClose);
        if (notifyHandler)
            client.removeEventListener("notify", onNotify);
    }));

    return subscriptions[subscriptions.length - 1];
}

function packageKitTransaction(method, arglist, signalHandlers, notifyHandler) {
    return packageKitCall("/org/freedesktop/PackageKit", "org.freedesktop.PackageKit", "CreateTransaction", [])
        .then(([transactionPath]) => {
            if (!signalHandlers && !notifyHandler)
                return transactionPath;

            watchPackageKitTransaction(transactionPath, signalHandlers, notifyHandler);
            if (!method)
                return transactionPath;

            return packageKitCall(transactionPath, PACKAGEKIT_TRANSACTION_INTERFACE, method, arglist)
                .then(() => transactionPath);
        });
}

function packageKitCancellableTransaction(method, arglist, progressCallback, signalHandlers = {}) {
    return new Promise((resolve, reject) => {
        let cancelled = false;
        let status;
        let allowWaitStatus = false;
        const progressData = {
            waiting: false,
            percentage: 0,
            cancel: null,
        };

        function changed(props, transactionPath) {
            function cancel() {
                cancelled = true;
                packageKitCall(transactionPath, PACKAGEKIT_TRANSACTION_INTERFACE, "Cancel", []).catch(() => {});
            }

            if (!progressCallback)
                return;

            if ("Status" in props)
                status = props.Status;
            progressData.waiting = allowWaitStatus && (status === PACKAGEKIT_ENUM.STATUS_WAIT || status === PACKAGEKIT_ENUM.STATUS_WAITING_FOR_LOCK);
            if ("AllowCancel" in props)
                progressData.cancel = props.AllowCancel ? cancel : null;
            if ("Percentage" in props && props.Percentage <= 100)
                progressData.percentage = props.Percentage;

            progressCallback(progressData);
        }

        window.setTimeout(() => {
            allowWaitStatus = true;
            changed({});
        }, 1000);

        packageKitTransaction(method, arglist, {
            ...signalHandlers,
            ErrorCode: (code, detail) => {
                progressCallback = null;
                reject(new Error(cancelled ? "cancelled" : detail || code));
            },
            Finished: exit => {
                progressCallback = null;
                if (cancelled || exit === PACKAGEKIT_ENUM.EXIT_CANCELLED)
                    reject(new Error("cancelled"));
                else
                    resolve(exit);
            },
        }, changed).catch(error => {
            progressCallback = null;
            reject(error);
        });
    });
}

function packageProgressMessage(prefix, progress) {
    if (progress?.waiting)
        return "正在等待其他软件管理操作完成";
    if (!progress?.package)
        return prefix;

    if (progress.info === INSTALL_PROGRESS_TYPE.DOWNLOADING)
        return `正在下载 ${progress.package}`;
    if (progress.info === INSTALL_PROGRESS_TYPE.REMOVING)
        return `正在移除 ${progress.package}`;

    return `正在安装 ${progress.package}`;
}

function formatInstallError(error) {
    const message = formatError(error);
    if (/ServiceUnknown|not-found|not supported|No package manager/i.test(message))
        return "当前系统没有可用的软件管理服务，无法从此页面安装软件包。";
    if (/immutable|read-only|只读|不可变/i.test(message))
        return "当前系统不支持在不可变的 /usr 上安装附加软件包。";
    return message;
}

async function checkMissingPackages(packageNames, progressCallback) {
    const data = {
        download_size: 0,
        missing_ids: [],
        missing_names: [],
        unavailable_names: [],
        extra_names: [],
        remove_names: [],
    };

    await packageKitCancellableTransaction("RefreshCache", [false], progressCallback);

    const installedNames = new Set();
    await packageKitCancellableTransaction("Resolve", [
        PACKAGEKIT_ENUM.FILTER_ARCH | PACKAGEKIT_ENUM.FILTER_NOT_SOURCE | PACKAGEKIT_ENUM.FILTER_NEWEST,
        packageNames,
    ], progressCallback, {
        Package: (_info, packageId) => {
            const parts = packageId.split(";");
            const repos = parts[3]?.split(":") || [];
            if (repos.includes("installed")) {
                installedNames.add(parts[0]);
                return;
            }

            data.missing_ids.push(packageId);
            data.missing_names.push(parts[0]);
        },
    });

    packageNames.forEach(name => {
        if (!installedNames.has(name) && !data.missing_names.includes(name))
            data.unavailable_names.push(name);
    });

    if (data.missing_ids.length > 0 && data.unavailable_names.length === 0) {
        const installIds = [];
        await packageKitCancellableTransaction("InstallPackages", [
            PACKAGEKIT_ENUM.TRANSACTION_FLAG_SIMULATE,
            data.missing_ids,
        ], progressCallback, {
            Package: (info, packageId) => {
                const name = packageId.split(";")[0];
                if (info === PACKAGEKIT_ENUM.INFO_REMOVING) {
                    data.remove_names.push(name);
                } else if (info === PACKAGEKIT_ENUM.INFO_INSTALLING || info === PACKAGEKIT_ENUM.INFO_UPDATING) {
                    installIds.push(packageId);
                    if (!data.missing_names.includes(name))
                        data.extra_names.push(name);
                }
            },
        });

        if (installIds.length > 0) {
            await packageKitCancellableTransaction("GetDetails", [installIds], progressCallback, {
                Details: (...args) => {
                    const details = args[0];
                    const size = details?.size?.v || args[5]?.v || args[5];
                    if (Number.isFinite(Number(size)))
                        data.download_size += Number(size);
                },
            });
        }
    }

    data.missing_names.sort();
    data.extra_names.sort();
    data.remove_names.sort();
    return data;
}

async function installMissingPackages(data, progressCallback) {
    if (!data || data.missing_ids.length === 0)
        return;

    let lastProgress = null;
    let lastInfo = 0;
    let lastName = "";

    function reportProgress() {
        if (!lastProgress)
            return;

        progressCallback({
            waiting: lastProgress.waiting,
            percentage: lastProgress.percentage,
            cancel: lastProgress.cancel,
            info: PACKAGEKIT_INSTALL_PROGRESS_MAP[lastInfo],
            package: lastName,
        });
    }

    await packageKitCancellableTransaction("InstallPackages", [0, data.missing_ids], progress => {
        lastProgress = progress;
        reportProgress();
    }, {
        Package: (info, packageId) => {
            lastInfo = info;
            lastName = packageId.split(";")[0];
            reportProgress();
        },
    });
}

function createPackageKitManager() {
    return {
        name: "packagekit",
        check_missing_packages: checkMissingPackages,
        install_missing_packages: installMissingPackages,
    };
}

function dnf5DbusClient() {
    if (!dnf5Client) {
        dnf5Client = cockpit.dbus("org.rpm.dnf.v0", { superuser: "try", track: true });
        dnf5Client.addEventListener("close", () => {
            dnf5Client = null;
        });
    }

    return dnf5Client;
}

function dnf5Call(objectPath, iface, method, args, options) {
    return dnf5DbusClient().call(objectPath, iface, method, args, options);
}

async function openDnf5Session() {
    const [session] = await dnf5Call("/org/rpm/dnf/v0", "org.rpm.dnf.v0.SessionManager", "open_session", [{}]);
    return session;
}

function closeDnf5Session(session) {
    return dnf5Call("/org/rpm/dnf/v0", "org.rpm.dnf.v0.SessionManager", "close_session", [session]);
}

async function withDnf5Session(executor, signalHandler) {
    let session = null;
    let subscription = null;
    const client = dnf5DbusClient();

    if (signalHandler)
        subscription = client.subscribe({}, signalHandler);

    try {
        session = await openDnf5Session();
        return await executor(session);
    } finally {
        if (session)
            await closeDnf5Session(session);
        if (subscription)
            subscription.remove();
    }
}

function dnf5PackageName(pkg) {
    return pkg?.name?.v || "";
}

function createDnf5DaemonManager() {
    async function refresh(_force, _progressCallback) {
        await withDnf5Session(async session => {
            await dnf5Call(session, "org.rpm.dnf.v0.Base", "read_all_repos", []);
            const [, resolveResult] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "resolve", [{}]);
            if (resolveResult !== 0) {
                const [problem] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "get_transaction_problems_string", []);
                throw createPackageManagerError("ResolveError", `Resolving read_all_repos failed with result=${resolveResult} - ${problem}`);
            }
            await dnf5Call(session, "org.rpm.dnf.v0.Goal", "do_transaction", [{}]);
        });
    }

    async function checkMissingPackagesDnf5(packageNames, progressCallback) {
        const data = {
            download_size: 0,
            missing_ids: [],
            missing_names: [],
            unavailable_names: [],
            extra_names: [],
            remove_names: [],
        };

        if (packageNames.length === 0)
            return data;

        async function resolve(session) {
            const installedNames = new Set();
            const seenNames = new Set();
            const [results] = await dnf5Call(session, "org.rpm.dnf.v0.rpm.Rpm", "list", [{
                package_attrs: { t: "as", v: ["name", "is_installed"] },
                scope: { t: "s", v: "all" },
                patterns: { t: "as", v: packageNames },
            }]);

            for (const pkg of results || []) {
                const name = dnf5PackageName(pkg);
                if (!name || seenNames.has(name))
                    continue;

                if (pkg.is_installed?.v) {
                    installedNames.add(name);
                } else {
                    data.missing_ids.push(name);
                    data.missing_names.push(name);
                }

                seenNames.add(name);
            }

            packageNames.forEach(name => {
                if (!installedNames.has(name) && !data.missing_names.includes(name))
                    data.unavailable_names.push(name);
            });
        }

        async function simulate(session) {
            if (data.missing_ids.length === 0 || data.unavailable_names.length > 0)
                return;

            await dnf5Call(session, "org.rpm.dnf.v0.rpm.Rpm", "install", [packageNames, {}]);
            const [transactionItems, result] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "resolve", [{}]);
            if (result !== 0) {
                const [problem] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "get_transaction_problems_string", []);
                throw createPackageManagerError("ResolveError", `Resolving install failed with result=${result}. ${problem}`);
            }

            for (const transactionItem of transactionItems || []) {
                const [objectType, action, reason,, pkg] = transactionItem;
                const name = dnf5PackageName(pkg);
                if (objectType !== "Package" || !name)
                    continue;

                data.download_size += Number(pkg.download_size?.v || 0);
                if (reason === "Dependency" && !data.missing_names.includes(name))
                    data.extra_names.push(name);
                if (action === "Replaced" && !data.remove_names.includes(name))
                    data.remove_names.push(name);
            }

            await dnf5Call(session, "org.rpm.dnf.v0.Goal", "reset", []);
        }

        function signalEmitted() {
            if (progressCallback) {
                progressCallback({
                    waiting: false,
                    percentage: 0,
                    cancel: null,
                });
            }
        }

        await refresh(false);
        await withDnf5Session(async session => {
            await resolve(session);
            await simulate(session);
        }, signalEmitted);

        data.missing_names.sort();
        data.extra_names.sort();
        data.remove_names.sort();
        return data;
    }

    async function installMissingPackagesDnf5(data, progressCallback) {
        if (!data || data.missing_ids.length === 0)
            return;

        let lastInfo = INSTALL_PROGRESS_TYPE.INSTALLING;
        let lastProgress = 0;
        let lastName = "";
        let totalPackages = 0;

        function signalEmitted(_path, _iface, signal, args) {
            switch (signal) {
            case "download_add_new":
                lastInfo = INSTALL_PROGRESS_TYPE.DOWNLOADING;
                lastName = args[2] || "";
                break;
            case "download_progress":
                lastInfo = INSTALL_PROGRESS_TYPE.DOWNLOADING;
                break;
            case "download_end":
                lastInfo = INSTALL_PROGRESS_TYPE.INSTALLING;
                lastName = "";
                break;
            case "transaction_before_begin":
                totalPackages = Number(args[1] || 0);
                lastInfo = INSTALL_PROGRESS_TYPE.INSTALLING;
                break;
            case "transaction_elem_progress":
                lastName = args[1] || "";
                lastProgress = totalPackages ? Number(args[2] || 0) / totalPackages * 100 : 0;
                break;
            }

            if (progressCallback) {
                progressCallback({
                    cancel: null,
                    info: lastInfo,
                    package: lastName,
                    percentage: lastProgress,
                    waiting: false,
                });
            }
        }

        await withDnf5Session(async session => {
            try {
                await dnf5Call(session, "org.rpm.dnf.v0.rpm.Rpm", "install", [data.missing_names, {}]);
                const [, resolveResult] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "resolve", [{}]);
                if (resolveResult !== 0) {
                    const [problem] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "get_transaction_problems_string", []);
                    throw createPackageManagerError("ResolveError", `Resolving install failed with result=${resolveResult} ${problem}`);
                }
                await dnf5Call(session, "org.rpm.dnf.v0.Goal", "do_transaction", [{}]);
            } catch (error) {
                console.warn("install error", error);
            }
        }, signalEmitted);
    }

    return {
        name: "dnf5daemon",
        check_missing_packages: checkMissingPackagesDnf5,
        install_missing_packages: installMissingPackagesDnf5,
        refresh,
    };
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

function unwrapVariant(value) {
    let current = value;
    while (
        current &&
        typeof current === "object" &&
        Object.prototype.hasOwnProperty.call(current, "v") &&
        Object.keys(current).length === 1
    ) {
        current = current.v;
    }
    return current;
}

function normalizePromptText(value, fallback = "") {
    const text = String(unwrapVariant(value) || "").replace(/^\[sudo] /, "").trim();
    if (!text)
        return fallback;
    return text.charAt(0).toUpperCase() + text.slice(1);
}

function getSuperuserMethods() {
    const methods = unwrapVariant(state.superuserProxy?.Methods);
    if (!methods || typeof methods !== "object")
        return [];

    return Object.keys(methods).map(id => {
        const definition = unwrapVariant(methods[id]);
        const label = normalizePromptText(unwrapVariant(definition?.label), id);
        return { id, label: label || id };
    });
}

function resetSuperuserDialog() {
    if (typeof state.superuserDialog.cleanup === "function")
        state.superuserDialog.cleanup();

    state.superuserDialog = {
        open: false,
        methods: [],
        selectedMethod: "",
        message: "",
        prompt: "",
        value: "",
        echo: false,
        error: "",
        errorTone: "warning",
        inProgress: false,
        promptSeen: false,
        cleanup: null,
        closeAfterSuccess: false,
    };
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
    element.classList.remove("tone-success", "tone-warning", "tone-danger", "tone-loading", "pf-m-green", "pf-m-orange", "pf-m-red");
    if (tone === "success")
        element.classList.add("pf-m-green");
    else if (tone === "warning")
        element.classList.add("pf-m-orange");
    else if (tone === "danger")
        element.classList.add("pf-m-red");
    if (tone === "loading")
        element.classList.add("tone-loading");
}

function setCallout(id, text, tone = "neutral") {
    const element = document.getElementById(id);
    if (!element)
        return;

    element.textContent = text;
    element.hidden = !text;
    element.classList.remove("tone-success", "tone-warning", "tone-danger");
    if (tone === "success")
        element.classList.add("tone-success");
    else if (tone === "warning")
        element.classList.add("tone-warning");
    else if (tone === "danger")
        element.classList.add("tone-danger");
}

function getCurrentFirewallTool() {
    return REQUIRED_TOOLS[state.firewallBackend] || REQUIRED_TOOLS.ufw;
}

function renderFirewallInstallState(missing) {
    const tool = getCurrentFirewallTool();
    const content = getElement("firewall-settings-content");
    const installState = getElement("firewall-install-state");
    const title = getElement("firewall-install-title");
    const copy = getElement("firewall-install-copy");
    const action = getElement("firewall-install-action");

    if (content)
        content.hidden = Boolean(missing);
    if (installState)
        installState.hidden = !missing;

    if (!missing)
        return;

    setBadge("firewall-status-pill", "未安装", isWritable() ? "warning" : "neutral");
    if (title)
        title.textContent = tool.installTitle;
    if (copy)
        copy.textContent = isWritable() ? tool.installCopy : `${tool.installCopy} 安装软件需要管理员权限。`;
    if (action) {
        action.textContent = tool.installTitle;
        action.dataset.installTool = tool.id;
    }
}

function renderFail2BanInstallState(missing) {
    const content = getElement("fail2ban-settings-content");
    const installState = getElement("fail2ban-install-state");
    const copy = installState?.querySelector(".pf-v6-c-empty-state__body");

    if (content)
        content.hidden = Boolean(missing);
    if (installState)
        installState.hidden = !missing;

    if (copy)
        copy.textContent = isWritable()
            ? "需要安装 Fail2Ban 才能查看 jail 状态和管理封禁 IP。"
            : "需要安装 Fail2Ban 才能查看 jail 状态和管理封禁 IP。安装软件需要管理员权限。";

    if (missing)
        setBadge("fail2ban-service-pill", "未安装", isWritable() ? "warning" : "neutral");
}

function resetInstallDialog(options = {}) {
    if (options.cancel !== false && typeof state.installDialog.cancel === "function")
        state.installDialog.cancel();

    state.installDialog = {
        open: false,
        toolId: "",
        packageNames: [],
        data: null,
        checking: false,
        busy: false,
        progressMessage: "",
        error: "",
        cancel: null,
    };
}

function updateInstallDialog(patch) {
    state.installDialog = {
        ...state.installDialog,
        ...patch,
    };
    renderInstallDialog();
}

function appendPackageList(container, label, items) {
    if (!items?.length)
        return;

    const section = document.createElement("div");
    section.className = "security-package-list";
    const heading = document.createElement("p");
    heading.textContent = label;
    const list = document.createElement("ul");
    list.className = "package-list-ct";

    items.forEach(item => {
        const listItem = document.createElement("li");
        listItem.textContent = item;
        list.append(listItem);
    });

    section.append(heading, list);
    container.append(section);
}

function renderInstallDialog() {
    const dialog = getElement("security-install-dialog");
    const title = getElement("security-install-title");
    const alert = getElement("security-install-alert");
    const body = getElement("security-install-body");
    const footerMessage = getElement("security-install-footer-message");
    const submit = getElement("security-install-submit");
    const cancel = getElement("security-install-cancel");
    const close = getElement("security-install-close");

    if (!dialog || !title || !alert || !body || !footerMessage || !submit || !cancel || !close)
        return;

    const current = state.installDialog;
    const tool = REQUIRED_TOOLS[current.toolId] || REQUIRED_TOOLS.ufw;
    dialog.hidden = !current.open;
    if (!current.open)
        return;

    title.textContent = "安装软件";
    alert.hidden = !current.error;
    alert.textContent = current.error;
    alert.classList.toggle("tone-danger", Boolean(current.error));

    body.replaceChildren();
    const text = document.createElement("p");
    const packageNames = (current.packageNames?.length ? current.packageNames : tool.packages).join(", ");
    const packageName = document.createElement("strong");
    packageName.textContent = packageNames;
    text.append(packageName, " 将被安装。");
    body.append(text);

    appendPackageList(body, "附加软件包：", current.data?.extra_names || []);
    appendPackageList(body, "将被移除：", current.data?.remove_names || []);

    let footerText = current.progressMessage;
    if (!footerText && current.data?.download_size)
        footerText = `总大小：${cockpit.format_bytes(current.data.download_size)}`;

    footerMessage.hidden = !footerText;
    footerMessage.replaceChildren();
    if (footerText) {
        footerMessage.append(document.createTextNode(footerText));
        if (current.checking || current.busy) {
            const spinner = document.createElement("span");
            spinner.className = "pf-v6-c-spinner pf-m-sm";
            spinner.setAttribute("role", "progressbar");
            spinner.setAttribute("aria-label", "加载中");
            footerMessage.append(spinner);
        }
    }

    submit.disabled = current.checking || current.busy || !current.data || Boolean(current.error && !current.data);
    submit.textContent = current.busy ? "安装中..." : "安装";
    cancel.disabled = false;
    close.disabled = false;
}

async function resolveToolInstallPackages(manager, tool, progressCallback) {
    const candidates = tool.packageCandidates?.length ? tool.packageCandidates : [tool.packages];
    let lastResult = null;
    const unavailableNames = new Set();

    for (const packageNames of candidates) {
        updateInstallDialog({ packageNames });
        const data = await manager.check_missing_packages(packageNames, progressCallback);
        lastResult = { packageNames, data };
        if (!data.unavailable_names.length)
            return lastResult;

        data.unavailable_names.forEach(name => unavailableNames.add(name));
    }

    if (lastResult && unavailableNames.size > 0)
        lastResult.data.unavailable_names = Array.from(unavailableNames);

    return lastResult;
}

async function openInstallDialog(toolId) {
    const tool = REQUIRED_TOOLS[toolId];
    if (!tool || !isWritable())
        return;

    if (await checkToolInstalled(toolId, { force: true })) {
        if (toolId === "fail2ban")
            refreshFail2BanStatus();
        else
            refreshFirewallStatus();
        return;
    }

    resetInstallDialog();
    state.installDialog = {
        open: true,
        toolId,
        packageNames: tool.packages,
        data: null,
        checking: true,
        busy: false,
        progressMessage: "正在检查已安装的软件",
        error: "",
        cancel: null,
    };
    renderInstallDialog();

    try {
        const manager = await getPackageManager();
        const result = await resolveToolInstallPackages(manager, tool, progress => {
            updateInstallDialog({
                progressMessage: progress?.waiting ? "正在等待其他软件管理操作完成" : "正在检查已安装的软件",
                cancel: progress?.cancel || null,
            });
        });
        const data = result?.data || { unavailable_names: tool.packages };

        updateInstallDialog({
            packageNames: result?.packageNames || tool.packages,
            data: data.unavailable_names.length ? null : data,
            checking: false,
            progressMessage: "",
            cancel: null,
            error: data.unavailable_names.length
                ? `${data.unavailable_names[0]} 不在任何可用软件仓库中。`
                : "",
        });
    } catch (error) {
        if (formatError(error) === "cancelled") {
            closeInstallDialog();
            return;
        }

        updateInstallDialog({
            checking: false,
            progressMessage: "",
            cancel: null,
            error: formatInstallError(error) || "无法使用系统软件管理服务。",
        });
    }
}

function closeInstallDialog(options = {}) {
    resetInstallDialog(options);
    renderInstallDialog();
}

async function handleInstallDialogSubmit() {
    const current = state.installDialog;
    if (!isWritable() || !current.open || current.checking || current.busy || !current.data)
        return;

    const toolId = current.toolId;
    updateInstallDialog({
        busy: true,
        error: "",
        progressMessage: "正在安装软件包",
    });

    try {
        const manager = await getPackageManager();
        await manager.install_missing_packages(current.data, progress => {
            updateInstallDialog({
                progressMessage: packageProgressMessage("正在安装软件包", progress),
                cancel: progress?.cancel || null,
            });
        });
    } catch (error) {
        if (formatError(error) === "cancelled") {
            closeInstallDialog();
            return;
        }

        updateInstallDialog({
            busy: false,
            progressMessage: "",
            cancel: null,
            error: formatInstallError(error) || "安装软件包失败。",
        });
        return;
    }

    closeInstallDialog({ cancel: false });
    await checkToolInstalled(toolId, { force: true });
    if (toolId === "fail2ban")
        await refreshFail2BanStatus();
    else
        await refreshFirewallStatus();
    refreshSecurityLogs();
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

function renderDetailList(id, items, emptyText = "暂无详情。") {
    const list = document.getElementById(id);
    if (!list)
        return;

    list.replaceChildren();

    const entries = items.length ? items : [["状态", emptyText]];
    const fragment = document.createDocumentFragment();

    entries.forEach(([label, value]) => {
        const group = document.createElement("div");
        group.className = "pf-v6-c-description-list__group";

        const dt = document.createElement("dt");
        dt.className = "pf-v6-c-description-list__term";
        const termText = document.createElement("span");
        termText.className = "pf-v6-c-description-list__text";
        termText.textContent = label;
        dt.append(termText);

        const dd = document.createElement("dd");
        dd.className = "pf-v6-c-description-list__description";
        const descriptionText = document.createElement("div");
        descriptionText.className = "pf-v6-c-description-list__text";
        descriptionText.textContent = value;
        dd.append(descriptionText);

        group.append(dt, dd);
        fragment.append(group);
    });

    list.append(fragment);
}

function renderTable(headId, bodyId, emptyId, columns, rows, emptyText) {
    const head = document.getElementById(headId);
    const body = document.getElementById(bodyId);
    const empty = document.getElementById(emptyId);

    if (!head || !body || !empty)
        return;

    const normalizedRows = rows.map(row => Array.isArray(row) ? { cells: row } : row);
    const hasActions = normalizedRows.some(row => row.delete);
    const table = body.closest("table");
    const headRow = document.createElement("tr");
    headRow.className = "pf-v6-c-table__tr";
    columns.forEach(column => {
        const th = document.createElement("th");
        th.className = "pf-v6-c-table__th";
        th.scope = "col";
        th.textContent = column;
        headRow.append(th);
    });
    if (hasActions) {
        const th = document.createElement("th");
        th.className = "pf-v6-c-table__th";
        th.scope = "col";
        th.textContent = "操作";
        headRow.append(th);
    }

    head.replaceChildren(headRow);
    body.replaceChildren();
    table?.classList.toggle("ct-table-empty", !normalizedRows.length);

    if (!normalizedRows.length) {
        empty.hidden = true;
        const row = document.createElement("tr");
        row.className = "pf-v6-c-table__tr";
        const cell = document.createElement("td");
        cell.className = "pf-v6-c-table__td empty-message";
        cell.colSpan = columns.length + (hasActions ? 1 : 0);
        cell.textContent = emptyText;
        row.append(cell);
        body.append(row);
        return;
    }

    empty.hidden = true;
    normalizedRows.forEach(row => {
        const tr = document.createElement("tr");
        tr.className = "pf-v6-c-table__tr";

        row.cells.forEach((cell, index) => {
            const element = document.createElement(index === 0 ? "th" : "td");
            if (index === 0) {
                element.scope = "row";
                element.className = "pf-v6-c-table__th data-table__primary";
            } else {
                element.className = "pf-v6-c-table__td";
            }
            element.dataset.label = columns[index] || "";
            element.textContent = cell;
            tr.append(element);
        });

        if (hasActions) {
            const actionCell = document.createElement("td");
            actionCell.className = "pf-v6-c-table__td data-table__action";
            actionCell.dataset.label = "操作";

            if (row.delete && !row.delete.disabled) {
                const button = document.createElement("button");
                button.type = "button";
                button.className = "pf-v6-c-button pf-m-link pf-m-inline data-table__delete";
                button.textContent = row.delete.label || "删除";
                button.addEventListener("click", () => {
                    deleteFirewallRule(row.delete);
                });
                actionCell.append(button);
            } else if (row.delete?.disabled) {
                const hint = document.createElement("span");
                hint.className = "data-table__hint";
                hint.textContent = "由外部工具管理";
                actionCell.append(hint);
            }

            tr.append(actionCell);
        }

        body.append(tr);
    });
}

function getFirewallRuleTotalPages() {
    return Math.max(1, Math.ceil(state.firewallRules.rows.length / state.firewallRules.pageSize));
}

function updateFirewallRulePageOptions(totalPages) {
    const options = document.getElementById("firewall-rules-page-options");
    if (!options)
        return;

    const fragment = document.createDocumentFragment();
    for (let page = 1; page <= totalPages; page++) {
        const option = document.createElement("option");
        option.value = String(page);
        option.label = `第 ${page} 页`;
        fragment.append(option);
    }
    options.replaceChildren(fragment);
}

function renderFirewallRulePagination(totalRows) {
    const container = document.getElementById("firewall-rules-pagination");
    const meta = document.getElementById("firewall-rules-page-meta");
    const prev = document.getElementById("firewall-rules-prev");
    const next = document.getElementById("firewall-rules-next");
    const jumpInput = document.getElementById("firewall-rules-page-jump");

    if (!container || !meta || !prev || !next)
        return;

    const totalPages = Math.max(1, Math.ceil(totalRows / state.firewallRules.pageSize));
    container.hidden = totalRows <= state.firewallRules.pageSize;
    meta.textContent = `第 ${state.firewallRules.page} / ${totalPages} 页`;
    prev.disabled = state.firewallRules.page <= 1;
    next.disabled = state.firewallRules.page >= totalPages;
    updateFirewallRulePageOptions(totalPages);

    if (jumpInput) {
        jumpInput.value = String(state.firewallRules.page);
        jumpInput.setAttribute("aria-label", `跳转到页码，共 ${totalPages} 页`);
    }
}

function renderFirewallRulesTable() {
    const { columns, rows, emptyText, page, pageSize } = state.firewallRules;
    const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
    const currentPage = Math.min(Math.max(1, page), totalPages);
    state.firewallRules.page = currentPage;

    const start = (currentPage - 1) * pageSize;
    const pageRows = rows.slice(start, start + pageSize);
    renderTable("firewall-rules-head", "firewall-rules-body", "firewall-rules-empty", columns, pageRows, emptyText);
    renderFirewallRulePagination(rows.length);
}

function jumpToFirewallRulesPage(value) {
    const pageText = String(value || "").trim();
    if (!/^\d+$/.test(pageText)) {
        renderFirewallRulesTable();
        return;
    }

    const totalPages = getFirewallRuleTotalPages();
    const nextPage = Math.min(Math.max(1, Number(pageText)), totalPages);
    state.firewallRules.page = nextPage;
    renderFirewallRulesTable();
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
        token.className = "pf-v6-c-label pf-m-outline token";
        token.textContent = options.emptyText;
        container.append(token);
        return;
    }

    items.forEach(item => {
        if (options.clickable) {
            const button = document.createElement("button");
            button.type = "button";
            button.className = "pf-v6-c-button pf-m-tertiary token-button";
            button.textContent = item;
            button.addEventListener("click", () => options.onClick(item));
            container.append(button);
            return;
        }

        const token = document.createElement("span");
        token.className = "pf-v6-c-label pf-m-outline token";
        token.textContent = item;
        container.append(token);
    });
}

function getSecurityLogSource(id = state.securityLogSource) {
    return SECURITY_LOG_SOURCES.find(source => source.id === id) || SECURITY_LOG_SOURCES[0];
}

function renderSecurityLogSourceOptions() {
    const menuList = document.getElementById("security-log-menu-list");
    const toggleText = document.getElementById("security-log-source-text");
    if (!menuList || !toggleText)
        return;

    const currentSource = getSecurityLogSource();
    toggleText.textContent = currentSource.label;

    menuList.replaceChildren();
    SECURITY_LOG_SOURCES.forEach(source => {
        const item = document.createElement("li");
        item.setAttribute("role", "menuitem");
        item.className = "pf-v6-c-menu__item";
        if (source.id === state.securityLogSource)
            item.classList.add("pf-m-selected");
        item.textContent = source.label;

        const button = document.createElement("button");
        button.type = "button";
        button.className = "pf-v6-c-menu__item";
        if (source.id === state.securityLogSource)
            button.classList.add("pf-m-selected");
        button.textContent = source.label;
        button.addEventListener("click", () => {
            switchSecurityLogSource(source.id);
            closeSecurityLogMenu();
        });

        const listItem = document.createElement("li");
        listItem.setAttribute("role", "none");
        listItem.append(button);
        menuList.append(listItem);
    });
}

function toggleSecurityLogMenu() {
    const menu = document.getElementById("security-log-menu");
    if (!menu)
        return;
    menu.hidden = !menu.hidden;
}

function closeSecurityLogMenu() {
    const menu = document.getElementById("security-log-menu");
    if (menu)
        menu.hidden = true;
}

function buildSecurityLogArgs(source = getSecurityLogSource()) {
    const args = ["journalctl", "-q", "--no-pager", "-n", String(SECURITY_LOG_FETCH_LIMIT), "-o", "json"];
    let hasMatch = false;

    source.units.forEach(unit => {
        if (hasMatch)
            args.push("+");
        args.push(`_SYSTEMD_UNIT=${unit}`);
        hasMatch = true;
    });

    if (source.kernelScope) {
        if (hasMatch)
            args.push("+");
        args.push("_TRANSPORT=kernel");
    }

    return args;
}

function getSecurityLogUrl(source = getSecurityLogSource()) {
    const params = new URLSearchParams({ prio: "debug" });
    if (source.units.length)
        params.set("_SYSTEMD_UNIT", source.units.join(","));
    if (source.kernelScope)
        params.set("_TRANSPORT", "kernel");

    return `/system/logs/#/?${params.toString()}`;
}

function getSecurityLogParentOptions(source = getSecurityLogSource()) {
    const options = { prio: "debug" };
    if (source.units.length)
        options._SYSTEMD_UNIT = source.units.join(",");
    if (source.kernelScope)
        options._TRANSPORT = "kernel";
    return options;
}

function isKernelJournalEntry(entry) {
    return entry._TRANSPORT === "kernel" || entry.SYSLOG_IDENTIFIER === "kernel" || entry._COMM === "kernel";
}

function isUfwKernelMessage(message) {
    return /\bUFW\b|\[UFW\s+/i.test(message);
}

function isFirewallKernelMessage(message) {
    const normalized = normalizeWhitespace(message);
    return isUfwKernelMessage(normalized) ||
        /\b(?:IN|OUT|MAC|SRC|DST|LEN|TOS|PREC|TTL|ID|PROTO|SPT|DPT|WINDOW|RES|UID|GID)=/i.test(normalized) ||
        /\b(?:iptables|ip6tables|nftables|netfilter)\b/i.test(normalized);
}

function entryMatchesSecurityLogSource(entry, source = getSecurityLogSource()) {
    if (source.units.includes(entry._SYSTEMD_UNIT))
        return true;

    if (!source.kernelScope || !isKernelJournalEntry(entry))
        return false;

    const message = getJournalMessage(entry);
    if (source.kernelScope === "ufw")
        return isUfwKernelMessage(message);
    if (source.kernelScope === "iptables")
        return isFirewallKernelMessage(message) && !isUfwKernelMessage(message);

    return isFirewallKernelMessage(message);
}

function formatJournalTimestamp(entry, options) {
    const timestamp = Number(entry.__REALTIME_TIMESTAMP);
    if (!Number.isFinite(timestamp))
        return "";

    return new Date(timestamp / 1000).toLocaleString("zh-CN", options);
}

function formatJournalDay(entry) {
    return formatJournalTimestamp(entry, {
        year: "numeric",
        month: "long",
        day: "numeric",
    });
}

function formatJournalTime(entry) {
    return formatJournalTimestamp(entry, {
        hour: "2-digit",
        minute: "2-digit",
    });
}

function getJournalIdentifier(entry) {
    return entry.SYSLOG_IDENTIFIER || entry._COMM || entry._SYSTEMD_UNIT || "journal";
}

function getJournalMessage(entry) {
    return String(entry.MESSAGE || "").trim() || "没有日志消息。";
}

function openJournalEntry(entry) {
    if (!entry.__CURSOR)
        return;

    const parentOptions = encodeURIComponent(JSON.stringify(getSecurityLogParentOptions()));
    cockpit.jump(`system/logs#/${entry.__CURSOR}?parent_options=${parentOptions}`);
}

function getSecurityLogContainer() {
    return document.getElementById("security-log-list");
}

function renderSecurityLogs(entries) {
    const container = getSecurityLogContainer();
    if (!container)
        return;

    container.replaceChildren();

    if (!entries.length) {
        const empty = document.createElement("div");
        empty.className = "empty-message";
        empty.textContent = "没有安全日志。";
        container.append(empty);
        return;
    }

    let currentDay = "";
    entries.forEach(entry => {
        const day = formatJournalDay(entry);
        if (day && day !== currentDay) {
            currentDay = day;
            const heading = document.createElement("div");
            heading.className = "panel-heading";
            heading.textContent = day;
            container.append(heading);
        }

        const row = document.createElement("div");
        row.className = "cockpit-logline";
        row.role = "row";
        row.tabIndex = 0;
        row.addEventListener("click", () => openJournalEntry(entry));
        row.addEventListener("keydown", event => {
            if (event.key === "Enter")
                openJournalEntry(entry);
        });

        const warning = document.createElement("div");
        warning.className = "cockpit-log-warning";
        warning.role = "cell";
        warning.textContent = Number(entry.PRIORITY) < 4 ? "!" : "";

        const time = document.createElement("div");
        time.className = "cockpit-log-time";
        time.role = "cell";
        time.textContent = formatJournalTime(entry);

        const message = document.createElement("span");
        message.className = "cockpit-log-message";
        message.role = "cell";
        message.textContent = getJournalMessage(entry);

        const service = document.createElement("div");
        service.className = "cockpit-log-service";
        service.role = "cell";
        service.textContent = getJournalIdentifier(entry);

        row.append(warning, time, message, service);
        container.append(row);
    });
}

function renderSecurityLogMessage(message) {
    const container = getSecurityLogContainer();
    if (!container)
        return;

    const empty = document.createElement("div");
    empty.className = "empty-message";
    empty.textContent = message;
    container.replaceChildren(empty);
}

async function refreshSecurityLogs() {
    if (state.refreshLocks.logs) {
        state.securityLogsRefreshPending = true;
        renderSecurityLogMessage("正在加载安全日志...");
        return state.refreshLocks.logs;
    }

    const task = withRefreshLock("logs", async () => {
        if (state.superuserAllowed === null)
            return;

        const sourceId = state.securityLogSource;
        const source = getSecurityLogSource();
        renderSecurityLogMessage("正在加载安全日志...");
        const result = await captureRead(buildSecurityLogArgs(source));
        if (state.securityLogSource !== sourceId) {
            state.securityLogsRefreshPending = true;
            return;
        }

        if (!result.ok) {
            renderSecurityLogMessage(isPermissionError(result.output)
                ? "需要管理员权限才能读取系统日志。"
                : summarizeOutput(result.output, false));
            return;
        }

        const entries = String(result.output || "")
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(Boolean)
            .map(line => {
                try {
                    return JSON.parse(line);
                } catch (_error) {
                    return null;
                }
            })
            .filter(Boolean)
            .filter(entry => entryMatchesSecurityLogSource(entry, source))
            .slice(-SECURITY_LOG_DISPLAY_LIMIT);

        renderSecurityLogs(entries);
    });

    return task.finally(() => {
        if (state.securityLogsRefreshPending && state.superuserAllowed !== null) {
            state.securityLogsRefreshPending = false;
            return refreshSecurityLogs();
        }
    });
}

function switchSecurityLogSource(sourceId) {
    state.securityLogSource = sourceId;
    renderSecurityLogSourceOptions();
    refreshSecurityLogs();
}

function positionSecurityLogMenu() {
    const toggle = document.getElementById("security-log-source-toggle");
    const menu = document.getElementById("security-log-menu");
    if (!toggle || !menu)
        return;
    const rect = toggle.getBoundingClientRect();
    menu.style.position = "fixed";
    menu.style.top = (rect.bottom + 4) + "px";
    menu.style.left = rect.left + "px";
    menu.style.minWidth = rect.width + "px";
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

async function resolveServiceUnit(candidates, fallback) {
    for (const candidate of candidates) {
        const result = await captureRead(["systemctl", "show", candidate, "--property=LoadState", "--value"]);
        if (result.ok && String(result.output || "").trim() !== "not-found")
            return candidate;
    }

    return fallback;
}

async function resolveFail2BanService() {
    state.fail2banService = await resolveServiceUnit(FAIL2BAN_SERVICE_CANDIDATES, "fail2ban.service");
    return state.fail2banService;
}

// ---------------------------------------------------------------------------
// Firewall backends
//
// A backend is one entry in FIREWALL_BACKENDS. It owns exactly four things:
//
//   capabilities          which buttons the UI may offer (enable, disable,
//                         reload, addRule, deleteRule, persist)
//   read()                turns manager specific output into the common status
//                         shape { summary, statusLabel, tone, details, columns,
//                         rows, chains, persist, emptyText }
//   buildAddRule()/...    turns form values or a table row into command steps
//   quickActions()        backend specific one-shot commands ("reload", "save")
//
// The UI layer below never mentions ufw/iptables/nft/firewalld by name; it only
// talks to the selected backend. A new manager therefore only needs a new
// object here.
// ---------------------------------------------------------------------------

const FIREWALL_BACKEND_ORDER = ["firewalld", "ufw", "nftables", "iptables"];
const FIREWALL_BACKEND_STORAGE_KEY = "cockpit-security:firewall-backend";

const FIREWALL_CONTEXT = {
    read: captureRead,
    tool: getToolCommand,
};

function getFirewallBackend(id = state.firewallBackend) {
    return FIREWALL_BACKENDS[id] || FIREWALL_BACKENDS.ufw;
}

async function permissionResult(label, output, units = []) {
    const details = [["权限", "读取规则需要管理员权限。"]];
    for (const unit of units) {
        const result = await captureRead(["systemctl", "show", unit, "--property=ActiveState,UnitFileState,LoadState"]);
        if (!result.ok)
            continue;
        const values = parseSystemdShow(result.output);
        if (!values.LoadState || values.LoadState === "not-found")
            continue;
        details.push([unit, `${normalizeStatus(values.ActiveState || "")} / ${normalizeStatus(values.UnitFileState || "")}`]);
    }

    return {
        kind: "permission",
        summary: `${label} 规则需要管理员权限才能读取。`,
        detail: summarizeOutput(output, false),
        details,
    };
}

function backendError(output) {
    return { kind: "error", message: output };
}

function persistDetail(persist) {
    if (!persist)
        return ["持久化", "未知"];

    const stateLabels = {
        saved: "已持久化",
        managed: "由服务自身管理",
        pending: "运行时规则未保存",
        missing: "未找到持久化文件",
        unreadable: "无法读取（需要管理员权限）",
        unsupported: "未检测到持久化机制",
        unknown: "无法确认",
    };
    const where = persist.file ? `（${persist.file}）` : "";
    return ["持久化", `${stateLabels[persist.state] || stateLabels.unknown}${where}`];
}

function buildPersistSteps(mechanism, file) {
    if (mechanism === "netfilter-persistent")
        return [{ args: ["netfilter-persistent", "save"], label: "保存 iptables 规则" }];

    const target = file || "/etc/iptables/rules.v4";
    return [{
        args: ["sh", "-c", `umask 077 && iptables-save > '${target}'`],
        label: `保存 iptables 规则到 ${target}`,
    }];
}

function buildNftablesPersistSteps(file) {
    const target = file || "/etc/nftables.conf";
    return [{
        args: ["sh", "-c", `umask 077 && nft list ruleset > '${target}' && systemctl enable nftables.service`],
        label: `保存 nftables 规则到 ${target}`,
    }];
}

const FIREWALL_BACKENDS = {
    ufw: {
        id: "ufw",
        label: "UFW",
        toolId: "ufw",
        addRuleLabel: "添加规则",
        dialogTitle: "添加 UFW 规则",
        dialogHint: "",
        fields: ["action", "port", "protocol", "source"],
        actionOptions: [
            { value: "allow", label: "allow" },
            { value: "deny", label: "deny" },
            { value: "reject", label: "reject" },
        ],
        capabilities: ["enable", "disable", "reload", "addRule", "deleteRule"],
        async read(ctx) {
            const ufw = ctx.tool("ufw");
            const [verbose, numbered] = await Promise.all([
                ctx.read([ufw, "status", "verbose"]),
                ctx.read([ufw, "status", "numbered"]),
            ]);

            if (!verbose.ok && !numbered.ok) {
                if (isPermissionError(numbered.output) || isPermissionError(verbose.output))
                    return permissionResult("UFW", numbered.output || verbose.output, ["ufw.service"]);
                return backendError(numbered.output || verbose.output);
            }

            return parseUfwStatus(numbered.output, verbose.output);
        },
        buildAddRule(ctx, values) {
            const ufw = ctx.tool("ufw");
            const args = values.source
                ? [ufw, values.action, "from", values.source, "to", "any", "port", values.port, "proto", values.protocol]
                : [ufw, values.action, `${values.port}/${values.protocol}`];
            return { steps: [{ args, label: `UFW ${values.action} ${values.port}/${values.protocol}` }] };
        },
        buildDeleteRule(ctx, rule) {
            return {
                steps: [{
                    args: [ctx.tool("ufw"), "--force", "delete", rule.value],
                    label: `UFW 删除规则 #${rule.value}`,
                }],
            };
        },
        quickActions(ctx) {
            const ufw = ctx.tool("ufw");
            return {
                enable: {
                    args: [ufw, "--force", "enable"],
                    label: "UFW 启用",
                    confirm: "这会立即启用 UFW 并应用当前规则。请先确认当前管理连接所需端口已经放行。",
                },
                disable: {
                    args: [ufw, "disable"],
                    label: "UFW 禁用",
                    confirm: "禁用 UFW 会移除所有过滤，确定继续吗？",
                },
                reload: { args: [ufw, "reload"], label: "UFW 重新加载" },
            };
        },
    },

    iptables: {
        id: "iptables",
        label: "iptables",
        toolId: "iptables",
        addRuleLabel: "插入规则",
        dialogTitle: "插入 iptables 规则",
        dialogHint: "规则插入到所选链的顶部并立即生效；如需重启后保留，请使用“保存规则”。",
        fields: ["chain", "action", "port", "protocol", "source"],
        actionOptions: [
            { value: "ACCEPT", label: "ACCEPT" },
            { value: "DROP", label: "DROP" },
            { value: "REJECT", label: "REJECT" },
        ],
        capabilities: ["addRule", "deleteRule", "persist"],
        fallbackChains: ["INPUT", "FORWARD", "OUTPUT"],
        async read(ctx) {
            const tool = ctx.tool("iptables");
            const [rules, persist, manager] = await Promise.all([
                ctx.read([tool, "-S"]),
                readIptablesPersistence(ctx),
                detectIptablesManager(ctx),
            ]);

            if (!rules.ok) {
                if (isPermissionError(rules.output)) {
                    const permission = await permissionResult("iptables", rules.output, ["iptables.service", "netfilter-persistent.service"]);
                    permission.persist = persist;
                    return permission;
                }
                return backendError(rules.output);
            }

            const parsed = parseIptablesRuleset(rules.output, persist);
            if (manager) {
                // UFW and firewalld generate these very rules. Warn, don't block:
                // the operator is allowed to touch them, same as on the CLI.
                parsed.manager = manager;
                parsed.notices = [
                    `${manager} 正在管理这台机器的防火墙规则，这里的规则由它生成：改动可能在它重新加载时被覆盖。`,
                    ...parsed.notices,
                ];
                parsed.persist = {
                    ...persist,
                    manager,
                };
            }
            return parsed;
        },
        buildAddRule(ctx, values) {
            const args = [ctx.tool("iptables"), "-I", values.chain, "-p", values.protocol];
            if (values.source)
                args.push("-s", values.source);
            args.push("--dport", values.port, "-j", values.action);
            return { steps: [{ args, label: `iptables 插入规则到 ${values.chain}` }] };
        },
        buildDeleteRule(ctx, rule) {
            return {
                steps: [{
                    args: [ctx.tool("iptables"), "-D", rule.chain, ...rule.tokens],
                    label: `iptables 删除 ${rule.chain} 链规则`,
                }],
            };
        },
        quickActions() {
            const persist = state.firewallPersist || {};
            const managerWarning = persist.manager
                ? `\n\n注意：规则由 ${persist.manager} 生成并持久化，这里保存的内容可能与它冲突。`
                : "";
            return {
                persist: {
                    steps: buildPersistSteps(persist.mechanism, persist.file),
                    confirm: `把当前运行时规则写入持久化文件，使其在重启后仍然生效。${managerWarning}`,
                },
            };
        },
    },

    nftables: {
        id: "nftables",
        label: "nftables",
        toolId: "nftables",
        addRuleLabel: "添加规则",
        dialogTitle: "添加 nftables 规则",
        dialogHint: "规则追加到所选链的末尾并立即生效；如需重启后保留，请使用“保存规则”。",
        fields: ["chain", "action", "port", "protocol", "source"],
        actionOptions: [
            { value: "accept", label: "accept" },
            { value: "drop", label: "drop" },
            { value: "reject", label: "reject" },
        ],
        capabilities: ["addRule", "deleteRule", "persist"],
        async read(ctx) {
            const tool = ctx.tool("nftables");
            const [ruleset, persist] = await Promise.all([
                ctx.read([tool, "-a", "list", "ruleset"]),
                readNftablesPersistence(ctx),
            ]);

            if (!ruleset.ok) {
                if (isPermissionError(ruleset.output))
                    return permissionResult("nftables", ruleset.output, ["nftables.service"]);
                return backendError(ruleset.output);
            }

            return parseNftablesRuleset(ruleset.output, persist);
        },
        buildAddRule(ctx, values) {
            const chain = getNftablesChain(values.chain);
            if (!chain)
                return null;

            const args = [ctx.tool("nftables"), "add", "rule", chain.family, chain.table, chain.name];
            if (values.source)
                args.push(values.source.includes(":") ? "ip6" : "ip", "saddr", values.source);
            args.push(values.protocol, "dport", values.port, values.action);
            return { steps: [{ args, label: `nftables 添加规则到 ${chain.name} 链` }] };
        },
        buildDeleteRule(ctx, rule) {
            return {
                steps: [{
                    args: [ctx.tool("nftables"), "delete", "rule", rule.family, rule.table, rule.chain, "handle", String(rule.handle)],
                    label: `nftables 删除 ${rule.chain} 链规则 ${rule.handle}`,
                }],
            };
        },
        quickActions() {
            const persist = state.firewallPersist || {};
            return {
                persist: {
                    steps: buildNftablesPersistSteps(persist.file),
                    confirm: "把当前规则写入持久化文件，并确保 nftables.service 开机启用。",
                },
            };
        },
    },

    firewalld: {
        id: "firewalld",
        label: "firewalld",
        toolId: "firewalld",
        addRuleLabel: "添加端口",
        dialogTitle: "添加 firewalld 端口",
        dialogHint: "写入默认区域的运行时与永久配置；填写来源 IP 时生成 accept/drop 富规则。",
        fields: ["action", "port", "protocol", "source"],
        actionOptions: [
            { value: "accept", label: "accept" },
            { value: "drop", label: "drop" },
        ],
        capabilities: ["reload", "addRule", "deleteRule"],
        async read(ctx) {
            const tool = ctx.tool("firewalld");
            const [stateResult, zoneResult, runtime, permanent] = await Promise.all([
                ctx.read([tool, "--state"]),
                ctx.read([tool, "--get-default-zone"]),
                ctx.read([tool, "--list-all"]),
                ctx.read([tool, "--list-all", "--permanent"]),
            ]);

            if (!runtime.ok && !permanent.ok) {
                if (isPermissionError(runtime.output) || isPermissionError(permanent.output))
                    return permissionResult("firewalld", runtime.output || permanent.output, ["firewalld.service"]);
                return backendError(runtime.output || permanent.output);
            }

            return parseFirewalldStatus({ stateResult, zoneResult, runtime, permanent });
        },
        buildAddRule(ctx, values) {
            const tool = ctx.tool("firewalld");
            const steps = [];
            if (values.source) {
                const family = values.source.includes(":") ? "ipv6" : "ipv4";
                const action = values.action === "drop" ? "drop" : "accept";
                const rule = `rule family="${family}" source address="${values.source}" port port="${values.port}" protocol="${values.protocol}" ${action}`;
                steps.push({ args: [tool, `--add-rich-rule=${rule}`], label: `firewalld 添加富规则（${values.port}/${values.protocol}）` });
                steps.push({ args: [tool, "--permanent", `--add-rich-rule=${rule}`], label: "firewalld 写入永久配置" });
            } else {
                steps.push({ args: [tool, `--add-port=${values.port}/${values.protocol}`], label: `firewalld 放行端口 ${values.port}/${values.protocol}` });
                steps.push({ args: [tool, "--permanent", `--add-port=${values.port}/${values.protocol}`], label: "firewalld 写入永久配置" });
            }
            return { steps };
        },
        buildDeleteRule(ctx, rule) {
            const tool = ctx.tool("firewalld");
            const steps = [];
            const flag = `--remove-${rule.type === "rich" ? "rich-rule" : rule.type}`;
            if (rule.inRuntime !== false)
                steps.push({ args: [tool, `${flag}=${rule.value}`], label: `firewalld 删除运行时条目 ${rule.value}` });
            if (rule.inPermanent)
                steps.push({ args: [tool, "--permanent", `${flag}=${rule.value}`], label: `firewalld 删除永久条目 ${rule.value}` });
            return { steps };
        },
        quickActions(ctx) {
            return {
                reload: { args: [ctx.tool("firewalld"), "--reload"], label: "firewalld 重新加载" },
            };
        },
    },
};

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
        rows: rules.map(rule => ({
            cells: [rule.number, rule.to, rule.action, rule.direction, rule.from],
            delete: {
                kind: "ufw",
                value: rule.number,
                label: "删除",
            },
        })),
        emptyText: isActive ? "当前没有 UFW 规则。" : "UFW 未启用，暂无规则可显示。",
        chains: [],
        persist: { state: "managed", mechanism: "ufw", file: "/etc/ufw" },
    };
}

function describeIptablesRule(tokens) {
    const description = { target: "", protocol: "", source: "", destination: "", ports: "", spec: tokens.join(" ") };

    for (let index = 0; index < tokens.length; index++) {
        const token = tokens[index];
        const next = tokens[index + 1];
        switch (token) {
        case "-j":
        case "-g":
        case "--jump":
        case "--goto":
            description.target = next || "";
            index++;
            break;
        case "-p":
        case "--protocol":
            description.protocol = next || "";
            index++;
            break;
        case "-s":
        case "--source":
            description.source = next || "";
            index++;
            break;
        case "-d":
        case "--destination":
            description.destination = next || "";
            index++;
            break;
        case "--dport":
        case "--destination-port":
            description.ports = next || "";
            index++;
            break;
        default:
            break;
        }
    }

    return description;
}

function splitIptablesSpec(spec) {
    // `iptables -S` quotes arguments such as comments; split without losing the
    // quoted value so `-D <chain> <spec>` can be replayed verbatim.
    const tokens = [];
    const pattern = /"([^"]*)"|'([^']*)'|(\S+)/g;
    let match;
    while ((match = pattern.exec(spec)) !== null) {
        if (match[1] !== undefined)
            tokens.push(match[1]);
        else if (match[2] !== undefined)
            tokens.push(match[2]);
        else
            tokens.push(match[3]);
    }
    return tokens;
}

function parseIptablesRuleset(output, persist) {
    const policies = {};
    const chains = [];
    const rules = [];

    String(output || "").split(/\r?\n/).forEach(line => {
        const trimmed = line.trim();
        if (!trimmed)
            return;

        const policyMatch = trimmed.match(/^-P\s+(\S+)\s+(\S+)$/);
        if (policyMatch) {
            policies[policyMatch[1]] = policyMatch[2];
            if (!chains.includes(policyMatch[1]))
                chains.push(policyMatch[1]);
            return;
        }

        const chainMatch = trimmed.match(/^-N\s+(\S+)$/);
        if (chainMatch) {
            if (!chains.includes(chainMatch[1]))
                chains.push(chainMatch[1]);
            return;
        }

        const ruleMatch = trimmed.match(/^-A\s+(\S+)\s+(.*)$/);
        if (!ruleMatch)
            return;

        const tokens = splitIptablesSpec(ruleMatch[2].trim());
        if (!tokens.length)
            return;
        if (!chains.includes(ruleMatch[1]))
            chains.push(ruleMatch[1]);
        rules.push({ chain: ruleMatch[1], tokens, ...describeIptablesRule(tokens) });
    });

    const inputPolicy = policies.INPUT || "未定义";
    const policySummary = Object.keys(policies).length
        ? Object.entries(policies).map(([chain, policy]) => `${chain}=${policy}`).join("、")
        : "未解析到默认策略。";
    const unpersisted = persist?.state === "pending" || persist?.state === "missing";
    const inputFiltered = inputPolicy === "DROP" || inputPolicy === "REJECT" || rules.some(rule => rule.chain === "INPUT");
    const dockerChains = chains.filter(chain => chain.startsWith("DOCKER"));
    const notices = [];

    if (!rules.some(rule => rule.chain === "INPUT"))
        notices.push("INPUT 链没有任何规则，入站流量全部放行。");
    if (dockerChains.length)
        notices.push(`检测到 Docker 链（${dockerChains.join("、")}），这些规则由 Docker 维护，重启后由 Docker 自行恢复。`);
    if (unpersisted && persist?.boot !== "enabled")
        notices.push("未检测到开机加载机制（netfilter-persistent / iptables.service），保存规则文件不会在重启后生效。");

    return {
        summary: [
            `INPUT 链策略为 ${inputPolicy}，共 ${rules.length} 条规则。`,
            !inputFiltered ? "主机当前没有入站过滤。" : "",
            unpersisted && persist?.boot === "enabled" ? "运行时规则尚未保存。" : "",
        ].filter(Boolean).join(""),
        statusLabel: inputPolicy === "ACCEPT" && !inputFiltered ? "入站未过滤" : `策略 ${inputPolicy}`,
        tone: inputPolicy === "ACCEPT" && !inputFiltered ? "warning" : "success",
        ruleCount: String(rules.length),
        policySummary: `默认策略：${policySummary}`,
        notices,
        details: [
            ["默认策略", policySummary],
            ["规则数", String(rules.length)],
            ["链", chains.join("、") || "无"],
            dockerChains.length ? ["Docker 链", dockerChains.join("、")] : null,
            persistDetail(persist),
        ].filter(Boolean),
        columns: ["链", "目标", "协议", "来源", "端口", "规则"],
        rows: rules.map(rule => ({
            cells: [
                rule.chain,
                rule.target || "-",
                rule.protocol || "any",
                rule.source || "any",
                rule.ports || "-",
                rule.spec,
            ],
            delete: {
                kind: "iptables",
                chain: rule.chain,
                tokens: rule.tokens,
                value: rule.spec,
                description: `iptables ${rule.chain} 链规则`,
                label: "删除",
                disabled: rule.chain.startsWith("DOCKER"),
            },
        })),
        emptyText: "当前没有 iptables 规则。",
        chains: chains.map(chain => ({
            value: chain,
            label: chain.startsWith("DOCKER") ? `${chain}（Docker 管理）` : chain,
        })),
        persist,
    };
}

// Which higher level tool owns the rules currently in the kernel. ufw and
// firewalld both generate iptables/nftables rules; editing them from here works
// until that tool reloads.
async function detectIptablesManager(ctx) {
    const script = [
        "if systemctl is-active --quiet firewalld 2>/dev/null; then echo firewalld; exit 0; fi",
        "if systemctl is-active --quiet ufw 2>/dev/null; then echo ufw; exit 0; fi",
        "if [ -f /etc/ufw/ufw.conf ] && grep -q '^ENABLED=yes' /etc/ufw/ufw.conf 2>/dev/null; then echo ufw; exit 0; fi",
        "exit 0",
    ].join("\n");

    const result = await ctx.read(["sh", "-c", script]);
    if (!result.ok)
        return "";

    return String(result.output || "").trim().split(/\s+/).filter(Boolean)[0] || "";
}

async function readIptablesPersistence(ctx) {
    const script = [
        "mech=iptables-save",
        "file=/etc/iptables/rules.v4",
        "if command -v netfilter-persistent >/dev/null 2>&1; then mech=netfilter-persistent; fi",
        "if [ -e /etc/sysconfig/iptables ]; then file=/etc/sysconfig/iptables; fi",
        "printf 'MECHANISM=%s\\n' \"$mech\"",
        "printf 'FILE=%s\\n' \"$file\"",
        "if ! command -v iptables-save >/dev/null 2>&1; then printf 'SAVE=unsupported\\n';",
        "elif [ ! -e \"$file\" ]; then printf 'SAVE=missing\\n';",
        "elif [ ! -r \"$file\" ]; then printf 'SAVE=unreadable\\n';",
        "else",
        "  current=$(iptables-save 2>/dev/null | grep -v '^#' | grep -v '^[[:space:]]*$')",
        "  saved=$(grep -v '^#' \"$file\" 2>/dev/null | grep -v '^[[:space:]]*$')",
        "  if [ -z \"$current\" ]; then printf 'SAVE=unknown\\n';",
        "  elif [ \"$current\" = \"$saved\" ]; then printf 'SAVE=saved\\n';",
        "  else printf 'SAVE=pending\\n'; fi",
        "fi",
        "if systemctl is-enabled netfilter-persistent.service >/dev/null 2>&1; then printf 'BOOT=enabled\\n';",
        "elif systemctl is-enabled iptables.service >/dev/null 2>&1; then printf 'BOOT=enabled\\n';",
        "else printf 'BOOT=disabled\\n'; fi",
        "if iptables -S 2>/dev/null | grep -qE '^-N DOCKER'; then printf 'FOREIGN=docker\\n'; else printf 'FOREIGN=none\\n'; fi",
    ].join("\n");

    const result = await ctx.read(["sh", "-c", script]);
    return parsePersistenceReport(result.ok ? result.output : "", { mechanism: "iptables-save", file: "/etc/iptables/rules.v4" });
}

function parsePersistenceReport(output, defaults = {}) {
    const values = {};
    String(output || "").split(/\r?\n/).forEach(line => {
        const index = line.indexOf("=");
        if (index > 0)
            values[line.slice(0, index).trim()] = line.slice(index + 1).trim();
    });

    const known = ["saved", "pending", "missing", "unreadable", "unsupported", "unknown"];
    const boot = values.BOOT || "";
    const foreign = values.FOREIGN && values.FOREIGN !== "none" ? values.FOREIGN : "";
    return {
        mechanism: values.MECHANISM || defaults.mechanism || "",
        file: values.FILE || defaults.file || "",
        boot,
        foreign,
        // A rules file only protects against reboots if something loads it at
        // boot; without that the file is decoration.
        loadedAtBoot: boot === "enabled",
        // `flush ruleset` in the nftables config wipes everything, including
        // tables owned by iptables or Docker, when the service starts.
        flushesEverything: values.FLUSH === "ruleset",
        declaredTables: String(values.TABLES || "").split(",").map(item => item.trim()).filter(Boolean),
        state: known.includes(values.SAVE) ? values.SAVE : "unknown",
    };
}

function getNftablesChain(value) {
    const match = String(value || "").match(/^(\S+)\s+(\S+)\/(\S+)$/);
    return match ? { family: match[1], table: match[2], name: match[3] } : null;
}

function parseNftablesRuleset(output, persist) {
    const chains = [];
    const rules = [];
    const stack = [];
    const foreignTables = new Map();

    String(output || "").split(/\r?\n/).forEach(line => {
        const trimmed = line.trim();
        if (!trimmed)
            return;

        // `nft list ruleset` also prints iptables-nft managed tables and warns
        // about them. Such tables belong to iptables (or Docker) and must not be
        // edited or saved through nftables.
        const foreignMatch = trimmed.match(/^#\s*Warning: table\s+(\S+)\s+(\S+)\s+is managed by\s+([^,\s]+)/i);
        if (foreignMatch) {
            foreignTables.set(`${foreignMatch[1]} ${foreignMatch[2]}`, foreignMatch[3]);
            return;
        }

        if (trimmed.startsWith("#"))
            return;

        const current = stack[stack.length - 1];
        if (current?.type === "chain") {
            const handleMatch = trimmed.match(/^(.*?)#\s*handle\s+(\d+)\s*$/);
            if (handleMatch) {
                rules.push({
                    family: current.family,
                    table: current.table,
                    chain: current.name,
                    handle: handleMatch[2],
                    spec: handleMatch[1].trim().replace(/;$/, ""),
                });
                return;
            }

            const typeMatch = trimmed.match(/\btype\s+(\S+)\s/);
            const policyMatch = trimmed.match(/policy\s+([a-z-]+)/i);
            const hookMatch = trimmed.match(/hook\s+(\S+?)\s/);
            if (typeMatch)
                current.kind = typeMatch[1];
            if (policyMatch)
                current.policy = policyMatch[1];
            if (hookMatch)
                current.hook = hookMatch[1];
        }

        const opensBlock = trimmed.includes("{");
        const closesBlock = trimmed.includes("}");

        if (opensBlock && !closesBlock) {
            const tableMatch = trimmed.match(/^table\s+(\S+)\s+(\S+)/);
            const chainMatch = trimmed.match(/^chain\s+(\S+)/);
            if (tableMatch) {
                stack.push({ type: "table", family: tableMatch[1], table: tableMatch[2] });
            } else if (chainMatch) {
                const table = [...stack].reverse().find(entry => entry.type === "table");
                if (!table) {
                    stack.push({ type: "other" });
                    return;
                }
                const foreign = foreignTables.get(`${table.family} ${table.table}`) || "";
                const chain = {
                    type: "chain",
                    family: table.family,
                    table: table.table,
                    name: chainMatch[1],
                    policy: "",
                    hook: "",
                    kind: "filter",
                    foreign,
                    docker: /^DOCKER/i.test(chainMatch[1]),
                };
                stack.push(chain);
                chains.push(chain);
            } else {
                stack.push({ type: "other" });
            }
            return;
        }

        if (closesBlock && !opensBlock)
            stack.pop();
    });

    // Chains the UI may add rules to. Two conditions, both conservative:
    // the table must not belong to another tool (iptables-nft, Docker), and the
    // host must actually run its firewall through nftables.service. On hosts
    // where nftables.service is disabled (Debian/Ubuntu with iptables-nft and
    // Docker) the live ruleset belongs to iptables, and writing through nft
    // would silently edit another tool's state.
    const serviceManaged = persist?.loadedAtBoot === true;
    const declaredTables = persist?.declaredTables || [];
    const isDeclared = chain => declaredTables.includes(`${chain.family} ${chain.table}`);
    // A host running nftables.service owns exactly the tables its configuration
    // declares; everything else in the live ruleset was created by another tool.
    const editableChains = serviceManaged
        ? chains.filter(chain => isDeclared(chain) && !chain.foreign && !chain.docker)
        : [];
    const hookChains = chains.filter(chain => chain.hook);
    const policySummary = summarizeNftablesPolicies(hookChains);
    const unpersisted = persist?.state === "pending" || persist?.state === "missing";
    const inputChains = hookChains.filter(chain => chain.hook === "input");
    const inputFiltered = inputChains.length > 0 && inputChains.every(chain => chain.policy === "drop");
    const dockerChains = chains.filter(chain => chain.docker && !chain.foreign).map(chain => `${chain.family} ${chain.table}/${chain.name}`);
    const foreignNames = [...foreignTables.keys()];
    const readOnly = editableChains.length === 0;
    const orderedChains = [...editableChains].sort((left, right) => chainSortKey(left) - chainSortKey(right));

    const notices = [];
    if (inputChains.length === 0)
        notices.push("未发现 input 钩子链，nftables 层面没有入站过滤策略。");
    else if (!inputFiltered)
        notices.push(`input 链默认策略为 ${inputChains.map(chain => chain.policy || "无").join("、")}，入站流量默认放行。`);
    if (foreignNames.length)
        notices.push(`${foreignNames.join("、")} 由 ${foreignTables.values().next().value} 管理（通常是 Docker），不通过 nftables 修改或保存。`);
    if (!serviceManaged)
        notices.push("nftables.service 未启用，本机防火墙不由 nftables 加载；修改规则请使用 iptables 后端，或先启用 nftables.service。");
    else if (chains.some(chain => !chain.foreign && !isDeclared(chain)))
        notices.push(`未在 ${persist.file || "nftables 配置"} 中声明的表（${[...new Set(chains.filter(chain => !chain.foreign && !isDeclared(chain)).map(chain => `${chain.family} ${chain.table}`))].join("、")}）不提供修改入口。`);
    if (persist?.flushesEverything && (foreignNames.length || chains.length))
        notices.push(`${persist.file || "nftables 配置"} 包含 “flush ruleset”，启动 nftables.service 会清空当前所有规则（包括 iptables/Docker 的规则）。`);
    if (dockerChains.length)
        notices.push(`Docker 链（${dockerChains.join("、")}）由 Docker 维护，不提供修改入口。`);
    if (unpersisted && (foreignNames.length || !serviceManaged))
        notices.push("保存 nftables 配置不会在重启后生效，规则由 iptables/Docker 自行恢复。");

    return {
        summary: readOnly
            ? `解析到 ${rules.length} 条规则，全部属于外部管理的表${foreignNames.length ? `（${foreignNames.join("、")}）` : ""}。`
            : `共解析到 ${rules.length} 条 nftables 规则${unpersisted ? "；运行时规则尚未保存" : ""}。`,
        statusLabel: inputChains.length ? describeNftablesPolicy(inputChains[0].policy) : "无 input 过滤",
        tone: inputFiltered && !readOnly ? "success" : "warning",
        ruleCount: String(rules.length),
        policySummary: `默认策略：${policySummary}`,
        details: [
            ["规则数", String(rules.length)],
            ["链", chains.map(chain => `${chain.family} ${chain.table}/${chain.name}${chain.hook ? `（${chain.hook}）` : ""}${chain.foreign ? "［外部管理］" : ""}`).join("、") || "无"],
            ["默认策略", policySummary],
            foreignNames.length ? ["外部管理的表", foreignNames.join("、")] : null,
            persistDetail(persist),
        ].filter(Boolean),
        notices,
        readOnly,
        columns: ["链", "规则", "句柄"],
        rows: rules.map(rule => ({
            cells: [`${rule.family} ${rule.table}/${rule.chain}`, rule.spec, rule.handle],
            delete: {
                kind: "nftables",
                family: rule.family,
                table: rule.table,
                chain: rule.chain,
                handle: rule.handle,
                value: rule.handle,
                description: `nftables ${rule.chain} 链规则（句柄 ${rule.handle}）`,
                label: "删除",
                disabled: chains.some(chain => chain.name === rule.chain && chain.foreign),
            },
        })),
        emptyText: "当前没有 nftables 规则。",
        chains: orderedChains.map(chain => ({
            value: `${chain.family} ${chain.table}/${chain.name}`,
            label: `${chain.family} ${chain.table}/${chain.name}${chain.hook ? `（hook ${chain.hook}）` : ""}`,
        })),
        persist: foreignNames.length ? { ...(persist || {}), blocked: true, blockedReason: `${foreignNames.join("、")} 由外部工具管理，保存会写入不属于 nftables 的规则。` } : persist,
    };
}

function describeNftablesPolicy(policy) {
    if (policy === "drop")
        return "input 默认拒绝";
    if (policy === "accept")
        return "input 默认放行";
    return policy ? `input ${policy}` : "input 无策略";
}

function summarizeNftablesPolicies(hookChains) {
    const filterChains = hookChains.filter(chain => chain.kind === "filter" && ["input", "forward", "output"].includes(chain.hook));
    const groups = new Map();
    filterChains.forEach(chain => {
        const key = `${chain.family} ${chain.table}`;
        if (!groups.has(key))
            groups.set(key, []);
        groups.get(key).push(`${chain.hook}=${chain.policy || "无"}`);
    });

    if (!groups.size)
        return "未解析到 ip/ip6 filter 钩子链策略。";

    return [...groups.entries()].map(([table, policies]) => `${table} ${policies.join("/")}`).join("；");
}

function chainSortKey(chain) {
    if (chain.kind === "filter" && chain.hook === "input")
        return 0;
    if (chain.kind === "filter" && chain.hook)
        return 1;
    if (chain.hook)
        return 2;
    return 3;
}

async function readNftablesPersistence(ctx) {
    const script = [
        "file=/etc/nftables.conf",
        "printf 'MECHANISM=%s\\n' nftables.service",
        "printf 'FILE=%s\\n' \"$file\"",
        "if ! command -v nft >/dev/null 2>&1; then printf 'SAVE=unsupported\\n';",
        "elif ! systemctl cat nftables.service >/dev/null 2>&1; then printf 'SAVE=unsupported\\n';",
        "elif [ ! -e \"$file\" ]; then printf 'SAVE=missing\\n';",
        "elif [ ! -r \"$file\" ]; then printf 'SAVE=unreadable\\n';",
        "else",
        "  current=$(nft list ruleset 2>/dev/null | grep -v '^#' | grep -v '^[[:space:]]*$')",
        "  saved=$(grep -v '^#' \"$file\" 2>/dev/null | grep -v '^[[:space:]]*$' | grep -v '^flush ruleset')",
        "  if [ -z \"$current\" ]; then printf 'SAVE=unknown\\n';",
        "  elif [ \"$current\" = \"$saved\" ]; then printf 'SAVE=saved\\n';",
        "  else printf 'SAVE=pending\\n'; fi",
        "fi",
        "if systemctl is-enabled nftables.service >/dev/null 2>&1; then printf 'BOOT=enabled\\n'; else printf 'BOOT=disabled\\n'; fi",
        "if [ -r \"$file\" ]; then",
        "  grep -qE '^[[:space:]]*flush[[:space:]]+ruleset' \"$file\" && printf 'FLUSH=ruleset\\n' || printf 'FLUSH=none\\n';",
        "  declared=$(grep -oE '^[[:space:]]*table[[:space:]]+[A-Za-z0-9_]+[[:space:]]+[A-Za-z0-9_-]+' \"$file\" 2>/dev/null | awk '{print $2\" \"$3}' | sort -u | tr '\\n' ',');",
        "  printf 'TABLES=%s\\n' \"$declared\";",
        "fi",
    ].join("\n");

    const result = await ctx.read(["sh", "-c", script]);
    return parsePersistenceReport(result.ok ? result.output : "", { mechanism: "nftables.service", file: "/etc/nftables.conf" });
}

function parseFirewalldListAll(output) {
    const info = { zone: "", active: false, items: {} };
    let currentKey = null;

    String(output || "").split(/\r?\n/).forEach(line => {
        if (!line.trim())
            return;

        const zoneMatch = line.match(/^(\S+)(?:\s+\(([^)]+)\))?\s*$/);
        if (zoneMatch && !line.startsWith(" ")) {
            info.zone = zoneMatch[1];
            info.active = zoneMatch[2] === "active";
            currentKey = null;
            return;
        }

        const keyMatch = line.match(/^\s*([a-z][a-z0-9_ -]*?)\s*:\s*(.*)$/i);
        if (keyMatch) {
            currentKey = keyMatch[1];
            info.items[currentKey] = keyMatch[2].trim();
            return;
        }

        if (currentKey)
            info.items[currentKey] = [info.items[currentKey], line.trim()].filter(Boolean).join("\n");
    });

    return info;
}

function firewalldLines(info, key) {
    return String(info.items[key] || "")
        .split(/\n/)
        .map(value => value.trim())
        .filter(Boolean);
}

function firewalldValues(info, key) {
    return firewalldLines(info, key).flatMap(value => value.split(/\s+/)).filter(Boolean);
}

function parseFirewalldStatus({ stateResult, zoneResult, runtime, permanent }) {
    const runtimeInfo = parseFirewalldListAll(runtime.ok ? runtime.output : "");
    const permanentInfo = parseFirewalldListAll(permanent.ok ? permanent.output : "");
    const running = /running/i.test(String(stateResult.output || ""));
    const zoneName = String(zoneResult.output || "").trim() || runtimeInfo.zone || permanentInfo.zone || "public";

    const permanentServices = new Set(firewalldValues(permanentInfo, "services"));
    const permanentPorts = new Set(firewalldValues(permanentInfo, "ports"));
    const permanentRich = new Set(firewalldLines(permanentInfo, "rich rules"));

    const rows = [];
    const addRows = (label, runtimeValues, permanentValues, type) => {
        const values = new Set([...runtimeValues, ...permanentValues]);
        values.forEach(value => {
            const inRuntime = runtimeValues.has(value);
            const inPermanent = permanentValues.has(value);
            const persistedLabel = inRuntime
                ? (inPermanent ? "运行时 + 永久" : "仅运行时")
                : "仅永久（未生效）";
            rows.push({
                cells: [label, value, persistedLabel],
                delete: {
                    kind: "firewalld",
                    type,
                    value,
                    inRuntime,
                    inPermanent,
                    description: `firewalld ${label} ${value}`,
                    label: "删除",
                },
            });
        });
    };

    addRows("服务", new Set(firewalldValues(runtimeInfo, "services")), permanentServices, "service");
    addRows("端口", new Set(firewalldValues(runtimeInfo, "ports")), permanentPorts, "port");
    addRows("富规则", new Set(firewalldLines(runtimeInfo, "rich rules")), permanentRich, "rich");

    ["forward-ports", "source-ports", "protocols", "icmp-blocks"].forEach(key => {
        firewalldValues(runtimeInfo, key).forEach(value => {
            rows.push({ cells: [key, value, "-"] });
        });
    });

    const countByLabel = label => rows.filter(row => row.cells[2] === label).length;
    const runtimeOnly = countByLabel("仅运行时");
    const permanentOnly = countByLabel("仅永久（未生效）");
    const blockers = [
        runtimeOnly ? `${runtimeOnly} 个仅运行时` : "",
        permanentOnly ? `${permanentOnly} 个仅永久` : "",
    ].filter(Boolean).join("，");
    const summary = running
        ? `firewalld 运行中，默认区域 ${zoneName}，共 ${rows.length} 个条目${blockers ? `（${blockers}）` : ""}。`
        : `firewalld 未运行，默认区域 ${zoneName}，显示永久配置共 ${rows.length} 个条目。`;

    return {
        summary,
        statusLabel: running ? "运行中" : normalizeStatus(String(stateResult.output || "未运行").trim()),
        tone: running ? (blockers ? "warning" : "success") : "warning",
        ruleCount: String(rows.length),
        policySummary: `默认区域：${zoneName}${runtimeInfo.active ? "（活动）" : ""}`,
        details: [
            ["服务状态", running ? "运行中" : normalizeStatus(String(stateResult.output || "未运行").trim())],
            ["默认区域", `${zoneName}${runtimeInfo.active ? "（活动）" : ""}`],
            runtimeInfo.items.target ? ["目标", runtimeInfo.items.target] : null,
            runtimeInfo.items.interfaces ? ["接口", runtimeInfo.items.interfaces] : null,
            runtimeInfo.items.forward ? ["转发", runtimeInfo.items.forward] : null,
            runtimeInfo.items.masquerade ? ["伪装", runtimeInfo.items.masquerade] : null,
            ["条目", `${rows.length} 个${blockers ? `（${blockers}）` : ""}`],
            ["持久化", "firewalld 只持久化 --permanent 配置；“仅运行时”条目会在重新加载或重启后丢失，“仅永久”条目尚未生效。"],
        ].filter(Boolean),
        columns: ["类型", "条目", "持久化"],
        rows,
        emptyText: `默认区域 ${zoneName} 没有配置服务、端口或富规则。`,
        chains: [],
        persist: { state: "managed", mechanism: "firewalld", file: "/etc/firewalld" },
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
    let permission = false;

    if (serviceOk && statusOk) {
        summary = jails.length
            ? `当前共有 ${jails.length} 个 jail：${jails.join("、")}。`
            : "当前没有已启用的 jail。";
        tone = activeState === "active" ? "success" : "warning";
    } else if (isPermissionError(statusOutput)) {
        permission = true;
        summary = "Fail2Ban 套接字需要管理员权限，当前会话只能看到服务状态。";
    } else if (!statusOk) {
        summary = summarizeOutput(statusOutput, false);
        tone = "danger";
    }

    return {
        jailCount,
        jails: permission ? [] : jails,
        serviceState,
        summary,
        tone,
        permission,
        details: [
            ["服务", service.Id || "fail2ban.service"],
            service.Description ? ["说明", service.Description] : null,
            service.ActiveState ? ["运行状态", normalizeStatus(service.ActiveState)] : null,
            service.SubState ? ["子状态", service.SubState] : null,
            service.UnitFileState ? ["开机策略", normalizeStatus(service.UnitFileState)] : null,
            service.LoadState ? ["加载状态", normalizeStatus(service.LoadState)] : null,
            permission ? ["jail", "需要管理员权限才能读取 jail 列表。"] : null,
            ["Jail 数量", permission ? "需要管理员权限" : String(jailCount)],
            !permission && jails.length ? ["Jail 列表", jails.join("、")] : null,
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

function backendCapabilities() {
    if (state.firewallReadOnly)
        return [];

    return getFirewallBackend().capabilities || [];
}

function canFirewall(capability) {
    return isWritable() && backendCapabilities().includes(capability);
}

function visibleFirewallRows(rows) {
    if (canFirewall("deleteRule"))
        return rows;

    return rows.map(row => ({ cells: row.cells }));
}

function renderFirewallPersistState() {
    const callout = getElement("firewall-persist-callout");
    if (!callout)
        return;

    const persist = state.firewallPersist;
    const state_ = persist?.state;
    const lines = [];

    if (persist?.blocked && persist.blockedReason)
        lines.push(persist.blockedReason);
    else if (persist && state_ !== "saved" && state_ !== "managed") {
        const messages = {
            pending: `运行时规则与已保存文件不一致（${persist.file || "未知文件"}）。`,
            missing: `尚未找到持久化文件${persist.file ? `（${persist.file}）` : ""}。`,
            unreadable: `无法读取持久化文件${persist.file ? `（${persist.file}）` : ""}，需要管理员权限才能确认。`,
            unsupported: "未检测到持久化机制，规则只存在于运行时。",
            unknown: "无法确认规则是否已持久化。",
        };
        lines.push(messages[state_] || messages.unknown);
        if (persist.loadedAtBoot === false)
            lines.push("未检测到开机加载机制，即使保存规则文件，重启后也不会生效。");
    }

    lines.push(...(state.firewallNotices || []));

    callout.textContent = lines.join("\n");
    callout.hidden = !lines.length;
    callout.classList.remove("tone-success", "tone-warning", "tone-danger");
    callout.classList.add("tone-warning");
}

function renderFirewallStatus(parsed) {
    renderFirewallInstallState(false);
    setText("firewall-backend-label", getFirewallBackend().label);
    setText("firewall-summary-copy", parsed.summary);
    setText("firewall-policy-summary", parsed.policySummary);
    setBadge("firewall-status-pill", parsed.statusLabel, parsed.tone);
    renderDetailList("firewall-details", parsed.details, "没有解析到防火墙详情。");
    state.firewallChains = parsed.chains || [];
    state.firewallPersist = parsed.persist || null;
    state.firewallNotices = parsed.notices || [];
    state.firewallReadOnly = parsed.readOnly === true;
    state.firewallManager = parsed.manager || "";
    state.firewallRules.columns = parsed.columns;
    state.firewallRules.rows = visibleFirewallRows(parsed.rows);
    state.firewallRules.emptyText = parsed.emptyText;
    state.firewallRules.page = 1;
    renderFirewallPersistState();
    renderFirewallRulesTable();
    updateFirewallActionBar();
}

function renderFirewallError(message) {
    renderFirewallInstallState(false);
    setText("firewall-summary-copy", summarizeOutput(message, false));
    setText("firewall-policy-summary", "状态刷新失败。");
    setBadge("firewall-status-pill", "刷新失败", "danger");
    renderDetailList("firewall-details", [["错误", summarizeOutput(message, false)]], "状态刷新失败。");
    state.firewallChains = [];
    state.firewallPersist = null;
    state.firewallNotices = [];
    state.firewallReadOnly = false;
    state.firewallManager = "";
    state.firewallRules.columns = ["状态"];
    state.firewallRules.rows = [];
    state.firewallRules.emptyText = "无法读取规则列表。";
    state.firewallRules.page = 1;
    renderFirewallPersistState();
    renderFirewallRulesTable();
    updateFirewallActionBar();
}

function renderFirewallPermission(parsed) {
    renderFirewallInstallState(false);
    const backend = getFirewallBackend();
    setText("firewall-backend-label", backend.label);
    setText("firewall-summary-copy", parsed.summary);
    setText("firewall-policy-summary", "需要管理员权限才能读取规则。");
    setBadge("firewall-status-pill", "需要管理员权限", "warning");
    renderDetailList("firewall-details", parsed.details || [["权限", parsed.summary]], "需要管理员权限。");
    state.firewallChains = [];
    state.firewallPersist = parsed.persist || null;
    state.firewallNotices = [];
    state.firewallReadOnly = false;
    state.firewallManager = "";
    state.firewallRules.columns = ["状态"];
    state.firewallRules.rows = [];
    state.firewallRules.emptyText = "需要管理员权限才能查看规则。";
    state.firewallRules.page = 1;
    renderFirewallPersistState();
    renderFirewallRulesTable();
    updateFirewallActionBar();
}

function renderFirewallMissing() {
    const tool = getCurrentFirewallTool();
    renderFirewallInstallState(true);
    setText("firewall-backend-label", tool.label);
    setText("firewall-policy-summary", `${tool.label} 未安装。`);
    state.firewallChains = [];
    state.firewallPersist = null;
    state.firewallNotices = [];
    state.firewallReadOnly = false;
    state.firewallManager = "";
    state.firewallRules.columns = ["状态"];
    state.firewallRules.rows = [];
    state.firewallRules.emptyText = `${tool.label} 未安装。`;
    state.firewallRules.page = 1;
    renderFirewallPersistState();
    renderFirewallRulesTable();
    updateFirewallActionBar();
}

function renderFail2BanStatus(parsed) {
    renderFail2BanInstallState(false);
    setText("fail2ban-service-state", parsed.serviceState);
    setText("fail2ban-service-copy", parsed.summary);
    setText("fail2ban-jail-count", parsed.permission ? "需要管理员权限" : String(parsed.jailCount));
    setBadge("fail2ban-service-pill", parsed.permission ? "需要管理员权限" : parsed.serviceState, parsed.permission ? "warning" : parsed.tone);
    renderDetailList("fail2ban-details", parsed.details, "没有解析到 Fail2Ban 总体状态。");
    renderTokenRow("fail2ban-jail-list", parsed.jails, {
        clickable: true,
        emptyText: parsed.permission ? "需要管理员权限" : "没有 jail",
        onClick: jail => {
            fillJailInputs(jail);
            loadFail2BanJail(jail);
        },
    });

    if (parsed.permission)
        clearFail2BanJail("需要管理员权限才能查看 jail 详情。");
}

function renderFail2BanMissing() {
    renderFail2BanInstallState(true);
    setText("fail2ban-service-state", "未安装");
    setText("fail2ban-service-copy", "Fail2Ban 未安装。");
    setText("fail2ban-jail-count", "--");
    clearFail2BanJail("Fail2Ban 未安装。");
}

function renderFail2BanJail(parsed, tone = "success") {
    state.currentJail = parsed.name;
    setText("fail2ban-current-jail", parsed.name);
    setText("fail2ban-current-jail-copy", parsed.summary);
    setBadge("fail2ban-jail-pill", parsed.name, tone);
    renderMetricCards("fail2ban-jail-metrics", parsed.metrics);
    renderDetailList("fail2ban-jail-details", parsed.details, "没有解析到 jail 详情。");
    renderTokenRow("fail2ban-banned-ips", parsed.bannedIps, {
        emptyText: "当前没有封禁 IP",
    });
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
}

function showCommandResult(prefix, label, text, ok = true, summaryOverride = "") {
    setBadge(`${prefix}-command-label`, label, ok ? "success" : "danger");
    setCallout(`${prefix}-result-summary`, summaryOverride || summarizeOutput(text, ok), ok ? "success" : "danger");
}

async function execute(prefix, label, argsOrScript, options = {}) {
    const commandLabel = Array.isArray(argsOrScript) ? argsOrScript.join(" ") : argsOrScript;
    const shouldUpdateResult = options.updateResult !== false;

    if (shouldUpdateResult)
        showCommandResult(prefix, label, `执行中...\n\n${commandLabel}`, true, "正在执行命令...");

    const result = await capture(argsOrScript, options);
    if (shouldUpdateResult) {
        showCommandResult(prefix, result.ok ? label : `${label} 失败`, result.output, result.ok, options.summary);
        refreshSecurityLogs();
    }

    return result;
}

async function executeSteps(prefix, steps) {
    let result = { ok: true, output: "" };
    for (const step of steps) {
        result = await execute(prefix, step.label, step.args, { summary: step.summary });
        if (!result.ok)
            return result;
    }

    return result;
}

async function refreshFirewallStatus() {
    return withRefreshLock("firewall", async () => {
        const backend = getFirewallBackend();
        // Tool detection is unprivileged; the read itself degrades to a
        // permission notice when the session cannot escalate.
        const installed = await checkToolInstalled(backend.toolId, { force: true });
        if (!installed) {
            renderFirewallMissing();
            return;
        }

        renderFirewallInstallState(false);
        setText("firewall-summary-copy", "正在刷新防火墙状态...");
        setBadge("firewall-status-pill", "加载中", "loading");

        const parsed = await backend.read(FIREWALL_CONTEXT);
        if (parsed.kind === "permission") {
            renderFirewallPermission(parsed);
            return;
        }

        if (parsed.kind === "error") {
            renderFirewallError(parsed.message);
            return;
        }

        renderFirewallStatus(parsed);
    });
}

async function refreshFail2BanStatus() {
    return withRefreshLock("fail2ban", async () => {
        const installed = await checkToolInstalled("fail2ban", { force: true });
        if (!installed) {
            renderFail2BanMissing();
            return;
        }

        renderFail2BanInstallState(false);
        setText("fail2ban-service-copy", "正在刷新 Fail2Ban 状态...");
        setBadge("fail2ban-service-pill", "加载中", "loading");

        const serviceName = await resolveFail2BanService();
        const [serviceResult, statusResult] = await Promise.all([
            captureRead([
                "systemctl",
                "show",
                serviceName,
                "--property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,FragmentPath",
            ]),
            captureRead([getToolCommand("fail2ban"), "status"]),
        ]);

        const parsed = parseFail2BanOverview(serviceResult.output, statusResult.output, serviceResult.ok, statusResult.ok);
        renderFail2BanStatus(parsed);

        if (state.currentJail && !parsed.permission) {
            if (parsed.jails.includes(state.currentJail))
                await loadFail2BanJail(state.currentJail, { quiet: true });
            else
                clearFail2BanJail("当前 jail 已不在总列表中，请重新选择。");
        }
    });
}

async function loadFail2BanJail(jail, options = {}) {
    const jailName = jail.trim();
    if (!jailName) {
        showCommandResult("fail2ban", "jail 查询失败", "jail 名称不能为空。", false);
        return;
    }

    setBadge("fail2ban-jail-pill", "加载中", "loading");
    setText("fail2ban-current-jail", jailName);
    setText("fail2ban-current-jail-copy", "正在加载 jail 详情...");

    const result = await captureRead([getToolCommand("fail2ban"), "status", jailName]);
    if (!result.ok) {
        const permission = isPermissionError(result.output);
        const summary = permission ? "需要管理员权限才能查询 jail 详情。" : summarizeOutput(result.output, false);
        setText("fail2ban-current-jail", jailName);
        setText("fail2ban-current-jail-copy", summary);
        setBadge("fail2ban-jail-pill", permission ? "需要管理员权限" : "加载失败", permission ? "warning" : "danger");
        renderMetricCards("fail2ban-jail-metrics", []);
        renderDetailList("fail2ban-jail-details", [["错误", summary]], "jail 查询失败。");
        renderTokenRow("fail2ban-banned-ips", [], {
            emptyText: "当前没有封禁 IP",
        });
        if (!options.quiet)
            showCommandResult("fail2ban", `jail: ${jailName} 失败`, result.output, false, summary);
        return;
    }

    const parsed = parseFail2BanJail(result.output, jailName);
    renderFail2BanJail(parsed);
    if (!options.quiet)
        showCommandResult("fail2ban", `jail: ${jailName}`, result.output, true, parsed.summary);
}

function readRememberedFirewallBackend() {
    try {
        return window.localStorage.getItem(FIREWALL_BACKEND_STORAGE_KEY) || "";
    } catch (error) {
        console.debug("Unable to read remembered firewall backend", error);
        return "";
    }
}

function rememberFirewallBackend(backend) {
    try {
        window.localStorage.setItem(FIREWALL_BACKEND_STORAGE_KEY, backend);
    } catch (error) {
        console.debug("Unable to remember firewall backend", error);
    }
}

function renderFirewallBackendToggle() {
    const container = getElement("firewall-backend-toggle");
    const group = container?.querySelector(".pf-v6-c-toggle-group");
    if (!container || !group)
        return;

    const available = state.firewallBackends.length ? state.firewallBackends : [state.firewallBackend];
    container.hidden = available.length < 2;
    group.replaceChildren();

    available.forEach(id => {
        const backend = FIREWALL_BACKENDS[id];
        if (!backend)
            return;

        const item = document.createElement("div");
        item.className = "pf-v6-c-toggle-group__item";

        const button = document.createElement("button");
        button.type = "button";
        button.className = "pf-v6-c-toggle-group__button backend-button";
        button.dataset.backend = id;
        const active = id === state.firewallBackend;
        button.classList.toggle("pf-m-selected", active);
        button.setAttribute("aria-pressed", active ? "true" : "false");

        const text = document.createElement("span");
        text.className = "pf-v6-c-toggle-group__text";
        text.textContent = backend.label;
        button.append(text);
        item.append(button);
        group.append(item);
    });
}

async function detectAvailableFirewallBackends() {
    const detected = await Promise.all(FIREWALL_BACKEND_ORDER.map(async id => {
        const backend = FIREWALL_BACKENDS[id];
        const installed = await checkToolInstalled(backend.toolId);
        return installed ? id : null;
    }));

    return detected.filter(Boolean);
}

async function resolvePreferredFirewallBackend(available) {
    if (available.includes("firewalld")) {
        const result = await captureRead([getToolCommand("firewalld"), "--state"]);
        if (result.ok && /running/i.test(result.output))
            return "firewalld";
    }

    if (available.includes("ufw")) {
        const result = await captureRead(["systemctl", "is-enabled", "ufw.service"]);
        if (result.ok && /enabled/i.test(result.output))
            return "ufw";
    }

    if (available.includes("nftables")) {
        const result = await captureRead(["systemctl", "is-enabled", "nftables.service"]);
        if (result.ok && /enabled/i.test(result.output))
            return "nftables";
    }

    // iptables is always meaningful (Docker and most tools write rules through
    // it, even when that lands in the nftables kernel implementation).
    if (available.includes("iptables"))
        return "iptables";

    return available[0] || "ufw";
}

async function initFirewallBackends() {
    state.firewallBackends = await detectAvailableFirewallBackends();

    const remembered = readRememberedFirewallBackend();
    const preferred = state.firewallBackends.includes(remembered)
        ? remembered
        : await resolvePreferredFirewallBackend(state.firewallBackends);

    switchFirewallBackend(preferred, { refresh: false, remember: false });
    state.firewallBackendsReady = true;

    if (state.superuserAllowed !== null)
        await refreshSecurityPage();
}

function switchFirewallBackend(backendId, options = {}) {
    state.firewallBackend = FIREWALL_BACKENDS[backendId] ? backendId : "ufw";
    if (options.remember !== false)
        rememberFirewallBackend(state.firewallBackend);

    renderFirewallBackendToggle();

    // Only reveal/hide the settings vs install state once detection has actually run.
    // While still null (not yet checked) keep both hidden so we never flash the
    // operations UI for a tool that may turn out to be missing.
    if (state.toolInstalled[state.firewallBackend] !== null)
        renderFirewallInstallState(state.toolInstalled[state.firewallBackend] === false);
    updateFirewallActionBar();
    setText("firewall-backend-label", getFirewallBackend().label);
    if (state.firewallDialog.open)
        closeFirewallDialog();
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

function updateFirewallActionBar() {
    const backend = getFirewallBackend();

    const toggle = (id, capability) => {
        setHidden(id, !canFirewall(capability));
    };

    toggle("firewall-enable-button", "enable");
    toggle("firewall-disable-button", "disable");
    toggle("firewall-reload-button", "reload");
    toggle("firewall-add-button", "addRule");

    const addButton = getElement("firewall-add-button");
    if (addButton)
        addButton.textContent = backend.addRuleLabel;

    const persistButton = getElement("firewall-persist-button");
    if (persistButton) {
        const persistState = state.firewallPersist?.state;
        const needsPersist = canFirewall("persist") &&
            !state.firewallPersist?.blocked &&
            persistState && persistState !== "saved" && persistState !== "managed";
        persistButton.hidden = !needsPersist;
    }
}

function resetFirewallDialog() {
    state.firewallDialog = {
        open: false,
        mode: "",
        busy: false,
        error: "",
    };
}

function updateFirewallDialog(patch) {
    state.firewallDialog = {
        ...state.firewallDialog,
        ...patch,
    };
    renderFirewallDialog();
}

function setFirewallRuleActionOptions(backend) {
    const select = getElement("firewall-rule-action");
    if (!select)
        return;

    select.replaceChildren();
    (backend.actionOptions || []).forEach(option => {
        const element = document.createElement("option");
        element.value = option.value;
        element.textContent = option.label;
        select.append(element);
    });
}

function renderFirewallChainOptions(backend) {
    const select = getElement("firewall-rule-chain");
    if (!select)
        return;

    const chains = state.firewallChains?.length
        ? state.firewallChains
        : (backend.fallbackChains || []).map(chain => ({ value: chain, label: chain }));

    select.replaceChildren();
    chains.forEach(chain => {
        const option = document.createElement("option");
        option.value = chain.value;
        option.textContent = chain.label;
        select.append(option);
    });
}

function renderFirewallRuleForm() {
    const backend = getFirewallBackend();
    const groups = {
        action: "firewall-rule-action-group",
        chain: "firewall-rule-chain-group",
        port: "firewall-rule-port-group",
        protocol: "firewall-rule-protocol-group",
        source: "firewall-rule-source-group",
    };

    Object.entries(groups).forEach(([field, id]) => {
        setHidden(id, !backend.fields.includes(field));
    });

    setFirewallRuleActionOptions(backend);
    renderFirewallChainOptions(backend);
}

function renderFirewallDialog() {
    const dialog = getElement("firewall-modal");
    const title = getElement("firewall-modal-title");
    const copy = getElement("firewall-modal-copy");
    const form = getElement("firewall-rule-form");
    const alert = getElement("firewall-modal-alert");
    const submit = getElement("firewall-modal-submit");
    const cancel = getElement("firewall-modal-cancel");
    const close = getElement("firewall-modal-close");

    if (!dialog || !title || !copy || !form || !alert || !submit || !cancel || !close)
        return;

    const current = state.firewallDialog;
    dialog.hidden = !current.open;
    if (!current.open)
        return;

    const backend = getFirewallBackend();
    const hint = [backend.dialogHint, ...(state.firewallNotices || [])].filter(Boolean).join(" ");
    title.textContent = backend.dialogTitle || backend.addRuleLabel;
    copy.hidden = !hint;
    copy.textContent = hint;
    form.hidden = false;
    alert.hidden = !current.error;
    alert.textContent = current.error;
    submit.textContent = current.busy ? "执行中..." : "应用";
    submit.disabled = current.busy;
    cancel.disabled = current.busy;
    close.disabled = current.busy;
    form.querySelectorAll("input, select").forEach(field => {
        field.disabled = current.busy;
    });
}

function openFirewallRuleDialog() {
    const form = getElement("firewall-rule-form");
    if (form)
        form.reset();

    renderFirewallRuleForm();
    const portInput = getElement("firewall-rule-port");
    if (portInput)
        portInput.removeAttribute("aria-invalid");
    updateFirewallDialog({
        open: true,
        mode: "add-rule",
        busy: false,
        error: "",
    });
}

function closeFirewallDialog() {
    resetFirewallDialog();
    renderFirewallDialog();
}

function confirmDestructiveAction(message) {
    return new Promise(resolve => {
        const confirmed = window.confirm(message);
        resolve(confirmed);
    });
}

async function deleteFirewallRule(rule) {
    if (!rule || rule.disabled || !canFirewall("deleteRule"))
        return;

    const plan = getFirewallBackend().buildDeleteRule(FIREWALL_CONTEXT, rule);
    if (!plan)
        return;

    const managerWarning = state.firewallManager
        ? `\n\n注意：${state.firewallManager} 正在管理本机规则，这次改动可能在它重新加载时被覆盖。`
        : "";
    const confirmed = await confirmDestructiveAction(`确定要删除${rule.description || rule.value} 吗？此操作不可撤销。${managerWarning}`);
    if (!confirmed)
        return;

    const result = await executeSteps("firewall", plan.steps);
    if (result.ok)
        await refreshFirewallStatus();
}

const PORT_PATTERN = /^\d+(?:[:-]\d+)?$/;
const SOURCE_PATTERN = /^[0-9a-fA-F.:]+(?:\/\d{1,3})?$/;

function validateFirewallRuleForm(backend, values) {
    if (!PORT_PATTERN.test(values.port))
        return { field: "firewall-rule-port", message: "端口格式不正确，请输入 22、22:80 或 22-80。" };

    if (values.source && !SOURCE_PATTERN.test(values.source))
        return { field: "firewall-rule-source", message: "来源格式不正确，请输入 IP、CIDR 或留空。" };

    if (backend.fields.includes("chain") && !values.chain)
        return { field: "firewall-rule-chain", message: "请先选择规则所属的链。" };

    return null;
}

async function handleFirewallDialogSubmit() {
    if (!state.firewallDialog.open || state.firewallDialog.busy)
        return;

    if (!isWritable()) {
        updateFirewallDialog({ error: "修改防火墙需要管理员权限。" });
        return;
    }

    const backend = getFirewallBackend();
    const form = getElement("firewall-rule-form");
    if (!form)
        return;

    const values = {
        action: getFormValue(form, "action") || backend.actionOptions?.[0]?.value || "",
        chain: getFormValue(form, "chain"),
        port: getFormValue(form, "port"),
        protocol: getFormValue(form, "protocol") || "tcp",
        source: getFormValue(form, "source"),
    };

    const invalid = validateFirewallRuleForm(backend, values);
    if (invalid) {
        ["firewall-rule-port", "firewall-rule-source", "firewall-rule-chain"].forEach(id => getElement(id)?.removeAttribute("aria-invalid"));
        getElement(invalid.field)?.setAttribute("aria-invalid", "true");
        updateFirewallDialog({ error: invalid.message });
        return;
    }

    const plan = backend.buildAddRule(FIREWALL_CONTEXT, values);
    if (!plan) {
        updateFirewallDialog({ error: "请先刷新状态并选择规则所属的链。" });
        return;
    }

    updateFirewallDialog({ busy: true, error: "" });
    const result = await executeSteps("firewall", plan.steps);
    if (!result.ok) {
        updateFirewallDialog({
            busy: false,
            error: summarizeOutput(result.output, false),
        });
        return;
    }

    closeFirewallDialog();
    form.reset();
    await refreshFirewallStatus();
}

async function handleQuickAction(action) {
    if (!isWritable())
        return;

    if (action.startsWith("fail2ban")) {
        const fail2banService = state.fail2banService || "fail2ban.service";
        const actions = {
            "fail2ban-start": () => execute("fail2ban", "启动 Fail2Ban", ["systemctl", "start", fail2banService]),
            "fail2ban-stop": () => execute("fail2ban", "停止 Fail2Ban", ["systemctl", "stop", fail2banService]),
            "fail2ban-restart": () => execute("fail2ban", "重启 Fail2Ban", ["systemctl", "restart", fail2banService]),
            "fail2ban-reload": () => execute("fail2ban", "重新加载 Fail2Ban", [getToolCommand("fail2ban"), "reload"]),
        };

        const handler = actions[action];
        if (!handler)
            return;

        await handler();
        await refreshFail2BanStatus();
        return;
    }

    const step = getFirewallBackend().quickActions(FIREWALL_CONTEXT)[action];
    if (!step)
        return;

    if (step.confirm && !(await confirmDestructiveAction(step.confirm)))
        return;

    const steps = step.steps || [{ args: step.args, label: step.label }];
    const result = await executeSteps("firewall", steps);
    if (result.ok)
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
    if (!isWritable())
        return;

    const form = event.currentTarget;
    const jail = getFormValue(form, "jail");
    const ip = getFormValue(form, "ip");

    if (!jail || !ip) {
        showCommandResult("fail2ban", "解封失败", "jail 和 IP 都不能为空。", false);
        return;
    }

    fillJailInputs(jail);
    await execute("fail2ban", "Fail2Ban 解封 IP", [getToolCommand("fail2ban"), "set", jail, "unbanip", ip]);
    form.reset();
    fillJailInputs(jail);
    await refreshFail2BanStatus();
    await loadFail2BanJail(jail, { quiet: true });
}

function bindEvents() {
    document.getElementById("firewall-backend-toggle")?.addEventListener("click", event => {
        const button = event.target.closest?.(".backend-button");
        if (button)
            switchFirewallBackend(button.dataset.backend);
    });

    document.querySelectorAll("[data-action]").forEach(button => {
        button.addEventListener("click", () => handleQuickAction(button.dataset.action));
    });

    document.querySelectorAll("[data-install-tool]").forEach(button => {
        button.addEventListener("click", () => openInstallDialog(button.dataset.installTool));
    });

    document.getElementById("security-readonly-action")?.addEventListener("click", requestSuperuserAccess);
    document.getElementById("security-auth-form")?.addEventListener("submit", handleSuperuserDialogSubmit);
    document.getElementById("security-auth-form")?.addEventListener("input", handleSuperuserDialogInput);
    document.getElementById("security-auth-form")?.addEventListener("change", handleSuperuserDialogInput);
    document.getElementById("security-auth-cancel")?.addEventListener("click", () => closeSuperuserDialog());
    document.getElementById("security-auth-close")?.addEventListener("click", () => closeSuperuserDialog());
    document.getElementById("firewall-add-button")?.addEventListener("click", openFirewallRuleDialog);
    document.getElementById("firewall-modal-submit")?.addEventListener("click", handleFirewallDialogSubmit);
    document.getElementById("firewall-modal-cancel")?.addEventListener("click", closeFirewallDialog);
    document.getElementById("firewall-modal-close")?.addEventListener("click", closeFirewallDialog);
    document.getElementById("firewall-rule-form")?.addEventListener("submit", event => {
        event.preventDefault();
        handleFirewallDialogSubmit();
    });
    document.getElementById("firewall-modal")?.addEventListener("click", event => {
        if (event.target?.id === "firewall-modal")
            closeFirewallDialog();
    });
    document.getElementById("security-install-submit")?.addEventListener("click", handleInstallDialogSubmit);
    document.getElementById("security-install-cancel")?.addEventListener("click", closeInstallDialog);
    document.getElementById("security-install-close")?.addEventListener("click", closeInstallDialog);
    document.getElementById("security-install-dialog")?.addEventListener("click", event => {
        if (event.target?.id === "security-install-dialog")
            closeInstallDialog();
    });
    document.getElementById("security-auth-dialog")?.addEventListener("click", event => {
        if (event.target?.id === "security-auth-dialog")
            closeSuperuserDialog();
    });
    document.getElementById("firewall-rules-prev")?.addEventListener("click", () => {
        state.firewallRules.page = Math.max(1, state.firewallRules.page - 1);
        renderFirewallRulesTable();
    });
    document.getElementById("firewall-rules-next")?.addEventListener("click", () => {
        const totalPages = getFirewallRuleTotalPages();
        state.firewallRules.page = Math.min(totalPages, state.firewallRules.page + 1);
        renderFirewallRulesTable();
    });
    document.getElementById("firewall-rules-page-go")?.addEventListener("click", () => {
        jumpToFirewallRulesPage(document.getElementById("firewall-rules-page-jump")?.value);
    });
    document.getElementById("firewall-rules-page-jump")?.addEventListener("change", event => {
        jumpToFirewallRulesPage(event.target.value);
    });
    document.getElementById("firewall-rules-page-jump")?.addEventListener("keydown", event => {
        if (event.key !== "Enter")
            return;

        event.preventDefault();
        jumpToFirewallRulesPage(event.target.value);
    });
    document.getElementById("security-log-source-toggle")?.addEventListener("click", () => {
        positionSecurityLogMenu();
        toggleSecurityLogMenu();
    });
    document.addEventListener("click", event => {
        const menu = document.getElementById("security-log-menu");
        const toggle = document.getElementById("security-log-source-toggle");
        if (menu && !menu.hidden && toggle && !toggle.contains(event.target) && !menu.contains(event.target))
            closeSecurityLogMenu();
    });
    document.getElementById("security-log-refresh")?.addEventListener("click", refreshSecurityLogs);
    document.getElementById("security-log-view-all")?.addEventListener("click", () => {
        cockpit.jump(getSecurityLogUrl());
    });
    document.getElementById("fail2ban-jail-form")?.addEventListener("submit", handleFail2BanJail);
    document.getElementById("fail2ban-unban-form")?.addEventListener("submit", handleFail2BanUnban);

    document.addEventListener("visibilitychange", () => {
        if (document.hidden) {
            stopAutoRefresh();
            return;
        }

        if (state.superuserAllowed !== null) {
            refreshSecurityPage();
            startAutoRefresh();
        }
    });

    document.addEventListener("keydown", event => {
        if (event.key === "Escape" && state.firewallDialog.open) {
            closeFirewallDialog();
            return;
        }

        if (event.key === "Escape" && state.installDialog.open) {
            closeInstallDialog();
            return;
        }

        if (event.key === "Escape" && state.superuserDialog.open)
            closeSuperuserDialog();
    });
}

document.addEventListener("DOMContentLoaded", async () => {
    bindEvents();
    bindDarkMode();
    initSuperuser();
    renderSecurityLogSourceOptions();
    clearFail2BanJail("可从 jail 列表快速打开，也可以手动输入名称查看。");
    renderFirewallDialog();
    renderInstallDialog();
    renderSuperuserDialog();
    renderAccessState();
    await initFirewallBackends();
});
