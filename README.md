# Cockpit Security

Security tooling for a [Cockpit](https://cockpit-project.org/) module.

This project follows the starter-kit layout, but keeps the repository root as the project root:

- source files live in `src/`
- the build output goes to `dist/`
- the installed Cockpit package is the built `dist/` directory

The current UI adds a new “安全” entry in Cockpit with two areas:

- 防火墙
  - UFW
  - iptables
- Fail2Ban

# Development dependencies

On Debian/Ubuntu:

    sudo apt install nodejs npm make

On Fedora:

    sudo dnf install nodejs npm make

On openSUSE Tumbleweed and Leap:

    sudo zypper in nodejs npm make

# Getting and building the source

These commands check out the source and build it into the `dist/` directory:

```sh
git clone https://github.com/Bia951/cockpit-security.git
cd cockpit-security
npm install
make build
```

The build chain is intentionally simple and keeps PatternFly bundled with the plugin:

- `npm install` downloads the frontend dependency set and creates the lockfile
- `node build.js` copies the package files from `src/` into `dist/`
- `node build.js` also copies `@patternfly/patternfly` assets into `dist/`, so the plugin does not depend on Cockpit's shared PatternFly bundle
- `make build` is a thin wrapper around that command
- `make watch` watches `src/` and rebuilds on change

# Installing

`make install` builds the plugin and installs it to `/usr/local/share/cockpit/security/`:

```sh
make install
```

For development, you usually want to run the module straight out of the git tree. To do that, run:

```sh
make devel-install
```

This links `dist/` into Cockpit’s local package directory. If you prefer to do it manually:

```sh
mkdir -p ~/.local/share/cockpit
ln -s "$(pwd)/dist" ~/.local/share/cockpit/security
```

After changing the code and rebuilding, reload the Cockpit page in your browser.

You can also use watch mode to rebuild automatically:

```sh
make watch
```

To remove the local development link:

```sh
make devel-uninstall
```

# Project structure

The repository is organized like this:

```text
.
├── src/
│   ├── index.css
│   ├── index.html
│   ├── index.js
│   └── manifest.json
├── dist/
├── build.js
├── Makefile
└── README.md
```

# Current functionality

- Firewall page
  - detects the firewall managers present on the host and offers them as a
    toggle: firewalld, UFW, nftables, iptables
  - the preferred backend is picked automatically (a running firewalld, then an
    enabled UFW, then an enabled nftables service, then iptables) and the manual
    choice is remembered in the browser
  - for UFW: status, enable, disable, reload, add rule, delete by number
  - for iptables: full ruleset from `iptables -S`, per-chain insert, delete by
    rule spec, and rule persistence (`netfilter-persistent save` or
    `iptables-save` into `/etc/iptables/rules.v4`, `/etc/sysconfig/iptables`)
  - for nftables: ruleset from `nft -a list ruleset`, add/delete rules by chain
    and handle, save into `/etc/nftables.conf` and enable `nftables.service`
  - nftables only offers edit actions for tables the host's own
    `/etc/nftables.conf` declares, and only when `nftables.service` is enabled.
    On hosts where `iptables` is the nftables kernel implementation (Debian 12,
    Ubuntu) plus Docker, the whole live ruleset belongs to iptables/Docker; those
    tables are shown read-only and saving is blocked, because
    `nft list ruleset > /etc/nftables.conf` there would copy Docker's rules into
    the nftables config and duplicate them at boot. A `flush ruleset` in that
    file is reported as well, since enabling the service would then wipe the
    live ruleset.
  - for firewalld: default zone services, ports and rich rules, configured in
    both the runtime and the permanent configuration
  - every backend reports whether its rules are persisted, and warns when the
    runtime state is not saved
- Fail2Ban page
  - refresh service and global status
  - start, stop, restart, reload
  - inspect a jail
  - unban an IP from a jail
- Read-only mode
  - read-only commands run with `superuser: "try"`, so an unprivileged session
    still sees everything the host lets it see
  - the page is never hidden behind an admin gate; mutating controls are hidden
    and a banner offers "开启管理员访问"

# Backend abstraction

All firewall managers implement the same small driver interface in
`src/index.js` (`FIREWALL_BACKENDS`), and the UI only talks to the selected
driver:

- `capabilities` - which actions the UI may show (`enable`, `disable`, `reload`,
  `addRule`, `deleteRule`, `persist`)
- `read(ctx)` - turns manager specific output into
  `{ summary, statusLabel, tone, details, columns, rows, chains, persist, emptyText }`,
  or `{ kind: "permission" }` / `{ kind: "error" }`
- `buildAddRule(ctx, values)` / `buildDeleteRule(ctx, rule)` / `quickActions(ctx)`
  - return command steps, so multi-command operations (firewalld writes both the
  runtime and the permanent configuration) stay declarative
- `fields` / `actionOptions` / `fallbackChains` - which dialog fields the backend
  needs and what they contain

Adding another firewall manager means adding one object to `FIREWALL_BACKENDS`.

# Notes

- Write operations are executed through `cockpit.spawn()` with
  `superuser: "require"`; read operations use `superuser: "try"` and degrade to
  a permission notice instead of failing the page.
- If the target host does not have `ufw`, `iptables`, `nft`, `firewall-cmd` or
  `fail2ban-client`, the install hint is shown instead of the data.
- iptables persistence is detected and reported (`netfilter-persistent` or a
  saved rules file); reads that cannot be answered without root say so instead
  of showing a raw error.
- A rules file alone does not survive a reboot: the UI also checks whether
  `netfilter-persistent.service` or `iptables.service` is enabled, and says so
  when saving would have no effect.
- Docker-managed chains (`DOCKER*`) are labelled and cannot be deleted from the
  iptables view.
- An `INPUT` policy of `ACCEPT` with no `INPUT` rules is reported as "no inbound
  filtering" instead of a healthy firewall.
- This repository currently ships a lightweight build chain. It does not yet reintroduce the full starter-kit packaging, translation, and CI stack.
- The current build uses `npm` only to vendor frontend assets such as PatternFly into the plugin package; the UI code itself is still plain HTML/CSS/JS.

# Further reading

- [Cockpit Deployment and Developer documentation](https://cockpit-project.org/guide/latest/)
- [Cockpit Starter Kit announcement](https://cockpit-project.org/blog/cockpit-starter-kit.html)
- [Make your project easily discoverable](https://cockpit-project.org/blog/making-a-cockpit-application.html)
