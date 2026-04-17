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

The build is intentionally simple:

- `src/index.js` is bundled into `dist/index.js`
- `src/index.html`, `src/index.css`, and `src/manifest.json` are copied into `dist/`

# Installing

`make install` builds the plugin and installs it to `/usr/local/share/cockpit/cockpit-security/`:

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
ln -s "$(pwd)/dist" ~/.local/share/cockpit/cockpit-security
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
├── package.json
└── README.md
```

# Current functionality

- Firewall page
  - switch between UFW and iptables
  - refresh firewall state
  - for UFW: status, enable, disable, reload, add rule, delete by number
  - for iptables: show `INPUT` chain, insert rule, delete by line number
- Fail2Ban page
  - refresh service and global status
  - start, stop, restart, reload
  - inspect a jail
  - unban an IP from a jail

# Notes

- All system commands are executed through `cockpit.spawn()` with `superuser: "require"`.
- If the target host does not have `ufw`, `iptables`, or `fail2ban-client`, the command error is shown directly in the UI.
- The current iptables integration only changes runtime rules; it does not persist them across reboots.
- This repository currently ships a lightweight build chain. It does not yet reintroduce the full starter-kit packaging, translation, and CI stack.

# Further reading

- [Cockpit Deployment and Developer documentation](https://cockpit-project.org/guide/latest/)
- [Cockpit Starter Kit announcement](https://cockpit-project.org/blog/cockpit-starter-kit.html)
- [Make your project easily discoverable](https://cockpit-project.org/blog/making-a-cockpit-application.html)
