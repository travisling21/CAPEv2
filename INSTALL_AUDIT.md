# Install audit

**Scope:** static read of every install script under `installer/` plus
the systemd units that the installer deploys. I did not actually run
the installer (it requires root, KVM, libvirt, and a fresh Ubuntu
host), so this is code review, not a live test.

**Verdict:** the install will fail or silently degrade on a default
poetry install today, mainly because of one wrong command in
`install_CAPE`. Three other smaller bugs make follow-on failures
opaque. All four are fixed in the same commit as this doc.

---

## Critical: `install_CAPE` doesn't install the Python deps (poetry path)

**`installer/cape2.sh:1383` (pre-fix):**

```bash
sudo -u ${USER} bash -c "export PYTHON_KEYRING_BACKEND=...; \
    CRYPTOGRAPHY_DONT_BUILD_RUST=1 $PYTHON_MGR pip install -r pyproject.toml"
```

`$PYTHON_MGR` defaults to `/etc/poetry/bin/poetry`. The command expands to:

```
/etc/poetry/bin/poetry pip install -r pyproject.toml
```

Poetry has no `pip` subcommand. The invocation prints
`Command "pip" is not defined.` and exits 1. Because the script has
no `set -e`, the installer then chugs through `install_libvirt`,
`install_yara_python`, the conf copy, `community.py`, etc. — none of
which can succeed because the CAPE virtualenv was never populated.
The systemd services later fail to start with `ModuleNotFoundError`.

The `--use-uv` path coincidentally works because
`uv pip install -r pyproject.toml` is a real uv command.

**Fix:** branch on `USE_UV` and call the right command:

```bash
if [ "$USE_UV" = "true" ] || [ "$USE_UV" = "True" ]; then
    $PYTHON_MGR pip install -r pyproject.toml
else
    $PYTHON_MGR install --no-root        # poetry install
fi
```

`--no-root` is necessary because `pyproject.toml [tool.poetry]
package-mode = false` already tells poetry not to install the
project as a package — without it newer poetry warns about it.

---

## High: `install_systemd` passes an empty unit name to systemctl

**`installer/cape2.sh:1480-1481` (pre-fix):**

```bash
cape_web_enable_string=''
if [ "$MONGO_ENABLE" -ge 1 ]; then
    cape_web_enable_string="cape-web"
fi
systemctl enable cape cape-rooter cape-processor "$cape_web_enable_string" suricata
systemctl restart cape cape-rooter cape-processor "$cape_web_enable_string" suricata
```

When `MONGO_ENABLE=0` (operator wants ES-only or no web tier), the
empty string is still a positional argument:

```
systemctl enable cape cape-rooter cape-processor "" suricata
```

systemctl rejects the empty unit name with
`Failed to look up unit file state for : No such file or directory`,
then refuses to enable any of the units in the same call. The
install appears to succeed but no services are enabled.

**Fix:** build a bash array, conditionally append, then expand:

```bash
cape_units=(cape cape-rooter cape-processor)
if [ "${MONGO_ENABLE:-0}" -ge 1 ]; then
    cape_units+=(cape-web)
fi
cape_units+=(suricata)
systemctl enable "${cape_units[@]}"
systemctl restart "${cape_units[@]}"
```

---

## Medium: malformed `limits.conf` line for root hard nofile

**`installer/cape2.sh:1196-1198` (pre-fix):**

```bash
if ! grep -q -E '^root hard nofile' /etc/security/limits.conf; then
    echo "root soft hard 1048576" >> /etc/security/limits.conf
fi
```

The check is `^root hard nofile` but the line being written is
`root soft hard 1048576`. That's a malformed limits.conf entry:

| field | should be | is |
|---|---|---|
| domain | root | root |
| type | hard | soft |
| item | nofile | hard |
| value | 1048576 | 1048576 |

pam_limits silently ignores the malformed line. Result: root's hard
nofile stays at the system default (typically 4096), and the
guard `grep -q '^root hard nofile'` keeps matching false on every
re-run, so we never get a correct line either.

**Fix:** the obvious typo correction — `"root hard nofile 1048576"`.

---

## Medium: dependency install bails on de4dot download failure

**`installer/cape2.sh:1114-1125` (pre-fix):**

```bash
de4dot_package_name="de4dot_3.1.41592.3405-2_all.deb"
if [ ! -f $de4dot_package_name ]; then
    wget http://archive.ubuntu.com/ubuntu/pool/universe/d/de4dot/$de4dot_package_name
fi
if [ -f $de4dot_package_name ]; then
    sudo dpkg -i $de4dot_package_name
    sudo rm $de4dot_package_name
else
    echo "[-] de4dot package not found"
    return                # <-- aborts the whole dependencies() function
fi
```

de4dot is one optional .NET unpacking helper. If the Ubuntu
universe mirror is temporarily flaky or the wget fails, `return`
silently aborts the rest of `dependencies()` — PostgreSQL,
apparmor-utils, tor, sysctl/limits config, all skipped.

**Fix:** warn and continue. The miss degrades .NET unpacking but
doesn't prevent CAPE from running.

---

## Lower-severity findings (not fixed in this pass)

These don't block install but are worth a future cleanup:

- **`cape2.sh:1735`** — `tr "{A-Z}" "{a-z}"` lowercases via the
  literal char set `{` + `A-Z` + `}` → `{` + `a-z` + `}`. The braces
  are no-ops, but the comment immediately above says
  `# Doesn't work ${$1,,}` which suggests the author already
  knew there was a problem. The standard form is `tr '[:upper:]'
  '[:lower:]'` or just `${1,,}` (which DOES work in bash 4+).

- **`cape2.sh:1743-1749`** — args parsing only handles 0 and 3
  positional args; 1 and 2 args silently fall through and the script
  proceeds with whatever defaults are at the top of the file (e.g.
  `IFACE_IP=192.168.1.1`). The README example
  `sudo bash cape2.sh all | tee cape2.log` is a 1-arg call. It
  works today only because the static defaults are usable, but
  passing a custom IFACE_IP as the 2nd arg silently does nothing.

- **`cape2.sh:1117`** — `wget http://archive.ubuntu.com/...` over
  HTTP. archive.ubuntu.com supports HTTPS; the download isn't
  signature-verified either way (dpkg validates the .deb only if a
  signing key is configured). Low impact since Ubuntu archive is
  already an MITM-adversary's first stop on a compromised network.

- **`cape2.sh:1049-1050`** — `psql -d \"${USER}\" -c \"ALTER
  DATABASE cape REFRESH COLLATION VERSION;\"` hardcodes `cape` as
  the database name while everything around it uses `${USER}`. Works
  on default install (`USER=cape`), breaks if the operator
  overrides `USER`.

- **`install_systemd` only copies 5 units** (`cape`, `cape-rooter`,
  `cape-processor`, `cape-web`, `suricata`) but the `systemd/` tree
  carries 14. The rest (`cape-fstab`, `cape-dist`, `cape-pubsub`,
  `cape-sigma-update.{service,timer}`, `guac-web`, `guacd`,
  `suricata-update.{service,timer}`) are intentionally opt-in
  (`distributed()`, `install_guacamole()` deploy their own subset)
  but `cape-sigma-update` and `cape-pubsub` have no installer
  function at all — operators who enable those features must drop
  the unit files in by hand.

- **No `set -e` anywhere.** Every apt-get call, every wget,
  every systemctl invocation can fail silently. Adding a global
  `set -euo pipefail` would expose dozens of other latent bugs; the
  pragmatic alternative is a `trap` that logs which line failed,
  and `|| true` on calls that are intentionally allowed to fail.

- **`README.md`** is two lines:

  ```
  # From @doomedraven with love.
  * Use `sudo cape2.sh -h`
  ```

  Given the script is 1900 lines and takes a non-trivial set of
  positional args + env vars + flags, a fuller install guide
  (Ubuntu version matrix, prerequisite KVM/libvirt setup, what
  `sudo bash cape2.sh all` actually does in order) would save many
  first-timer support tickets.

---

## What's in the same commit as this doc

Direct edits to `installer/cape2.sh`:

- Branch on `USE_UV` in `install_CAPE`; call `poetry install
  --no-root` for the default path and `uv pip install -r
  pyproject.toml` for the uv path.
- Replace the `cape_web_enable_string` string with a bash array in
  `install_systemd`.
- Fix the `root soft hard` typo in `dependencies` → `root hard
  nofile`.
- Replace `return` with a warn-and-continue in the de4dot block of
  `dependencies`.

`bash -n installer/cape2.sh` parses cleanly after the changes.

---

## Things to verify on a real install host

Operators who want to be sure the installer works end-to-end after
these fixes should check:

1. After `sudo bash cape2.sh all | tee cape2.log`:
   - `systemctl is-enabled cape cape-rooter cape-processor cape-web suricata` returns `enabled` for each (when `MONGO_ENABLE=1`).
   - `sudo -u cape /etc/poetry/bin/poetry --directory /opt/CAPEv2 run python -c 'import lib.cuckoo'` succeeds.
   - `ulimit -Hn` returned by `sudo -u root /bin/bash -c 'ulimit -Hn'` is 1048576 (after a fresh login).
2. The tor TransPort/DNSPort lines were appended to `/etc/tor/torrc` only once (the `cat >>` in `dependencies()` doesn't guard against duplicates on re-runs).
3. `/etc/sudoers.d/cape` exists and the `${USER} ALL=NOPASSWD: …` lines are visible to `sudo -l -U ${USER}`.

A genuine end-to-end test would require a clean Ubuntu 22.04 or 24.04
VM and is out of scope for this static review.
