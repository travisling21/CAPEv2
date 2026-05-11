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

---

# Second-pass findings

These came out of a deeper read of the rest of `cape2.sh` plus a
spot-check of `kvm-qemu.sh`. Fixes are in the same commit unless
flagged otherwise.

## High: `install_mongo` ExecReload `$MAINPID` gets eaten by the installer's shell

**`installer/cape2.sh:975-999` (pre-fix):**

```bash
cat >> /lib/systemd/system/mongodb.service << EOF
...
ExecReload=/bin/kill -HUP $MAINPID
...
EOF
```

The heredoc delimiter `EOF` is unquoted, so the installer's bash
expands `$MAINPID` before writing the file. `$MAINPID` is unset in
the installer process, so it expands to the empty string. The
resulting unit file contains:

```
ExecReload=/bin/kill -HUP
```

`/bin/kill -HUP` with no PID errors out, so `systemctl reload
mongodb` reports failure on every call. mongodb still works, but
config reloads silently no-op.

**Fix:** quote the heredoc delimiter `<<'EOF'` so the literal
`$MAINPID` lands in the unit file for systemd to expand at runtime.
Also flip the redirector from `>>` to `>` so re-runs of the
installer don't duplicate the unit content (the `if [ ! -f ... ]`
guard already protects against multiple runs, but `>` is safer if
that guard is ever removed).

Also dedupe the literal `rm /lib/systemd/system/mongod.service`
appearing twice on lines 968-969; the second `rm` always failed.

## High: `install_nginx` `[ ! -d zlib-1.3.1]` syntax error skips the zlib download

**`installer/cape2.sh:375-377` (pre-fix):**

```bash
if [ ! -d zlib-1.3.1]; then
    wget https://www.zlib.net/zlib-"$ZLIB_VERSION".tar.gz && tar xzvf zlib-"$ZLIB_VERSION".tar.gz
fi
```

Missing space before the `]`. Bash parses the test as
`[ ! -d zlib-1.3.1]`, where the closing `]` is consumed as part of
the filename. The `[` command then errors with `[: missing ']'` and
returns nonzero, so the `if` evaluates to false and the body never
runs. The follow-up `./configure --with-zlib=../zlib-1.3.1`
subsequently fails because the directory doesn't exist.

**Fix:** add the missing space, use `"$ZLIB_VERSION"` for
consistency.

## Medium: `install_suricata` checks the wrong directory

**`installer/cape2.sh:728-733` (pre-fix):**

```bash
if [ -d /usr/share/suricata/rules/ ]; then
    if [ "$(ls -A /var/lib/suricata/rules/)" ]; then    # <-- wrong dir
        cp "/usr/share/suricata/rules/"* "/etc/suricata/rules/"
    fi
fi
```

The outer guard checks `/usr/share/suricata/rules/`, the inner
guard checks `/var/lib/suricata/rules/`, the copy reads from
`/usr/share/`. On a fresh suricata install where
`/var/lib/suricata/rules/` is empty, the rules in `/usr/share/`
don't get copied even though they should. Result: suricata starts
with an empty `/etc/suricata/rules/` and matches nothing.

**Fix:** check the same dir we copy from.

## Medium: `install_suricata` appends a duplicate `include:` block on every re-run

**`installer/cape2.sh:765` (pre-fix):**

```bash
sed -i '$a include:\n  - cape.yaml\n' /etc/suricata/suricata.yaml
```

Unconditionally appends. Running `cape2.sh suricata` twice produces:

```yaml
include:
  - cape.yaml

include:
  - cape.yaml
```

Suricata's YAML loader rejects this as a duplicate top-level key
and `suricata -T -c suricata.yaml` exits 1. Subsequent
`systemctl restart suricata` then fails.

**Fix:** guard the `sed` with `grep -qE '...cape\.yaml...'` so the
include is added at most once.

## Medium: `kvm-qemu.sh` installs nonexistent `language-pack-UTF-8`

**`installer/kvm-qemu.sh:1292` (pre-fix):**

```bash
aptitude install -f language-pack-UTF-8 python3-pip -y
```

There's no Debian package called `language-pack-UTF-8`. aptitude
prints a "couldn't find package" warning and continues, so the
install proceeds — but the English locale isn't installed, which
matters for downstream tooling that assumes en_US.UTF-8.

**Fix:** use the real package name `language-pack-en`.

## Medium: `kvm-qemu.sh` no-ip cd glob is quoted

**`installer/kvm-qemu.sh:1345` (pre-fix):**

```bash
cd "noip-*" || return
```

Double-quoted glob doesn't expand. Bash tries to `cd` into a
literal directory named `noip-*`. The `cd` fails, `||` triggers
`return`, and the rest of the noip block (`make install`, the
crontab line) silently skips.

**Fix:** unquote the glob: `cd noip-* || return`.

## Lower-severity findings (documented, not fixed)

- **`install_yara`** (`cape2.sh:849`): `if [ ! -f "$yara_version" ]`
  uses the GitHub tag name (e.g. `v4.5.0`) as a literal filename
  check in `/tmp`. Works on a clean install because wget happens to
  save the zipball as `v4.5.0` (no extension), but it's fragile.
  Re-running the function in a `/tmp` that already has `v4.5.0`
  skips the re-download, which is fine, but then the directory
  detection at line 854 (`ls | grep "VirusTotal-yara-*"`) depends
  on the previous extraction having succeeded.

- **`install_yara`** (`cape2.sh:843`): apt-installs `libyara-dev`
  (system yara) and *then* builds yara from source and dpkg-deb
  installs that. You end up with two yara installations. The dpkg-deb
  install probably wins (newer version) but the apt one isn't removed.

- **`install_nginx`** (`cape2.sh:364`): `gpg --verify` is called
  before the nginx signing key is imported into the keyring, so the
  verify always fails. There's no error handling, so install
  continues. The signature check is effectively decorative.

- **`install_nginx`** (`cape2.sh:362,372,376,380`): tarball
  downloads over HTTP. Each upstream supports HTTPS; using it gives
  TLS-level integrity for free even when GPG verification is broken.

- **`install_mongo`** (`cape2.sh:937`): writes to
  `/etc/apt/keyrings/mongo.gpg` without `mkdir -p
  /etc/apt/keyrings/` first. On older Ubuntu (20.04) where the
  directory doesn't exist by default, the `gpg --dearmor -o ...`
  call fails and the subsequent apt-get update can't find the
  signing key for the mongo repo, leading to an unauthenticated
  package warning or refusal to install mongo.

- **`install_suricata`** (`cape2.sh:766-767`): `usermod -aG pcap
  suricata` and `usermod -aG suricata "${USER}"` run unconditionally.
  Both fail loudly if `apt-get install suricata` failed earlier (no
  `suricata` user/group), but the function continues, leaving the
  CAPE user without pcap permissions. Worth guarding with `id -u
  suricata >/dev/null 2>&1 || return`.

- **`kvm-qemu.sh:1341`** noip-duc download uses HTTP.

## Updated post-install checklist

In addition to the checks from the first pass:

4. `sudo -u cape /etc/poetry/bin/poetry --directory /opt/CAPEv2 run python -c 'import yara; yara.compile(source="rule x { condition: true }")'` succeeds (verifies the source-built yara is the one in the venv).

5. `sudo -u suricata suricata -T -c /etc/suricata/suricata.yaml` exits 0 (catches the duplicate-include bug if any).

6. `systemctl reload mongodb` exits 0 (catches the `$MAINPID` heredoc bug).

7. After running with `MONGO_ENABLE=0`, `systemctl is-enabled cape cape-rooter cape-processor suricata` all return `enabled` (catches the empty-unit-name bug regression).

8. `ls -A /etc/suricata/rules/ | wc -l` returns a non-zero count after install (catches the wrong-dir-check bug).
