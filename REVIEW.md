# CAPEv2 Code Review

**Scope:** Full-repo review at HEAD `7bf9917` on branch `claude/repo-code-review-rve0v`.
**Stats:** ~180k LOC of Python across 805 source files; Django web UI, SQLAlchemy core,
plugin-based analyzer / processing / signatures / reporting / machinery.

This review is organized by severity. Each finding cites file paths and line numbers
so you can jump straight to the code. Findings are observations from reading the
code, not pen-test results — but several of them would not survive a security
review of a public-facing instance.

> Threat model note: many findings below are reasonable for a *local* malware-lab
> deployment (host-only network, single operator) and dangerous for a *public*
> deployment. The README advertises a public instance at capesandbox.com, so the
> distinction matters.

---

## 1. Critical / High Severity

### 1.1 Django runs with `DEBUG = True` and `ALLOWED_HOSTS = ["*"]` by default
`web/web/settings.py:105`, `web/web/settings.py:409`

```python
# settings.py:105
DEBUG = True
...
# settings.py:409
ALLOWED_HOSTS = ["*"]
```

`DEBUG` is unconditionally `True` — there is no env-var override, no
`local_settings.py` toggle in the file. With `DEBUG=True`, Django:
- emits full tracebacks (including settings, env vars, request bodies) on any
  unhandled error,
- disables `ALLOWED_HOSTS` validation,
- emits sensitive headers and never caches static files,
- enables the template "debug" context (settings.py:184: `"debug": True`).

`ALLOWED_HOSTS = ["*"]` further disables Host-header validation, so an attacker
can poison password-reset / absolute-URL flows even after `DEBUG=False` is set.

Combined with `RECAPTCHA_PRIVATE_KEY = "TEST_PUBLIC_KEY"` /
`RECAPTCHA_PUBLIC_KEY = "TEST_PRIVATE_KEY"` (settings.py:302-303) being shipped
as hardcoded test keys, the default state of the web tier is "developer laptop,"
not "service."

**Fix:** drive `DEBUG` and `ALLOWED_HOSTS` from `web_cfg` (the existing INI config
already used for nearly everything else in this file), default `DEBUG=False`,
and refuse to start if `ALLOWED_HOSTS == ["*"]` AND `DEBUG == False`.

---

### 1.2 REST framework falls back to `AllowAny` when token auth is disabled
`web/web/settings.py:277-295`, `web/apiv2/views.py` (entire file)

```python
# settings.py
if api_cfg.api.token_auth_enabled:
    REST_FRAMEWORK = { ... "IsAuthenticated" ... }
else:
    REST_FRAMEWORK = {
        "DEFAULT_AUTHENTICATION_CLASSES": [],
        "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"],
    }
```

When `api.conf` has `token_auth_enabled = no` (the default I expect on most
installs given how the WEB_AUTHENTICATION flag also defaults to False at
settings.py:60), **every API endpoint is unauthenticated**.

Concrete impact: `tasks_create_url` (`apiv2/views.py:412`), `tasks_create_file`
(`apiv2/views.py:207`), `tasks_create_dlnexec` (`apiv2/views.py:513`) all accept
POSTs from anyone reachable. The file is decorated `@csrf_exempt` 45 times
(`@login_required` appears exactly once) — there is no defense-in-depth here:
when token auth is off, anyone who can hit the port can submit tasks, fetch
arbitrary URLs through the sandbox, or use `dlnexec` to make the host download
files from operator-supplied URLs.

**Fix:** make `IsAuthenticated` the unconditional default and require
`token_auth_enabled` to be explicitly set to disable it. The current "off by
default, fail-open" stance is the wrong direction.

---

### 1.3 `dlnexec` and 3rd-party download fetch user URLs with no SSRF guard
`lib/cuckoo/common/web_utils.py:844`, `lib/cuckoo/common/web_utils.py:1042-1088`

```python
# web_utils.py:844 (download_file)
r = requests.get(kwargs["url"], params=..., headers=..., verify=False)
```

```python
# web_utils.py:1082-1083 (_download_file used by dlnexec)
url = url_defang(url)
response = requests.get(url, headers=headers, proxies=proxies)
```

User-supplied URLs flow into `requests.get()` with:

- `verify=False` (TLS validation disabled at `web_utils.py:844`),
- no scheme allowlist (`file://`, `http://`, `https://` all accepted by
  `requests` — `file://` won't work on `requests` by default, but plenty of
  internal HTTP services will),
- no IP allowlist — `127.0.0.1`, `169.254.169.254` (cloud metadata),
  `10.0.0.0/8`, internal hostnames all reachable,
- no redirect cap / cross-host redirect check.

Because of finding 1.2, this endpoint is anonymous on default installs. An
attacker can use the CAPE host as an SSRF relay against the operator's
private network.

**Fix:** centralize a `safe_get(url)` helper that (a) resolves the hostname,
(b) rejects RFC1918 / link-local / loopback / 100.64/10 / unique-local v6,
(c) enforces `https://` (or a small allowlist), (d) sets a short timeout,
(e) caps redirects and re-validates on each hop, (f) does not pass `verify=False`.

---

### 1.4 `mark_safe` on analysis-data-derived HTML
`web/analysis/templatetags/analysis_tags.py:75-79`, `:127-140`, `:158-172`, `:204`, `:248`

```python
# :65, :75-79
malware_name_url_pattern = """<a href="/analysis/search/detections:{malware_name}"><span style="font-weight: bold;">{malware_name}</span></a>"""

@register.filter("get_detection_by_pid")
def get_detection_by_pid(dictionary, key):
    ...
    output = malware_name_url_pattern.format(malware_name=detections[0])
    return mark_safe(output)
```

```python
# :127-140 (flare_capa_capabilities)
for namespaces, capabilities in obj.get("CAPABILITY", {}).items():
    _print(4, '<th width="25%" scope="row">' + namespaces + "</th>\n")
    for capability in capabilities:
        _print(5, "<li>" + capability + "</li>\n")
...
return mark_safe(ret_result)
```

Strings drawn from analysis output (YARA rule names, CAPA capabilities, malware
config dict keys/values) are concatenated into HTML with no `escape()` and
returned as `mark_safe`. If any of these strings can carry attacker control —
trivially true for malware-config extractors, which output adversary-controlled
strings; possible for YARA rule names from `data/yara` — the result is stored
XSS against any analyst viewing the report.

Same pattern at `:204` (`flare_capa_mbc`) and `:248` (`malware_config`).

**Fix:** call `django.utils.html.escape(value)` on every interpolated value
before concatenation. Or better, use `format_html` / `format_html_join`, which
auto-escapes.

---

### 1.5 Optional path-traversal guard, not mandatory
`web/analysis/views.py:207-209`

```python
def _path_safe(path: str) -> bool:
    if web_cfg.security.check_path_safe:
        return path_safe(path)
```

The function silently returns `None` (falsy) when the check is disabled, but
callers like `analysis/views.py:2463` use it as a positive gate. If
`web.conf [security] check_path_safe = no`, the path-traversal check is
short-circuited and untrusted `file_name` / `task_id` parameters flow into
`os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "files",
file_name)` (analysis/views.py:2322 etc.) and into a file download.

The check should not be optional. Make `path_safe` always run; the config flag
is a foot-gun, not a feature.

---

### 1.6 `shell=True` with f-string interpolation in machinery and processing
`modules/machinery/vmwareserver.py:51-58, 85-93, 108-118, 133-140, 151-158`
`modules/processing/suricata.py:48-50`
`modules/machinery/hyperv.py:48`

```python
# vmwareserver.py:51-57
check_string = (
    f"{self.options.vmwareserver.path} -T ws-shared -h {self.options.vmwareserver.vmware_url} "
    f"-u {self.options.vmwareserver.username} -p {self.options.vmwareserver.password} "
    f'listSnapshots "{vmx_path}"'
)
p = subprocess.Popen(check_string, universal_newlines=True, shell=True)
```

Operator-controlled (`conf/vmwareserver.conf`) values — including the literal
VMware **password** — are concatenated into a shell command line with `shell=True`.
Two concrete problems:

1. Any `'`/`"`/`$`/`` ` `` in the password breaks the command silently, and the
   error path raises an opaque `CuckooMachineError` rather than diagnosing the
   shell-quoting failure. Real passwords contain those characters.
2. `vmx_path` is taken from machine config and embedded inside double quotes,
   which is *not* a safe quoting strategy.

These are config-trusted inputs, so this is not a remote-attacker vuln, but it
is a correctness bug (passwords with shell metacharacters silently fail) and
turns into a privilege issue if any config value ever becomes user-tweakable.

**Fix:** pass a `list` argv and drop `shell=True` everywhere these patterns
appear. Each of the listed files is mechanically convertible.

The Suricata wrapper (`suricata.py:48`) is the same shape; it works on
operator-controlled config but is needlessly `shell=True`.

---

### 1.7 A 2.3 MB sample HTML report is committed at the repo root
`report.html` (71,392 lines, 2.3 MB, committed in `51c7a2f` "Proerly fix
behavior buttons (#2890)")

```
$ git log --stat -1 -- report.html
commit 51c7a2fc689ecd788787250872ef88cc81594f1b
    Proerly fix behavior buttons (#2890)
 report.html | 71392 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 71392 insertions(+)
```

This is clearly an accidental commit (PR title is about JS buttons, not adding
a report fixture). The file is not referenced from anywhere in the codebase
(I grepped). It bloats clones, slows CI checkouts, and — depending on what
sample produced it — may itself contain malware-config strings that flag on AV
scanners pulling the repo.

**Fix:** `git rm report.html` and add `report.html` to `.gitignore`. Consider
a BFG / `filter-repo` pass if the file is sensitive.

---

## 2. Medium Severity

### 2.1 `AuthenticationMiddleware` is listed twice in MIDDLEWARE
`web/web/settings.py:209` and `:216`

```python
MIDDLEWARE = [
    ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    ...
]
```

Duplicate entries cause two `get_user(request)` calls per request, both
re-doing the session lookup. Harmless functionally, but bloats every request
and signals a stale merge.

---

### 2.2 Pre-commit Black is pinned to a version older than the dev dep
`.pre-commit-config.yaml:26` pins `black 22.3.0`, but `pyproject.toml`
requires `black >= 24.3.0` for the dev install. CI runs Ruff but not Black,
so the two formatters can drift and pre-commit will rewrite files that
Black 24 would leave alone. Bump the pre-commit hook to match.

`isort` has the same shape (pre-commit `5.12.0`, dev dep `>=5.10.1`); the
direction is fine but pin them together.

`flake8` is configured in `pyproject.toml` but not actually run by anything in
CI or pre-commit. Either wire it up or drop the config.

---

### 2.3 mypy is scoped to `agent/` only
`pyproject.toml:194` configures mypy to type-check `agent/**/*.py`. The
180k-line core (`lib/`, `modules/`, `web/`) is unchecked. Given the bug
density I'd expect, even gradual mypy adoption in `lib/cuckoo/core/` would
catch a lot. Start with `database.py` and `plugins.py`.

---

### 2.4 `format` workflow auto-pushes to master from CI
`.github/workflows/python-package.yml:75-86`

```yaml
- name: Commit changes if any
  if: ${{ !env.ACT }}
  run: |
    git config user.name "GitHub Actions"
    git config user.email "action@github.com"
    if output=$(git status --porcelain) && [ ! -z "$output" ]; then
      git pull
      git add .
      git commit -m "style: Automatic code formatting" -a
      git push
    fi
```

`git add .` from CI is broad — anything else CI dropped in the workdir
(downloaded `data/7zz` at step :35-39, pytest caches, etc.) gets staged too.
The `.gitignore` is what saves you, but it's narrow (4 entries). A future
contributor who adds a tool that writes outside the ignore set will start
shipping artifacts into master via the formatter job.

Also: this job pushes to master with the default `GITHUB_TOKEN`. If the repo
ever enables branch protection requiring linear history, this loop breaks.

**Fix:** stage explicitly (`git add '*.py'`) and add a `[ci-skip]` marker so
the formatter commit doesn't re-trigger itself in a loop. Or, more simply,
fail CI on formatting drift and require the PR author to fix it.

---

### 2.5 `install/cape2.sh` downloads without integrity checks
`installer/cape2.sh` performs multiple `wget` / `curl` of release artifacts
(nginx tarballs, introvirt agent, jq binary, etc.) with no checksum or
signature verification. Not a `curl | bash` style RCE, but a single
upstream tag-rewrite or storage compromise could swap in a backdoored
agent that the install script then deploys. Pin SHA256 sums per artifact.

---

### 2.6 Bare `except Exception` in hot paths
A few specific spots I want to call out (there are many more):

- `lib/cuckoo/core/scheduler.py:116, 123, 150, 178, 338, 343` — bare
  `except Exception` in the main loop. The scheduler is the most important
  process in the system; swallowing exceptions here means hangs and zombie
  tasks look identical to success in the logs.
- `lib/cuckoo/core/plugins.py:52-63` — `import_plugin()` catches
  `ImportError, SyntaxError` and prints to stdout. A syntactically broken
  signature should be a startup failure, not a `print()` and a degraded
  signature set. Bonus: `startup.py:307` warns if fewer than 5 signature
  modules loaded — that means "silent failures are expected." Make import
  failures fatal in dev and gated behind `cuckoo.conf:strict_plugins=yes` in
  prod.
- `lib/cuckoo/core/scheduler.py:110-117` calls `sys._current_frames()`
  (private API) to dump stuck threads. Works today, won't necessarily work
  on a future CPython.

---

### 2.7 Linux analyzer file dumping is unimplemented
`analyzer/linux/analyzer.py:56-59`

```python
def dump_files(self, file_path):
    log.info("PLS IMPLEMENT DUMP, want to dump %s", file_path)
```

Linux samples can't have their dropped files uploaded. Either remove the call
site (so it's clear the feature doesn't exist on Linux) or implement it — the
current state is a silent no-op that makes Linux analyses look "complete"
without artifact capture.

---

### 2.8 Guac session token is `uuid.uuid4()`, not `secrets.token_urlsafe()`
`web/guac/views.py:75`

```python
token = uuid.uuid4()
```

`uuid4` is *probably* CSPRNG on CPython on Linux (it uses `os.urandom`), but
the docs do not guarantee it for security purposes, and the practice across
Django apps is to use `secrets`. Switch to `secrets.token_urlsafe(32)` for
clarity and forward-compat.

---

### 2.9 ResultServer file metadata log is appended without a lock
`lib/cuckoo/core/resultserver.py:~280` (per agent survey)

`FileUpload` handler appends to `files.json` for each uploaded artifact. There
is no per-task lock around the write, so two concurrent uploads from the same
guest can interleave bytes and corrupt the file. Wrap with `fcntl.flock` or
serialize via the per-task worker.

---

### 2.10 `SECURITY.md` is the GitHub default template
The file declares 5.1.x and 4.0.x as supported versions but the "Use this
section to tell people…" boilerplate placeholder text is still present.
Either flesh it out with the actual reporting address (`kev@capesandbox.com`
appears elsewhere) and an SLA, or delete the file. A stub `SECURITY.md` is
worse than none — researchers stop reading at "boilerplate".

---

## 3. Low Severity / Cleanup

### 3.1 Lock-file & dependency hygiene
- `pyproject.toml:50` depends on `bs4==0.0.1`. That's the dummy "wrapper"
  package on PyPI; the actual library is `beautifulsoup4`, which is correctly
  pinned in `requirements.txt:178` (`beautifulsoup4==4.12.3`) but not present
  in `pyproject.toml`. Drop `bs4` from `pyproject.toml` and add
  `beautifulsoup4` directly so `poetry export` and `uv` produce a non-redundant
  set.
- Two lockfiles (`poetry.lock`, `uv.lock`) are kept in sync via
  `.github/workflows/export-requirements.yml`. This is workable but doubles the
  surface area for drift; pick one. Given `uv` is what the new bot uses
  (`.github/workflows/auto_answer.yml`), uv is probably the right choice.
- `CSRF_COOKIE_SECURE = "True"` is commented out at `settings.py:49` — and note
  the string, not the bool. Don't bring it back as-is. Set it from config.

### 3.2 Singleton config cache and env-var interpolation hack
`lib/cuckoo/common/config.py:97-132` — `ConfigMeta` caches `Config(name)` per
process; `refresh()` reloads but anyone holding a reference to the previous
object sees stale data. Env-var interpolation uses a custom `%%` doubling
because of `ConfigParser` quirks. Both work today, both will eventually bite.

### 3.3 Dead Python-2 remnants
`modules/reporting/mongodb.py:63` references `.iteritems()`. The line is
unreachable on Python 3 but suggests this file hasn't been audited for the
migration. A `ruff --select UP` pass would remove these.

### 3.4 `cuckoo.py:17-18` allows running as root via env-var
```python
if os.getuid() == 0 and not os.environ.get("CAPE_AS_ROOT"):
    sys.exit("...")
```
This is fine for the rare cases that need it, but the env-var name should be
documented in `README.md`/`SECURITY.md` so it's not a silent escape hatch.

### 3.5 No Dockerfile despite `.dockerignore`
`.dockerignore` exists but there is no `Dockerfile`. Either ship the container
build (the install script suggests this would be high-value) or delete the
orphan `.dockerignore`.

### 3.6 Disabled workflows live alongside active ones
`.github/workflows/yara-audit.yml`, `antitemplaters.yml`, `todo.yml` are
disabled. Either re-enable or remove — they add noise to the workflow list
and rot.

### 3.7 Systemd unit hardening
None of the units under `systemd/` set `NoNewPrivileges=true`,
`ProtectSystem=strict`, `ProtectHome=true`, or `PrivateTmp=yes`. `cape-rooter`
genuinely needs root (it manipulates iptables), but the other services
(`cape-web`, `cape-processor`, `cape-pubsub`) should run hardened. The
[`ProtectSystem=strict`, `ProtectHome=true`, `NoNewPrivileges=true`,
`RestrictSUIDSGID=true`] set is essentially free.

---

## 4. Architecture notes (not findings — context for future work)

- **Plugin loading** (`lib/cuckoo/core/plugins.py:66-104`): `pkgutil`-driven
  discovery with a module-level `_modules` `defaultdict`. Works, but the
  global mutable state makes testing painful and reload semantics unclear.
- **Concurrency model** mixes `threading.Thread` per analysis (one
  `AnalysisManager` thread per task — `scheduler.py:190`) with `gevent`
  greenlets inside the `ResultServer` (`resultserver.py:29, 784`). This is
  fine but the boundary needs to be precise: blocking calls inside a
  greenlet stall every other guest's uploads.
- **Database** is SQLAlchemy 2.x with `DeclarativeBase` (`db_common.py:29`).
  Defaults to SQLite (`database.py:100-114`). The hardcoded `SCHEMA_VERSION
  = "2b3c4d5e6f7g"` (`database.py:52`) and the "a little bit dirty, needs
  refactoring" comment at `:143-150` are honest, but consider Alembic — it's
  already a SQLAlchemy 2 codebase.
- **Host↔guest** is HTTP on port 7000 (`lib/cuckoo/core/guest.py:80`,
  `agent/agent.py`). The in-guest agent has an `/execute` endpoint
  (`agent/agent.py:651`) that runs arbitrary commands; this is *by design*
  — the host needs it to drive the sandbox — and is mitigated by IP pinning
  (`agent/agent.py:202-207`), not authentication. That's acceptable for a
  host-only-network VM. Don't expose port 7000 outside the lab.

---

## 5. Suggested fix order

1. **Today.** Flip `DEBUG`, `ALLOWED_HOSTS`, REST-framework default (`1.1`,
   `1.2`). Centralize a `safe_url_get()` (`1.3`). Remove the accidental
   `report.html` commit (`1.7`).
2. **This week.** XSS hardening in `analysis_tags.py` (`1.4`). Make
   `path_safe` non-optional (`1.5`). Lock the `files.json` append (`2.9`).
   De-dupe `AuthenticationMiddleware` (`2.1`).
3. **This sprint.** Convert `vmwareserver.py` / `hyperv.py` / `suricata.py`
   shell-string calls to argv (`1.6`). Add SHA256 pins to installer (`2.5`).
   Tighten the scheduler / plugin import error handling (`2.6`).
4. **Background.** Expand mypy beyond `agent/` (`2.3`), pick one lockfile
   (`3.1`), harden systemd units (`3.7`), remove dead Py2 code (`3.3`).

---

*Reviewed by Claude (opus-4-7) against HEAD `7bf9917`.*
