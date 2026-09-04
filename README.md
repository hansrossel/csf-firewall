# csf-firewall

A fork of **ConfigServer Security & Firewall (CSF)** carrying the security
fixes that cPanel shipped in CSF 16.31, applied on top of the last published
release of [`Aetherinox/csf-firewall`](https://github.com/Aetherinox/csf-firewall)
(15.10, 28 February 2026).

## Why this fork exists

Upstream's most recent release is 15.10 and predates the security work cPanel
did in July and August 2026. Those fixes were published as part of the
`cpanel-csf` package; the public `cpanel/cpanel-csf` repository has not moved
since 25 February 2026 and does not contain them. This fork exists so that
hosts which do not run cPanel can still get that hardening.

## Version numbering

`csf/version.txt` reports **16.31**.

Read that as *security-fix parity with cPanel CSF 16.31*, not as "this is
cPanel's 16.31". The code here is upstream's 15.10 line with the relevant
fixes backported; cPanel's 16.31 is a separate codebase with many other
changes. The number is aligned so that version comparisons in existing
deployment tooling do the right thing.

Because of that, `csf -v` alone does not prove the fixes are present. If you
need to verify a deployed copy, grep for a backported symbol:

```
grep -c dropprivileges /usr/local/csf/lib/ConfigServer/Messenger.pm   # 16.31
grep -c _open_unblock_queue /etc/csf/lfd.pl                           # 16.30
```

A quick way to confirm the CVE-2026-67402 configuration is gone is that
neither template still maps `/usr/bin` into the URL space:

```
grep -r ScriptAlias /etc/csf/apache.*.txt   # must print nothing
```

## What was changed

Each area is its own commit.

Backported for parity with cPanel CSF 16.30:

| Area | File |
|---|---|
| Fallback URL fetch built as an argv list, URL passed on stdin | `csf/ConfigServer/URLGet.pm` |
| reCAPTCHA messenger: token grammar, non-root `MESSENGER_USER`, `recaptcha.php` mode | `csf/ConfigServer/Messenger.pm` |
| reCAPTCHA unblock queue opened with `O_NOFOLLOW` and verified | `csf/lfd.pl` |
| `GLOBAL_*` feed and advanced-rule field validation | `csf/lfd.pl`, `csf/csf.pl`, `csf/ConfigServer/CheckIP.pm` |

Added for parity with cPanel CSF 16.31, the release carrying CVE-2026-67402:

| Area | File |
|---|---|
| Messenger vhost no longer grants CGI, SSI, symlink following or `AllowOverride All`; `ScriptAlias /local-bin /usr/bin` removed | `csf/apache.http.txt`, `csf/apache.https.txt`, `csf/litespeed.http.txt`, `csf/litespeed.https.txt`, `csf/ConfigServer/Messenger.pm` |
| Messenger drops to `MESSENGER_USER` irreversibly (`setgroups`/`setgid`/`setuid`), verified against `/proc/self/status` | `csf/ConfigServer/Messenger.pm` |
| Messenger document root refused when the configured group resolves to gid 0 | `csf/ConfigServer/Messenger.pm` |
| Record separator narrowed to the byte-oriented set, so a non-ASCII comment no longer splits an entry | `csf/ConfigServer/Slurp.pm` |
| Allow/deny/temp comments refused when they carry a record separator | `csf/csf.pl` |
| Temporary IP entries and iptables log fields escaped in the UI | `csf/ConfigServer/DisplayUI.pm` |

Three items in cPanel's 16.31 release notes have no counterpart here, each for
a checked reason rather than an assumed one:

- *Apache status details in load average alerts, with the `server-status` key
  redacted.* This fork has no `server-status` handling at all: `server-status`
  and `server_status` appear nowhere in `lfd.pl`, `ServerStats.pm` or
  `ServerCheck.pm`.
- *lfd killing cPanel's internal login/theme rendering process.* That is an
  exclusion for a cPanel-only process.
- *Preserving port, direction and comment on temporary rules,* which cPanel
  pairs with `valid_temp_ports()` and `valid_temp_direction()`. In this
  lineage those two fields cannot carry a separator by construction: the
  direction is only ever assigned the literals `in`, `out` or `inout`, and the
  port is matched by `[\w\,\*\;]+`, which admits neither `|` nor a line
  break. The comment, which is free text, is guarded above.

Two deliberate divergences from cPanel's implementation:

- **Certificate validation is not disabled** on the fallback fetch path.
  Upstream passes `curl -k` there; this fork does not.
- **`/0` masks** are refused in the feed parser and in `csf.ignore`, rather
  than by changing the default behaviour of `checkip()` for every caller.
  `csf.allow` and `csf.deny` still accept a `/0`.

The first commit in this repository is the unmodified upstream 15.10 release,
so every change here is reviewable as a plain diff against it.

## Building the release artifact

The published archive is the tracked `csf/` directory, zipped with the same
layout as upstream's release asset:

```
zip -r csf-firewall-v16.31.zip csf
```

Two files are intentionally not tracked in git: `csf/ui/server.key` and
`csf/ui/ssl-expired/server.key`. Upstream ships the same self-signed TLS
private key to every installation, so it is a shared published credential
rather than a secret, and this fork does not republish private keys. They are
present in the release artifact so that an install matches upstream.

## Installing

Unchanged from upstream:

```
unzip csf-firewall-v16.31.zip
cd csf
sh install.sh
```

## Licence

GPLv3, unchanged from upstream. See `csf/LICENSE.md`. This fork is a modified
version: the changes are the commits in this repository, and the complete
corresponding source is what you are reading.

Original CSF is copyright Way to the Web Ltd. and Jonathan Michaelson; the
15.10 base is copyright Aetherinox.
