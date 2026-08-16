# csf-firewall

A fork of **ConfigServer Security & Firewall (CSF)** carrying the security
fixes that cPanel shipped in CSF 16.30, applied on top of the last published
release of [`Aetherinox/csf-firewall`](https://github.com/Aetherinox/csf-firewall)
(15.10, 28 February 2026).

## Why this fork exists

Upstream's most recent release is 15.10 and predates the security work cPanel
did in July and August 2026. Those fixes were published as part of the
`cpanel-csf` package; the public `cpanel/cpanel-csf` repository has not moved
since 25 February 2026 and does not contain them. This fork exists so that
hosts which do not run cPanel can still get that hardening.

## Version numbering

`csf/version.txt` reports **16.30**.

Read that as *security-fix parity with cPanel CSF 16.30*, not as "this is
cPanel's 16.30". The code here is upstream's 15.10 line with the relevant
fixes backported; cPanel's 16.30 is a separate codebase with many other
changes. The number is aligned so that version comparisons in existing
deployment tooling do the right thing.

Because of that, `csf -v` alone does not prove the fixes are present. If you
need to verify a deployed copy, grep for a backported symbol, for example:

```
grep -c _open_unblock_queue /etc/csf/lfd.pl
```

## What was changed

Four areas were hardened, each in its own commit:

| Area | File |
|---|---|
| Fallback URL fetch built as an argv list, URL passed on stdin | `csf/ConfigServer/URLGet.pm` |
| reCAPTCHA messenger: token grammar, non-root `MESSENGER_USER`, `recaptcha.php` mode | `csf/ConfigServer/Messenger.pm` |
| reCAPTCHA unblock queue opened with `O_NOFOLLOW` and verified | `csf/lfd.pl` |
| `GLOBAL_*` feed and advanced-rule field validation | `csf/lfd.pl`, `csf/csf.pl`, `csf/ConfigServer/CheckIP.pm` |

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
zip -r csf-firewall-v16.30.zip csf
```

Two files are intentionally not tracked in git: `csf/ui/server.key` and
`csf/ui/ssl-expired/server.key`. Upstream ships the same self-signed TLS
private key to every installation, so it is a shared published credential
rather than a secret, and this fork does not republish private keys. They are
present in the release artifact so that an install matches upstream.

## Installing

Unchanged from upstream:

```
unzip csf-firewall-v16.30.zip
cd csf
sh install.sh
```

## Licence

GPLv3, unchanged from upstream. See `csf/LICENSE.md`. This fork is a modified
version: the changes are the commits in this repository, and the complete
corresponding source is what you are reading.

Original CSF is copyright Way to the Web Ltd. and Jonathan Michaelson; the
15.10 base is copyright Aetherinox.
