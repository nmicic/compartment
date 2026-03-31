<!-- Copyright (c) 2026 Nenad Mićić <nenad@micic.be> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# tinyproxy — local proxy → corporate upstream

Listens on `127.0.0.1:8080`, forwards everything through `proxy.corporation.com:8080`.
Works fully in **userspace** — no root, no systemd, no Docker required.

---

## Quick start (userspace, compile from source)

```bash
# 1. Build (one time only)
./build.sh

# 2. Edit upstream in tinyproxy.conf if needed
#    Upstream  http  proxy.corporation.com:8080

# 3. Start
./start.sh

# 4. Test
curl -x http://127.0.0.1:8080 https://example.com -I

# 5. Survive reboots (adds @reboot to your crontab)
./enable.sh
```

## Scripts

| Script | What it does |
|---|---|
| `build.sh` | git clone + compile + install to `~/.local/bin` |
| `start.sh` | start tinyproxy, write PID to `run/` |
| `stop.sh` | graceful stop via PID file |
| `reload.sh` | SIGHUP — reload config without dropping connections |
| `status.sh` | show process state + last 10 log lines |
| `enable.sh` | `@reboot` crontab entry — auto-start on boot |
| `disable.sh` | remove crontab entry + stop |
| `docker-start.sh` | optional Docker variant |

## Layout after start

```
tinyproxy/
├── build.sh / start.sh / stop.sh / ...
├── tinyproxy.conf        ← edit this (upstream, auth, bypasses)
├── run/
│   ├── tinyproxy.conf    ← rendered at start time (don't edit)
│   └── tinyproxy.pid
└── logs/
    └── tinyproxy.log
```

## Upstream auth

```ini
Upstream  http  user:password@proxy.corporation.com:8080
```

## Bypass internal hosts (no upstream)

```ini
Upstream  none  .internal.corp
Upstream  none  10.0.0.0/8
```

## Build deps (ask sysadmin if missing)

```
git  gcc  make  autoconf  automake  gperf
```

These are standard dev tools available in every corporate Linux mirror.

## Set proxy in your shell / tools

```bash
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
export no_proxy=localhost,127.0.0.1,.internal.corp
```
