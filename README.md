## Summary

A set of container images of AmneziaWG-Go. [Source Code](https://github.com/vnxme/docker-amneziawg-go).

### Registries

The container images are published in the following registries:
- [Docker Hub](https://hub.docker.com/r/vnxme/amneziawg-go)
- [GitHub Container Registry](https://github.com/vnxme/docker-amneziawg-go/pkgs/container/amneziawg-go)

## Description

**AmneziaWG-Go** is an implementation of [Amnezia WireGuard](https://docs.amnezia.org/documentation/amnezia-wg/) in Go. It inherits the architectural simplicity and high performance of the original WireGuard implementation, but eliminates the identifiable network signatures that make WireGuard easily detectable by Deep Packet Inspection (DPI) systems.

## Software

The container images include the following **key software packages**:
- [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) provides `amneziawg-go`
- [amneziawg-tools](https://github.com/amnezia-vpn/amneziawg-tools) provides `awg` and `awg-quick`

The following **extra software packages** are included as well:
- [bash](https://pkgs.alpinelinux.org/package/v3.23/main/x86_64/bash)
- [curl](https://pkgs.alpinelinux.org/package/v3.23/main/x86_64/curl)
- [iproute2](https://pkgs.alpinelinux.org/package/v3.23/main/x86_64/iproute2)
- [iptables](https://pkgs.alpinelinux.org/package/v3.23/main/x86_64/iptables) and [iptables-legacy](https://pkgs.alpinelinux.org/package/v3.23/main/x86_64/iptables-legacy)
- [iputils-ping](https://pkgs.alpinelinux.org/package/v3.23/main/x86_64/iputils-ping)
- [jq](https://pkgs.alpinelinux.org/package/v3.23/main/x86_64/jq)
- [libcap](https://pkgs.alpinelinux.org/package/v3.23/main/x86_64/libcap)
- [mandoc](https://pkgs.alpinelinux.org/package/v3.23/main/x86_64/mandoc)
- [net-tools](https://pkgs.alpinelinux.org/package/v3.23/main/x86_64/net-tools)
- [openssl](https://pkgs.alpinelinux.org/package/v3.23/main/x86_64/openssl)
- [tcpdump](https://pkgs.alpinelinux.org/package/v3.23/main/x86_64/tcpdump)

## Platforms

The container images are based on [Alpine](https://hub.docker.com/_/alpine). The repository uses [Golang](https://hub.docker.com/_/golang) for multi-stage build and the [XX helpers](https://hub.docker.com/r/tonistiigi/xx) for AMD64-based cross-compilation. Below is a summary of the platforms supported by this repository and its dependencies.

| OS/Arch        | Alpine | Golang | XX Helpers  | AmneziaWG-Go |
|----------------|--------|--------|-------------|--------------|
| linux/386      | Yes    | Yes    | Yes         | Yes          |
| linux/amd64    | Yes    | Yes    | Yes         | Yes          |
| linux/arm/v5   | No     | No     | Yes         | No           |
| linux/arm/v6   | Yes    | Yes    | Yes         | Yes          |
| linux/arm/v7   | Yes    | Yes    | Yes         | Yes          |
| linux/arm64    | Yes    | Yes    | Yes         | Yes          |
| linux/loong64  | No     | No     | Yes         | No           |
| linux/mips     | No     | No     | Yes         | No           |
| linux/mips64   | No     | No     | Yes         | No           |
| linux/mips64le | No     | No     | Yes         | No           |
| linux/mipsle   | No     | No     | Yes         | No           |
| linux/ppc64le  | Yes    | Yes    | Yes         | Yes          |
| linux/riscv64  | Yes    | Yes    | Yes         | Yes          |
| linux/s390x    | Yes    | Yes    | Yes         | Yes          |

## Hooks

### Entrypoint Hooks

The entrypoint script (`/app/entrypoint.sh`) supports four predefined lifecycle hooks:

- **pre-up**: Executed before tunnels are enabled  
- **post-up**: Executed after tunnels are enabled  
- **pre-down**: Executed before tunnels are disabled  
- **post-down**: Executed after tunnels are disabled  

### Hook Script Locations

Hook scripts must be shell scripts (`*.sh`) and are executed from the following directories by default:

- `/app/hooks/pre-up`
- `/app/hooks/post-up`
- `/app/hooks/pre-down`
- `/app/hooks/post-down`

These directories are created automatically if they do not exist.

### Customizing Hook Paths

The base working directory (`/app`) can be overridden using the `-w` or `--workdir` option of the `docker run` command.

The intermediate hooks directory can be customized by setting the `HOOK_DIR` environment variable via the `-e` or `--env` option of the `docker run` command. If `HOOK_DIR` is not set, it defaults to `./hooks`.

## Logs

### Entrypoing Logging

The entrypoint supports the following log levels:

- `fatal`
- `error`
- `warn`
- `info`
- `debug`
- `trace`

The default log level is `info`. The log level can be configured by setting the `LOG_LEVEL` environment variable.

When `LOG_LEVEL` is set to `fatal`, no log messages are expected to be produced, and the container will be almost completely silent.

When `LOG_LEVEL` is set to `trace`, the entrypoint outputs additional diagnostic information, including the standard output and exit codes of various subcommands, in addition to its own log messages.

All entrypoint log messages are written to standard output (`stdout`).

### Executable Output Redirection

The `awg`, `awg-quick`, and `amneziawg-go` executables are typically verbose. Any output produced by these executables is redirected to per-interface log files located at: `${LOG_DIR}/${INTERFACE}.log`. If the `LOG_DIR` environment variable is not set or is empty, logs are written to the default directory: `/var/log/amneziawg`.
