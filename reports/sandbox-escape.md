# Sandbox escape attempt

Image `python:3.12-slim` · container config: `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --user <invoking uid> --pids-limit 128 --memory 512m --cpus 1`.

**Result: 0 of 10 breakout primitives succeeded.**

| probe | primitive | outcome | detail |
|---|---|---|---|
| `write_rootfs` | write to the read-only root filesystem | blocked | `OSError: [Errno 30] Read-only file system: '/quarantine_escape_test'` |
| `read_shadow` | read /etc/shadow as an unprivileged user | blocked | `PermissionError: [Errno 13] Permission denied: '/etc/shadow'` |
| `read_host_path` | read a host file that was not mounted | blocked | `FileNotFoundError: [Errno 2] No such file or directory: '/home/logic/win/NEW-IDEA-DECISION.md'` |
| `mount_tmpfs` | mount(2) a filesystem | blocked | `PermissionError: [Errno 1] Operation not permitted` |
| `unshare_userns` | unshare(CLONE_NEWUSER) | blocked | `PermissionError: [Errno 1] Operation not permitted` |
| `chroot` | chroot(2) | blocked | `PermissionError: [Errno 1] Operation not permitted: '/'` |
| `setuid_root` | become uid 0 | blocked | `PermissionError: [Errno 1] Operation not permitted` |
| `raw_socket` | open a raw socket (CAP_NET_RAW) | blocked | `PermissionError: [Errno 1] Operation not permitted` |
| `reach_host` | connect to the host's model server over the loopback | blocked | `ConnectionRefusedError: [Errno 111] Connection refused` |
| `resolve_dns` | resolve a public name | blocked | `gaierror: [Errno -3] Temporary failure in name resolution` |

## Reading this table

- `blocked` rows are the containment working. The `detail` column names the mechanism (an errno, a missing file, a namespace boundary) — not a promise.
- **Any `ESCAPED` row is a real finding** and must be reported as one before this tool is claimed to be safe for untrusted artifacts.
- These are ten well-known primitives, not a fuzzing campaign. A clean table means *these ten* failed; it does not mean the box cannot be broken.

Identity inside the box: `{"uid": 1000, "euid": 1000, "pid": 1}`
