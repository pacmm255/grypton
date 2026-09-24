"""Fail-closed filesystem and identity boundary for Kraude's native shell.

OpenCode itself remains the trusted transport so its provider and local MCP
connections keep working.  Only commands selected through the native ``bash``
tool enter this launcher.  The launcher removes the provider environment,
drops to a target-specific unprivileged numeric identity, and applies a
Landlock allowlist before executing Bash.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import os
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import sys
from dataclasses import dataclass


_CREATE_RULESET_VERSION = 1
_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_RET_K = 0x06
_AF_UNIX = 1

_FS_EXECUTE = 1 << 0
_FS_WRITE_FILE = 1 << 1
_FS_READ_FILE = 1 << 2
_FS_READ_DIR = 1 << 3
_FS_REMOVE_DIR = 1 << 4
_FS_REMOVE_FILE = 1 << 5
_FS_MAKE_CHAR = 1 << 6
_FS_MAKE_DIR = 1 << 7
_FS_MAKE_REG = 1 << 8
_FS_MAKE_SOCK = 1 << 9
_FS_MAKE_FIFO = 1 << 10
_FS_MAKE_BLOCK = 1 << 11
_FS_MAKE_SYM = 1 << 12
_FS_REFER = 1 << 13
_FS_TRUNCATE = 1 << 14
_FS_IOCTL_DEV = 1 << 15

_READ_ONLY = _FS_EXECUTE | _FS_READ_FILE | _FS_READ_DIR
_READ_WRITE = (
    _READ_ONLY | _FS_WRITE_FILE | _FS_REMOVE_DIR | _FS_REMOVE_FILE
    | _FS_MAKE_DIR | _FS_MAKE_REG | _FS_MAKE_SOCK | _FS_MAKE_FIFO
    | _FS_MAKE_SYM | _FS_REFER | _FS_TRUNCATE | _FS_IOCTL_DEV
)
_DEVICE_RW = _FS_READ_FILE | _FS_WRITE_FILE | _FS_IOCTL_DEV
_FILE_RW = _FS_READ_FILE | _FS_WRITE_FILE | _FS_TRUNCATE | _FS_IOCTL_DEV
_SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_WORKSPACE_DIRECTORIES = ("research", "scripts", "loot", "workspace", "flows")
_WORKSPACE_DOCUMENTS = (
    "findings.md", "attack-surface.md", "tested-techniques.md",
    "scope-rules.md", "progress.md",
)
_SYSTEM_READ_PATHS = (
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/sys",
    "/etc/alternatives", "/etc/ca-certificates", "/etc/pki", "/etc/ssl",
    "/etc/gai.conf", "/etc/group", "/etc/host.conf", "/etc/hosts",
    "/etc/ld.so.cache", "/etc/localtime", "/etc/nsswitch.conf",
    "/etc/passwd", "/etc/protocols", "/etc/resolv.conf", "/etc/services",
)
_SYSCALLS = {
    # Landlock uses the same syscall numbers on the Linux architectures we
    # support here. Refuse unknown architectures instead of running unconfined.
    "x86_64": (444, 445, 446),
    "amd64": (444, 445, 446),
    "aarch64": (444, 445, 446),
    "arm64": (444, 445, 446),
}
_SECCOMP_ARCH = {
    # audit architecture, socket(2), io_uring_setup(2)
    "x86_64": (0xC000003E, 41, 425),
    "amd64": (0xC000003E, 41, 425),
    "aarch64": (0xC00000B7, 198, 425),
    "arm64": (0xC00000B7, 198, 425),
}


class NativeShellError(RuntimeError):
    """The native shell cannot be started with its mandatory boundary."""


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


def _syscall_numbers() -> tuple[int, int, int]:
    value = _SYSCALLS.get(platform.machine().lower())
    if value is None or sys.platform != "linux":
        raise NativeShellError("Linux Landlock is unavailable on this platform")
    return value


def _libc() -> ctypes.CDLL:
    library = ctypes.CDLL(None, use_errno=True)
    library.syscall.restype = ctypes.c_long
    return library


def landlock_abi() -> int:
    """Return the kernel Landlock ABI, or zero when it is unavailable."""
    try:
        create, _, _ = _syscall_numbers()
    except NativeShellError:
        return 0
    result = _libc().syscall(
        ctypes.c_long(create), ctypes.c_void_p(), ctypes.c_size_t(0),
        ctypes.c_uint(_CREATE_RULESET_VERSION),
    )
    return int(result) if result >= 1 else 0


def _handled_access(abi: int) -> int:
    access = (1 << 13) - 1
    if abi >= 2:
        access |= _FS_REFER
    if abi >= 3:
        access |= _FS_TRUNCATE
    if abi >= 5:
        access |= _FS_IOCTL_DEV
    return access


def sandbox_uid(target_slug: str) -> int:
    """Derive a stable, non-login identity with negligible cross-target overlap."""
    digest = hashlib.sha256(str(target_slug).encode("utf-8")).digest()
    return 1_000_000 + int.from_bytes(digest[:4], "big") % 1_000_000_000


@dataclass(frozen=True)
class NativeShellSpec:
    launcher: Path
    transport: Path
    workspace: Path
    home: Path
    temporary: Path
    native_bin: Path
    broker_socket: Path
    uid: int

    def internal_environment(self) -> dict[str, str]:
        """Return launcher-only state; the launcher removes every field."""
        return {
            "GRYPTON_NATIVE_TRANSPORT": str(self.transport),
            "GRYPTON_NATIVE_WORKSPACE": str(self.workspace),
            "GRYPTON_NATIVE_HOME": str(self.home),
            "GRYPTON_NATIVE_TMP": str(self.temporary),
            "GRYPTON_NATIVE_UID": str(self.uid),
        }


def _run_setfacl(*args: str) -> None:
    binary = shutil.which("setfacl")
    if not binary:
        raise NativeShellError("POSIX ACL support is unavailable")
    try:
        result = subprocess.run(
            [binary, *args], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise NativeShellError("native shell ACL setup failed") from exc
    if result.returncode:
        raise NativeShellError("native shell ACL setup failed")


def _grant_transport_access(path: Path, uid: int) -> None:
    """Permit discovery at the transport root without persistent writes."""
    for parent in reversed(path.parents):
        _run_setfacl("-m", f"u:{uid}:--x", str(parent))
    # Revoke permissions left by an older launcher before adding the narrow
    # grants below. A default no-access entry also keeps newly created OpenCode
    # transport artifacts private from the native shell.
    _run_setfacl("-P", "-R", "-m", f"u:{uid}:---", str(path))
    _run_setfacl("-m", f"u:{uid}:r-x,d:u:{uid}:---", str(path))
    for name in (".native-home", ".native-tmp"):
        child = path / name
        _run_setfacl("-P", "-R", "-m", f"u:{uid}:rwX", str(child))
        _run_setfacl("-m", f"d:u:{uid}:rwx", str(child))
    native_bin = path / ".native-bin"
    _run_setfacl("-P", "-R", "-m", f"u:{uid}:r-X", str(native_bin))
    broker_dir = path / ".native-broker"
    _run_setfacl("-m", f"u:{uid}:--x", str(broker_dir))


def _grant_workspace_access(path: Path, uid: int) -> None:
    """Grant the worker its public engagement data without private siblings."""
    for parent in reversed(path.parents):
        _run_setfacl("-m", f"u:{uid}:--x", str(parent))
    _run_setfacl("-m", f"u:{uid}:r-x", str(path))
    for name in _WORKSPACE_DIRECTORIES:
        child = path / name
        if child.is_symlink() or not child.is_dir():
            raise NativeShellError("native shell workspace layout is invalid")
        _run_setfacl("-P", "-R", "-m", f"u:{uid}:rwX", str(child))
        _run_setfacl("-m", f"d:u:{uid}:rwx", str(child))
    for name in _WORKSPACE_DOCUMENTS:
        child = path / name
        if child.is_symlink() or not child.is_file():
            raise NativeShellError("native shell workspace layout is invalid")
        _run_setfacl("-m", f"u:{uid}:rw-", str(child))


def prepare_native_shell(
    *, target_slug: str, transport: Path, workspace: Path,
    runtime: Path, source_root: Path,
) -> NativeShellSpec:
    """Create the trusted launcher and grant access only to transport state."""
    if os.geteuid() != 0:
        raise NativeShellError("native shell isolation requires a privileged launcher")
    if landlock_abi() < 1:
        raise NativeShellError("Linux Landlock is unavailable")

    transport = transport.resolve()
    workspace = workspace.resolve()
    runtime = runtime.resolve()
    source_root = source_root.resolve()
    if (not transport.is_dir() or not workspace.is_dir()
            or not runtime.is_dir() or not source_root.is_dir()):
        raise NativeShellError("native shell isolation paths are unavailable")

    uid = sandbox_uid(target_slug)
    home = transport / ".native-home"
    temporary = transport / ".native-tmp"
    native_bin = transport / ".native-bin"
    broker_dir = transport / ".native-broker"
    for directory in (home, temporary, native_bin, broker_dir):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)

    broker_socket = broker_dir / "http.sock"
    from .network_broker import curl_wrapper_source
    curl_wrapper = native_bin / "curl"
    wrapper_tmp = native_bin / ".curl.tmp"
    wrapper_fd = os.open(
        wrapper_tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o500
    )
    with os.fdopen(wrapper_fd, "w", encoding="utf-8") as stream:
        stream.write(curl_wrapper_source(broker_socket))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(wrapper_tmp, curl_wrapper)
    os.chmod(curl_wrapper, 0o500)

    launcher = runtime / "native-shell"
    content = (
        "#!/usr/bin/python3\n"
        "import sys\n"
        f"sys.path.insert(0, {str(source_root)!r})\n"
        "from grypton.native_shell import main\n"
        "raise SystemExit(main())\n"
    )
    temporary_launcher = runtime / ".native-shell.tmp"
    fd = os.open(
        temporary_launcher,
        os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW,
        0o500,
    )
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary_launcher, launcher)
    os.chmod(launcher, 0o500)
    _grant_transport_access(transport, uid)
    _grant_workspace_access(workspace, uid)
    return NativeShellSpec(
        launcher=launcher, transport=transport, workspace=workspace, home=home,
        temporary=temporary, native_bin=native_bin,
        broker_socket=broker_socket, uid=uid,
    )


def _required_path(name: str) -> Path:
    value = os.environ.get(name, "")
    if not value or "\x00" in value:
        raise NativeShellError("native shell launch context is incomplete")
    try:
        path = Path(value).resolve(strict=True)
    except OSError as exc:
        raise NativeShellError("native shell launch context is unavailable") from exc
    return path


def _required_uid() -> int:
    try:
        uid = int(os.environ.get("GRYPTON_NATIVE_UID", ""))
    except ValueError as exc:
        raise NativeShellError("native shell identity is invalid") from exc
    if uid < 100_000 or uid >= 2**32 - 1:
        raise NativeShellError("native shell identity is invalid")
    return uid


def _add_rule(ruleset_fd: int, path: Path, access: int, handled: int) -> None:
    try:
        flags = os.O_PATH | os.O_CLOEXEC
        parent_fd = os.open(path, flags)
    except OSError as exc:
        raise NativeShellError("a native shell allowlist path is unavailable") from exc
    try:
        attr = _PathBeneathAttr(
            allowed_access=access & handled,
            parent_fd=parent_fd,
        )
        _, add, _ = _syscall_numbers()
        result = _libc().syscall(
            ctypes.c_long(add), ctypes.c_int(ruleset_fd),
            ctypes.c_int(_RULE_PATH_BENEATH), ctypes.byref(attr),
            ctypes.c_uint(0),
        )
        if result < 0:
            raise NativeShellError("native shell allowlist setup failed")
    finally:
        os.close(parent_fd)


def _workspace_allowlist(workspace: Path) -> tuple[tuple[Path, int], ...]:
    paths: list[tuple[Path, int]] = []
    for name in _WORKSPACE_DIRECTORIES:
        candidate = workspace / name
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise NativeShellError("native shell workspace layout is unavailable") from exc
        if candidate.is_symlink() or resolved.parent != workspace:
            raise NativeShellError("native shell workspace layout is invalid")
        paths.append((resolved, _READ_WRITE))
    for name in _WORKSPACE_DOCUMENTS:
        candidate = workspace / name
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise NativeShellError("native shell workspace layout is unavailable") from exc
        if candidate.is_symlink() or resolved.parent != workspace:
            raise NativeShellError("native shell workspace layout is invalid")
        paths.append((resolved, _FILE_RW))
    return tuple(paths)


def _ruleset(transport: Path, workspace: Path, home: Path,
             temporary: Path, native_bin: Path, broker_dir: Path) -> int:
    abi = landlock_abi()
    if abi < 1:
        raise NativeShellError("Linux Landlock is unavailable")
    handled = _handled_access(abi)
    attr = _RulesetAttr(handled_access_fs=handled)
    create, _, _ = _syscall_numbers()
    fd = _libc().syscall(
        ctypes.c_long(create), ctypes.byref(attr), ctypes.sizeof(attr),
        ctypes.c_uint(0),
    )
    if fd < 0:
        raise NativeShellError("native shell ruleset creation failed")
    ruleset_fd = int(fd)
    try:
        for raw in _SYSTEM_READ_PATHS:
            path = Path(raw)
            if path.exists():
                access = _READ_ONLY if path.is_dir() else _FS_READ_FILE
                _add_rule(ruleset_fd, path, access, handled)
        for raw in ("/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/tty"):
            path = Path(raw)
            if path.exists():
                _add_rule(ruleset_fd, path, _DEVICE_RW, handled)
        # The transport root is listable but immutable. Only disposable shell
        # state is writable; the generated curl shim stays read/execute-only.
        _add_rule(ruleset_fd, transport, _FS_READ_DIR, handled)
        for path in dict.fromkeys((home, temporary)):
            _add_rule(ruleset_fd, path, _READ_WRITE, handled)
        _add_rule(ruleset_fd, native_bin, _READ_ONLY, handled)
        _add_rule(ruleset_fd, broker_dir, _FS_READ_DIR, handled)
        _add_rule(ruleset_fd, workspace, _FS_READ_DIR, handled)
        for path, access in _workspace_allowlist(workspace):
            _add_rule(ruleset_fd, path, access, handled)
        return ruleset_fd
    except BaseException:
        os.close(ruleset_fd)
        raise


def _sanitized_environment(home: Path, temporary: Path,
                           native_bin: Path) -> dict[str, str]:
    """Build an environment without provider, OpenCode, or operator state."""
    return {
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "PATH": str(native_bin) + os.pathsep + _SAFE_PATH,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "TERM": "dumb",
        "NO_COLOR": "1",
        "USER": "grypton-worker",
        "LOGNAME": "grypton-worker",
        "SHELL": "/bin/bash",
    }


def _drop_identity(uid: int) -> None:
    try:
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    except OSError as exc:
        raise NativeShellError("native shell identity isolation failed") from exc


def _close_inherited_descriptors(keep_fd: int) -> None:
    """Remove connected provider/network descriptors before sandbox entry."""
    try:
        maximum = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        if maximum == resource.RLIM_INFINITY:
            maximum = 1_048_576
        maximum = min(int(maximum), 1_048_576)
        if keep_fd > 3:
            os.closerange(3, keep_fd)
        os.closerange(max(3, keep_fd + 1), maximum)
    except (OSError, ValueError) as exc:
        raise NativeShellError("native shell descriptor isolation failed") from exc


def _restrict_self(ruleset_fd: int) -> None:
    library = _libc()
    if library.prctl(
        ctypes.c_int(_PR_SET_NO_NEW_PRIVS), ctypes.c_ulong(1),
        ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0),
    ) != 0:
        raise NativeShellError("native shell privilege lock failed")
    _, _, restrict = _syscall_numbers()
    if library.syscall(
        ctypes.c_long(restrict), ctypes.c_int(ruleset_fd), ctypes.c_uint(0)
    ) < 0:
        error = ctypes.get_errno()
        if error in {errno.ENOSYS, errno.EOPNOTSUPP}:
            raise NativeShellError("Linux Landlock is unavailable")
        raise NativeShellError("native shell restriction failed")


def _deny_direct_network() -> None:
    """Deny every socket family except Unix plus the io_uring bypass."""
    machine = platform.machine().lower()
    values = _SECCOMP_ARCH.get(machine)
    if values is None:
        raise NativeShellError("native shell network isolation is unavailable")
    audit_arch, socket_syscall, io_uring_setup_syscall = values

    def statement(code: int, value: int) -> _SockFilter:
        return _SockFilter(code=code, jt=0, jf=0, k=value)

    def jump(code: int, value: int, yes: int, no: int) -> _SockFilter:
        return _SockFilter(code=code, jt=yes, jf=no, k=value)

    instructions = (_SockFilter * 11)(
        statement(_BPF_LD_W_ABS, 4),
        jump(_BPF_JMP_JEQ_K, audit_arch, 1, 0),
        statement(_BPF_RET_K, _SECCOMP_RET_KILL_PROCESS),
        statement(_BPF_LD_W_ABS, 0),
        jump(_BPF_JMP_JEQ_K, io_uring_setup_syscall, 5, 0),
        jump(_BPF_JMP_JEQ_K, socket_syscall, 0, 3),
        statement(_BPF_LD_W_ABS, 16),
        jump(_BPF_JMP_JEQ_K, _AF_UNIX, 1, 0),
        statement(_BPF_RET_K, _SECCOMP_RET_ERRNO | errno.EPERM),
        statement(_BPF_RET_K, _SECCOMP_RET_ALLOW),
        statement(_BPF_RET_K, _SECCOMP_RET_ERRNO | errno.EPERM),
    )
    program = _SockFprog(length=len(instructions), filter=instructions)
    library = _libc()
    if library.prctl(
        ctypes.c_int(_PR_SET_SECCOMP), ctypes.c_ulong(_SECCOMP_MODE_FILTER),
        ctypes.byref(program), ctypes.c_ulong(0), ctypes.c_ulong(0),
    ) != 0:
        raise NativeShellError("native shell network isolation failed")


def main(argv: list[str] | None = None) -> int:
    """OpenCode-compatible shell entry point (``launcher -c command``)."""
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(args) != 2 or args[0] != "-c":
            raise NativeShellError("native shell accepts only one command string")
        transport = _required_path("GRYPTON_NATIVE_TRANSPORT")
        workspace = _required_path("GRYPTON_NATIVE_WORKSPACE")
        home = _required_path("GRYPTON_NATIVE_HOME")
        temporary = _required_path("GRYPTON_NATIVE_TMP")
        uid = _required_uid()
        if home.parent != transport or temporary.parent != transport:
            raise NativeShellError("native shell launch context is invalid")

        native_bin = transport / ".native-bin"
        if not native_bin.is_dir():
            raise NativeShellError("native shell tool directory is unavailable")
        broker_dir = transport / ".native-broker"
        if not broker_dir.is_dir():
            raise NativeShellError("native shell broker directory is unavailable")
        ruleset_fd = _ruleset(
            transport, workspace, home, temporary, native_bin, broker_dir
        )
        environment = _sanitized_environment(home, temporary, native_bin)
        _close_inherited_descriptors(ruleset_fd)
        _drop_identity(uid)
        _restrict_self(ruleset_fd)
        _deny_direct_network()
        os.close(ruleset_fd)
        os.execve(
            "/bin/bash",
            ["bash", "--noprofile", "--norc", "-c", args[1]],
            environment,
        )
    except NativeShellError as exc:
        print(f"Grypton native shell unavailable: {exc}", file=sys.stderr)
        return 126
    except OSError:
        print("Grypton native shell unavailable: command launch failed", file=sys.stderr)
        return 126
    return 126


if __name__ == "__main__":
    raise SystemExit(main())
