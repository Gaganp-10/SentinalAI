import os
import signal
import subprocess
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


def run_scanner_subprocess(
    cmd: List[str],
    timeout_seconds: Optional[int] = None,
    cwd: Optional[str] = None,
    env: Optional[dict] = None
) -> subprocess.CompletedProcess:
    """
    Executes a scanner subprocess in its own process group (POSIX).
    If execution exceeds `timeout_seconds`, sends SIGKILL to the entire process group
    so that all child workers (e.g. Bandit/Semgrep multiprocessing pools) are killed cleanly.
    """
    if timeout_seconds is None:
        try:
            timeout_seconds = int(os.environ.get("SCANNER_TIMEOUT_SECONDS", "300"))
        except ValueError:
            timeout_seconds = 300
    is_posix = os.name == "posix"
    kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "cwd": cwd,
        "env": env if env is not None else os.environ.copy(),
    }
    if is_posix:
        kwargs["start_new_session"] = True

    proc = subprocess.Popen(cmd, **kwargs)
    try:
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr
        )
    except subprocess.TimeoutExpired:
        logger.warning("Scanner subprocess '%s' (PID %s) timed out after %ss. Killing process group.", cmd[0], proc.pid, timeout_seconds)
        if is_posix:
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError) as e:
                logger.debug("Process group kill warning: %s", e)
                proc.kill()
        else:
            proc.kill()

        try:
            proc.communicate(timeout=2)
        except Exception:
            pass

        raise TimeoutError(f"Process {cmd[0]} timed out after {timeout_seconds}s and was terminated.")

