import subprocess
import sys
from pathlib import Path
import pytest


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows ACL and Authenticode APIs')
def test_windows_installer_security_guards():
    result = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                             '-File', str(Path(__file__).with_name('windows_security.ps1'))],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
