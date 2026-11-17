"""Read CPU time and RSS of our own lab subprocesses without extra packages."""
import os
from pathlib import Path
import sys

def sample(pid):
    if sys.platform == "linux":
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        ticks = int(fields[11]) + int(fields[12])
        rss = int(Path(f"/proc/{pid}/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE")
        return {"cpu_seconds": ticks / os.sysconf("SC_CLK_TCK"), "rss_bytes": rss}
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        class Memory(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [(name, ctypes.c_size_t) for name in
                ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Memory), wintypes.DWORD]
        handle = kernel.OpenProcess(0x1010, False, pid)
        if not handle:
            raise OSError(ctypes.get_last_error(), "OpenProcess failed")
        try:
            created, exited, system, user = (wintypes.FILETIME() for _ in range(4))
            mem = Memory(); mem.cb = ctypes.sizeof(mem)
            if not kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(system), ctypes.byref(user)):
                raise OSError(ctypes.get_last_error(), "GetProcessTimes failed")
            if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(mem), mem.cb):
                raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo failed")
            seconds = sum((value.dwHighDateTime << 32) + value.dwLowDateTime for value in (system, user)) / 1e7
            return {"cpu_seconds": seconds, "rss_bytes": mem.WorkingSetSize}
        finally:
            kernel.CloseHandle(handle)
    raise NotImplementedError("resource sampling supports Windows and Linux")
