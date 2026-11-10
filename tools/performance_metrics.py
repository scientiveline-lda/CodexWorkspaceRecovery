"""Sample Windows process-tree working sets and validation-volume storage, without dependencies."""

import ctypes
import os
import shutil
import threading
from ctypes import wintypes
from pathlib import Path


class ProcessEntry(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("pid", wintypes.DWORD),
        ("heap", ctypes.c_size_t),
        ("module", wintypes.DWORD),
        ("threads", wintypes.DWORD),
        ("parent", wintypes.DWORD),
        ("priority", wintypes.LONG),
        ("flags", wintypes.DWORD),
        ("exe", wintypes.WCHAR * 260),
    ]


class MemoryCounters(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
        (name, ctypes.c_size_t)
        for name in [
            "peak_working_set",
            "working_set",
            "peak_paged",
            "paged",
            "peak_nonpaged",
            "nonpaged",
            "pagefile",
            "peak_pagefile",
        ]
    ]


def working_set_tree():
    if os.name != "nt":
        raise RuntimeError("Windows performance sampling required")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.K32GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(MemoryCounters),
        wintypes.DWORD,
    ]
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise OSError("Process snapshot failed")
    parents = {}
    try:
        entry = ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        ok = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            parents[entry.pid] = entry.parent
            ok = kernel.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)
    ids = {os.getpid()}
    while True:
        expanded = ids | {pid for pid, parent in parents.items() if parent in ids}
        if expanded == ids:
            break
        ids = expanded
    total, unavailable = 0, []
    for pid in ids:
        handle = kernel.OpenProcess(0x410, False, pid)
        if not handle:
            unavailable.append(pid)
            continue
        try:
            counters = MemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            if kernel.K32GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                total += counters.working_set
            else:
                unavailable.append(pid)
        finally:
            kernel.CloseHandle(handle)
    return total, unavailable


class Sampler:
    def __init__(self, root, interval=0.5):
        self.root = Path(root)
        self.interval = interval
        self.stop = threading.Event()
        self.values = {
            "sampled_peak_process_tree_working_set_bytes": 0,
            "peak_retained_file_bytes": 0,
            "minimum_volume_free_bytes": shutil.disk_usage(self.root).free,
            "samples": 0,
            "unavailable_process_samples": 0,
            "errors": [],
            "interval_seconds": interval,
            "scope": "sampled process-tree working set; volume free may include unrelated writers; brief peaks can be missed",
        }

    def sample(self):
        try:
            memory, missing = working_set_tree()
            size = sum(p.stat().st_size for p in self.root.rglob("*") if p.is_file())
            self.values["sampled_peak_process_tree_working_set_bytes"] = max(
                memory, self.values["sampled_peak_process_tree_working_set_bytes"]
            )
            self.values["peak_retained_file_bytes"] = max(
                size, self.values["peak_retained_file_bytes"]
            )
            self.values["minimum_volume_free_bytes"] = min(
                shutil.disk_usage(self.root).free, self.values["minimum_volume_free_bytes"]
            )
            self.values["samples"] += 1
            self.values["unavailable_process_samples"] += bool(missing)
        except OSError, RuntimeError:
            self.values["errors"].append("sample_unavailable")

    def __enter__(self):
        self.sample()

        def monitor():
            while not self.stop.wait(self.interval):
                self.sample()

        self.thread = threading.Thread(target=monitor, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(timeout=5)
        self.sample()
