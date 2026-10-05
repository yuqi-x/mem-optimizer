# -*- coding: utf-8 -*-
"""
MemOptimizer —— Windows 内存优化小工具

内核级实现：先启用 SeProfileSingleProcessPrivilege / SeIncreaseQuotaPrivilege，
再用 ntdll!NtSetSystemInformation 直接向内核下发指令，由内核统一处理，不逐进程折腾：
      SystemMemoryListInformation(80) + 2  →  清空所有进程工作集
      SystemMemoryListInformation(80) + 3  →  刷回已修改页
      SystemMemoryListInformation(80) + 4  →  清空备用内存列表（真正"掉数字"的那步）
另有几项扩展操作（低优先级备用列表 / 系统文件缓存 / 注册表缓存 / 合并物理内存）
做成了可选开关，默认只开上面三步。

纯标准库 + ctypes，无第三方依赖。
"""

import ctypes
import os
import queue
import sys
import threading
import time
from ctypes import wintypes

APP_TITLE = "内存优化 · MemOptimizer"
VERSION = "1.0"

# ----------------------------------------------------------------------------
# Win32 / NT 定义
# ----------------------------------------------------------------------------
ntdll = ctypes.WinDLL("ntdll")
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32")

SYS_MEMORY_LIST_INFORMATION = 80            # SystemMemoryListInformation
SYS_FILE_CACHE_INFORMATION_EX = 81          # SystemFileCacheInformationEx
SYS_COMBINE_PHYSICAL_MEMORY = 130           # SystemCombinePhysicalMemoryInformation
SYS_REGISTRY_RECONCILIATION = 155           # SystemRegistryReconciliationInformation

PRIV_INCREASE_QUOTA = 5                     # SeIncreaseQuotaPrivilege
PRIV_PROFILE_SINGLE_PROCESS = 13            # SeProfileSingleProcessPrivilege

MEM_EMPTY_WORKING_SETS = 2                  # MemoryEmptyWorkingSets
MEM_FLUSH_MODIFIED_LIST = 3                 # MemoryFlushModifiedList
MEM_PURGE_STANDBY_LIST = 4                  # MemoryPurgeStandbyList
MEM_PURGE_LOW_PRIORITY_STANDBY_LIST = 5     # MemoryPurgeLowPriorityStandbyList


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class SYSTEM_FILECACHE_INFORMATION(ctypes.Structure):
    # 9 个 ULONG_PTR 字段
    _fields_ = [(n, ctypes.c_size_t) for n in (
        "CurrentSize", "PeakSize", "PageFaultCount",
        "MinimumWorkingSet", "MaximumWorkingSet",
        "CurrentSizeIncludingTransitionInPages",
        "PeakSizeIncludingTransitionInPages",
        "TransitionRePurposeCount", "Flags")]


class MEMORY_COMBINE_INFORMATION_EX(ctypes.Structure):
    _fields_ = [("Handle", ctypes.c_void_p),
                ("PagesCombined", ctypes.c_size_t),
                ("Flags", ctypes.c_ulong)]


ntdll.NtSetSystemInformation.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong]
ntdll.NtSetSystemInformation.restype = ctypes.c_uint32
ntdll.RtlAdjustPrivilege.argtypes = [ctypes.c_ulong, ctypes.c_ubyte, ctypes.c_ubyte,
                                     ctypes.POINTER(wintypes.BOOL)]
ntdll.RtlAdjustPrivilege.restype = ctypes.c_uint32
kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL


# ----------------------------------------------------------------------------
# 基础工具
# ----------------------------------------------------------------------------
def is_admin():
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate_and_exit():
    """用 UAC 重新以管理员身份拉起自己。返回 True 表示已发起提权。"""
    exe = sys.executable
    script = os.path.abspath(__file__)
    # python.exe -> pythonw.exe，避免弹黑框
    d, b = os.path.split(exe)
    cand = os.path.join(d, "pythonw.exe")
    if os.path.isfile(cand):
        exe = cand
    try:
        r = shell32.ShellExecuteW(None, "runas", exe, '"%s"' % script, None, 1)
        return int(r) > 32
    except Exception:
        return False


def get_mem():
    m = MEMORYSTATUSEX()
    m.dwLength = ctypes.sizeof(m)
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
        raise ctypes.WinError(ctypes.get_last_error())
    return m


def fmt(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024.0:
            return "%.2f %s" % (n, u)
        n /= 1024.0
    return "%.2f PB" % n


def enable_privilege(idx):
    """启用令牌中的某项特权，返回 NTSTATUS（0 = 成功）。"""
    enabled = wintypes.BOOL()
    return int(ntdll.RtlAdjustPrivilege(ctypes.c_ulong(idx), ctypes.c_ubyte(1),
                                        ctypes.c_ubyte(0), ctypes.byref(enabled)))


# ----------------------------------------------------------------------------
# 内核操作
# ----------------------------------------------------------------------------
def op_memory_list(value):
    v = ctypes.c_int(value)
    return int(ntdll.NtSetSystemInformation(SYS_MEMORY_LIST_INFORMATION,
                                            ctypes.byref(v), 4))


def op_file_cache():
    s = SYSTEM_FILECACHE_INFORMATION()
    s.MinimumWorkingSet = 0xFFFFFFFF
    s.MaximumWorkingSet = 0xFFFFFFFF
    return int(ntdll.NtSetSystemInformation(SYS_FILE_CACHE_INFORMATION_EX,
                                            ctypes.byref(s), ctypes.sizeof(s)))


def op_registry_reconciliation():
    return int(ntdll.NtSetSystemInformation(SYS_REGISTRY_RECONCILIATION, None, 0))


def op_combine_physical_memory():
    s = MEMORY_COMBINE_INFORMATION_EX()
    return int(ntdll.NtSetSystemInformation(SYS_COMBINE_PHYSICAL_MEMORY,
                                            ctypes.byref(s), ctypes.sizeof(s)))


# (显示名, 执行函数, 默认开启?)
STEPS = [
    ("清空进程工作集 (EmptyWorkingSets)", lambda: op_memory_list(MEM_EMPTY_WORKING_SETS), True),
    ("刷回已修改页 (FlushModifiedList)", lambda: op_memory_list(MEM_FLUSH_MODIFIED_LIST), True),
    ("清空备用内存列表 (PurgeStandbyList)", lambda: op_memory_list(MEM_PURGE_STANDBY_LIST), True),
    ("清空低优先级备用列表", lambda: op_memory_list(MEM_PURGE_LOW_PRIORITY_STANDBY_LIST), False),
    ("清空系统文件缓存", op_file_cache, False),
    ("清空注册表缓存", op_registry_reconciliation, False),
    ("合并物理内存", op_combine_physical_memory, False),
]


def optimize(selected, log):
    """执行内存优化。selected = 要执行的步骤显示名集合；log = 回调(str)。"""
    if not is_admin():
        raise RuntimeError("内存优化需要管理员权限")

    log("启用特权 SeProfileSingleProcessPrivilege / SeIncreaseQuotaPrivilege ...")
    for idx, nm in ((PRIV_PROFILE_SINGLE_PROCESS, "SeProfileSingleProcessPrivilege"),
                    (PRIV_INCREASE_QUOTA, "SeIncreaseQuotaPrivilege")):
        st = enable_privilege(idx)
        log("    %-32s %s" % (nm, "OK" if st == 0 else "失败 NTSTATUS=0x%08X" % st))

    m0 = get_mem()
    before = int(m0.ullAvailPhys)
    log("开始 —— 可用物理内存 %s / 共 %s，占用率 %d%%"
        % (fmt(before), fmt(m0.ullTotalPhys), m0.dwMemoryLoad))
    if m0.dwMemoryLoad < 60:
        log("    （当前内存并不紧张，优化后数字可能变化不大，属正常）")

    t0 = time.perf_counter()
    done = 0
    for name, fn, _default in STEPS:
        if name not in selected:
            continue
        try:
            st = fn()
        except Exception as e:                      # noqa: BLE001
            log("    %-34s 异常 %s" % (name, e))
            continue
        if st == 0:
            done += 1
            log("    %-34s 成功" % name)
        else:
            log("    %-34s 未生效 NTSTATUS=0x%08X" % (name, st))
    dt = time.perf_counter() - t0

    m1 = get_mem()
    after = int(m1.ullAvailPhys)
    delta = after - before
    log("完成 —— 可用物理内存 %s（变化 %s%s），占用率 %d%%，耗时 %.2f s"
        % (fmt(after), "+" if delta >= 0 else "-", fmt(abs(delta)),
           m1.dwMemoryLoad, dt))
    log("    共执行 %d 项内核指令，均已下发。" % done)
    return before, after, dt, m0, m1


# ----------------------------------------------------------------------------
# 图形界面
# ----------------------------------------------------------------------------
def run_gui():
    import tkinter as tk
    from tkinter import font as tkfont

    BG = "#1e1f26"
    FG = "#e8e8ee"
    AC = "#5aa9e6"
    DIM = "#9a9aa8"

    root = tk.Tk()
    root.title(APP_TITLE)
    root.configure(bg=BG)
    root.geometry("620x520")
    root.minsize(560, 460)

    try:
        root.iconbitmap(default="")
    except Exception:
        pass

    q = queue.Queue()

    tk.Label(root, text="内存优化", bg=BG, fg=FG,
             font=("Microsoft YaHei UI", 17, "bold")).pack(anchor="w", padx=18, pady=(16, 2))
    tk.Label(root, text="内核级 NtSetSystemInformation · 一键腾出可用内存",
             bg=BG, fg=DIM, font=("Microsoft YaHei UI", 9)).pack(anchor="w", padx=18)

    info = tk.Label(root, text="读取中 …", bg=BG, fg=AC,
                    font=("Consolas", 11), justify="left")
    info.pack(anchor="w", padx=18, pady=(12, 4))

    bar_bg = tk.Frame(root, bg="#33343d", height=14)
    bar_bg.pack(fill="x", padx=18, pady=(0, 10))
    bar_bg.pack_propagate(False)
    bar = tk.Frame(bar_bg, bg=AC, height=14)
    bar.place(x=0, y=0, relwidth=0, relheight=1)

    def refresh():
        m = get_mem()
        used = m.ullTotalPhys - m.ullAvailPhys
        info.config(text="总内存 %s   已用 %s   可用 %s   占用率 %d%%"
                         % (fmt(m.ullTotalPhys), fmt(used), fmt(m.ullAvailPhys), m.dwMemoryLoad))
        bar.place_configure(relwidth=max(0.0, min(1.0, m.dwMemoryLoad / 100.0)))
        root.after(2000, refresh)

    # 可选步骤
    box = tk.LabelFrame(root, text=" 执行项目 ", bg=BG, fg=DIM,
                        font=("Microsoft YaHei UI", 9), bd=1)
    box.pack(fill="x", padx=18, pady=(0, 8))
    vars_ = {}
    for i, (name, _fn, default) in enumerate(STEPS):
        v = tk.BooleanVar(value=default)
        vars_[name] = v
        tk.Checkbutton(box, text=name, variable=v, bg=BG, fg=FG,
                       selectcolor="#2c2d36", activebackground=BG, activeforeground=FG,
                       font=("Microsoft YaHei UI", 9), anchor="w").grid(
            row=i // 2, column=i % 2, sticky="w", padx=8, pady=1)

    logbox = tk.Text(root, height=11, bg="#14151a", fg="#c9d1d9", bd=0,
                     font=("Consolas", 9), wrap="word", insertbackground=FG)
    logbox.pack(fill="both", expand=True, padx=18, pady=(0, 8))

    def put(text):
        q.put(text)

    def on_run():
        selected = {n for n, v in vars_.items() if v.get()}
        if not selected:
            put("没有勾选任何项目。")
            return
        btn.config(state="disabled", text="优化中 …")

        def work():
            try:
                optimize(selected, put)
            except Exception as e:                  # noqa: BLE001
                put("出错：%s" % e)
            finally:
                q.put("__DONE__")

        threading.Thread(target=work, daemon=True).start()

    def pump_done():
        try:
            while True:
                item = q.get_nowait()
                if item == "__DONE__":
                    btn.config(state="normal", text="开始优化")
                    continue
                logbox.insert("end", item + "\n")
                logbox.see("end")
        except queue.Empty:
            pass
        root.after(80, pump_done)

    btns = tk.Frame(root, bg=BG)
    btns.pack(fill="x", padx=18, pady=(0, 16))
    btn = tk.Button(btns, text="开始优化", command=on_run, bg=AC, fg="#0b0c10",
                    activebackground="#7bc0f5", relief="flat",
                    font=("Microsoft YaHei UI", 11, "bold"), padx=22, pady=6)
    btn.pack(side="right")
    tk.Label(btns, text="v%s   以管理员身份运行" % VERSION, bg=BG, fg=DIM,
             font=("Microsoft YaHei UI", 8)).pack(side="left")

    refresh()
    pump_done()
    put("就绪。默认勾选三项，点「开始优化」即可。")
    root.mainloop()


# ----------------------------------------------------------------------------
def main():
    cli = "--cli" in sys.argv
    if not is_admin():
        if cli:
            print("需要管理员权限运行。")
            return 3
        if elevate_and_exit():
            return 0
        print("提权被拒绝，无法继续。")
        return 4

    if cli:
        selected = {n for n, _f, d in STEPS if d}
        optimize(selected, lambda s: print(s))
        return 0

    run_gui()
    return 0


if __name__ == "__main__":
    sys.exit(main())
