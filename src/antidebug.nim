import winim, strutils, std/sequtils

const
  ProcessDebugPort  = 7'i32
  ProcessDebugFlags = 31'i32
 
type NtQIP = proc(h: HANDLE, cls: int32, info: pointer, len: ULONG, retLen: ptr ULONG): int32 {.stdcall.}
 
var pfnIsDbg : proc(): BOOL {.stdcall.} = nil
var pfnNtQIP : NtQIP = nil
 
proc getNtdll(): HMODULE =
  GetModuleHandleW(newWideCString("ntdll.dll"))


proc initAntiDebug*() =
  let k = GetModuleHandleW(newWideCString("kernel32.dll"))
  pfnIsDbg = cast[proc(): BOOL {.stdcall.}](
    GetProcAddress(k, "IsDebuggerPresent"))
  pfnNtQIP = cast[NtQIP](
    GetProcAddress(getNtdll(), "NtQueryInformationProcess"))


proc check1(): bool =
  if pfnIsDbg == nil: return false
  pfnIsDbg() == TRUE

proc check2(): bool =
  if pfnNtQIP == nil: return false
  var port: int64 = 0
  let r = pfnNtQIP(GetCurrentProcess(), ProcessDebugPort,
                    addr port, ULONG(sizeof(port)), nil)
  r >= 0 and port != 0

proc check2b(): bool =
  if pfnNtQIP == nil: return false
  var flags: ULONG = 0
  let r = pfnNtQIP(GetCurrentProcess(), ProcessDebugFlags,
                    addr flags, ULONG(sizeof(flags)), nil)
  r >= 0 and flags == 0 and check2()

proc check3(): bool =
  var pebPtr: uint64
  asm """
    movq %%gs:0x60, %0
    : "=r" (`pebPtr`)
    :
    : "rax"
  """
  if pebPtr == 0: return false
  let ntGlobalFlag = cast[ptr uint32](pebPtr + 0xBC)[]
  (ntGlobalFlag and 0x70'u32) != 0

proc check4(): bool =
  var pebPtr: uint64
  asm """
    movq %%gs:0x60, %0
    : "=r" (`pebPtr`)
    :
    : "rax"
  """
  if pebPtr == 0: return false
  let heapPtr = cast[ptr uint64](pebPtr + 0x30)[]
  if heapPtr == 0: return false
  let flags      = cast[ptr uint32](heapPtr + 0x70)[]
  let forceFlags = cast[ptr uint32](heapPtr + 0x74)[]
  let suspiciousFlags = (flags and 0x40'u32) != 0 and
                        (flags and 0x20'u32) != 0
  let suspiciousForce = (forceFlags and 0x40000060'u32) == 0x40000060'u32
  suspiciousFlags or suspiciousForce

proc rdtsc(): uint64 {.inline.} =
  var lo, hi: uint32
  asm """
    rdtsc
    movl %%eax, %0
    movl %%edx, %1
    : "=r" (`lo`), "=r" (`hi`)
    :
    : "eax", "edx"
  """
  (uint64(hi) shl 32) or uint64(lo)

proc check5(): bool =
  let t1 = rdtsc()
  var dummy = t1 xor 0xDEADBEEF'u64
  dummy = dummy * 6364136223846793005'u64
  let t2 = rdtsc()
  (t2 - t1) > 10_000_000'u64


proc check6(): bool =
  var present: BOOL = FALSE
  CheckRemoteDebuggerPresent(GetCurrentProcess(), addr present)
  present == TRUE

proc check7(): bool =
  var ctx: CONTEXT
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
  if GetThreadContext(GetCurrentThread(), addr ctx) == FALSE: return false
  ctx.Dr0 != 0 or ctx.Dr1 != 0 or ctx.Dr2 != 0 or ctx.Dr3 != 0

proc getParentPID(): DWORD =
  if pfnNtQIP == nil: return 0
  type BasicInfo = object
    ExitStatus     : int32
    PebBaseAddress : pointer
    AffinityMask   : uint64
    BasePriority   : int32
    UniqueProcessId: uint64
    InheritedFromId: uint64
  var bi: BasicInfo
  discard pfnNtQIP(GetCurrentProcess(), 0,
                    addr bi, ULONG(sizeof(bi)), nil)
  DWORD(bi.InheritedFromId)

proc check8(): bool =
  let ppid = getParentPID()
  if ppid == 0: return false
 
  let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  if snap == INVALID_HANDLE_VALUE: return false
  defer: CloseHandle(snap)
 
  var pe: PROCESSENTRY32W
  pe.dwSize = DWORD(sizeof(pe))

  let allowedParents = [
    "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
    "conhost.exe",  "svchost.exe",
    "WindowsTerminal.exe", "wt.exe",
    "taskmgr.exe",
    "code.exe",          # VS Code
    "devenv.exe",        # Visual Studio
    "rider64.exe",       # JetBrains Rider
    "clion64.exe",       # CLion
    "fleet.exe",         # JetBrains Fleet
    "sublime_text.exe",  # Sublime Text
    "nim.exe",           # Nim compiler direct launch
    "nimble.exe",        # Nimble
    "bash.exe",          # Git Bash / WSL
    "mintty.exe",        # MSYS2 terminal
    "msys2.exe",
    ""                   # PID 0 / system
  ]
 
  if Process32FirstW(snap, addr pe) == TRUE:
    while true:
      if pe.th32ProcessID == ppid:
        let name = ($cast[WideCString](unsafeAddr pe.szExeFile[0])).toLowerAscii()
        return name notin allowedParents.mapIt(it.toLowerAscii())
      if Process32NextW(snap, addr pe) == FALSE: break
  false


var gAntiDebugTripped* = false
 
proc runChecks*(): bool =
  var score = 0
 
  if check1():  inc score, 10   # IsDebuggerPresent
  if check6():  inc score, 10   # CheckRemoteDebugger
  if check2():  inc score, 15   # NtQuery DebugPort
  if check2b(): inc score, 8    # NtQuery DebugFlags
  if check7():  inc score, 20   # Hardware breakpoints
  if check3():  inc score, 12   # PEB NtGlobalFlag
  if check4():  inc score, 8    # Heap flags
  if check5():  inc score, 4    # RDTSC timing
  if check8():  inc score, 3    # Parent process
 
  if score >= 20:
    gAntiDebugTripped = true
    return true
  false
 
proc periodicCheck*() =
  if runChecks():
    gAntiDebugTripped = true

