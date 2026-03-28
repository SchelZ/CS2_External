import winim, options, strutils, strformat, std/private/ospaths2

type
  ProcessInfo* = object
    pid*   : DWORD
    name*  : string
    handle*: HANDLE 

  ProcessError* = object of CatchableError

var gEnumTarget: tuple[pid: DWORD, hwnd: HWND]

proc enumWindowsCb(hwnd: HWND, _: LPARAM): BOOL {.stdcall.} =
  var pid: DWORD = 0
  GetWindowThreadProcessId(hwnd, addr pid)
  if pid == gEnumTarget.pid and IsWindowVisible(hwnd) == TRUE:
    let style    = GetWindowLongW(hwnd, GWL_STYLE)
    let exStyle  = GetWindowLongW(hwnd, GWL_EXSTYLE)
    let isApp    = (style    and WS_CAPTION.int32) != 0
    let isTool   = (exStyle  and WS_EX_TOOLWINDOW.int32) != 0
    if isApp and not isTool:
      gEnumTarget.hwnd = hwnd
      return FALSE
  return TRUE

# ── Public API ───────────────────────────────────────────────────────────────

proc listProcesses*(): seq[ProcessInfo] =
  result = @[]
  let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  if snap == INVALID_HANDLE_VALUE:
    return
  defer: CloseHandle(snap)

  var pe: PROCESSENTRY32W
  pe.dwSize = DWORD(sizeof(PROCESSENTRY32W))

  if Process32FirstW(snap, addr pe) == TRUE:
    while true:
      let name = $cast[WideCString](unsafeAddr pe.szExeFile[0])
      result.add ProcessInfo(pid: pe.th32ProcessID, name: name)
      if Process32NextW(snap, addr pe) == FALSE:
        break

proc findProcessByName*(name: string): Option[ProcessInfo] =
  let needle = name.toLowerAscii().addFileExt("exe").replace(".exe.exe", ".exe")
  for p in listProcesses():
    if p.name.toLowerAscii() == needle:
      return some(p)
  none(ProcessInfo)

proc openProcess*(pid: DWORD, access: DWORD = PROCESS_VM_READ or PROCESS_QUERY_INFORMATION): HANDLE =
  result = OpenProcess(access, FALSE, pid)
  if result == 0:
    raise newException(ProcessError, &"OpenProcess failed for PID {pid} (error {GetLastError()})")

proc closeProcess*(handle: HANDLE) =
  if handle != 0 and handle != INVALID_HANDLE_VALUE:
    CloseHandle(handle)

proc getProcessMainWindow*(pid: DWORD): HWND =
  gEnumTarget = (pid: pid, hwnd: HWND(0))
  EnumWindows(enumWindowsCb, 0)
  gEnumTarget.hwnd

proc getWindowTitle*(hwnd: HWND): string =
  var buf = newWideCString("", 256)
  let len = GetWindowTextW(hwnd, buf, 256)
  if len > 0: result = $buf else: result = "<no title>"

proc getWindowRect*(hwnd: HWND): RECT =
  var rc: RECT
  discard GetWindowRect(hwnd, addr rc)
  rc
proc printProcessList*(procs: seq[ProcessInfo], filter = "") =
  when defined(debug):
    echo ""
    echo "  PID       Process Name"
    echo "  ────────  ─────────────────────────────────────"
  for p in procs:
    if filter.len == 0 or filter.toLowerAscii() in p.name.toLowerAscii():
      echo &"  {p.pid:<8}  {p.name}"
  echo ""
