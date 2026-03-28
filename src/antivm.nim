import winim, strutils

proc cpuid(leaf: uint32): tuple[eax, ebx, ecx, edx: uint32] =
  var a, b, c, d: uint32
  asm """
    movl %4, %%eax
    xorl %%ecx, %%ecx
    cpuid
    movl %%eax, %0
    movl %%ebx, %1
    movl %%ecx, %2
    movl %%edx, %3
    : "=r"(`a`), "=r"(`b`), "=r"(`c`), "=r"(`d`)
    : "r"(`leaf`)
    : "eax","ebx","ecx","edx"
  """
  (a, b, c, d)

proc uint32ToString(v: uint32): string =
  result = newString(4)
  result[0] = char(v and 0xFF)
  result[1] = char((v shr 8)  and 0xFF)
  result[2] = char((v shr 16) and 0xFF)
  result[3] = char((v shr 24) and 0xFF)

proc checkHypervisorVendor(): bool =
  let (_, hbx, hcx, hdx) = cpuid(0x40000000)
  let vendor = uint32ToString(hbx) & uint32ToString(hcx) & uint32ToString(hdx)
  let knownVMs = ["VMwareVMware", "VBoxVBoxVBox", "KVMKVMKVM",
                  "XenVMMXenVMM", "prl hyperv  ",
                  "ACRNACRNACRN", " lrpepyh vr "]
  for v in knownVMs:
    if v in vendor: return true
  false

proc checkSmbios(): bool =
  type GetSystemFirmwareTableT = proc(sig, id: DWORD, buf: pointer, sz: DWORD): DWORD {.stdcall.}
  let kernel32 = GetModuleHandleW(newWideCString("kernel32.dll"))
  if kernel32 == 0: return false
  let fn = cast[GetSystemFirmwareTableT](GetProcAddress(kernel32, "GetSystemFirmwareTable"))
  if fn == nil: return false

  const RSMB = DWORD(0x52534D42)  # cast to DWORD explicitly
  let size = fn(RSMB, DWORD(0), nil, DWORD(0))
  if size == 0: return false

  var buf = newSeq[byte](int(size))
  if fn(RSMB, DWORD(0), addr buf[0], size) == 0: return false

  let raw = cast[string](buf).toLowerAscii()
  let vmStrings = ["vmware", "virtualbox", "vbox", "qemu",
                   "xen", "bochs", "parallels", "innotek",
                   "virtual machine", "hyper-v"]
  for s in vmStrings:
    if s in raw: return true
  false

proc isServiceRunning(name: string): bool =
  let scm = OpenSCManagerW(nil, nil, SC_MANAGER_CONNECT)
  if scm == 0: return false
  defer: CloseServiceHandle(scm)
  let svc = OpenServiceW(scm, newWideCString(name), SERVICE_QUERY_STATUS)
  if svc == 0: return false
  defer: CloseServiceHandle(svc)
  var status: SERVICE_STATUS
  if QueryServiceStatus(svc, addr status) == FALSE: return false
  status.dwCurrentState == SERVICE_RUNNING

proc checkGuestServicesRunning(): bool =
  let guestServices = ["VBoxGuest", "VBoxSF", "VBoxVideo", "vmhgfs",   "vmmouse", "vmrawdsk"]
  for s in guestServices:
    if isServiceRunning(s): return true
  false

var gVmTripped* = false
proc runVmChecks*(): bool =
  let hvVendor  = checkHypervisorVendor()
  let smbios    = checkSmbios()
  let svcRunning = checkGuestServicesRunning()

  when defined(debug):
    echo "[antivm] hvVendor=", hvVendor,
         " smbios=",           smbios,
         " guestServices=",    svcRunning

  if hvVendor or smbios or svcRunning:
    gVmTripped = true
    return true
  false