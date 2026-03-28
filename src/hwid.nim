import winim, strutils, strformat

proc fnv1a32(data: openArray[byte]): uint32 =
  result = 0x811C9DC5'u32
  for b in data:
    result = result xor uint32(b)
    result = result * 0x01000193'u32

proc mixStr(acc: var uint64, s: string) =
  for i, c in s:
    acc = acc xor (uint64(ord(c)) shl (i mod 56))
    acc = acc * 6364136223846793005'u64 + 1442695040888963407'u64

proc hexU64(v: uint64): string =
  result = ""
  for i in 0..7:
    let b = uint8((v shr (56 - i*8)) and 0xFF)
    result.add toHex(b.int, 2)

proc getVolSerial(): string =
  var serial: DWORD = 0
  let root = newWideCString("C:\\")
  if GetVolumeInformationW(root, nil, 0,
                            addr serial, nil, nil, nil, 0) == TRUE:
    return &"{serial:08X}"
  "00000000"

proc getMacAddress(): string =
  type
    IP_ADDRESS_STRING = array[16, char]
    IP_MASK_STRING    = array[16, char]
    IP_ADDR_STRING    = object
      Next      : pointer
      IpAddress : IP_ADDRESS_STRING
      IpMask    : IP_MASK_STRING
      Context   : DWORD
    IP_ADAPTER_INFO = object
      Next             : pointer
      ComboIndex       : DWORD
      AdapterName      : array[260, char]
      Description      : array[132, char]
      AddressLength    : UINT
      Address          : array[8, byte]
      Index            : DWORD
      Type             : UINT
      DhcpEnabled      : UINT
      CurrentIpAddress : pointer
      IpAddressList    : IP_ADDR_STRING
      GatewayList      : IP_ADDR_STRING
      DhcpServer       : IP_ADDR_STRING
      HaveWins         : BOOL
      PrimaryWinsServer : IP_ADDR_STRING
      SecondaryWinsServer : IP_ADDR_STRING
      LeaseObtained    : int64
      LeaseExpires     : int64

  proc GetAdaptersInfo(buf: pointer, size: ptr ULONG): DWORD
    {.stdcall, dynlib: "iphlpapi.dll", importc: "GetAdaptersInfo".}

  var size: ULONG = 0
  discard GetAdaptersInfo(nil, addr size)
  if size == 0: return "000000000000"

  var buf = newSeq[byte](int(size))
  if GetAdaptersInfo(addr buf[0], addr size) != 0:
    return "000000000000"

  let info = cast[ptr IP_ADAPTER_INFO](addr buf[0])
  result = ""
  let addrLen = min(int(info.AddressLength), 6)
  for i in 0 ..< addrLen:
    result.add toHex(int(info.Address[i]), 2)
  while result.len < 12: result.add "0"

proc getWmiString(query, field: string): string =
  result = ""
  if CoInitializeEx(nil, COINIT_MULTITHREADED) < 0: return

  var pLoc: ptr IUnknown = nil
  var pSvc: ptr IUnknown = nil

  let cmd  = &"wmic {query} get {field} /value"
  let wCmd = newWideCString(cmd)

  var sa: SECURITY_ATTRIBUTES
  sa.nLength = DWORD(sizeof(sa))
  sa.bInheritHandle = TRUE

  var hRead, hWrite: HANDLE
  if CreatePipe(addr hRead, addr hWrite, addr sa, 0) == FALSE: return

  var si: STARTUPINFOW
  var pi: PROCESS_INFORMATION
  si.cb          = DWORD(sizeof(si))
  si.dwFlags     = STARTF_USESTDHANDLES
  si.hStdOutput  = hWrite
  si.hStdError   = hWrite

  let wShell = newWideCString("cmd.exe /c " & cmd)
  let created = CreateProcessW(nil, wShell, nil, nil, TRUE, CREATE_NO_WINDOW, nil, nil, addr si, addr pi)
  CloseHandle(hWrite)
  if created == FALSE:
    CloseHandle(hRead); return

  WaitForSingleObject(pi.hProcess, 5000)

  var raw = newString(1024)
  var bytesRead: DWORD = 0
  discard ReadFile(hRead, addr raw[0], 1023, addr bytesRead, nil)
  CloseHandle(hRead)
  CloseHandle(pi.hProcess)
  CloseHandle(pi.hThread)
  raw.setLen(int(bytesRead))

  for line in raw.splitLines():
    let parts = line.strip().split('=')
    if parts.len >= 2 and parts[1].strip().len > 0:
      return parts[1].strip()

proc generateHWID*(): string =
  let volSerial  = getVolSerial()
  let mac        = getMacAddress()
  let cpuId      = getWmiString("cpu", "ProcessorId")
  let boardSN    = getWmiString("baseboard", "SerialNumber")
  let productId  = getWmiString("os", "SerialNumber")

  var acc1: uint64 = 0xDEADBEEFCAFEBABE'u64
  var acc2: uint64 = 0x0123456789ABCDEF'u64

  mixStr(acc1, volSerial)
  mixStr(acc2, mac)
  mixStr(acc1, cpuId)
  mixStr(acc2, boardSN)
  mixStr(acc1, productId)
  acc2 = acc2 xor acc1
  acc1 = acc1 xor (acc2 shl 17) xor (acc2 shr 3)

  result = hexU64(acc1) & hexU64(acc2)
  assert result.len == 32

proc hwidMatches*(stored, current: string, threshold = 3): bool =
  if stored.len != current.len: return false
  var diff = 0
  for i in 0 ..< stored.len:
    if stored[i] != current[i]: inc diff
  diff <= threshold
