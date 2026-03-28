import winim, strutils, strformat, options

type
  MemoryError* = object of CatchableError

  MemoryRegion* = object
    base*  : uint64
    size*  : uint64
    state* : DWORD
    prot*  : DWORD

  Pattern* = object
    bytes* : seq[byte]
    mask*  : seq[bool]

proc readMemory*[T](handle: HANDLE, address: uint64): T =
  var bytesRead: SIZE_T = 0
  if ReadProcessMemory(handle,
                       cast[LPCVOID](address),
                       addr result,
                       SIZE_T(sizeof(T)),
                       addr bytesRead) == FALSE or
     bytesRead != SIZE_T(sizeof(T)):
    raise newException(MemoryError,
      &"ReadProcessMemory failed at 0x{address:016X} (error {GetLastError()})")

proc readBytes*(handle: HANDLE, address: uint64, size: int): seq[byte] =
  result = newSeq[byte](size)
  var bytesRead: SIZE_T = 0
  discard ReadProcessMemory(handle,
                            cast[LPCVOID](address),
                            addr result[0],
                            SIZE_T(size),
                            addr bytesRead)
  result.setLen(int(bytesRead))

proc tryReadMemory*[T](handle: HANDLE, address: uint64, value: var T): bool =
  var bytesRead: SIZE_T = 0
  ReadProcessMemory(handle,
                    cast[LPCVOID](address),
                    addr value,
                    SIZE_T(sizeof(T)),
                    addr bytesRead) == TRUE and
  bytesRead == SIZE_T(sizeof(T))

proc readInt32*(h: HANDLE, address: uint64):  int32   = readMemory[int32](h, address)
proc readInt64*(h: HANDLE, address: uint64):  int64   = readMemory[int64](h, address)
proc readUInt32*(h: HANDLE, address: uint64): uint32  = readMemory[uint32](h, address)
proc readUInt64*(h: HANDLE, address: uint64): uint64  = readMemory[uint64](h, address)
proc readFloat*(h: HANDLE, address: uint64):  float32 = readMemory[float32](h, address)
proc readDouble*(h: HANDLE, address: uint64): float64 = readMemory[float64](h, address)
proc readBool*(h: HANDLE, address: uint64):   bool    = readMemory[byte](h, address) != 0

proc readString*(h: HANDLE, address: uint64, maxLen = 256): string =
  let raw = readBytes(h, address, maxLen)
  for b in raw:
    if b == 0: break
    result.add char(b)

proc readWString*(h: HANDLE, address: uint64, maxChars = 128): string =
  for i in 0 ..< maxChars:
    let c = readMemory[uint16](h, address + uint64(i * 2))
    if c == 0: break
    result.add char(c and 0xFF)
    
proc resolvePointerChain*(handle : HANDLE, base: uint64, offsets: openArray[uint64]): uint64 =
  var address = base
  for i, off in offsets:
    if i == offsets.high:
      return address + off
    address = readMemory[uint64](handle, address + off)
    if address == 0:
      raise newException(MemoryError,
        &"Null pointer at level {i} (offset 0x{off:X})")

proc getModuleBase*(pid: DWORD, moduleName: string): uint64 =
  let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE or TH32CS_SNAPMODULE32, pid)
  if snap == INVALID_HANDLE_VALUE: return 0
  defer: CloseHandle(snap)
 
  var me: MODULEENTRY32W
  me.dwSize = DWORD(sizeof(MODULEENTRY32W))
  let needle = moduleName.toLowerAscii()
 
  if Module32FirstW(snap, addr me) == TRUE:
    while true:
      let name = $cast[WideCString](unsafeAddr me.szModule[0])
      if name.toLowerAscii() == needle:
        return uint64(cast[int](me.modBaseAddr))
      if Module32NextW(snap, addr me) == FALSE:
        break
  return 0


proc getModuleSize*(pid: DWORD, moduleName: string): uint64 =
  let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE or TH32CS_SNAPMODULE32, pid)
  if snap == INVALID_HANDLE_VALUE: return 0
  defer: CloseHandle(snap)
 
  var me: MODULEENTRY32W
  me.dwSize = DWORD(sizeof(MODULEENTRY32W))
  let needle = moduleName.toLowerAscii()
 
  if Module32FirstW(snap, addr me) == TRUE:
    while true:
      let name = $cast[WideCString](unsafeAddr me.szModule[0])
      if name.toLowerAscii() == needle:
        return uint64(me.modBaseSize)
      if Module32NextW(snap, addr me) == FALSE:
        break
  return 0

type ModuleInfo* = tuple[base: uint64, size: uint64]
 
proc getModuleInfo*(pid: DWORD, moduleName: string): ModuleInfo =
  let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE or TH32CS_SNAPMODULE32, pid)
  if snap == INVALID_HANDLE_VALUE: return (0'u64, 0'u64)
  defer: CloseHandle(snap)
 
  var me: MODULEENTRY32W
  me.dwSize = DWORD(sizeof(MODULEENTRY32W))
  let needle = moduleName.toLowerAscii()
 
  if Module32FirstW(snap, addr me) == TRUE:
    while true:
      let name = $cast[WideCString](unsafeAddr me.szModule[0])
      if name.toLowerAscii() == needle:
        return (uint64(cast[int](me.modBaseAddr)),
                uint64(me.modBaseSize))
      if Module32NextW(snap, addr me) == FALSE:
        break
  return (0'u64, 0'u64)

proc compilePattern*(pattern: string): Pattern =
  for token in pattern.splitWhitespace():
    if token == "??" or token == "?":
      result.bytes.add 0x00
      result.mask.add false     # wildcard — skip comparison
    else:
      result.bytes.add byte(parseHexInt(token))
      result.mask.add true      # must match
 
proc matchAt(data: seq[byte], offset: int, pat: Pattern): bool {.inline.} =
  for j in 0 ..< pat.bytes.len:
    if pat.mask[j] and data[offset + j] != pat.bytes[j]:
      return false
  true
 
proc scanData(data: seq[byte], pat: Pattern): Option[int] =
  if data.len < pat.bytes.len: return none(int)
  for i in 0 .. data.len - pat.bytes.len:
    if matchAt(data, i, pat):
      return some(i)
  none(int)
 
proc scanDataAll(data: seq[byte], pat: Pattern): seq[int] =
  if data.len < pat.bytes.len: return
  for i in 0 .. data.len - pat.bytes.len:
    if matchAt(data, i, pat):
      result.add i
 
proc scan*(handle: HANDLE, base: uint64, size: uint64, pattern: string): Option[uint64] =
  if base == 0 or size == 0: return none(uint64)
  let data = readBytes(handle, base, int(size))
  let idx  = scanData(data, compilePattern(pattern))
  if idx.isNone: return none(uint64)
  some(base + uint64(idx.get))
 
proc scanAll*(handle: HANDLE, base: uint64, size: uint64, pattern: string): seq[uint64] =
  if base == 0 or size == 0: return
  let data  = readBytes(handle, base, int(size))
  let pat   = compilePattern(pattern)
  let idxs  = scanDataAll(data, pat)
  for i in idxs: result.add base + uint64(i)
 
proc resolveRip*(handle: HANDLE, instrAddr: uint64, instrLen: int = 7, dispOffset: int = 3): uint64 =
  let disp = readMemory[int32](handle, instrAddr + uint64(dispOffset))
  instrAddr + uint64(instrLen) + uint64(disp)
 
proc scanAndResolveRip*(handle: HANDLE, base, size: uint64, pattern: string, instrLen: int = 7, dispOffset: int = 3): uint64 =
  let hit = scan(handle, base, size, pattern)
  if hit.isNone: return 0
  try: 
    let ctrHit = some(resolveRip(handle, hit.get, instrLen, dispOffset))
    if ctrHit.isSome: return ctrHit.get
  except MemoryError:
    return 0
 
proc enumMemoryRegions*(handle: HANDLE): seq[MemoryRegion] =
  result = @[]
  var 
    address: uint64 = 0 
    mbi: MEMORY_BASIC_INFORMATION
  while VirtualQueryEx(handle, cast[LPCVOID](address), mbi.addr, SIZE_T(sizeof(mbi))) == SIZE_T(sizeof(mbi)):
    if mbi.State == MEM_COMMIT and
       (mbi.Protect and PAGE_NOACCESS) == 0 and
       (mbi.Protect and PAGE_GUARD)    == 0:
      result.add MemoryRegion(
        base : cast[int](mbi.BaseAddress).uint64,
        size : mbi.RegionSize.uint64,
        state: mbi.State,
        prot : mbi.Protect)
    address = cast[int](mbi.BaseAddress).uint64 + mbi.RegionSize.uint64
    if address == 0: break
 
proc aobScan*(handle: HANDLE, pattern: string): seq[uint64] =
  for region in enumMemoryRegions(handle):
    try:
      let 
        data = readBytes(handle, region.base, region.size.int)
        pat  = compilePattern(pattern)
      for i in scanDataAll(data, pat): result.add region.base + i.uint64
    except: discard
