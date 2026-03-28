import winim/lean, macros, tables

const 
  FNV_OFFSET = 0xCBF29CE484222325'u64
  FNV_PRIME  = 0x100000001B3'u64

proc fnv1a64*(s: openArray[byte]): uint64 {.inline.} =
  result = FNV_OFFSET
  for b in s:
    result = result xor uint64(b)
    result = result * FNV_PRIME

proc fnv1a64*(s: string): uint64 {.inline.} =
  result = FNV_OFFSET
  for c in s:
    result = result xor uint64(ord(c))
    result = result * FNV_PRIME

proc fnv1a64Ct*(s: static[string]): uint64 {.compileTime.} =
  result = FNV_OFFSET
  for c in s:
    result = result xor uint64(ord(c))
    result = result * FNV_PRIME

template hash*(s: static[string]): uint64 = fnv1a64Ct(s)

type
  IMAGE_DOS_HEADER {.packed.} = object
    e_magic : uint16
    pad     : array[29, uint16]
    e_lfanew: int32

  IMAGE_EXPORT_DIRECTORY {.packed.} = object
    Characteristics      : uint32
    TimeDateStamp        : uint32
    MajorVersion         : uint16
    MinorVersion         : uint16
    Name                 : uint32
    Base                 : uint32
    NumberOfFunctions    : uint32
    NumberOfNames        : uint32
    AddressOfFunctions   : uint32
    AddressOfNames       : uint32
    AddressOfNameOrdinals: uint32

proc getExportByHash*(moduleBase: uint64, nameHash: uint64): pointer =
  ## Walks the PE export directory of a loaded module and returns
  if moduleBase == 0: return nil

  let dosHdr = cast[ptr IMAGE_DOS_HEADER](moduleBase)
  if dosHdr.e_magic != 0x5A4D: return nil   # 'MZ'

  let 
    peOff     = uint64(dosHdr.e_lfanew)
    optOff    = moduleBase + peOff + 24
    exportRVA = cast[ptr uint32](optOff + 112)[]

  if exportRVA == 0: return nil

  let 
    exp = cast[ptr IMAGE_EXPORT_DIRECTORY](moduleBase + exportRVA)
    nameRVAs  = cast[ptr UncheckedArray[uint32]](moduleBase + exp.AddressOfNames)
    ordinals  = cast[ptr UncheckedArray[uint16]](moduleBase + exp.AddressOfNameOrdinals)
    funcRVAs  = cast[ptr UncheckedArray[uint32]](moduleBase + exp.AddressOfFunctions)

  for i in 0 ..< int(exp.NumberOfNames):
    let namePtr = cast[cstring](moduleBase + nameRVAs[i])
    var h = FNV_OFFSET
    var j = 0
    while namePtr[j] != '\0':
      h = h xor uint64(ord(namePtr[j]))
      h = h * FNV_PRIME
      inc j
    if h == nameHash:
      let ordinal = ordinals[i]
      return cast[pointer](moduleBase + funcRVAs[ordinal])
  nil

type
  LIST_ENTRY_PTR {.packed.} = object
    Flink, Blink: uint64

  LDR_DATA_TABLE_ENTRY {.packed.} = object
    InLoadOrderLinks      : LIST_ENTRY_PTR
    InMemoryOrderLinks    : LIST_ENTRY_PTR
    InInitializationLinks : LIST_ENTRY_PTR
    DllBase               : uint64
    EntryPoint            : uint64
    SizeOfImage           : uint32
    pad                   : uint32
    FullDllName_Len       : uint16
    FullDllName_MaxLen    : uint16
    pad2                  : uint32
    FullDllName_Buf       : uint64
    BaseDllName_Len       : uint16
    BaseDllName_MaxLen    : uint16
    pad3                  : uint32
    BaseDllName_Buf       : uint64

proc getModuleBaseByHash*(moduleNameHash: uint64): uint64 =
  ## Finds a loaded DLL's base address by hashing its name from the PEB.
  ## No GetModuleHandle no import entry.
  var peb: uint64
  asm """
    mov rax, qword ptr gs:[0x60]
    mov %0, rax
    : "=r" (`peb`)
  """
  if peb == 0: return 0

  # PEB+0x18 = Ldr pointer
  let ldrPtr  = cast[ptr uint64](peb + 0x18)[]
  # PEB_LDR_DATA+0x10 = InLoadOrderModuleList
  let listHead = ldrPtr + 0x10
  var cur = cast[ptr uint64](listHead)[]   # Flink

  while cur != listHead:
    let entry = cast[ptr LDR_DATA_TABLE_ENTRY](cur)
    let base  = entry.DllBase
    if base != 0:
      let nameBuf = cast[ptr UncheckedArray[uint16]](entry.BaseDllName_Buf)
      let nameLen = int(entry.BaseDllName_Len) div 2
      var h = FNV_OFFSET
      for i in 0 ..< nameLen:
        let c = uint64(nameBuf[i] and 0x00FF)
        let lc = if c >= 65 and c <= 90: c + 32 else: c
        h = h xor lc
        h = h * FNV_PRIME
      if h == moduleNameHash:
        return base
    cur = cast[ptr uint64](cur)[] 
  0


var gApiCache: Table[uint64, pointer]

proc resolveApi*(modHash: uint64, fnHash: uint64): pointer =
  ## Resolves and caches a function pointer by (module hash, function hash).
  let key = modHash xor (fnHash shl 32) xor (fnHash shr 32)
  if key in gApiCache: return gApiCache[key]
  let base = getModuleBaseByHash(modHash)
  let p    = getExportByHash(base, fnHash)
  if p != nil: gApiCache[key] = p
  p

proc getApi*[T](modHash: uint64, fnHash: uint64): T =
  cast[T](resolveApi(modHash, fnHash))

# ── Convenience macro ─────────────────────────────────────────────────────────

macro dynCall*(modName: static[string], fnName: static[string], sig: typedesc, args: varargs[untyped]): untyped =
  let mh = fnv1a64(modName & ".dll")
  let fh = fnv1a64(fnName)
  result = quote do:
    getApi[`sig`](`mh`, `fh`)(`args`)

# Use these instead of getModuleHandle("kernel32.dll") etc.
const
  hKernel32* = fnv1a64Ct("kernel32.dll")
  hUser32*   = fnv1a64Ct("user32.dll")
  hNtdll*    = fnv1a64Ct("ntdll.dll")
  hWinHttp*  = fnv1a64Ct("winhttp.dll")
  hBcrypt*   = fnv1a64Ct("bcrypt.dll")
  hIpHlp*    = fnv1a64Ct("iphlpapi.dll")