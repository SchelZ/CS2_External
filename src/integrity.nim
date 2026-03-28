
import winim/lean
from apihash import getExportByHash


type
  IMAGE_SECTION_HEADER {.packed.} = object
    Name             : array[8, byte]
    VirtualSize      : uint32
    VirtualAddress   : uint32
    SizeOfRawData    : uint32
    PointerToRawData : uint32
    PointerToRelocs  : uint32
    PointerToLinenums: uint32
    NumberOfRelocs   : uint16
    NumberOfLinenums : uint16
    Characteristics  : uint32

static:
  assert sizeof(IMAGE_SECTION_HEADER) == 40,
    "IMAGE_SECTION_HEADER must be 40 bytes"

proc findSection(base: uint64, name: string): tuple[rva: uint64, size: uint64] =
  if cast[ptr uint16](base)[] != 0x5A4D: return (0'u64, 0'u64)
 
  let e_lfanew = cast[ptr int32](base + 0x3C)[]
  let peBase   = base + uint64(e_lfanew)
 
  # Validate PE signature
  if cast[ptr uint32](peBase)[] != 0x00004550: return (0'u64, 0'u64)
 
  let numSects = cast[ptr uint16](peBase + 6)[]
  let optSize  = cast[ptr uint16](peBase + 20)[]
  let sectBase = peBase + 24 + uint64(optSize)
 
  for i in 0 ..< int(numSects):
    let sh = cast[ptr IMAGE_SECTION_HEADER](sectBase + uint64(i) * uint64(sizeof(IMAGE_SECTION_HEADER)))
    var sname = ""
    for b in sh.Name:
      if b == 0: break
      sname.add char(b)
    if sname == name:
      return (uint64(sh.VirtualAddress), uint64(sh.VirtualSize))
  (0'u64, 0'u64)

proc fnvRange(start: uint64, length: uint64): uint64 =
  result = 0xCBF29CE484222325'u64
  let data = cast[ptr UncheckedArray[byte]](start)
  for i in 0 ..< int(length):
    result = result xor uint64(data[i])
    result = result * 0x100000001B3'u64
 
var
  gTextBase  : uint64 = 0
  gTextSize  : uint64 = 0
  gHashNonce : uint64 = 0
  gHashEnc   : uint64 = 0
  gInitDone  : bool   = false
 
var gIntegrityTripped* = false
 
proc initIntegrity*() =
  let base = uint64(GetModuleHandleW(nil))
  if base == 0: return
 
  let (rva, sz) = findSection(base, ".text")
  if rva == 0 or sz == 0: return   # skip
 
  gTextBase = base + rva
  gTextSize = sz
 
  let h = fnvRange(gTextBase, gTextSize)
 
  var stackVar: uint64 = 0xDEADC0DEDEADC0DE'u64
  gHashNonce = uint64(cast[int](addr stackVar)) xor 0xBAADF00D13371337'u64
  gHashEnc   = h xor gHashNonce
  gInitDone  = true
 
proc checkIntegrity*(): bool =
  ## Returns true if .text was modified. False = clean (or not initialized).
  if not gInitDone: return false
 
  let current  = fnvRange(gTextBase, gTextSize)
  let expected = gHashEnc xor gHashNonce
 
  if current != expected:
    gIntegrityTripped = true
    return true
  false
 
type ApiCheck* = tuple[base: uint64, fnHash: uint64, name: string]
 
proc checkForInlineHooks*(apis: openArray[ApiCheck]): bool =
  for (base, fnHash, name) in apis:
    if base == 0: continue
    let p = getExportByHash(base, fnHash)
    if p == nil: continue
    let b0 = cast[ptr byte](p)[]
    if b0 == 0xE9'u8 or b0 == 0xFF'u8:
      gIntegrityTripped = true
      return true
    if b0 == 0x48'u8:
      let b1 = cast[ptr byte](cast[uint64](p) + 1)[]
      if b1 == 0xB8'u8:
        gIntegrityTripped = true 
        return true
  false
