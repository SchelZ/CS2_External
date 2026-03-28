import macros
# Compile with -d:buildSalt=<random 32-char hex> to vary per-build.

const 
  kSalt {.strdefine.} = "A3F9B2C1D4E5F607A8B9CADBECFD0E1F"
  kBase = kSalt & CompileDate & CompileTime

proc keyByte(i: int): uint8 {.compileTime.} =
  var h: uint32 = 0x811C9DC5'u32
  for c in kBase:
    h = h xor uint32(ord(c))
    h = h * 0x01000193'u32
  h = h xor uint32(i * 0x9E3779B9)
  h = h * 0x01000193'u32
  uint8(h and 0xFF)


macro xs*(s: static[string]): untyped =
  let L = s.len
  var 
    encLit = nnkBracket.newTree()
    keyLit = nnkBracket.newTree()
  for i, c in s:
    let 
      kb  = keyByte(i)
      enc = uint8(ord(c)) xor kb
    encLit.add newLit(enc)   # encrypted byte baked in
    keyLit.add newLit(kb)    # key byte baked in

  let 
    bufSym = genSym(nskVar, "xbuf")
    resSym = genSym(nskVar, "xres")

  result = quote do:
    block:
      var 
        `bufSym`: array[`L`, uint8] = `encLit`
        `resSym` = newString(`L`)
      for ii in 0 ..< `L`:
        `resSym`[ii] = char(`bufSym`[ii] xor (`keyLit`[ii]))
      zeroMem(addr `bufSym`[0], `L`)
      `resSym`

