import macros, std/monotimes, times

template opaqueTrue*(): bool =
  ## Always evaluates to true, but involves enough indirection
  block:
    let n {.volatile.} = getMonoTime().ticks and 0xFF
    ((n * (n + 1)) and 1) == 0

template opaqueFalse*(): bool =
  block:
    let n {.volatile.} = getMonoTime().ticks and 0xFF
    (n * n) mod 4 == 3

template guardedBlock*(body: untyped) =
  ## Wraps body in an opaque predicate so the decompiler sees it as
  ## conditional even though it always executes.
  if opaqueTrue():
    body
  else:
    discard

template junk1*() =
  ## Inserts a harmless CPUID that does nothing useful but breaks
  asm """
    push rax
    push rbx
    push rcx
    push rdx
    xor eax, eax
    cpuid
    pop rdx
    pop rcx
    pop rbx
    pop rax
  """

template junk2*() =
  ## RDTSC into scratch registers side-effect free but changes
  ## apparent timing and confuses emulators.
  asm """
    push rax
    push rdx
    rdtsc
    xor eax, eax
    pop rdx
    pop rax
  """

template junk3*() =
  ## A push/pop pair with a MOV
  asm """
    push rax
    mov rax, 0x1337C0DE1337C0DE
    xor rax, rax
    pop rax
  """

template scatterJunk*() =
  junk1(); junk2(); junk3()

type IndirectTable* = object
  slots: array[32, pointer]
  count: int

var gIndirect*: IndirectTable

proc registerFn*(tbl: var IndirectTable, p: pointer): int =
  result = tbl.count
  tbl.slots[tbl.count] = p
  inc tbl.count

proc callSlot*[T](tbl: IndirectTable, idx: int): T =
  cast[T](tbl.slots[idx])

proc dispatcher*(steps: openArray[proc() {.closure.}]) =
  let key = int(getMonoTime().ticks and 0xF)
  var state = 0
  while state < steps.len:
    let idx = (state xor key) mod steps.len
    steps[idx]()
    inc state

proc sequencedDispatch*(steps: openArray[proc() {.closure.}]) =
  let mask = int(getMonoTime().ticks and 0xFF) or 1
  var encoded = newSeq[int](steps.len)
  for i in 0 ..< steps.len:
    encoded[i] = i xor mask        # store XOR i
  var i = 0
  while i < steps.len:
    let idx = encoded[i] xor mask  # decode (i xor mask) xor mask = i
    steps[idx]()
    inc i

type CheckVariant* = proc(): bool {.closure.}

proc polymorphicCheck*(variants: openArray[CheckVariant]): bool =
  let idx = int(getMonoTime().ticks mod int64(variants.len))
  variants[idx]()
