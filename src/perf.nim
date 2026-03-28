import winim/lean, os, atomics, std/monotimes, times

type
  ReadSpec* = object
    srcAddr* : uint64   ## absolute VA in target process
    dstOff*  : int      ## byte offset into our output buffer
    size*    : int      ## bytes to read

  BatchReader* = object
    handle  : HANDLE
    specs   : seq[ReadSpec]
    scratch : seq[byte]

proc initBatchReader*(handle: HANDLE, capacity = 64): BatchReader =
  result.handle  = handle
  result.specs   = newSeqOfCap[ReadSpec](capacity)
  result.scratch = newSeq[byte](4096)

proc addRead*(br: var BatchReader, srcAddr: uint64, dstOff: int, size: int) =
  br.specs.add ReadSpec(srcAddr: srcAddr, dstOff: dstOff, size: size)

proc executeBatch*(br: var BatchReader, outBuf: var openArray[byte]) =
  const MERGE_GAP = 512   ## merge reads within 512 bytes of each other

  if br.specs.len == 0: return
  for i in 1 ..< br.specs.len:
    var j = i
    while j > 0 and br.specs[j-1].srcAddr > br.specs[j].srcAddr:
      swap(br.specs[j-1], br.specs[j]); dec j

  var i = 0
  while i < br.specs.len:
    # Find run of specs that can be merged
    var runEnd  = i
    var runBase = br.specs[i].srcAddr
    var runSize = uint64(br.specs[i].size)

    while runEnd + 1 < br.specs.len:
      let next = br.specs[runEnd + 1]
      let gap  = next.srcAddr - (runBase + runSize)
      if gap <= MERGE_GAP:
        runSize = next.srcAddr + uint64(next.size) - runBase
        inc runEnd
      else:
        break

    if br.scratch.len < int(runSize):
      br.scratch.setLen(int(runSize) * 2)

    # Single ReadProcessMemory for the entire run
    var bytesRead: SIZE_T = 0
    discard ReadProcessMemory(br.handle, cast[LPCVOID](runBase), addr br.scratch[0], SIZE_T(runSize), addr bytesRead)

    for j in i .. runEnd:
      let sp     = br.specs[j]
      let offset = int(sp.srcAddr - runBase)
      let avail  = int(bytesRead) - offset
      if avail >= sp.size:
        copyMem(addr outBuf[sp.dstOff],
                addr br.scratch[offset],
                sp.size)
    i = runEnd + 1
  br.specs.setLen(0)

type
  SeqVersion* = Atomic[uint64]

proc beginWrite*(v: var SeqVersion) {.inline.} =
  ## Call before writing shared data.
  var cur = v.load(moRelaxed)
  v.store(cur + 1, moRelease)   # odd = in progress
  atomicThreadFence(ATOMIC_ACQUIRE)

proc endWrite*(v: var SeqVersion) {.inline.} =
  ## Call after writing shared data.
  atomicThreadFence(ATOMIC_RELEASE)
  var cur = v.load(moRelaxed)
  v.store(cur + 1, moRelease)   # even = stable

proc tryRead*(v: var SeqVersion): uint64 {.inline.} =
  ## Returns the version snapshot before a read attempt.
  while true:
    let s = v.load(moAcquire)
    if (s and 1) == 0: return s   # wait until stable
    cpuRelax()

proc readValid*(v: var SeqVersion, snapshot: uint64): bool {.inline.} =
  ## Returns true if the data read since tryRead() was consistent.
  atomicThreadFence(ATOMIC_ACQUIRE)
  v.load(moRelaxed) == snapshot

type
  GameStateFast* = object
    version*  : SeqVersion         ## 8 bytes
    health*   : float32            ## 4
    maxHealth*: float32            ## 4
    ammo*     : int32              ## 4
    flags*    : uint32             ## 4  (valid=bit0, corrupted=bit1)
    posX*     : float32            ## 4
    posY*     : float32            ## 4
    posZ*     : float32            ## 4
    fps*      : float32            ## 4
    pad*      : array[88, byte]    ## padding to 128 bytes total

var gFastState* {.align(64).}: GameStateFast

proc writeGameState*(health, maxHealth: float32, ammo: int32, x, y, z, fps: float32, valid: bool) =
  beginWrite(gFastState.version)
  gFastState.health    = health
  gFastState.maxHealth = maxHealth
  gFastState.ammo      = ammo
  gFastState.posX      = x
  gFastState.posY      = y
  gFastState.posZ      = z
  gFastState.fps       = fps
  gFastState.flags     = if valid: 1 else: 0
  endWrite(gFastState.version)

proc readGameState*(dst: var GameStateFast): bool =
  ## Returns false if a write was in progress (caller should use stale data).
  let snap = tryRead(gFastState.version)
  dst = gFastState
  readValid(gFastState.version, snap)

# ── 4. SoA entity array for radar / ESP ───────────────────────────────────────

const MAX_ENTITIES* = 64

type
  EntityArraySoA* = object
    ## Structure-of-Arrays layout: all X coords together, all Y together
    x*     : array[MAX_ENTITIES, float32]
    y*     : array[MAX_ENTITIES, float32]
    z*     : array[MAX_ENTITIES, float32]
    health*: array[MAX_ENTITIES, float32]
    flags* : array[MAX_ENTITIES, uint32]   ## bit0=alive, bit1=enemy, bit2=visible
    count* : int

proc isAlive*(e: EntityArraySoA, i: int): bool {.inline.} =
  (e.flags[i] and 1) != 0

proc isEnemy*(e: EntityArraySoA, i: int): bool {.inline.} =
  (e.flags[i] and 2) != 0

proc isVisible*(e: EntityArraySoA, i: int): bool {.inline.} =
  (e.flags[i] and 4) != 0

proc prefetch*(p: pointer) {.inline.} =
  asm """
    prefetcht0 (%0)
    : : "r" (`p`)
  """

template prefetchNext*(arr: typed, i, ahead: int) =
  if i + ahead < arr.len:
    prefetch(addr arr[i + ahead])

type NtDelayFn = proc(alertable: BOOL, interval: ptr int64): int32 {.stdcall, gcsafe.}

var pfnNtDelay: NtDelayFn = nil

proc initHighResSleep*() =
  let ntdll = GetModuleHandleW(newWideCString("ntdll.dll"))
  pfnNtDelay = cast[NtDelayFn](GetProcAddress(ntdll, "NtDelayExecution"))
  # Set the timer resolution to 1ms via timeBeginPeriod
  proc timeBeginPeriod(p: UINT): UINT
    {.stdcall, dynlib: "winmm.dll", importc.}
  discard timeBeginPeriod(1)

proc sleepNs*(ns: int64) {.inline, gcsafe.} =
  if pfnNtDelay == nil: sleep(int(ns div 1_000_000)); return
  var interval = -(ns div 100)   # negative = relative interval in 100ns units
  discard pfnNtDelay(FALSE, addr interval)

proc sleepUs*(us: int64) {.inline, gcsafe.} = sleepNs(us * 1_000)
proc sleepMs*(ms: int64) {.inline, gcsafe.} = sleepNs(ms * 1_000_000)

type FramePacer* = object
  targetNs  : int64
  lastFrame : MonoTime

proc initFramePacer*(targetFps: int): FramePacer =
  FramePacer(targetNs: 1_000_000_000 div targetFps, lastFrame: getMonoTime())

proc pace*(fp: var FramePacer) =
  let now     = getMonoTime()
  let elapsed = (now - fp.lastFrame).inNanoseconds
  let remain  = fp.targetNs - elapsed
  if remain > 500_000:
    sleepNs(remain - 500_000)
  while (getMonoTime() - fp.lastFrame).inNanoseconds < fp.targetNs:
    discard   # spin-wait final sub-ms
  fp.lastFrame = getMonoTime()

type FrameArena* = object
  buf   : array[65536, byte]   ## 64 KB per frame
  cursor: int

proc reset*(a: var FrameArena) {.inline.} = a.cursor = 0

proc alloc*(a: var FrameArena, size: int): pointer {.inline.} =
  let aligned = (size + 7) and not 7   ## 8-byte alignment
  if a.cursor + aligned > a.buf.len: return nil
  result = addr a.buf[a.cursor]
  inc a.cursor, aligned

proc allocStr*(a: var FrameArena, s: string): cstring =
  let p = cast[cstring](a.alloc(s.len + 1))
  if p == nil: return nil
  if s.len > 0: copyMem(p, cast[pointer](s.cstring), s.len)
  cast[ptr char](cast[uint](p) + uint(s.len))[] = '\0'
  p