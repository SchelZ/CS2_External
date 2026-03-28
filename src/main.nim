import winim/lean
import os, strformat, times, options, locks

import process_manager
import memory_reader
import overlay
import license
import antidebug
import antivm
import integrity
import perf
import cfo
import tlscb
import cs2offsets
import xstr

var gLock      : Lock
var gViewMatrix: Matrix4x4
var gPlayers   : seq[Player]

initLock(gLock)


var gEnumPid : DWORD
var gEnumHwnd: HWND

proc enumCb(hwnd: HWND, _: LPARAM): BOOL {.stdcall.} =
  var pid: DWORD = 0
  GetWindowThreadProcessId(hwnd, addr pid)
  if pid == gEnumPid and IsWindowVisible(hwnd) == TRUE:
    let s = GetWindowLongW(hwnd, GWL_STYLE)
    let x = GetWindowLongW(hwnd, GWL_EXSTYLE)
    if (s and WS_CAPTION.int32) != 0 and (x and WS_EX_TOOLWINDOW.int32) == 0:
      gEnumHwnd = hwnd; return FALSE
  TRUE

proc findMainWindow(pid: DWORD): HWND =
  gEnumPid = pid; gEnumHwnd = HWND(0)
  EnumWindows(enumCb, 0); gEnumHwnd

var gCheckCounter = 0

proc periodicProtectionCheck() =
  inc gCheckCounter
  if gCheckCounter mod (120 + (gCheckCounter mod 97)) != 0: return
  if runChecks() or gIntegrityTripped or gVmTripped or gAntiDebugTripped:
    beginWrite(gFastState.version)
    gFastState.flags = gFastState.flags or 2   # bit1 = corrupted → silent sabotage
    endWrite(gFastState.version)

proc getBonePos(handle: HANDLE; pawn: uint64; boneId: int): Vector3 =
  let sceneNode = readUInt64(handle, pawn + m_pGameSceneNode)
  if sceneNode == 0: return
  let boneArray = readUInt64(handle, sceneNode + m_modelState + m_boneArray)
  if boneArray == 0: return
  let bonePosition = readMemory[Vector3](handle, boneArray + uint64(boneId * BONE_STRIDE))
  return bonePosition

proc readerThread(args: tuple[handle: HANDLE, clientBase: uint64, clientSize: uint64]) {.thread.} =
  let (h, clientBase, clientSize) = args

  let 
    viewMatrixVA  = scanAndResolveRip(h, clientBase, clientSize, xs("48 8D 0D ?? ?? ?? ?? 48 C1 E0 06"))
    entityListVA = readUInt64(h, scanAndResolveRip(h, clientBase, clientSize, xs("48 8B 0D ?? ?? ?? ?? 48 89 7C 24 ?? 8B FA C1 EB")))
    localControllerVA = readUInt64(h, scanAndResolveRip(h, clientBase, clientSize, xs("48 8B 05 ?? ?? ?? ?? 41 89 BE")))

  if entityListVA == 0 or localControllerVA == 0:
    echo "pattern scan failed"; return

  var 
    localTeam: int32 = 0
    health: int32 = 0
    newPlayers: seq[Player]
    newMatrix: Matrix4x4

  newPlayers.setLen(MAX_PLAYERS)
  newPlayers.setLen(0)

  while true:
    {.gcsafe.}:
      if not offsetsLoaded() or clientBase == 0:
        sleep(100); continue
      
      newPlayers.setLen(0)

      try:
        newMatrix = readMemory[Matrix4x4](h, viewMatrixVA)
        let listEntry = readUInt64(h, entityListVA + 0x10)
        if listEntry == 0: 
          acquire(gLock)
          gViewMatrix = newMatrix
          gPlayers.setLen(0)
          release(gLock)
          sleep(8)
          continue

        let localPawnHandle = readUInt64(h, localControllerVA + 0x6C4)
        if localPawnHandle == 0: continue

        let localPawnChunk = readUInt64(h, entityListVA + 0x10 + 0x8 * uint64((localPawnHandle and 0x7FFF) shr 9))
        if localPawnChunk == 0: continue

        let localPawn = readUInt64(h, localPawnChunk + 0x70 * uint64(localPawnHandle and 0x1FF))
        if localPawn == 0: continue

        localTeam = readMemory[int32](h, localPawn + 0x3F3)
        health = readMemory[int32](h, localPawn + 0x354)

        for i in 0 ..< MAX_PLAYERS:
          
          let controller = readUInt64(h, listEntry + uint64(i + 1) * 0x70)
          if controller == 0 or localControllerVA == controller: continue
          
          let pawnHandle = readUInt64(h, controller + 0x6C4)  # m_hPawn
          if pawnHandle == 0: continue

          let pawnChunk = readUInt64(h, entityListVA + 0x10 + 0x8 * ((pawnHandle and 0x7FFF) shr 9))
          if pawnChunk == 0: continue
  
          let pawn = readUInt64(h, pawnChunk + 0x70 * uint64(pawnHandle and 0x1FF))
          if pawn == 0: continue
          
          health = readMemory[int32](h, pawn + 0x354)
          if health <= 0 or health > 100: continue
          let team = readMemory[int32](h, pawn + 0x3F3)
          if team == localTeam and localTeam != 0: continue   # skip teammates
          let origin  = readMemory[Vector3](h, pawn + 0x1588)
          let headPos = getBonePos(h, pawn, HEAD_BONE_ID)

          newPlayers.add Player(
            pawn:    pawn,
            team:    team,
            health:  health,
            origin:  origin,
            headPos: headPos
          )
 
        acquire(gLock)
        gViewMatrix = newMatrix
        gPlayers    = newPlayers
        release(gLock)
        # writeGameState(float32(localHealth), 100.0f, 0, 0, 0, 0, gFastState.fps, localHealth > 0)
 
      except CatchableError:
        discard

    sleep(8)


var fpsFrames = 0; var fpsLast = 0'i64

proc tickFps() =
  inc fpsFrames
  let now = getTime().toUnix()
  if now != fpsLast:
    beginWrite(gFastState.version)
    gFastState.fps = float32(fpsFrames)
    endWrite(gFastState.version)
    fpsFrames = 0; fpsLast = now

var gArena: FrameArena

proc onDraw(ctx: DrawContext) =
  gArena.reset()
  tickFps()
  periodicProtectionCheck()
 
  let w = ctx.width
  let h = ctx.height

  var localMatrix : Matrix4x4
  var localPlayers: seq[Player]

  acquire(gLock)
  localMatrix  = gViewMatrix
  localPlayers = gPlayers
  release(gLock)
 
  # ── ESP: enemy boxes / health bars ───────────────────────────────────────
  for p in localPlayers:
    let feet = worldToScreen(p.origin,  localMatrix, w, h)
    let head = worldToScreen(p.headPos, localMatrix, w, h)
    if not feet.onScreen and not head.onScreen:
      continue

    let topY    = min(head.y, feet.y)
    let bottomY = max(head.y, feet.y)
    let boxH    = bottomY - topY
    if boxH < 5f: continue

    let boxW    = boxH / 2.5f
    let boxX    = head.x - boxW / 2f          # center on HEAD (best visual)
    let boxY    = topY

    let hpRatio = p.health.float32 / 100f
    let boxCol  = if hpRatio > 0.6f: clGreen
                  elif hpRatio > 0.3f: clYellow
                  else: clRed

    drawRect(ctx, boxX.int, boxY.int, boxW.int, boxH.int, boxCol)
    drawHealthBar(ctx, (boxX - 6).int, boxY.int, 4, boxH.int, p.health.float32, 100f, "")
    drawText(ctx, &"{p.health} HP",boxX.int, (boxY - 14).int, boxCol, size = 11)

  # ── Debug offset panel ────────────────────────────────────────────────────
  # when defined(debug):
  #   const px = 12; const py = 12; const pw = 310; const ph = 126
  #   let loaded   = offsetsLoaded()
  #   let panelCol = if loaded: rgb(18, 18, 18) else: rgb(40, 10, 10)
  #   let borderCol= if loaded: rgb(70, 70, 70) else: clRed
  #   let titleCol = if loaded: clCyan          else: clRed
  #   let statusCol= if loaded: clGreen         else: clYellow
  #   fillRect(ctx, px, py, pw, ph, panelCol)
  #   drawRect(ctx, px, py, pw, ph, borderCol)
  #   drawText(ctx, " CS2 OFFSETS", px + 6, py + 4, titleCol, size = 13)
  #   drawLine(ctx, px + 4, py + 22, px + pw - 4, py + 22, rgb(50, 50, 50))
  #   {.gcsafe.}:
  #     drawText(ctx, " " & gOffsets.status, px + 6, py + 26, statusCol, size = 10)
  #   drawLine(ctx, px + 4, py + 40, px + pw - 4, py + 40, rgb(50, 50, 50))
  #   {.gcsafe.}:
  #     drawText(ctx, &" dwEntityList      0x{gOffsets.client.dwEntityList:X}",      px + 6, py +  44, clWhite, size = 11)
  #     drawText(ctx, &" dwLocalPlayerPawn 0x{gOffsets.client.dwLocalPlayerPawn:X}", px + 6, py +  60, clWhite, size = 11)
  #     drawText(ctx, &" dwViewMatrix      0x{gOffsets.client.dwViewMatrix:X}",      px + 6, py +  76, clWhite, size = 11)
  #     drawText(ctx, &" dwViewAngles      0x{gOffsets.client.dwViewAngles:X}",      px + 6, py +  92, clWhite, size = 11)
  #     drawText(ctx, &" dwLocalController 0x{gOffsets.client.dwLocalPlayerController:X}", px + 6, py + 108, clWhite, size = 11)


proc waitForProcess(name: string, pollMs: int): tuple[pid: DWORD, hwnd: HWND] =
  while true:
    let found = findProcessByName(name)
    if found.isSome:
      sleep(800)
      let p = found.get()
      return (p.pid, findMainWindow(p.pid))
    sleepMs(int64(pollMs))

proc appMain() =
  if not verifyTlsCanary(): return

  initAntiDebug()
  initHighResSleep()

  var earlyFail = false
  sequencedDispatch([
    proc() = (if runChecks():   earlyFail = true),
    proc() = (if runVmChecks(): earlyFail = true),
    proc() = initIntegrity(),
  ])
  if earlyFail: return

  let 
    args = commandLineParams()
    targetName = "cs2.exe" 
    pollMs = 1000

  # Phase 3: License
  # let lic = checkLicense(licKey)
  # case lic.status
  # of lsValid, lsGrace: discard
  # of lsExpired:
  #   MessageBoxW(0, newWideCString("Subscription expired."),
  #               newWideCString("Overlay"), MB_OK or MB_ICONWARNING); return
  # of lsInvalidHwid:
  #   MessageBoxW(0, newWideCString("License bound to another device."),
  #               newWideCString("Overlay"), MB_OK or MB_ICONERROR); return
  # of lsInvalidKey:
  #   MessageBoxW(0, newWideCString("Invalid license key."),
  #               newWideCString("Overlay"), MB_OK or MB_ICONERROR); return
  # of lsError:
  #   MessageBoxW(0, newWideCString("Cannot verify license."),
  #               newWideCString("Overlay"), MB_OK or MB_ICONWARNING); return


  if checkIntegrity(): return
  discard loadOffsets()

  let (pid, gameHwnd) = waitForProcess(targetName, pollMs)
  if runChecks() or checkIntegrity(): return

  if not offsetsLoaded(): discard loadOffsets()

  var handle: HANDLE
  try: handle = openProcess(pid)
  except: return

  let (clientBase, clientSize) = getModuleInfo(pid, "client.dll")

  var rThread: Thread[tuple[handle: HANDLE, clientBase: uint64, clientSize: uint64]]
  createThread(rThread, readerThread, (handle, clientBase, clientSize))

  if createOverlay(gameHwnd, proc(ctx: DrawContext) = onDraw(ctx)):
    runOverlay()


  joinThread(rThread)
  closeProcess(handle)

when isMainModule:
  appMain()