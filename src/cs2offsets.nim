import httpclient, json, os, times, strutils, net
  
const
  m_pGameSceneNode* = 0x338'u64
  m_modelState*     = 0x160'u64     # inline struct — do NOT dereference
  m_boneArray*      = 0x80'u64      # pointer inside m_modelState
  BONE_STRIDE*      = 32            # Matrix3x4 → 12 × float32 → 48 bytes
  HEAD_BONE_ID*     = 6
  MAX_PLAYERS*      = 64

type
  Vector3* = object
    x*, y*, z*: float32

  Matrix4x4* = array[16, float32]   # row-major, as stored by CS2

  Player* = object
    pawn*    : uint64
    team*    : int32
    health*  : int32
    origin*  : Vector3
    headPos* : Vector3              # world-space head bone

proc worldToScreen*(world: Vector3; matrix: Matrix4x4; width, height: int): tuple[x, y: float32; onScreen: bool] =
  let sightX = width.float32  / 2.0f
  let sightY = height.float32 / 2.0f

  let view = matrix[12] * world.x + matrix[13] * world.y + matrix[14] * world.z + matrix[15]
  if view <= 0.01f: return (0f, 0f, false)

  result.x = sightX + (matrix[0] * world.x + matrix[1] * world.y + matrix[2]  * world.z + matrix[3])  / view * sightX
  result.y = sightY - (matrix[4] * world.x + matrix[5] * world.y + matrix[6]  * world.z + matrix[7])  / view * sightY

  result.onScreen = result.x >= 0f and result.x <= width.float32 and result.y >= 0f and result.y <= height.float32

type
  ClientOffsets* = object
    dwEntityList*                          : uint64
    dwGameEntitySystem*                    : uint64
    dwGameEntitySystem_highestEntityIndex* : uint64
    dwLocalPlayerController*               : uint64
    dwLocalPlayerPawn*                     : uint64
    dwPlantedC4*                           : uint64
    dwViewAngles*                          : uint64
    dwViewMatrix*                          : uint64
    dwViewRender*                          : uint64
    dwWeaponC4*                            : uint64
 
  Engine2Offsets* = object
    dwNetworkGameClient*            : uint64
    dwNetworkGameClient_localPlayer*: uint64
    dwNetworkGameClient_maxClients* : uint64
    dwWindowHeight*                 : uint64
    dwWindowWidth*                  : uint64
 
  CS2Offsets* = object
    client*    : ClientOffsets
    engine2*   : Engine2Offsets
    loaded*    : bool
    fetchedAt* : int64   ## Unix timestamp of last successful fetch
    status*    : string  ## Human-readable last-action string (for debug panel)
 
 
var gOffsets* : CS2Offsets 

const
  CACHE_XOR   : byte = 0xA7
  CACHE_MAGIC         = "CS2OFF3|"   # bump version so old caches are rejected
  CACHE_TTL           = int64(24 * 3600)
  OFFSETS_URL         = "https://raw.githubusercontent.com/a2x/cs2-dumper/" &
                        "d75c3c918bcf2a97202cb57cdc506cc4a81c9fa1/output/offsets.json"
  FETCH_TIMEOUT_MS    = 8_000

proc cacheFile(): string =
  getEnv("TEMP") & "\\cs2off.bin"
 
proc xorBuf(s: string): string =
  result = newString(s.len)
  for i, c in s:
    result[i] = char(byte(ord(c)) xor CACHE_XOR)
 
proc saveCache(raw: string; ts: int64) =
  try:
    writeFile(cacheFile(), xorBuf(CACHE_MAGIC & $ts & "|" & raw))
    when defined(debug): echo "[offsets] cache written → ", cacheFile()
  except CatchableError as e:
    when defined(debug): echo "[offsets] cache write failed: ", e.msg

proc loadCacheRaw(): tuple[ok: bool; raw: string; ts: int64] =
  try:
    let path = cacheFile()
    if not fileExists(path):
      when defined(debug): echo "[offsets] no cache file at ", path
      return (false, "", 0)
 
    let data = xorBuf(readFile(path))
    if not data.startsWith(CACHE_MAGIC):
      when defined(debug): echo "[offsets] cache magic mismatch (old version?)"
      return (false, "", 0)
 
    let rest = data[CACHE_MAGIC.len .. ^1]
    let sep  = rest.find('|')
    if sep < 0:
      when defined(debug): echo "[offsets] cache format corrupt"
      return (false, "", 0)
 
    let ts = parseBiggestInt(rest[0 ..< sep])
    when defined(debug): echo "[offsets] cache found, age=", getTime().toUnix() - ts, "s"
    return (true, rest[sep+1 .. ^1], ts)
 
  except CatchableError as e:
    when defined(debug): echo "[offsets] cache read error: ", e.msg
    return (false, "", 0)

# ── JSON parser ───────────────────────────────────────────────────────────────

proc parseOffsets(raw: string): tuple[ok: bool; data: CS2Offsets; err: string] =
  result.ok = false
  try:
    let root = parseJson(raw)
 
    # Validate top-level keys exist before indexing
    if not root.hasKey("client.dll"):
      return (false, result.data, "missing client.dll key")
    if not root.hasKey("engine2.dll"):
      return (false, result.data, "missing engine2.dll key")
 
    let c = root["client.dll"]
    let e = root["engine2.dll"]
 
    template getU64(node: JsonNode; key: string): uint64 =
      if node.hasKey(key): node[key].getBiggestInt().uint64 else: 0'u64

    result.data.client.dwEntityList                          = c.getU64("dwEntityList")
    result.data.client.dwGameEntitySystem                    = c.getU64("dwGameEntitySystem")
    result.data.client.dwGameEntitySystem_highestEntityIndex = c.getU64("dwGameEntitySystem_highestEntityIndex")
    result.data.client.dwLocalPlayerController               = c.getU64("dwLocalPlayerController")
    result.data.client.dwLocalPlayerPawn                     = c.getU64("dwLocalPlayerPawn")
    result.data.client.dwPlantedC4                           = c.getU64("dwPlantedC4")
    result.data.client.dwViewAngles                          = c.getU64("dwViewAngles")
    result.data.client.dwViewMatrix                          = c.getU64("dwViewMatrix")
    result.data.client.dwViewRender                          = c.getU64("dwViewRender")
    result.data.client.dwWeaponC4                            = c.getU64("dwWeaponC4")
 
    result.data.engine2.dwNetworkGameClient             = e.getU64("dwNetworkGameClient")
    result.data.engine2.dwNetworkGameClient_localPlayer = e.getU64("dwNetworkGameClient_localPlayer")
    result.data.engine2.dwNetworkGameClient_maxClients  = e.getU64("dwNetworkGameClient_maxClients")
    result.data.engine2.dwWindowHeight                  = e.getU64("dwWindowHeight")
    result.data.engine2.dwWindowWidth                   = e.getU64("dwWindowWidth")

    if result.data.client.dwEntityList == 0:
      return (false, result.data, "dwEntityList parsed as 0 — likely schema mismatch")
 
    result.data.loaded = true
    result.ok          = true
    result.err         = ""
 
  except JsonParsingError as e:
    result.err = "JSON parse error: " & e.msg
  except KeyError as e:
    result.err = "missing key: " & e.msg
  except ValueError as e:
    result.err = "value error: " & e.msg
# ── Public API ────────────────────────────────────────────────────────────────

proc loadOffsets*(): bool =
  ## Populates gOffsets. Returns true on success.
  ## Priority: fresh cache → network fetch → stale cache fallback.
  ## gOffsets.status is always set to describe what happened.
  let now = getTime().toUnix()
 
  # 1. Try fresh cache (< 24 h old)
  let (cacheOk, cachedRaw, cacheTs) = loadCacheRaw()
  if cacheOk and (now - cacheTs) < CACHE_TTL:
    let (ok, data, err) = parseOffsets(cachedRaw)
    if ok:
      gOffsets        = data
      gOffsets.fetchedAt = cacheTs
      gOffsets.status = "cache (age " & $(now - cacheTs) & "s)"
      when defined(debug):
        echo "[offsets] loaded from cache — dwEntityList=0x", gOffsets.client.dwEntityList.toHex()
        echo "[offsets] loaded from cache — dwLocalPlayerController=0x", gOffsets.client.dwLocalPlayerController.toHex()
        echo "[offsets] loaded from cache — dwLocalPlayerPawn=0x", gOffsets.client.dwLocalPlayerPawn.toHex()
        echo "[offsets] loaded from cache — dwViewMatrix=0x", gOffsets.client.dwViewMatrix.toHex()
        echo "[offsets] loaded from cache — dwEntityList=0x", gOffsets.client.dwEntityList.toHex()
      return true
    else:
      when defined(debug): echo "[offsets] cache parse failed: ", err
 
  # 2. Fetch from GitHub
  when defined(debug): echo "[offsets] fetching from GitHub…"
  try:
    var client = newHttpClient(timeout = FETCH_TIMEOUT_MS)
    client.headers = newHttpHeaders({"User-Agent": "cs2ov/1.1"})
    let raw = client.getContent(OFFSETS_URL)
    client.close()
 
    when defined(debug): echo "[offsets] HTTP OK, bytes=", raw.len
 
    let (ok, data, err) = parseOffsets(raw)
    if ok:
      gOffsets        = data
      gOffsets.fetchedAt = now
      gOffsets.status = "fetched fresh"
      saveCache(raw, now)
      when defined(debug):
        echo "[offsets] fresh fetch OK — dwEntityList=0x",
             gOffsets.client.dwEntityList.toHex()
      return true
    else:
      gOffsets.status = "fetch OK but parse failed: " & err
      when defined(debug): echo "[offsets] parse error after fetch: ", err
 
  except TimeoutError as e:
    gOffsets.status = "network timeout"
    when defined(debug): echo "[offsets] fetch timed out ", e.msg
  except CatchableError as e:
    gOffsets.status = "fetch error: " & e.msg
    when defined(debug): echo "[offsets] fetch error: ", e.msg
 
  # 3. Stale cache fallback
  if cacheOk:
    let (ok, data, err) = parseOffsets(cachedRaw)
    if ok:
      gOffsets        = data
      gOffsets.fetchedAt = cacheTs
      gOffsets.status = "stale cache (age " & $(now - cacheTs) & "s)"
      when defined(debug):
        echo "[offsets] using stale cache — dwEntityList=0x",
             gOffsets.client.dwEntityList.toHex()
      return true
    else:
      gOffsets.status = "stale cache parse failed: " & err
      when defined(debug): echo "[offsets] stale cache unusable: ", err
 
  gOffsets.status = "not loaded"
  when defined(debug): echo "[offsets] all sources failed"
  false
 
proc offsetsLoaded*(): bool = gOffsets.loaded