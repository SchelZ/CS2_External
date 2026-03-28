import winim/lean
import winim/inc/winhttp
import strutils, strformat, os, times

import xstr
import hwid

const
  kAppId        = "overlayapp_v2"
  kRegRoot      = "Software\\Mz9kXpQ2\\R7vLnW4j"
  kRegValTicket = "q3FmYh8s"
  kRegValStamp  = "Lk2vBn9r"
  kRegValHwid   = "Xp4wCm7t"
  kGraceSecs    = int64(72 * 3600)
  kServerHost   = "license.yourdomain.com"
  kServerPort   = INTERNET_DEFAULT_HTTPS_PORT   # = 443, from winim/winhttp
  kServerPath   = "/v1/validate"
  kHmacSecret   = "REPLACE_WITH_YOUR_64_CHAR_SECRET_KEY_DO_NOT_SHIP_DEFAULT"

type
  LicenseStatus* = enum
    lsValid
    lsGrace
    lsExpired
    lsInvalidHwid
    lsInvalidKey
    lsError

  LicenseInfo* = object
    status*  : LicenseStatus
    plan*    : string
    expires* : int64
    hwid*    : string

proc hmacSha256Hex(key, data: string): string =
  type
    BCRYPT_ALG_HANDLE  = pointer
    BCRYPT_HASH_HANDLE = pointer

  proc BCryptOpenAlgorithmProvider(h: ptr BCRYPT_ALG_HANDLE,
    id, impl: LPCWSTR, flags: ULONG): int32
    {.stdcall, dynlib: "bcrypt.dll", importc.}
  proc BCryptCreateHash(h: BCRYPT_ALG_HANDLE,
    hash: ptr BCRYPT_HASH_HANDLE,
    obj: pointer, objLen: ULONG,
    secret: pointer, secretLen: ULONG, flags: ULONG): int32
    {.stdcall, dynlib: "bcrypt.dll", importc.}
  proc BCryptHashData(h: BCRYPT_HASH_HANDLE,
    input: pointer, inputLen: ULONG, flags: ULONG): int32
    {.stdcall, dynlib: "bcrypt.dll", importc.}
  proc BCryptFinishHash(h: BCRYPT_HASH_HANDLE,
    output: pointer, outputLen: ULONG, flags: ULONG): int32
    {.stdcall, dynlib: "bcrypt.dll", importc.}
  proc BCryptDestroyHash(h: BCRYPT_HASH_HANDLE): int32
    {.stdcall, dynlib: "bcrypt.dll", importc.}
  proc BCryptCloseAlgorithmProvider(h: BCRYPT_ALG_HANDLE, flags: ULONG): int32
    {.stdcall, dynlib: "bcrypt.dll", importc.}

  var algH: BCRYPT_ALG_HANDLE
  let algName = newWideCString("HMAC")

  if BCryptOpenAlgorithmProvider(addr algH, algName, nil, 0x00000008) != 0:
    return ""
  defer: discard BCryptCloseAlgorithmProvider(algH, 0)

  var hashH: BCRYPT_HASH_HANDLE
  var keySeq = newSeq[byte](key.len)
  for i in 0 ..< key.len: keySeq[i] = byte(ord(key[i]))
  if BCryptCreateHash(algH, addr hashH, nil, 0,
                       addr keySeq[0], ULONG(keySeq.len), 0) != 0:
    return ""
  defer: discard BCryptDestroyHash(hashH)

  var dataSeq = newSeq[byte](data.len)
  for i in 0 ..< data.len: dataSeq[i] = byte(ord(data[i]))
  if BCryptHashData(hashH, addr dataSeq[0], ULONG(dataSeq.len), 0) != 0:
    return ""

  var digest: array[32, byte]
  if BCryptFinishHash(hashH, addr digest[0], 32, 0) != 0:
    return ""

  result = ""
  for b in digest: result.add toHex(b.int, 2).toLowerAscii()

proc machineKey(hwid: string): string =
  var k = ""
  for i in 0..31:
    let b = uint8(ord(hwid[i mod hwid.len])) xor uint8(i * 0x37 + 0xA5)
    k.add toHex(b.int, 2)
  k

proc xorEncrypt(data, key: string): string =
  result = newString(data.len)
  for i in 0 ..< data.len:
    result[i] = char(uint8(ord(data[i])) xor uint8(ord(key[i mod key.len])))

proc regWriteStr(root: HKEY, path, name, value: string) =
  var hKey: HKEY
  let wPath = newWideCString(path)
  let wName = newWideCString(name)
  if RegCreateKeyExW(root, wPath, 0, nil, 0,
                      KEY_WRITE, nil, addr hKey, nil) != 0: return
  let wVal = newWideCString(value)
  discard RegSetValueExW(hKey, wName, 0, REG_SZ,
                          cast[ptr BYTE](addr wVal),
                          DWORD((value.len + 1) * 2))
  RegCloseKey(hKey)

proc regReadStr(root: HKEY, path, name: string): string =
  var hKey: HKEY
  let wPath = newWideCString(path)
  let wName = newWideCString(name)
  if RegOpenKeyExW(root, wPath, 0, KEY_READ, addr hKey) != 0: return ""
  defer: RegCloseKey(hKey)
  var buf: array[1024, WCHAR]
  var bufLen = DWORD(sizeof(buf))
  var kind: DWORD
  if RegQueryValueExW(hKey, wName, nil, addr kind,
                       cast[ptr BYTE](cast[pointer](addr buf)),
                       addr bufLen) != 0:
    return ""
  $cast[WideCString](addr buf[0])

proc httpsPost(host, path, body: string, port: INTERNET_PORT = INTERNET_PORT(443)): string =
  let sess = WinHttpOpen(newWideCString("Mozilla/5.0"),
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME,     # = NULL (LPCWSTR)
                          WINHTTP_NO_PROXY_BYPASS,   # = NULL (LPCWSTR)
                          0)
  if sess == nil: return ""
  defer: discard WinHttpCloseHandle(sess)

  let conn = WinHttpConnect(sess, newWideCString(host), port, 0)
  if conn == nil: return ""
  defer: discard WinHttpCloseHandle(conn)

  let req = WinHttpOpenRequest(conn,
              newWideCString("POST"),
              newWideCString(path),
              nil,
              WINHTTP_NO_REFERER,
              WINHTTP_DEFAULT_ACCEPT_TYPES,
              WINHTTP_FLAG_SECURE)
  if req == nil: return ""
  defer: discard WinHttpCloseHandle(req)

  let headers = newWideCString("Content-Type: application/json\r\n")
  var bodyBytes = newSeq[byte](body.len)
  for i in 0 ..< body.len: bodyBytes[i] = byte(ord(body[i]))
  if WinHttpSendRequest(req, headers, cast[DWORD](0xFFFFFFFF), cast[LPVOID](addr bodyBytes[0]), DWORD(body.len), DWORD(body.len), DWORD_PTR(0)) == FALSE:
    return ""

  if WinHttpReceiveResponse(req, nil) == FALSE: return ""

  result = ""
  while true:
    var avail: DWORD = 0
    if WinHttpQueryDataAvailable(req, addr avail) == FALSE or avail == 0: break
    var buf = newString(int(avail))
    var nRead: DWORD = 0
    if WinHttpReadData(req, cast[LPVOID](addr buf[0]), avail, addr nRead) == FALSE: break
    result.add buf[0 ..< int(nRead)]


proc jsonField(json, key: string): string =
  let k = '"' & key & '"' & ':'
  let idx = json.find(k)
  if idx < 0: return ""
  var i = idx + k.len
  while i < json.len and json[i] in {' ', '\t'}: inc i
  if i >= json.len: return ""
  if json[i] == '"':
    inc i
    var r = ""
    while i < json.len and json[i] != '"': r.add json[i]; inc i
    return r
  else:
    var r = ""
    while i < json.len and json[i] notin {',', '}', ' ', '\n', '\r'}:
      r.add json[i]; inc i
    return r

proc validateWithServer(licenseKey, hwid: string): LicenseInfo =
  result = LicenseInfo(status: lsError)
  let ts   = getTime().toUnix()
  let body = &"""{{
  "key":  "{licenseKey}",
  "hwid": "{hwid}",
  "ts":   {ts},
  "app":  "{kAppId}"
}}"""

  let raw = httpsPost(kServerHost, kServerPath, body, INTERNET_PORT(kServerPort))
  if raw.len == 0: return

  let ok      = jsonField(raw, "ok")
  let expires = jsonField(raw, "expires")
  let plan    = jsonField(raw, "plan")
  let sig     = jsonField(raw, "sig")

  if ok != "true": return LicenseInfo(status: lsInvalidKey)

  let sigData  = licenseKey & hwid & expires & plan
  let expected = hmacSha256Hex(kHmacSecret, sigData)
  if sig.toLowerAscii() != expected:
    return LicenseInfo(status: lsError)

  let expTs = parseBiggestInt(expires)
  if expTs < ts:
    return LicenseInfo(status: lsExpired, plan: plan,
                        expires: expTs, hwid: hwid)

  discard LicenseInfo(status: lsValid, plan: plan, expires: expTs, hwid: hwid)

proc saveCache(info: LicenseInfo, licenseKey: string) =
  let h   = info.hwid
  let mk  = machineKey(h)
  let raw = &"{info.plan}|{info.expires}|{getTime().toUnix()}"
  let enc = xorEncrypt(raw, mk)
  regWriteStr(HKEY_CURRENT_USER, kRegRoot, kRegValTicket, enc)
  regWriteStr(HKEY_CURRENT_USER, kRegRoot, kRegValStamp, $getTime().toUnix())
  regWriteStr(HKEY_CURRENT_USER, kRegRoot, kRegValHwid, xorEncrypt(h, mk))

proc loadCache(hwid: string): tuple[ok: bool, info: LicenseInfo] =
  let mk  = machineKey(hwid)
  let enc = regReadStr(HKEY_CURRENT_USER, kRegRoot, kRegValTicket)
  if enc.len == 0: return (false, LicenseInfo())

  let hwidEnc = regReadStr(HKEY_CURRENT_USER, kRegRoot, kRegValHwid)
  let cachedH = xorEncrypt(hwidEnc, mk)
  if not hwidMatches(cachedH, hwid): return (false, LicenseInfo(status: lsInvalidHwid))

  let raw   = xorEncrypt(enc, mk)
  let parts = raw.split('|')
  if parts.len < 3: return (false, LicenseInfo())

  let plan     = parts[0]
  let expires  = parseBiggestInt(parts[1])
  let stampStr = regReadStr(HKEY_CURRENT_USER, kRegRoot, kRegValStamp)
  let stamp    = parseBiggestInt(if stampStr.len > 0: stampStr else: "0")
  let now      = getTime().toUnix()

  if now < stamp: return (false, LicenseInfo(status: lsError))
  if expires < now: return (true, LicenseInfo(status: lsExpired, plan: plan, expires: expires, hwid: hwid))
  if now - stamp > kGraceSecs: return (false, LicenseInfo(status: lsError))

  (true, LicenseInfo(status: lsValid, plan: plan, expires: expires, hwid: hwid))

proc checkLicense*(licenseKey: string): LicenseInfo =
  let myHwid = generateHWID()

  let (cacheOk, cached) = loadCache(myHwid)
  if cacheOk and cached.status == lsValid:
    if cached.expires > getTime().toUnix():
      return cached

  let srv = validateWithServer(licenseKey, myHwid)
  if srv.status == lsValid:
    var info = srv
    info.hwid = myHwid
    saveCache(info, licenseKey)
    return info

  if cacheOk and cached.status == lsValid:
    return LicenseInfo(status: lsGrace, plan: cached.plan, expires: cached.expires, hwid: myHwid)

  if srv.status != lsError: return srv
  return LicenseInfo(status: lsError, hwid: myHwid)

proc licenseStatusText*(s: LicenseStatus): string =
  case s
  of lsValid:       "License valid"
  of lsGrace:       "Offline grace period active"
  of lsExpired:     "Subscription expired"
  of lsInvalidHwid: "License bound to a different machine"
  of lsInvalidKey:  "Invalid license key"
  of lsError:       "License server unreachable"