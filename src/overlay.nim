#  WS_EX_LAYERED      – colour-key / alpha transparency
#  WS_EX_TRANSPARENT  – mouse & keyboard pass through to game
#  WS_EX_TOPMOST      – always above every other window
#  WS_EX_TOOLWINDOW   – HIDES the window from the taskbar and Alt-Tab list
#  WS_EX_NOACTIVATE   – never steals focus from the game

import winim/lean

const CHROMA_KEY*: COLORREF = RGB(0, 255, 0)
const OVERLAY_CLASS = "NimGhostOverlay"

type
  Color* = object
    r*, g*, b*: byte

  FontWeight* = enum
    fwNormal = FW_NORMAL
    fwBold   = FW_BOLD

proc rgb*(r, g, b: byte): Color = Color(r: r, g: g, b: b)
proc toRef(c: Color): COLORREF  = RGB(c.r, c.g, c.b)

let
  clWhite*  = rgb(255, 255, 255)
  clRed*    = rgb(240,  60,  60)
  clGreen*  = rgb( 60, 210,  60)
  clBlue*   = rgb( 60, 150, 255)
  clYellow* = rgb(255, 220,  40)
  clCyan*   = rgb(  0, 220, 220)
  clOrange* = rgb(255, 145,  30)
  clGray*   = rgb(150, 150, 150)

type
  DrawContext* = object
    hdc*   : HDC
    width* : int
    height*: int

type DrawProc* = proc(ctx: DrawContext) {.closure.}

type OverlayState = object
  hwnd      : HWND
  targetHwnd: HWND
  drawProc  : DrawProc
  running   : bool

var gOvr: OverlayState

proc fillRect*(ctx: DrawContext, x, y, w, h: int, c: Color) =
  let br = CreateSolidBrush(toRef(c))
  var rc = RECT(left: x.int32, top: y.int32, right: (x+w).int32, bottom: (y+h).int32)
  FillRect(ctx.hdc, addr rc, br)
  DeleteObject(br)

proc drawRect*(ctx: DrawContext, x, y, w, h: int, c: Color, thick = 1) =
  let pen  = CreatePen(PS_SOLID, thick.int32, toRef(c))
  let nullB = GetStockObject(NULL_BRUSH)
  let oldP = SelectObject(ctx.hdc, pen)
  let oldB = SelectObject(ctx.hdc, nullB)
  Rectangle(ctx.hdc, x.int32, y.int32, (x+w).int32, (y+h).int32)
  SelectObject(ctx.hdc, oldP); SelectObject(ctx.hdc, oldB)
  DeleteObject(pen)

proc drawLine*(ctx: DrawContext, x1, y1, x2, y2: int, c: Color, thick = 1) =
  let pen  = CreatePen(PS_SOLID, thick.int32, toRef(c))
  let oldP = SelectObject(ctx.hdc, pen)
  MoveToEx(ctx.hdc, x1.int32, y1.int32, nil)
  LineTo(ctx.hdc, x2.int32, y2.int32)
  SelectObject(ctx.hdc, oldP); DeleteObject(pen)

proc drawCircle*(ctx: DrawContext, cx, cy, r: int, c: Color, filled = false) =
  let pen  = CreatePen(PS_SOLID, 1, toRef(c))
  let br   = if filled: CreateSolidBrush(toRef(c)) else: GetStockObject(NULL_BRUSH)
  let oldP = SelectObject(ctx.hdc, pen)
  let oldB = SelectObject(ctx.hdc, br)
  Ellipse(ctx.hdc, (cx-r).int32, (cy-r).int32, (cx+r).int32, (cy+r).int32)
  SelectObject(ctx.hdc, oldP); SelectObject(ctx.hdc, oldB)
  DeleteObject(pen)
  if filled: DeleteObject(br)

proc drawText*(ctx: DrawContext, text: string, x, y: int, c: Color,
               size = 14, weight: FontWeight = fwBold) =
  let wFace = newWideCString("Consolas")
  let font  = CreateFontW(size.int32, 0, 0, 0, weight.int32,
                           FALSE, FALSE, FALSE,
                           ANSI_CHARSET, OUT_DEFAULT_PRECIS,
                           CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           DEFAULT_PITCH or FF_DONTCARE, wFace)
  let oldF = SelectObject(ctx.hdc, font)
  SetTextColor(ctx.hdc, toRef(c)); SetBkMode(ctx.hdc, TRANSPARENT)
  let wText = newWideCString(text)
  TextOutW(ctx.hdc, x.int32, y.int32, wText, text.len.int32)
  SelectObject(ctx.hdc, oldF); DeleteObject(font)

proc drawHealthBar*(ctx: DrawContext, x, y, w, h: int, current, maximum: float32, label = "") =
  let pct   = clamp(current / maximum, 0.0, 1.0)
  let fillW = int(float32(w) * pct)
  let barC  = if pct > 0.6: clGreen elif pct > 0.3: clYellow else: clRed
  fillRect(ctx, x, y, fillW, h, barC)
  drawRect(ctx, x, y, w, h, clWhite)
  if label.len > 0:
    drawText(ctx, label, x + 4, y + (h - 12) div 2, clWhite, size = 12)

proc drawCrosshair*(ctx: DrawContext, c: Color, size = 10, gap = 3, thick = 2) =
  let cx = ctx.width div 2; let cy = ctx.height div 2
  drawLine(ctx, cx - size - gap, cy, cx - gap,        cy, c, thick)
  drawLine(ctx, cx + gap,        cy, cx + size + gap, cy, c, thick)
  drawLine(ctx, cx, cy - size - gap, cx, cy - gap,        c, thick)
  drawLine(ctx, cx, cy + gap,        cx, cy + size + gap, c, thick)

proc overlayWndProc(hwnd: HWND, msg: UINT, wParam: WPARAM, lParam: LPARAM): LRESULT {.stdcall.} =
  case msg
  of WM_PAINT:
    var ps: PAINTSTRUCT
    let hdc = BeginPaint(hwnd, addr ps)
    var rc: RECT
    GetClientRect(hwnd, addr rc)
    let w = int(rc.right - rc.left)
    let h = int(rc.bottom - rc.top)
    let memDC  = CreateCompatibleDC(hdc)
    let memBmp = CreateCompatibleBitmap(hdc, w.int32, h.int32)
    let oldBmp = SelectObject(memDC, memBmp)
    let br = CreateSolidBrush(CHROMA_KEY)
    FillRect(memDC, addr rc, br)
    DeleteObject(br)
    if not gOvr.drawProc.isNil:
      gOvr.drawProc(DrawContext(hdc: memDC, width: w, height: h))
    BitBlt(hdc, 0, 0, w.int32, h.int32, memDC, 0, 0, SRCCOPY)
    SelectObject(memDC, oldBmp); DeleteObject(memBmp); DeleteDC(memDC)
    EndPaint(hwnd, addr ps)
    return 0
  of WM_TIMER:
    if gOvr.targetHwnd != 0:
      if IsWindow(gOvr.targetHwnd) == FALSE:
        PostMessageW(hwnd, WM_CLOSE, 0, 0)
        return 0
      var trc: RECT
      GetWindowRect(gOvr.targetHwnd, addr trc)
      SetWindowPos(hwnd, HWND_TOPMOST,
                   trc.left, trc.top,
                   trc.right - trc.left, trc.bottom - trc.top,
                   SWP_NOACTIVATE or SWP_NOSENDCHANGING)
    InvalidateRect(hwnd, nil, FALSE)
    return 0
  
  of WM_DESTROY:
    KillTimer(hwnd, 1)
    gOvr.running = false
    PostQuitMessage(0)
    return 0
  of WM_ERASEBKGND:
    return 1
  else:
    return DefWindowProcW(hwnd, msg, wParam, lParam)

proc createOverlay*(targetHwnd: HWND, drawCb: DrawProc): bool =
  gOvr.targetHwnd = targetHwnd
  gOvr.drawProc   = drawCb
  gOvr.running    = true

  let hInst = GetModuleHandleW(nil)
  let wName  = newWideCString(OVERLAY_CLASS)

  var wc: WNDCLASSEXW
  wc.cbSize        = DWORD(sizeof(WNDCLASSEXW))
  wc.style         = CS_HREDRAW or CS_VREDRAW
  wc.lpfnWndProc   = overlayWndProc
  wc.hInstance     = hInst
  wc.hbrBackground = cast[HBRUSH](nil)
  wc.lpszClassName = wName
  discard RegisterClassExW(addr wc)

  var x, y, w, h: int32
  if targetHwnd != 0 and IsWindow(targetHwnd) == TRUE:
    var trc: RECT
    GetWindowRect(targetHwnd, addr trc)
    x = trc.left; y = trc.top
    w = trc.right - trc.left; h = trc.bottom - trc.top
  else:
    x = 0; y = 0
    w = GetSystemMetrics(SM_CXSCREEN)
    h = GetSystemMetrics(SM_CYSCREEN)

  let wTitle = newWideCString("")

  gOvr.hwnd = CreateWindowExW(
    WS_EX_LAYERED    or
    WS_EX_TRANSPARENT or
    WS_EX_TOPMOST    or
    WS_EX_TOOLWINDOW or
    WS_EX_NOACTIVATE,
    wName, wTitle,
    WS_POPUP,
    x, y, w, h,
    0, 0, hInst, nil)

  if gOvr.hwnd == 0: return false

  SetLayeredWindowAttributes(gOvr.hwnd, CHROMA_KEY, 255, LWA_COLORKEY)
  ShowWindow(gOvr.hwnd, SW_SHOWNOACTIVATE)
  UpdateWindow(gOvr.hwnd)
  SetTimer(gOvr.hwnd, 1, 16, nil)
  true

proc runOverlay*() =
  var msg: MSG
  while gOvr.running and GetMessageW(addr msg, 0, 0, 0) == TRUE:
    TranslateMessage(addr msg)
    DispatchMessageW(addr msg)

proc stopOverlay*() = 
  if gOvr.hwnd != 0: PostMessageW(gOvr.hwnd, WM_CLOSE, 0, 0)
proc overlayRunning*(): bool = gOvr.running