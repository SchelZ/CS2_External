import winim/lean

var gTlsPoison* {.exportc: "tlscb_gTlsPoison".}: uint64 = 0
var gTlsCanary* {.exportc: "tlscb_gTlsCanary".}: uint64 = 0

{.emit: """
#include <windows.h>
#include <stdint.h>

extern uint64_t tlscb_gTlsPoison;
extern uint64_t tlscb_gTlsCanary;

#define CANARY_MAGIC 0xFEEDFACEDEADC0DEULL

__declspec(thread) volatile int _tls_anchor = 0;

static void __stdcall tlsCallbackC(PVOID module, DWORD reason, PVOID reserved) {
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return;

    uint64_t peb = 0;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));

    if (peb != 0) {
        uint8_t  beingDebugged = *(volatile uint8_t* )(peb + 0x02);
        uint32_t ntGlobalFlag  = *(volatile uint32_t*)(peb + 0xBC);
        if (beingDebugged || (ntGlobalFlag & 0x70u)) {
            tlscb_gTlsPoison = 0xBADBADBADBADBAD1ULL;
        }
    }

    uint64_t base = (uint64_t)(uintptr_t)module;
    tlscb_gTlsCanary = CANARY_MAGIC ^ base;
}

/* static  = internal linkage (prevents Nim getTypeDescAux error)
   __attribute__((used)) = tells GCC/ld to NEVER strip this symbol
   Together they solve both problems. */
#pragma section(".CRT$XLB", read)
__declspec(allocate(".CRT$XLB"))
static PIMAGE_TLS_CALLBACK _tls_callback_entry
    __attribute__((used)) = (PIMAGE_TLS_CALLBACK)tlsCallbackC;
""".}

proc verifyTlsCanary*(): bool =
  ## Returns false if a debugger was detected during TLS phase.
  ## Compile with -d:tlsStrict to also catch a missing canary (callback
  ## never ran). Only enable tlsStrict in --app:gui release builds —
  ## console/debug builds may not execute .CRT$XLB entries.
  if gTlsPoison != 0: return false
  when defined(tlsStrict):
    if gTlsCanary == 0: return false
  true