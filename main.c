// A patcher to let people on official XDKs run unsigned code (other than DXTs).
// (C)2020 Jannik Vogel

//FIXME: Needs detours
//FIXME: Untested
//FIXME: Needs to be compiled as DXT

#include <stdint.h>
#include <stdbool.h>
#include <winapi/winbase.h>
#include <xboxkrnl/xboxkrnl.h>
#include <xbdm/xbdm.h>

//FIXME: Remove soon, needed for `SUCCEEDED`-macro
#include <hal/winerror.h>

//FIXME: Alternative method to patch regions:
// Key XboxAlternateSignatureKeys[XBEIMAGE_ALTERNATE_TITLE_ID_COUNT]; // < export
// Key XboxCERTKey;
// Key XboxGameRegion; // < needs patching ?

static uintptr_t sWeX_allocation = 0;
static uint32_t real_regions;
static uint32_t real_media_types;
static bool patched = false;

static uint32_t* xbe = (uint32_t*)0x10000;

//FIXME: Might not be needed
static PVOID(NTAPI *real_ExAllocatePoolWithTag)(SIZE_T, ULONG) = NULL;
static pfXcPKEncPublic real_XcPKEncPublic = NULL;
static pfXcVerifyPKCS1Signature real_VerifyPKCS1Signature = NULL;

static void unpatch_xbe(void) {
  if (!patched) {
    return;
  }

  // Get certificate pointer
  uint32_t* certificate = (uint32_t*)xbe[0x118/4];

  // Patch certificate media type back
  certificate[0x9C/4] = real_media_types;

  // Patch certificate region back
  certificate[0xA0/4] = real_regions;

  // Mark file as unpatched
  OutputDebugString("XBE was partially restored");
  patched = true;
}

static void patch_xbe(void) {
  if (patched) {
    return;
  }

  // Patch entrypoint and kernel thunk with suitable key
  if ((xbe[0x128/4] & 0xF0000000) == 0xA0000000) {
    OutputDebugString("Loading retail XBE");
    xbe[0x128/4] ^= 0xA8FC57AB; // EP [retail]
    xbe[0x158/4] ^= 0x5B6D40B6; // KT [retail]
  } else if ((xbe[0x128/4] & 0xF0000000) == 0x90000000) {
    OutputDebugString("Loading debug XBE");
    xbe[0x128/4] ^= 0x94859D4B; // EP [debug]
    xbe[0x158/4] ^= 0xEFB1F152; // KT [debug]
  } else {
    OutputDebugString("Loading unknown XBE");
    return;
  }

  // Undo future kernel entrypoint and kernel thunk transformations
  uint32_t* kernel_xors = (uint32_t*)&XePublicKeyData[128];
  xbe[0x128/4] ^= kernel_xors[0] ^ kernel_xors[4]; // EP
  xbe[0x158/4] ^= kernel_xors[1] ^ kernel_xors[2]; // KT

  // Get certificate pointer
  uint32_t* certificate = (uint32_t*)xbe[0x118/4];

  // Patch certificate to allow any media type
  real_media_types = certificate[0x9C/4];
  certificate[0x9C/4] |= 0x00FFFFFF;

  // Patch certificate to allow any region
  //FIXME: Pick one from XboxGameRegion, so we don't pick an unsupported language
  real_regions = certificate[0xA0/4];
  certificate[0xA0/4] |= 0x7FFFFFFF;

  // Mark file as patched
  OutputDebugString("XBE is patched");
  patched = true;
}


static PVOID NTAPI hook_ExAllocatePoolWithTag(SIZE_T NumberOfBytes, ULONG Tag) {
  PVOID result = real_ExAllocatePoolWithTag(NumberOfBytes, Tag);
  if (Tag == 'sWeX') {
    //FIXME: Also check `NumberOfBytes`?
    sWeX_allocation = (uintptr_t)result;
  }
  return result;
}

static ULONG NTAPI hook_XcPKEncPublic(PUCHAR pbPubKey, PUCHAR pbInput, PUCHAR pbOutput) {
  if (sWeX_allocation != 0) {
    // Check the conditions
    if (pbPubKey == XePublicKeyData) {
      if (pbInput == (PUCHAR)(sWeX_allocation+0)) {
        if (pbOutput == (PUCHAR)(sWeX_allocation+0)) { //FIXME: !!!
          // Force success
          return TRUE;
        }
      }
    }
  }
  return real_XcPKEncPublic(pbPubKey, pbInput, pbOutput);
}

static BOOLEAN NTAPI hook_XCVerifyPKCS1SigningFmt(PUCHAR pbSig, PUCHAR pbPubKey, PUCHAR pbDigest) {
  if (sWeX_allocation != 0) {
    // Check the conditions
    if (pbSig == (PUCHAR)&xbe[0x4/4]) {
      if (pbPubKey == XePublicKeyData) {
        if (pbDigest == (PUCHAR)(sWeX_allocation+0)) { //FIXME: !!!
          // Patch XBE
          patch_xbe();

          // Reset state of hook
          sWeX_allocation = 0;

          // Force success
          return TRUE;
        }
      }
    }
  }
  return hook_XCVerifyPKCS1SigningFmt(pbSig, pbPubKey, pbDigest);
}

static void patch_kernel(void) {
  //FIXME: Disable kernel write protection
  //FIXME: Do these step by step as necessary instead?
  //FIXME: Hook ExAllocatePoolWithTag
  //FIXME: Hook XcPKEncPublic
  //FIXME: Hook XCVerifyPKCS1SigningFmt
  //FIXME: Enable kernel write protection
}

static void unpatch_kernel(void) {
  //FIXME: Disable kernel write protection
  //FIXME: ...
  //FIXME: Enable kernel write protection
}

DWORD NTAPI modload_callback(ULONG Notification, DWORD Parameter) {
  PDMN_MODLOAD Module = (PDMN_MODLOAD)Parameter;

  // Early out if this isn't what we wanted
  if (Notification != DM_MODLOAD) {
    return 0;
  }

  // Early out if no XBE was loaded
  if ((XeImageFileName->Length == 0) || (XeImageFileName->Buffer == NULL)) {
    return 0;
  }

  // Unpatch XBE, with exception of EP and KT
  unpatch_xbe();

  // Remove our patches (we'll be reloaded for the next XBE anyway)
  unpatch_kernel();

  // Close notification session
  //FIXME: DmCloseNotificationSession();

  // Unload ourselves
  //FIXME: DmUnloadExtension(module)

  return 0;
}


VOID NTAPI DxtEntry(ULONG* pfUnload) {
  static PDMN_SESSION DmSession;

  // Show that we are alive
  OutputDebugString("Debug Loader DXT loaded");

  // Create notification session
  HRESULT hr = DmOpenNotificationSession(DM_PERSISTENT, &DmSession);

  // Register callback for when the XBE is loaded
  if (SUCCEEDED(hr)) {
    hr = DmNotify(DmSession, DM_MODLOAD, modload_callback);
  }

  // Add kernel hooks
  if (SUCCEEDED(hr)) {
    patch_kernel();
  }

  // Remain in memory on success
  if (SUCCEEDED(hr)) {
    *pfUnload = FALSE;
  } else {
    *pfUnload = TRUE;
  }
}
