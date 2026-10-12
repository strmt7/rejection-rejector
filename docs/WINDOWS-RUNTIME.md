# Windows runtime prerequisite

Rejection Rejector's Windows executables (`rejection-rejector.exe` and `rr.exe`) are
64-bit native programs built with Microsoft's Visual C++ toolchain. Like most programs
built that way, they depend on the **Microsoft Visual C++ Redistributable** — a small
set of Microsoft-provided runtime libraries, including `VCRUNTIME140.dll`. Many Windows
PCs already have it. The application does not assume it is installed, and it never
installs it silently.

## Install or repair the runtime

1. Get the **latest supported Visual C++ Redistributable, X64** from Microsoft's
   official download page:
   https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist
2. The currently documented official X64 permalink is:
   https://aka.ms/vc14/vc_redist.x64.exe
3. Run the Microsoft installer, approve its own license and elevation prompt, and
   restart Windows if the installer asks. Then start `rejection-rejector.exe`.

If the application still reports a missing `VCRUNTIME140.dll` (or a similar runtime
DLL), use the installer's **Repair** option. Do not copy DLLs by hand.

### What not to do

Do not download individual DLLs from third-party "DLL download" sites, copy random
DLLs into `C:\Windows\System32`, uninstall other versions of the runtime, or disable
Windows security features. Unofficial DLL sources are a common malware distribution
path; see [THREAT_MODEL.md](THREAT_MODEL.md) for the trust assumptions this project
makes about the operating system and its libraries.

## Why the version matters

The installed runtime must be at least as recent as the Microsoft toolset used to build
the app; an older runtime is missing functions the binary needs. Windows 11 is a
supported OS for the current Microsoft package. The application ZIP does not silently
install or redistribute Microsoft's installer. Ollama installation is a separate,
explicitly confirmed action inside the **Local AI** tab (see [SETUP.md](SETUP.md)).

## Embedded application manifest

Both Windows executables embed a tracked Win32 application manifest at link time. A
**manifest** is a small XML resource that tells Windows how a program should be run —
for example whether it requires administrator rights. CI extracts the manifest resource
from the actual shipped binaries with the Windows SDK manifest tool and checks the
required declarations, so a build cannot silently lose them.

The manifest deliberately requests **asInvoker** with `uiAccess=false`: normal
application startup must not require administrative elevation. It also declares:

- **Windows 10/11 compatibility** — Windows treats the app as built for current Windows
  instead of applying older compatibility shims.
- **Per-Monitor V2 DPI awareness** — the app renders sharply on mixed-resolution
  multi-monitor setups and rescales correctly when a window moves between displays.
- **UTF-8 as the process active code page** — improves Unicode interoperability for
  file names and text on modern Windows.
- **Long-path awareness** — the application-side opt-in for paths longer than the
  historic 260-character `MAX_PATH` limit. Windows additionally requires the machine's
  `LongPathsEnabled` policy/registry setting before Win32 APIs honor long paths.

These declarations improve high-DPI/multi-monitor behavior, Unicode interoperability
and deep-path handling, but they do not replace the separate Windows Narrator/IME/DPI
acceptance checklist in [ACCESSIBILITY.md](ACCESSIBILITY.md).

## Sources (checked 2026-10-12)

- Microsoft Learn, "Latest supported Visual C++ downloads":
  https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist
- Microsoft Learn, "Application manifests" (`requestedExecutionLevel` / `asInvoker`):
  https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests
- Microsoft Learn, "Setting the default DPI awareness for a process" (Per-Monitor V2):
  https://learn.microsoft.com/en-us/windows/win32/hidpi/setting-the-default-dpi-awareness-for-a-process
- Microsoft Learn, "Maximum Path Length Limitation" (`MAX_PATH` and `LongPathsEnabled`):
  https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation
