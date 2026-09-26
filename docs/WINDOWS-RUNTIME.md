# Windows runtime prerequisite

The x64 executables use Microsoft's Visual C++ v14 runtime, including VCRUNTIME140.dll. Many Windows PCs already have it, but the app does not assume it is installed.

Install or repair the **latest supported Visual C++ v14 Redistributable, X64** from Microsoft's official page:

https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist

The currently documented official X64 permalink is:

https://aka.ms/vc14/vc_redist.x64.exe

Run the Microsoft installer, approve its own license/elevation prompt, restart if requested, then launch rejection-rejector.exe. Do not download individual DLLs from third-party sites, copy random DLLs into System32, uninstall other runtimes or disable Windows security globally.

The runtime must be at least as recent as the MSVC toolset used to build the app. Windows 11 is a supported OS for the current Microsoft package. The application ZIP does not silently install or redistribute Microsoft's installer. Ollama installation is a separate, explicitly confirmed action inside the Local AI tab.
