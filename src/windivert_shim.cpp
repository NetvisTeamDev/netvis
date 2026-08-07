#include "windivert_shim.h"
#include <string>

namespace wd {

bool LoadApi(Api& api, std::string* error) {
    api.dll = LoadLibraryW(L"WinDivert.dll");
    if (!api.dll) {
        if (error) *error = "LoadLibrary(WinDivert.dll) failed - is WinDivert.dll next to the exe?";
        return false;
    }
    api.Open = reinterpret_cast<OpenFn>(GetProcAddress(api.dll, "WinDivertOpen"));
    api.Recv = reinterpret_cast<RecvFn>(GetProcAddress(api.dll, "WinDivertRecv"));
    api.Send = reinterpret_cast<SendFn>(GetProcAddress(api.dll, "WinDivertSend"));
    api.Close = reinterpret_cast<CloseFn>(GetProcAddress(api.dll, "WinDivertClose"));
    api.CalcChecksums = reinterpret_cast<CalcChecksumsFn>(GetProcAddress(api.dll, "WinDivertHelperCalcChecksums"));
    if (!api.Open || !api.Recv || !api.Send || !api.Close || !api.CalcChecksums) {
        if (error) *error = "GetProcAddress failed for one or more WinDivert functions - wrong/old WinDivert.dll?";
        return false;
    }
    return true;
}

} // namespace wd
