#include "startup.h"
#include "log.h"

#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <string>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace {

const wchar_t* kTaskName = L"netvis";

std::wstring ExePathW() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return std::wstring(buf, n);
}

// RAII COM init that tolerates COM already being initialized on the thread.
struct ComScope {
    bool inited = false;
    ComScope() {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        inited = SUCCEEDED(hr); // S_FALSE (already init, same mode) is SUCCEEDED and must be balanced
    }
    ~ComScope() {
        if (inited) CoUninitialize();
    }
};

// Opens the Task Scheduler root folder. Caller releases both out-params.
bool OpenRootFolder(ITaskService** outService, ITaskFolder** outRoot) {
    *outService = nullptr;
    *outRoot = nullptr;
    ITaskService* svc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&svc)))
        return false;
    if (FAILED(svc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t()))) {
        svc->Release();
        return false;
    }
    ITaskFolder* root = nullptr;
    if (FAILED(svc->GetFolder(_bstr_t(L"\\"), &root))) {
        svc->Release();
        return false;
    }
    *outService = svc;
    *outRoot = root;
    return true;
}

} // namespace

namespace startup {

bool IsEnabled() {
    ComScope com;
    ITaskService* svc = nullptr;
    ITaskFolder* root = nullptr;
    if (!OpenRootFolder(&svc, &root)) return false;

    IRegisteredTask* task = nullptr;
    bool exists = SUCCEEDED(root->GetTask(_bstr_t(kTaskName), &task)) && task != nullptr;
    if (task) task->Release();
    root->Release();
    svc->Release();
    return exists;
}

bool SetEnabled(bool on) {
    ComScope com;
    ITaskService* svc = nullptr;
    ITaskFolder* root = nullptr;
    if (!OpenRootFolder(&svc, &root)) {
        Log("startup: could not open Task Scheduler");
        return false;
    }

    bool ok = false;

    if (!on) {
        HRESULT hr = root->DeleteTask(_bstr_t(kTaskName), 0);
        // 0x80070002 = ERROR_FILE_NOT_FOUND: already absent, treat as success.
        ok = SUCCEEDED(hr) || hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        Log("startup: delete task -> hr=0x%08lx", (unsigned long)hr);
    } else {
        ITaskDefinition* def = nullptr;
        if (SUCCEEDED(svc->NewTask(0, &def))) {
            if (IRegistrationInfo* reg = nullptr; SUCCEEDED(def->get_RegistrationInfo(&reg)) && reg) {
                reg->put_Author(_bstr_t(L"netvis"));
                reg->Release();
            }
            // Highest privileges, running as the interactive (logging-on) user.
            if (IPrincipal* prin = nullptr; SUCCEEDED(def->get_Principal(&prin)) && prin) {
                prin->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
                prin->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
                prin->Release();
            }
            if (ITaskSettings* set = nullptr; SUCCEEDED(def->get_Settings(&set)) && set) {
                set->put_StartWhenAvailable(VARIANT_TRUE);
                set->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
                set->put_StopIfGoingOnBatteries(VARIANT_FALSE);
                set->put_ExecutionTimeLimit(_bstr_t(L"PT0S")); // no time limit
                set->Release();
            }
            // Trigger: at logon of the current user.
            if (ITriggerCollection* trigs = nullptr; SUCCEEDED(def->get_Triggers(&trigs)) && trigs) {
                ITrigger* trig = nullptr;
                if (SUCCEEDED(trigs->Create(TASK_TRIGGER_LOGON, &trig)) && trig) {
                    if (ILogonTrigger* lt = nullptr; SUCCEEDED(trig->QueryInterface(IID_ILogonTrigger, (void**)&lt)) && lt) {
                        lt->put_Id(_bstr_t(L"logon"));
                        lt->Release();
                    }
                    trig->Release();
                }
                trigs->Release();
            }
            // Action: run netvis.exe from its own folder.
            if (IActionCollection* acts = nullptr; SUCCEEDED(def->get_Actions(&acts)) && acts) {
                IAction* act = nullptr;
                if (SUCCEEDED(acts->Create(TASK_ACTION_EXEC, &act)) && act) {
                    if (IExecAction* ea = nullptr; SUCCEEDED(act->QueryInterface(IID_IExecAction, (void**)&ea)) && ea) {
                        std::wstring exe = ExePathW();
                        ea->put_Path(_bstr_t(exe.c_str()));
                        size_t slash = exe.find_last_of(L"\\/");
                        if (slash != std::wstring::npos)
                            ea->put_WorkingDirectory(_bstr_t(exe.substr(0, slash).c_str()));
                        ea->Release();
                    }
                    act->Release();
                }
                acts->Release();
            }

            IRegisteredTask* reged = nullptr;
            HRESULT hr = root->RegisterTaskDefinition(_bstr_t(kTaskName), def, TASK_CREATE_OR_UPDATE, _variant_t(),
                                                       _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(), &reged);
            ok = SUCCEEDED(hr);
            if (reged) reged->Release();
            if (!ok) Log("startup: RegisterTaskDefinition failed hr=0x%08lx", (unsigned long)hr);
            def->Release();
        }
    }

    root->Release();
    svc->Release();
    Log("startup: SetEnabled(%d) -> %s", (int)on, ok ? "ok" : "failed");
    return ok;
}

} // namespace startup
