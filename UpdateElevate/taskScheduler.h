
#define _WIN32_DCOM

#include <string>

#include <windows.h>

DWORD schedule(bool install);
DWORD schedule_cb(bool install, const std::wstring& callback);