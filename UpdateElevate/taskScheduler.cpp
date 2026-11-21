#include "taskScheduler.h"
#include "common.h"

#include <Sddl.h>
#include <ctime>
#include <stdio.h>
#include <comdef.h>
#include <taskschd.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

using namespace std;

static std::wstring escapeCommandLineArg(const std::wstring& arg) {
	std::wstring out = L"\"";
	size_t backslashes = 0;
	for (wchar_t ch : arg) {
		if (ch == L'\\') {
			++backslashes;
		} else if (ch == L'"') {
			out.append(backslashes * 2 + 1, L'\\');
			out.push_back(L'"');
			backslashes = 0;
		} else {
			out.append(backslashes, L'\\');
			backslashes = 0;
			out.push_back(ch);
		}
	}
	out.append(backslashes * 2, L'\\');
	out.push_back(L'"');
	return out;
}

static DWORD scheduleInternal(bool install, bool elevate, BSTR name, BSTR condition, BSTR args);

DWORD schedule(bool install) {
	_bstr_t query(L"<QueryList><Query Id=\"0\" Path=\"Application\"><Select Path=\"Application\">*[System[Provider[@Name='" FULLID L"'] and EventID=" EVT_ID_REQUEST_S L"]]</Select></Query></QueryList>");
	_bstr_t args(L"trigger \"$(pkgPath)\"");
	_bstr_t taskName(FULLID);

	return scheduleInternal(install, true, taskName, query, args);
}

DWORD schedule_cb(bool install, const wstring& callbackExe) {
	_bstr_t query(L"<QueryList><Query Id=\"0\" Path=\"Application\"><Select Path=\"Application\">*[System[Provider[@Name='" FULLID L"'] and EventID=" EVT_ID_COMPLETED_S L"]]</Select></Query></QueryList>");
	wstring args = L"completed";
	if (!callbackExe.empty()) {
		args.append(L" ");
		args.append(escapeCommandLineArg(callbackExe));
	}
	_bstr_t bargs(args.c_str());
	_bstr_t taskName(FULLIDCB);

	return scheduleInternal(install, false, taskName, query, bargs);
}

static DWORD scheduleInternal(bool install, bool elevate, BSTR name, BSTR condition, BSTR args)
{
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
		return 1;

	hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		0,
		NULL);

	if (FAILED(hr) && hr != RPC_E_TOO_LATE)
	{
		CoUninitialize();
		return 1;
	}

	ITaskService *pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)&pService);
	if (FAILED(hr))
	{
		CoUninitialize();
		return 1;
	}

	hr = pService->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());
	if (FAILED(hr))
	{
		pService->Release();
		CoUninitialize();
		return 1;
	}

	ITaskFolder *pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
	if (FAILED(hr))
	{
		pService->Release();
		CoUninitialize();
		return 1;
	}

	pRootFolder->DeleteTask(name, 0);

	if (install) {
		ITaskDefinition *pTask = NULL;
		hr = pService->NewTask(0, &pTask);
		pService->Release();
		pService = NULL;
		if (FAILED(hr))
		{
			pRootFolder->Release();
			CoUninitialize();
			return 1;
		}

		IRegistrationInfo *pRegInfo = NULL;
		hr = pTask->get_RegistrationInfo(&pRegInfo);
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		hr = pRegInfo->put_Author(_bstr_t(NAME L" (Automatic Updater)"));
		pRegInfo->Release();
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		ITaskSettings *pSettings = NULL;
		hr = pTask->get_Settings(&pSettings);
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
		pSettings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
		pSettings->Release();

		if (elevate) {
			IPrincipal *pPrincipal = NULL;
			hr = pTask->get_Principal(&pPrincipal);
			if (FAILED(hr))
			{
				pRootFolder->Release();
				pTask->Release();
				CoUninitialize();
				return 1;
			}

			pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
			pPrincipal->Release();
		}

		ITriggerCollection *pTriggerCollection = NULL;
		hr = pTask->get_Triggers(&pTriggerCollection);
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		ITrigger *pTrigger = NULL;
		hr = pTriggerCollection->Create(TASK_TRIGGER_EVENT, &pTrigger);
		pTriggerCollection->Release();
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		IEventTrigger *pEventTrigger = NULL;
		hr = pTrigger->QueryInterface(IID_IEventTrigger, (void**)&pEventTrigger);
		pTrigger->Release();
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		hr = pEventTrigger->put_Subscription(condition);
		if (FAILED(hr))
		{
			pEventTrigger->Release();
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		if (!elevate) {
			time_t now;
			time(&now);
			now += 60 * 10;
			char buf[sizeof "2011-10-08T07:07:09Z"];
			tm expiry;
			gmtime_s(&expiry, &now);
			strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &expiry);

			hr = pEventTrigger->put_EndBoundary(_bstr_t(buf));
			if (FAILED(hr))
			{
				pEventTrigger->Release();
				pRootFolder->Release();
				pTask->Release();
				CoUninitialize();
				return 1;
			}
		}

		ITaskNamedValueCollection *pCollection = NULL;
		hr = pEventTrigger->get_ValueQueries(&pCollection);
		if (FAILED(hr))
		{
			pEventTrigger->Release();
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		ITaskNamedValuePair *pPair = NULL;
		hr = pCollection->Create(_bstr_t(L"pkgPath"), _bstr_t(L"Event/EventData/Data"), &pPair);
		if (FAILED(hr))
		{
			pCollection->Release();
			pEventTrigger->Release();
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		pPair->Release();
		pCollection->Release();
		pEventTrigger->Release();

		IActionCollection *pActionCollection = NULL;
		hr = pTask->get_Actions(&pActionCollection);
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		IAction *pAction = NULL;
		hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
		pActionCollection->Release();
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		IExecAction *pExecAction = NULL;
		hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
		pAction->Release();
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		HMODULE hModule = GetModuleHandleW(NULL);
		WCHAR executablePath[MAX_PATH];
		DWORD pathLen = GetModuleFileNameW(hModule, executablePath, MAX_PATH);
		if (pathLen == 0 || pathLen >= MAX_PATH)
		{
			pExecAction->Release();
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		wstring quotedExe = escapeCommandLineArg(executablePath);
		hr = pExecAction->put_Path(_bstr_t(quotedExe.c_str()));
		if (FAILED(hr))
		{
			pExecAction->Release();
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		hr = pExecAction->put_Arguments(args);
		pExecAction->Release();
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		VARIANT varnull;
		VariantInit(&varnull);
		varnull.vt = VT_NULL;

		IRegisteredTask *pRegisteredTask = NULL;
		hr = pRootFolder->RegisterTaskDefinition(
			name,
			pTask,
			TASK_CREATE_OR_UPDATE,
			elevate ? _variant_t(_bstr_t(L"S-1-5-18")) : varnull,
			varnull,
			TASK_LOGON_INTERACTIVE_TOKEN,
			_variant_t(L""),
			&pRegisteredTask);
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		pTask->Release();
		pRegisteredTask->Release();
	} else {
		pService->Release();
	}

	pRootFolder->Release();
	CoUninitialize();
	return 0;
}
