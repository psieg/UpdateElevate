#include "taskScheduler.h"
#include "common.h"

/********************************************************************
This sample schedules a task to start on a weekly basis.
********************************************************************/
#include <Sddl.h>

#include <iostream>
#include <stdio.h>
#include <comdef.h>
#include <wincred.h>
//  Include the task header file.
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "credui.lib")

using namespace std;


DWORD schedule(bool install)
{
	//  ------------------------------------------------------
	//  Initialize COM.
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		printf("\nCoInitializeEx failed: %x", hr);
		return 1;
	}

	//  Set general COM security levels.
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

	if (FAILED(hr))
	{
		printf("\nCoInitializeSecurity failed: %x", hr);
		CoUninitialize();
		return 1;
	}

	//  ------------------------------------------------------
	//  Create a name for the task.
	LPCWSTR wszTaskName = FULLID;

	//  Get the windows directory and set the path to notepad.exe.
	HMODULE hModule = GetModuleHandleW(NULL);
	WCHAR executablePath[MAX_PATH];
	GetModuleFileName(hModule, executablePath, MAX_PATH);
	WCHAR arg[] = L"trigger";


	//  ------------------------------------------------------
	//  Create an instance of the Task Service. 
	ITaskService *pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)&pService);
	if (FAILED(hr))
	{
		printf("Failed to create an instance of ITaskService: %x", hr);
		CoUninitialize();
		return 1;
	}

	//  Connect to the task service.
	hr = pService->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());
	if (FAILED(hr))
	{
		printf("ITaskService::Connect failed: %x", hr);
		pService->Release();
		CoUninitialize();
		return 1;
	}

	//  ------------------------------------------------------
	//  Get the pointer to the root task folder.  
	//  This folder will hold the new task that is registered.
	ITaskFolder *pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
	if (FAILED(hr))
	{
		printf("Cannot get Root Folder pointer: %x", hr);
		pService->Release();
		CoUninitialize();
		return 1;
	}

	//  If the same task exists, remove it.
	pRootFolder->DeleteTask(_bstr_t(wszTaskName), 0);

	if (install) {

		//  Create the task builder object to create the task.
		ITaskDefinition *pTask = NULL;
		hr = pService->NewTask(0, &pTask);

		pService->Release();  // COM clean up.  Pointer is no longer used.
		if (FAILED(hr))
		{
			printf("Failed to create a task definition: %x", hr);
			pRootFolder->Release();
			CoUninitialize();
			return 1;
		}

		//  ------------------------------------------------------
		//  Get the registration info for setting the identification.
		IRegistrationInfo *pRegInfo = NULL;
		hr = pTask->get_RegistrationInfo(&pRegInfo);
		if (FAILED(hr))
		{
			printf("\nCannot get identification pointer: %x", hr);
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		hr = pRegInfo->put_Author( NAME L" (Patrick Siegler)");
		pRegInfo->Release();  // COM clean up.  Pointer is no longer used.
		if (FAILED(hr))
		{
			printf("\nCannot put identification info: %x", hr);
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}


		//  ------------------------------------------------------
		//  Set other settings for the task

		//  Create the settings for the task
		ITaskSettings *pSettings = NULL;
		hr = pTask->get_Settings(&pSettings);
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		//  Set setting values for the task. 
		pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
		pSettings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
		pSettings->Release();

		//  ------------------------------------------------------
		//  Set the task to run elevated

		IPrincipal *pPrincipal;
		hr = pTask->get_Principal(&pPrincipal);
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);


		//  ------------------------------------------------------
		//  Get the trigger collection to insert the weekly trigger.
		ITriggerCollection *pTriggerCollection = NULL;
		hr = pTask->get_Triggers(&pTriggerCollection);
		if (FAILED(hr))
		{
			printf("\nCannot get trigger collection: %x", hr);
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
			printf("\nCannot create the trigger: %x", hr);
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		IEventTrigger *pEventTrigger = NULL;
		hr = pTrigger->QueryInterface(
			IID_IEventTrigger, (void**)&pEventTrigger);
		pTrigger->Release();
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		PCWSTR query = L"<QueryList><Query Id=\"0\" Path=\"Application\"><Select Path=\"Application\">*[System[Provider[@Name='" FULLID L"'] and EventID=" EVT_ID_REQUEST_S L"]]</Select></Query></QueryList>";

		hr = pEventTrigger->put_Subscription(_bstr_t(query));
		pEventTrigger->Release();

		//  ------------------------------------------------------
		//  Add an Action to the task. This task will execute notepad.exe.     
		IActionCollection *pActionCollection = NULL;

		//  Get the task action collection pointer.
		hr = pTask->get_Actions(&pActionCollection);
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		//  Create the action, specifying that it is an executable action.
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
		//  QI for the executable task pointer.
		hr = pAction->QueryInterface(
			IID_IExecAction, (void**)&pExecAction);
		pAction->Release();
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		//  Set the path of the executable to notepad.exe.
		hr = pExecAction->put_Path(_bstr_t(executablePath));
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		//  Set the path of the executable to notepad.exe.
		hr = pExecAction->put_Arguments(_bstr_t(arg));
		pExecAction->Release();
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}


		//  ------------------------------------------------------
		//  Save the task in the root folder.
		VARIANT varnull;
		varnull.vt = VT_NULL;

		BSTR xml;
		pTask->get_XmlText(&xml);

		IRegisteredTask *pRegisteredTask = NULL;
		hr = pRootFolder->RegisterTaskDefinition(
			_bstr_t(wszTaskName),
			pTask,
			TASK_CREATE_OR_UPDATE,
			_variant_t(_bstr_t(L"S-1-5-18")), // SYSTEM account
			varnull,
			TASK_LOGON_SERVICE_ACCOUNT,
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
	}

	//  Clean up
	pRootFolder->Release();
	CoUninitialize();
	return 0;
}

