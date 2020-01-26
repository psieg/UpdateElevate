
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <AclAPI.h>

#include <string>
#include <iostream>
#include <fstream>
#include <vector>
using namespace std;

#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "common.h"
#include "taskScheduler.h"

#define E_ARGS 1000
#define E_FILES_MISSING 1001
#define E_SIG_FAIL 1002
#define E_PRIVILEGE 1003

#define PUBKEY "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvOzz+Ih6jYbyEsjkF28s\n\
Four2hRPEjJCVXfHf2+sbFONqnPpM18Ri0+4zOidaZf/l790AJOh5YJZfVhPHTQa\n\
GTUWagPQ9RrXDDymFprQFpBXJSJvnFjOWGazB2x+dA+RrGiKymujrE5RIScHDeUC\n\
GJ60dGzGzAulWoFlbzkNMlO4HuyXJB8hgsFNNI1a9Bezv5ApfG+xtLvWznmiAvW5\n\
y7gwrFL3sko5bRhjGrzfKI/WT9XTzbwwIt8Wg2oOzg2PfBoXrMTRtrXuHkh9AyVH\n\
/Mi+3pBeT8TaaRsPD6s/qX/lphmaGNfuyKCENDcZKCUmGcFXSxFxPpBXcrSqn5hm\n\
LwIDAQAB\n\
-----END PUBLIC KEY-----"

BOOL logError(LPCWSTR msg) {
	HANDLE hEventSrc = RegisterEventSourceW(NULL, FULLID);
	BOOL rc = ReportEvent(hEventSrc, EVENTLOG_ERROR_TYPE & 0xFFFF, 0, EVT_ID_LOG, NULL, 1, 0, &msg, NULL);
	DeregisterEventSource(hEventSrc);
	return !rc;
}

BOOL logMessage(LPCWSTR msg) {
	HANDLE hEventSrc = RegisterEventSourceW(NULL, FULLID);
	BOOL rc = ReportEvent(hEventSrc, EVENTLOG_INFORMATION_TYPE & 0xFFFF, 0, EVT_ID_LOG, NULL, 1, 0, &msg, NULL);
	DeregisterEventSource(hEventSrc);
	return !rc;
}

BOOL send_request(LPCWSTR filepath) {
	HANDLE hEventSrc = RegisterEventSourceW(NULL, FULLID);
	BOOL rc = ReportEvent(hEventSrc, EVENTLOG_INFORMATION_TYPE & 0xFFFF, 0, EVT_ID_REQUEST, NULL, 1, 0, &filepath, NULL);
	DeregisterEventSource(hEventSrc);
	return !rc;
}

BOOL send_completed() {
	HANDLE hEventSrc = RegisterEventSourceW(NULL, FULLID);
	BOOL rc = ReportEvent(hEventSrc, EVENTLOG_INFORMATION_TYPE & 0xFFFF, 0, EVT_ID_COMPLETED, NULL, 0, 0, NULL, NULL);
	DeregisterEventSource(hEventSrc);
	return !rc;
}

BOOL IsUserAdmin() {
	// http://msdn.microsoft.com/en-us/library/windows/desktop/aa376389%28v=vs.85%29.aspx

	BOOL b;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;
	b = AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&AdministratorsGroup);
	if (b)
	{
		if (!CheckTokenMembership(NULL, AdministratorsGroup, &b))
		{
			b = FALSE;
		}
		FreeSid(AdministratorsGroup);
	}

	return(b);
}

bool FileExists(const TCHAR *fileName)
{
	DWORD fileAttr;

	fileAttr = GetFileAttributes(fileName);
	if (0xFFFFFFFF == fileAttr)
		return false;
	return true;
}

DWORD prepFile(const wstring& filename) {
	EXPLICIT_ACCESS eas[2];
	PACL pACL = 0;
	DWORD rc;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	PSID pEveryoneSID = NULL;
	memset(eas, 0, sizeof(eas));
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
		SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID)) {
		return GetLastError();
	}

	eas[0].grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
	eas[0].grfAccessMode = GRANT_ACCESS;
	eas[0].grfInheritance = NO_INHERITANCE;
	eas[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	eas[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	eas[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

	eas[1].grfAccessPermissions = GENERIC_ALL;
	eas[1].grfAccessMode = GRANT_ACCESS;
	eas[1].grfInheritance = NO_INHERITANCE;
	eas[1].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
	eas[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	eas[1].Trustee.ptstrName = L"CURRENT_USER";

	rc = SetEntriesInAcl(2, &eas[0], NULL, &pACL);
	if (rc != ERROR_SUCCESS)
	{
		//wstring msg = L"entries" + std::to_wstring(rc);
		//logError(msg.c_str());
		//printf("SetEntriesInAcl: %u\n", rc);
		return rc;
	}

	TCHAR namebuf[40];
	DWORD bufs = 40;
	rc = GetUserName(namebuf, &bufs);
	if (!rc) {
		//wstring msg = L"name" + std::to_wstring(rc);
		//logError(msg.c_str());
		return GetLastError();
	}

	BYTE sidbuf[1024];
	bufs = 1024;
	TCHAR sidbuf2[1024];
	DWORD bufs2 = 1024;
	SID_NAME_USE snu;
	rc = LookupAccountName(NULL, namebuf, sidbuf, &bufs, sidbuf2, &bufs2, &snu);
	if (!rc){
		//wstring msg = L"lookup" + std::to_wstring(rc);
		//logError(msg.c_str());
		return GetLastError();
	}

	rc = SetNamedSecurityInfo((LPTSTR)filename.c_str(), SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
		sidbuf, NULL, pACL, NULL);
	if (rc) return rc;

	// because these files are now hard to remove, schedule them for deletion upon reboot (we might fail to delete it in case of errors)
#ifdef _DEBUG
	if (IsUserAdmin()) {
#endif
		rc = MoveFileEx(filename.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
		if (!rc) return GetLastError();
#ifdef _DEBUG
	}
#endif

	LocalFree(pACL);

	return 0;
}

DWORD copyAndPrepFile(const wstring& src, const wstring& dest) {
	SECURITY_ATTRIBUTES attrs;
	attrs.bInheritHandle = FALSE;
	attrs.lpSecurityDescriptor = NULL;
	attrs.nLength = sizeof(SECURITY_ATTRIBUTES);
	HANDLE hFile = CreateFile(dest.c_str(), GENERIC_WRITE, NULL, &attrs, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		logError(L"Create host copy failed");
		return GetLastError();
	}
	CloseHandle(hFile);

	DWORD rc = prepFile(dest);
	if (rc) {
		logError(L"prep host copy failed");
		return GetLastError();
	}

	rc = CopyFile(src.c_str(), dest.c_str(), FALSE);
	if (!rc) {
		logError(L"copy host copy failed");
		return E_FILES_MISSING;
	}

	return 0;
}

DWORD verifyRSASignature(unsigned char *originalMessage, std::streamsize om_length,
	unsigned char *signature, unsigned siglen)
{
	int result;
	BIO *bio;
	RSA *rsa_pubkey;

	bio = BIO_new(BIO_s_mem());
	int rc = BIO_puts(bio, PUBKEY);
	if (rc < 0) return 1;
	rsa_pubkey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
	if (!rsa_pubkey) return 1;

	SHA512_CTX sha_ctx = { 0 };
	unsigned char digest[SHA512_DIGEST_LENGTH];

	rc = SHA512_Init(&sha_ctx);
	if (1 != rc) return 1;

	rc = SHA512_Update(&sha_ctx, originalMessage, om_length);
	if (1 != rc) return 1;

	rc = SHA512_Final(digest, &sha_ctx);
	if (1 != rc) return 1;

	result = RSA_verify(NID_sha512, digest, SHA512_DIGEST_LENGTH,
		signature, siglen, rsa_pubkey);

	RSA_free(rsa_pubkey);

	return (result == 1) ? 0 : E_SIG_FAIL;
}


int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hpInstance, LPTSTR nCmdLine, int iCmdShow){


	struct Args
	{
		int n;
		LPWSTR* p;

		~Args() { if (p != 0) { ::LocalFree(p); } }
		Args() : p(::CommandLineToArgvW(::GetCommandLine(), &n)) {}
	};

	Args    args;
	DWORD	rc;

	if (args.n > 1) {
		if (!wcscmp(args.p[1], L"install")) {
			return schedule(true);
		} else if (!wcscmp(args.p[1], L"uninstall")) {
			return schedule(false);
		} else if (!wcscmp(args.p[1], L"request")) {
			if (args.n > 2) {
				if (args.n > 3) {
					wstring cmdline = L"\"";
					cmdline.append(args.p[3]);
					cmdline.append(L"\"");
					for (int i = 4; i < args.n; i++) {
						cmdline.append(L" ");
						cmdline.append(args.p[i]);
					}
					if (schedule_cb(true, cmdline))
						logError(L"schedule callback");
				} else {
					rc = schedule_cb(false, L"");
				}
				return send_request(args.p[2]);
			} else {
				return E_ARGS;
			}
		} else if (!wcscmp(args.p[1], L"trigger") || !wcscmp(args.p[1], L"trigger-run")) {
			if (!IsUserAdmin()) {
				logError(L"Missing privileges");
				return E_PRIVILEGE;
			}

			if (args.n <= 2) {
				logError(L"Missing path argument");
				return E_ARGS;
			}
			wstring wd = args.p[2];
			if (wd[wd.length() - 1] != '\\')
				wd.append(L"\\");
			wstring pkgname = wd + FULLID EXT;
			wstring signame = wd + FULLID EXT L".sig";
			wstring hostDir = HOSTPATH FULLID;

			if (!(FileExists(pkgname.c_str()) && FileExists(signame.c_str()))) {
				logError(L"Files missing");
				return E_FILES_MISSING;
			}

			if (!wcscmp(args.p[1], L"trigger")) {
				logMessage(L"Triggered");

				HMODULE hModule = GetModuleHandleW(NULL);
				WCHAR executablePath[MAX_PATH];
				GetModuleFileName(hModule, executablePath, MAX_PATH);

				wstring executableDir(executablePath);
				executableDir.erase(executableDir.find_last_of('\\') + 1, string::npos);

				rc = CreateDirectory(hostDir.c_str(), NULL);
				if (!rc) {
					if (GetLastError() != ERROR_ALREADY_EXISTS) {
						logError(L"Host dir creation failure");
						return GetLastError();
					}
				}
				rc = prepFile(hostDir);
				if (rc) {
					logError(L"Host dir prep failure");
					return rc;
				}

				for (const WCHAR* fileName : {L"UpdateElevate.exe", L"libssl-1_1-x64.dll", L"libcrypto-1_1-x64.dll" , L"vcruntime140.dll", L"msvcp140.dll" }) {
					rc = copyAndPrepFile(executableDir + fileName, hostDir + L"\\" + fileName);
					if (rc) {
						logError(L"Run host failure");
						return rc;
					}
				}

				PROCESS_INFORMATION procInfo;
				STARTUPINFO startInfo;
				ZeroMemory(&startInfo, sizeof(startInfo));
				startInfo.cb = 0;
				wstring hostPath = hostDir + L"\\UpdateElevate.exe";
				wstring cmdline = hostPath + L" trigger-run " + wd;
				std::vector<wchar_t> cmdvec(cmdline.begin(), cmdline.end());
				cmdvec.push_back(L'\0');
				rc = CreateProcess(hostPath.c_str(),
					cmdvec.data(),
					NULL,
					NULL,
					false,
					0,
					NULL,
					NULL,
					&startInfo,
					&procInfo);
				if (!rc) {
					logError(L"Run host failure");
					return GetLastError();
				}

				CloseHandle(procInfo.hThread);
				CloseHandle(procInfo.hProcess);
			} else { // == "trigger-run"
				logMessage(L"Triggered to run");

				DWORD rc = prepFile(pkgname);
				if (rc) {
					logError(L"Prep failure");
					return rc;
				}

				std::ifstream file(pkgname, std::ios::binary | std::ios::ate);
				std::streamsize size = file.tellg();
				file.seekg(0, std::ios::beg);
				std::vector<char> buffer(size);
				if (!file.read(buffer.data(), size)) {
					logError(L"File read failure");
					return 1;
				}
				file.close();

				std::ifstream sigfile(signame, std::ios::binary | std::ios::ate);
				std::streamsize sigsize = sigfile.tellg();
				sigfile.seekg(0, std::ios::beg);
				std::vector<char> sigbuffer(sigsize);
				if (!sigfile.read(sigbuffer.data(), sigsize)) {
					logError(L"Sig read failure");
					return 1;
				}
				sigfile.close();

				rc = verifyRSASignature((unsigned char*)buffer.data(), size, (unsigned char*)sigbuffer.data(), (unsigned int)sigsize);
				if (rc == E_SIG_FAIL) {
					logError(L"Invalid signature");
					return E_SIG_FAIL;
				} else if (rc) {
					logError(L"Verification error");
					return rc;
				}

				// The file has a valid signature and cannot be modified by non-admins
				wstring cmdline = pkgname + L" " + ARGS;
				std::vector<wchar_t> cmdvec(cmdline.begin(), cmdline.end());
				cmdvec.push_back(L'\0');

				wstring logmsg = L"Signature verified, executing ";
				logmsg.append(cmdline);
				logMessage(logmsg.c_str());

				PROCESS_INFORMATION procInfo;
				STARTUPINFO startInfo;
				ZeroMemory(&startInfo, sizeof(startInfo));
				startInfo.cb = 0;

				rc = CreateProcess(NULL,
					cmdvec.data(),
					NULL,
					NULL,
					false,
					0,
					NULL,
					NULL,
					&startInfo,
					&procInfo);
				if (!rc) {
					logError(L"Run failure");
					return GetLastError();
				}

				rc = WaitForSingleObject(procInfo.hProcess, INFINITE);
				if (rc != WAIT_OBJECT_0)
					return rc;

				rc = -1;
				GetExitCodeProcess(procInfo.hProcess, &rc);

				wstring msg = L"Completed with exit code ";
				msg.append(to_wstring(rc));
				logMessage(msg.c_str());
				send_completed();

				CloseHandle(procInfo.hThread);
				CloseHandle(procInfo.hProcess);

				rc = DeleteFile(pkgname.c_str());
				rc = DeleteFile(signame.c_str());

				// Lastly, delete self via batch
				ZeroMemory(&startInfo, sizeof(startInfo));
				startInfo.cb = 0;
				cmdline = L"cmd.exe /C TIMEOUT 5 && rmdir /S /Q " + hostDir;
				cmdvec.assign(cmdline.begin(), cmdline.end());
				cmdvec.push_back(L'\0');
				rc = CreateProcess(L"C:\\Windows\\system32\\cmd.exe",
					cmdvec.data(),
					NULL,
					NULL,
					false,
					CREATE_NO_WINDOW,
					NULL,
					NULL,
					&startInfo,
					&procInfo);
			}
		} else if (!wcscmp(args.p[1], L"completed")) {
			schedule_cb(false, L"");

			if (args.n > 2) {
				wstring cmdline = L"\"";
				cmdline.append(args.p[2]);
				cmdline.append(L"\"");
				for (int i = 3; i < args.n; i++) {
					cmdline.append(L" ");
					cmdline.append(args.p[i]);
				}
				std::vector<wchar_t> cmdvec(cmdline.begin(), cmdline.end());
				cmdvec.push_back(L'\0');

				PROCESS_INFORMATION procInfo;
				STARTUPINFO startInfo;
				ZeroMemory(&startInfo, sizeof(startInfo));
				startInfo.cb = 0;

				DWORD rc = CreateProcess(NULL,
					&cmdvec[0],
					NULL,
					NULL,
					false,
					0,
					NULL,
					NULL,
					&startInfo,
					&procInfo);
				if (!rc) {
					logError(L"Run failure");
					return GetLastError();
				}
			} else {
				return E_ARGS;
			}
		} else {
			return E_ARGS;
		}
	} else {
		return E_ARGS;
	}

	return 0;
}