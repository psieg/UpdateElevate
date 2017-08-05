
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <AclAPI.h>


#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <string>
#include <iostream>
#include <fstream>
#include <vector>
using namespace std;

#include "common.h"
#include "taskScheduler.h"

#define E_ARGS 1000
#define E_FILES_MISSING 1001
#define E_SIG_FAIL 1002

#define PUBKEY "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvOzz+Ih6jYbyEsjkF28s\n\
Four2hRPEjJCVXfHf2+sbFONqnPpM18Ri0+4zOidaZf/l790AJOh5YJZfVhPHTQa\n\
GTUWagPQ9RrXDDymFprQFpBXJSJvnFjOWGazB2x+dA+RrGiKymujrE5RIScHDeUC\n\
GJ60dGzGzAulWoFlbzkNMlO4HuyXJB8hgsFNNI1a9Bezv5ApfG+xtLvWznmiAvW5\n\
y7gwrFL3sko5bRhjGrzfKI/WT9XTzbwwIt8Wg2oOzg2PfBoXrMTRtrXuHkh9AyVH\n\
/Mi+3pBeT8TaaRsPD6s/qX/lphmaGNfuyKCENDcZKCUmGcFXSxFxPpBXcrSqn5hm\n\
LwIDAQAB\n\
-----END PUBLIC KEY-----"

BOOL logMessage(LPCWSTR msg) {
	HANDLE hEventSrc = RegisterEventSourceW(NULL, FULLID);
	BOOL rc = ReportEvent(hEventSrc, EVENTLOG_INFORMATION_TYPE & 0xFFFF, 0, EVT_ID_LOG, NULL, 1, 0, &msg, NULL);
	DeregisterEventSource(hEventSrc);
	return !rc;
}


BOOL send_request() {
	HANDLE hEventSrc = RegisterEventSourceW(NULL, FULLID);
	BOOL rc = ReportEvent(hEventSrc, EVENTLOG_INFORMATION_TYPE & 0xFFFF, 0, EVT_ID_REQUEST, NULL, 0, 0, NULL, NULL);
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

DWORD prepFile(const wstring filename) {
	EXPLICIT_ACCESS eas[2];
	PACL pACL = 0;
	DWORD rc;

	eas[0].grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
	eas[0].grfAccessMode = GRANT_ACCESS;
	eas[0].grfInheritance = NO_INHERITANCE;
	eas[0].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
	eas[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	eas[0].Trustee.ptstrName = L"EVERYONE";

	eas[1].grfAccessPermissions = GENERIC_ALL;
	eas[1].grfAccessMode = GRANT_ACCESS;
	eas[1].grfInheritance = NO_INHERITANCE;
	eas[1].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
	eas[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	eas[1].Trustee.ptstrName = L"CURRENT_USER";

	rc = SetEntriesInAcl(2, &eas[0], NULL, &pACL);
	if (rc != ERROR_SUCCESS)
	{
		printf("SetEntriesInAcl: %u\n", rc);
		return rc;
	}

	TCHAR namebuf[40];
	DWORD bufs = 40;
	rc = GetUserName(namebuf, &bufs);
	if (!rc) return GetLastError();

	BYTE sidbuf[1024];
	bufs = 1024;
	TCHAR sidbuf2[1024];
	DWORD bufs2 = 1024;
	SID_NAME_USE snu;
	rc = LookupAccountName(NULL, namebuf, sidbuf, &bufs, sidbuf2, &bufs2, &snu);
	if (!rc) return GetLastError();

	rc = SetNamedSecurityInfo((LPTSTR)filename.c_str(), SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
		sidbuf, NULL, pACL, NULL);
	if (rc) return rc;
	/*
	SECURITY_DESCRIPTOR desc;
	rc = InitializeSecurityDescriptor(&desc, SECURITY_DESCRIPTOR_REVISION);
	if (!rc)
	{
	return INVALID_HANDLE_VALUE;
	}

	rc = SetSecurityDescriptorDacl(&desc, TRUE, pACL, FALSE);
	if (!rc)
	{
	return INVALID_HANDLE_VALUE;
	}

	SECURITY_ATTRIBUTES attrs;
	attrs.bInheritHandle = FALSE;
	attrs.lpSecurityDescriptor = &desc;
	attrs.nLength = sizeof(SECURITY_ATTRIBUTES);
	HANDLE hFile = CreateFile(filename.c_str(), GENERIC_ALL, FILE_SHARE_READ, &attrs, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
	return INVALID_HANDLE_VALUE;
	}

	rc = SetSecurityInfo(hFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, pACL, NULL);
	if (rc != ERROR_SUCCESS) {
	return INVALID_HANDLE_VALUE;
	}

	const WCHAR* buf = L"protected";
	int rc = WriteFile(hFile, buf, sizeof(TCHAR)*9, NULL, NULL);
	if (!rc)
	return 1;

	CloseHandle(hFile);

	*/

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

	if (args.n > 1) {
		if (!wcscmp(args.p[1], L"install")) {
			return schedule(true);
		}
		else
			if (!wcscmp(args.p[1], L"uninstall")) {
				return schedule(false);
			}
			else
				if (!wcscmp(args.p[1], L"request")) {
					return send_request();
				}
				else
					if (!wcscmp(args.p[1], L"trigger")) {
						if (IsUserAdmin()) {
							TCHAR filename[] = FILEPATH FULLID;
							TCHAR signame[] = FILEPATH FULLID L".sig";

							if (!(FileExists(filename) && FileExists(signame)))
								return E_FILES_MISSING;

							DWORD rc = prepFile(filename);
							if (rc)
								return rc;
							

							std::ifstream file(filename, std::ios::binary | std::ios::ate);
							std::streamsize size = file.tellg();
							file.seekg(0, std::ios::beg);
							std::vector<char> buffer(size);
							if (!file.read(buffer.data(), size))
								return 1;

							std::ifstream sigfile(signame, std::ios::binary | std::ios::ate);
							std::streamsize sigsize = sigfile.tellg();
							sigfile.seekg(0, std::ios::beg);
							std::vector<char> sigbuffer(sigsize);
							if (!sigfile.read(sigbuffer.data(), sigsize))
								return 1;

							rc = verifyRSASignature((unsigned char*)buffer.data(), size, (unsigned char*)sigbuffer.data(), (unsigned int)sigsize);
							if (rc == E_SIG_FAIL)
								return E_SIG_FAIL;
							else if (rc)
								return rc;
								
							// The file has a valid signature and cannot be modified by non-admins / sytem
							logMessage(L"Executing " FILEPATH FULLID L" (signature verified)");

							TCHAR cmdline[] = FILEPATH FULLID ARGS;
							PROCESS_INFORMATION procInfo;
							STARTUPINFO startInfo;
							ZeroMemory(&startInfo, sizeof(startInfo));
							startInfo.cb = 0;

							rc = CreateProcess(filename,
								cmdline,
								NULL,
								NULL,
								false,
								0,
								NULL,
								NULL,
								&startInfo,
								&procInfo);
							if (!rc)
								return GetLastError();

							rc = WaitForSingleObject(procInfo.hProcess, INFINITE);
							if (rc != WAIT_OBJECT_0)
								return rc;

							CloseHandle(procInfo.hThread);
							CloseHandle(procInfo.hProcess);

							rc = DeleteFile(filename);
							rc = DeleteFile(signame);

						}
						else {
							return E_ARGS;
						}
					}
	}
	else {
		return E_ARGS;
	}

	return 0;
}