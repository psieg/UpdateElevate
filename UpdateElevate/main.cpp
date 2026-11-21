#define _CRT_SECURE_NO_WARNINGS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <shellapi.h>
#include <AclAPI.h>
#include <Sddl.h>
#include <ShlObj.h>
#include <wincrypt.h>
#include <bcrypt.h>

#include <string>
#include <vector>

#include "common.h"
#include "taskScheduler.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

#define E_ARGS 1000
#define E_FILES_MISSING 1001
#define E_SIG_FAIL 1002
#define E_PRIVILEGE 1003
#define E_REPARSE_OR_PATH 1004
#define E_STAGE_FAIL 1005

static constexpr LONGLONG kMaxPackageBytes = 512LL * 1024 * 1024; // 512 MiB cap
static constexpr LONGLONG kMinSigBytes = 64;
static constexpr LONGLONG kMaxSigBytes = 1024; // 2048-bit RSA sig is 256 bytes

static const char kPubKeyPem[] =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvOzz+Ih6jYbyEsjkF28s\n"
"Four2hRPEjJCVXfHf2+sbFONqnPpM18Ri0+4zOidaZf/l790AJOh5YJZfVhPHTQa\n"
"GTUWagPQ9RrXDDymFprQFpBXJSJvnFjOWGazB2x+dA+RrGiKymujrE5RIScHDeUC\n"
"GJ60dGzGzAulWoFlbzkNMlO4HuyXJB8hgsFNNI1a9Bezv5ApfG+xtLvWznmiAvW5\n"
"y7gwrFL3sko5bRhjGrzfKI/WT9XTzbwwIt8Wg2oOzg2PfBoXrMTRtrXuHkh9AyVH\n"
"/Mi+3pBeT8TaaRsPD6s/qX/lphmaGNfuyKCENDcZKCUmGcFXSxFxPpBXcrSqn5hm\n"
"LwIDAQAB\n"
"-----END PUBLIC KEY-----";

static BOOL logError(LPCWSTR msg) {
	HANDLE hEventSrc = RegisterEventSourceW(NULL, FULLID);
	if (!hEventSrc) return TRUE;
	BOOL rc = ReportEventW(hEventSrc, EVENTLOG_ERROR_TYPE & 0xFFFF, 0, EVT_ID_LOG, NULL, 1, 0, &msg, NULL);
	DeregisterEventSource(hEventSrc);
	return !rc;
}

static BOOL logMessage(LPCWSTR msg) {
	HANDLE hEventSrc = RegisterEventSourceW(NULL, FULLID);
	if (!hEventSrc) return TRUE;
	BOOL rc = ReportEventW(hEventSrc, EVENTLOG_INFORMATION_TYPE & 0xFFFF, 0, EVT_ID_LOG, NULL, 1, 0, &msg, NULL);
	DeregisterEventSource(hEventSrc);
	return !rc;
}

static BOOL send_request(LPCWSTR filepath) {
	HANDLE hEventSrc = RegisterEventSourceW(NULL, FULLID);
	if (!hEventSrc) return TRUE;
	BOOL rc = ReportEventW(hEventSrc, EVENTLOG_INFORMATION_TYPE & 0xFFFF, 0, EVT_ID_REQUEST, NULL, 1, 0, &filepath, NULL);
	DeregisterEventSource(hEventSrc);
	return !rc;
}

static BOOL send_completed() {
	HANDLE hEventSrc = RegisterEventSourceW(NULL, FULLID);
	if (!hEventSrc) return TRUE;
	BOOL rc = ReportEventW(hEventSrc, EVENTLOG_INFORMATION_TYPE & 0xFFFF, 0, EVT_ID_COMPLETED, NULL, 0, 0, NULL, NULL);
	DeregisterEventSource(hEventSrc);
	return !rc;
}

static BOOL IsUserAdmin() {
	BOOL isAdmin = FALSE;
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	PSID administratorsGroup = NULL;
	if (AllocateAndInitializeSid(
		&ntAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&administratorsGroup))
	{
		if (!CheckTokenMembership(NULL, administratorsGroup, &isAdmin))
			isAdmin = FALSE;
		FreeSid(administratorsGroup);
	}
	return isAdmin;
}

static std::wstring quoteCommandLineArg(const std::wstring& arg) {
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

static bool getCurrentExecutablePath(std::wstring& exePath, std::wstring& exeDir) {
	std::vector<wchar_t> buf(MAX_PATH);
	for (;;) {
		DWORD len = GetModuleFileNameW(NULL, buf.data(), static_cast<DWORD>(buf.size()));
		if (len == 0)
			return false;
		if (len < buf.size() - 1) {
			exePath.assign(buf.data(), len);
			size_t slash = exePath.find_last_of(L"\\/");
			if (slash == std::wstring::npos)
				return false;
			exeDir = exePath.substr(0, slash + 1);
			return true;
		}
		if (buf.size() >= 32768)
			return false;
		buf.resize(buf.size() * 2);
	}
}

static std::wstring getStagingHostDir() {
	PWSTR pszProgramData = NULL;
	std::wstring base = L"C:\\ProgramData";
	if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_DEFAULT, NULL, &pszProgramData)) && pszProgramData) {
		base = pszProgramData;
		CoTaskMemFree(pszProgramData);
	}
	while (!base.empty() && (base.back() == L'\\' || base.back() == L'/'))
		base.pop_back();
	return base + L"\\" FULLID;
}

static bool normalizeDirectoryArg(const std::wstring& rawDir, std::wstring& normalizedDir) {
	if (rawDir.empty())
		return false;

	for (wchar_t ch : rawDir) {
		if (ch < 0x20 || ch == L'"' || ch == L'<' || ch == L'>' || ch == L'|' || ch == L'?' || ch == L'*')
			return false;
	}

	DWORD needed = GetFullPathNameW(rawDir.c_str(), 0, NULL, NULL);
	if (needed == 0 || needed > 32768)
		return false;

	std::vector<wchar_t> fullBuf(needed + 1, L'\0');
	DWORD written = GetFullPathNameW(rawDir.c_str(), needed + 1, fullBuf.data(), NULL);
	if (written == 0 || written >= needed + 1)
		return false;

	normalizedDir.assign(fullBuf.data(), written);
	while (normalizedDir.size() > 3 && (normalizedDir.back() == L'\\' || normalizedDir.back() == L'/'))
		normalizedDir.pop_back();

	// Reject UNC / device namespace paths (require standard local drive root e.g. C:\...)
	if (normalizedDir.size() < 3 || normalizedDir[1] != L':' || normalizedDir[2] != L'\\')
		return false;

	return true;
}

// Ensures `dirPath` is a real directory (not a symlink/junction/mount point) owned by Administrators
// with a Protected DACL granting access exclusively to SYSTEM (SY) and Administrators (BA).
static DWORD ensureLockedSystemDirectory(const std::wstring& dirPath) {
	PSECURITY_DESCRIPTOR pSD = NULL;
	// Protected DACL: SYSTEM Full Control + Builtin Administrators Full Control (inheritable)
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
		L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
		SDDL_REVISION_1,
		&pSD,
		NULL))
	{
		return GetLastError();
	}

	SECURITY_ATTRIBUTES sa = {};
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = pSD;
	sa.bInheritHandle = FALSE;

	if (!CreateDirectoryW(dirPath.c_str(), &sa)) {
		DWORD err = GetLastError();
		if (err != ERROR_ALREADY_EXISTS) {
			LocalFree(pSD);
			return err;
		}
	}

	// Open the directory WITHOUT following reparse points so junctions/mount-points cannot redirect us.
	HANDLE hDir = CreateFileW(
		dirPath.c_str(),
		READ_CONTROL | WRITE_DAC | WRITE_OWNER,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
		NULL);
	if (hDir == INVALID_HANDLE_VALUE) {
		DWORD err = GetLastError();
		LocalFree(pSD);
		return err;
	}

	BY_HANDLE_FILE_INFORMATION info = {};
	if (!GetFileInformationByHandle(hDir, &info)) {
		DWORD err = GetLastError();
		CloseHandle(hDir);
		LocalFree(pSD);
		return err;
	}

	if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
	{
		CloseHandle(hDir);
		LocalFree(pSD);
		return E_REPARSE_OR_PATH;
	}

	BOOL daclPresent = FALSE;
	BOOL daclDefaulted = FALSE;
	PACL pDacl = NULL;
	if (!GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefaulted) || !daclPresent || !pDacl) {
		CloseHandle(hDir);
		LocalFree(pSD);
		return E_STAGE_FAIL;
	}

	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	PSID pAdminsSid = NULL;
	if (!AllocateAndInitializeSid(
		&ntAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pAdminsSid))
	{
		DWORD err = GetLastError();
		CloseHandle(hDir);
		LocalFree(pSD);
		return err;
	}

	// Apply owner + protected DACL directly on the verified directory handle (race-free).
	DWORD rc = SetSecurityInfo(
		hDir,
		SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
		pAdminsSid,
		NULL,
		pDacl,
		NULL);

	FreeSid(pAdminsSid);
	CloseHandle(hDir);
	LocalFree(pSD);
	return rc;
}

static DWORD purgeStagingDirectory(const std::wstring& dirPath) {
	std::wstring pattern = dirPath + L"\\*";
	WIN32_FIND_DATAW fd = {};
	HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
	if (hFind == INVALID_HANDLE_VALUE) {
		DWORD err = GetLastError();
		return (err == ERROR_FILE_NOT_FOUND) ? 0 : err;
	}

	DWORD result = 0;
	do {
		if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
			continue;

		std::wstring itemPath = dirPath + L"\\" + fd.cFileName;
		if ((fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
			if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
				RemoveDirectoryW(itemPath.c_str());
			else
				DeleteFileW(itemPath.c_str());
			continue;
		}

		if ((fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY) != 0)
			SetFileAttributesW(itemPath.c_str(), FILE_ATTRIBUTE_NORMAL);

		if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
			DWORD subRc = purgeStagingDirectory(itemPath);
			if (subRc != 0 && result == 0)
				result = subRc;
			if (!RemoveDirectoryW(itemPath.c_str()) && result == 0)
				result = GetLastError();
		} else {
			if (!DeleteFileW(itemPath.c_str()) && result == 0)
				result = GetLastError();
		}
	} while (FindNextFileW(hFind, &fd));

	FindClose(hFind);
	return result;
}

static bool safeDeleteRegularFile(const std::wstring& path) {
	HANDLE hFile = CreateFileW(
		path.c_str(),
		DELETE | FILE_READ_ATTRIBUTES,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OPEN_REPARSE_POINT,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	BY_HANDLE_FILE_INFORMATION info = {};
	bool ok = false;
	if (GetFileInformationByHandle(hFile, &info) &&
		(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0)
	{
		FILE_DISPOSITION_INFO disp = {};
		disp.DeleteFile = TRUE;
		ok = SetFileInformationByHandle(hFile, FileDispositionInfo, &disp, sizeof(disp)) != FALSE;
	}
	CloseHandle(hFile);
	return ok;
}

static DWORD readSignatureFile(const std::wstring& sigPath, std::vector<BYTE>& outSig) {
	HANDLE hSig = CreateFileW(
		sigPath.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
		NULL);
	if (hSig == INVALID_HANDLE_VALUE)
		return E_FILES_MISSING;

	BY_HANDLE_FILE_INFORMATION info = {};
	LARGE_INTEGER fileSize = {};
	if (!GetFileInformationByHandle(hSig, &info) ||
		(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
		!GetFileSizeEx(hSig, &fileSize) ||
		fileSize.QuadPart < kMinSigBytes ||
		fileSize.QuadPart > kMaxSigBytes)
	{
		CloseHandle(hSig);
		return E_SIG_FAIL;
	}

	outSig.resize(static_cast<size_t>(fileSize.QuadPart));
	DWORD bytesRead = 0;
	BOOL readOk = ReadFile(hSig, outSig.data(), static_cast<DWORD>(outSig.size()), &bytesRead, NULL);
	CloseHandle(hSig);

	if (!readOk || bytesRead != outSig.size())
		return E_SIG_FAIL;

	return 0;
}

static DWORD stageCandidateFile(const std::wstring& srcPkgPath, const std::wstring& dstPkgPath) {
	HANDLE hSrc = CreateFileW(
		srcPkgPath.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
		NULL);
	if (hSrc == INVALID_HANDLE_VALUE)
		return E_FILES_MISSING;

	BY_HANDLE_FILE_INFORMATION srcInfo = {};
	LARGE_INTEGER srcSize = {};
	if (!GetFileInformationByHandle(hSrc, &srcInfo) ||
		(srcInfo.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
		!GetFileSizeEx(hSrc, &srcSize) ||
		srcSize.QuadPart <= 0 ||
		srcSize.QuadPart > kMaxPackageBytes)
	{
		CloseHandle(hSrc);
		return E_REPARSE_OR_PATH;
	}

	HANDLE hDst = CreateFileW(
		dstPkgPath.c_str(),
		GENERIC_WRITE,
		0, // Exclusive lock while staging
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hDst == INVALID_HANDLE_VALUE) {
		CloseHandle(hSrc);
		return E_STAGE_FAIL;
	}

	std::vector<BYTE> chunk(64 * 1024);
	LONGLONG totalCopied = 0;
	DWORD status = 0;

	for (;;) {
		DWORD bytesRead = 0;
		if (!ReadFile(hSrc, chunk.data(), static_cast<DWORD>(chunk.size()), &bytesRead, NULL)) {
			status = E_STAGE_FAIL;
			break;
		}
		if (bytesRead == 0)
			break;

		totalCopied += bytesRead;
		if (totalCopied > kMaxPackageBytes) {
			status = E_REPARSE_OR_PATH;
			break;
		}

		DWORD bytesWritten = 0;
		if (!WriteFile(hDst, chunk.data(), bytesRead, &bytesWritten, NULL) || bytesWritten != bytesRead) {
			status = E_STAGE_FAIL;
			break;
		}
	}

	if (status == 0 && totalCopied != srcSize.QuadPart)
		status = E_STAGE_FAIL;

	if (status == 0)
		FlushFileBuffers(hDst);

	CloseHandle(hDst);
	CloseHandle(hSrc);

	if (status != 0)
		DeleteFileW(dstPkgPath.c_str());

	return status;
}

// Verifies RSA-2048 PKCS#1 v1.5 SHA-512 signature over an open, write-locked file handle using Windows CNG.
static DWORD verifyFileRSASignature(HANDLE hLockedFile, const std::vector<BYTE>& signature) {
	if (hLockedFile == INVALID_HANDLE_VALUE || signature.empty())
		return E_SIG_FAIL;

	LARGE_INTEGER zero = {};
	if (!SetFilePointerEx(hLockedFile, zero, NULL, FILE_BEGIN))
		return E_SIG_FAIL;

	DWORD derLen = 0;
	if (!CryptStringToBinaryA(kPubKeyPem, 0, CRYPT_STRING_BASE64HEADER, NULL, &derLen, NULL, NULL) || derLen == 0)
		return E_SIG_FAIL;

	std::vector<BYTE> derKey(derLen);
	if (!CryptStringToBinaryA(kPubKeyPem, 0, CRYPT_STRING_BASE64HEADER, derKey.data(), &derLen, NULL, NULL))
		return E_SIG_FAIL;

	CERT_PUBLIC_KEY_INFO* pPubKeyInfo = NULL;
	DWORD pubKeyInfoLen = 0;
	if (!CryptDecodeObjectEx(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		X509_PUBLIC_KEY_INFO,
		derKey.data(),
		derLen,
		CRYPT_DECODE_ALLOC_FLAG,
		NULL,
		&pPubKeyInfo,
		&pubKeyInfoLen) || !pPubKeyInfo)
	{
		return E_SIG_FAIL;
	}

	BCRYPT_KEY_HANDLE hKey = NULL;
	BOOL imported = CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, pPubKeyInfo, 0, NULL, &hKey);
	LocalFree(pPubKeyInfo);
	if (!imported || !hKey)
		return E_SIG_FAIL;

	BCRYPT_ALG_HANDLE hHashAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	DWORD rc = E_SIG_FAIL;
	BYTE digest[64] = {};
	std::vector<BYTE> hashObj;
	DWORD hashObjLen = 0;
	DWORD cbResult = 0;

	if (BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA512_ALGORITHM, NULL, 0) != 0)
		goto cleanup;

	if (BCryptGetProperty(hHashAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hashObjLen), sizeof(hashObjLen), &cbResult, 0) != 0 || hashObjLen == 0)
		goto cleanup;

	hashObj.resize(hashObjLen);
	if (BCryptCreateHash(hHashAlg, &hHash, hashObj.data(), hashObjLen, NULL, 0, 0) != 0)
		goto cleanup;

	{
		std::vector<BYTE> readBuf(64 * 1024);
		LONGLONG hashedBytes = 0;
		for (;;) {
			DWORD bytesRead = 0;
			if (!ReadFile(hLockedFile, readBuf.data(), static_cast<DWORD>(readBuf.size()), &bytesRead, NULL))
				goto cleanup;
			if (bytesRead == 0)
				break;
			hashedBytes += bytesRead;
			if (hashedBytes > kMaxPackageBytes)
				goto cleanup;
			if (BCryptHashData(hHash, readBuf.data(), bytesRead, 0) != 0)
				goto cleanup;
		}
		if (hashedBytes <= 0)
			goto cleanup;
	}

	if (BCryptFinishHash(hHash, digest, sizeof(digest), 0) != 0)
		goto cleanup;

	{
		BCRYPT_PKCS1_PADDING_INFO padInfo = {};
		padInfo.pszAlgId = BCRYPT_SHA512_ALGORITHM;
		NTSTATUS verifyStatus = BCryptVerifySignature(
			hKey,
			&padInfo,
			digest,
			sizeof(digest),
			const_cast<PUCHAR>(signature.data()),
			static_cast<ULONG>(signature.size()),
			BCRYPT_PAD_PKCS1);
		if (verifyStatus == 0)
			rc = 0;
	}

cleanup:
	if (hHash) BCryptDestroyHash(hHash);
	if (hHashAlg) BCryptCloseAlgorithmProvider(hHashAlg, 0);
	if (hKey) BCryptDestroyKey(hKey);
	return rc;
}

// Validates that a requested post-update callback binary is `{exeDir}\{NAME}{EXT}` (Prismatik.exe alongside UpdateElevate.exe).
static bool resolveAllowedCallbackExecutable(const std::wstring& requestedPath, std::wstring& allowedExeOut) {
	std::wstring selfExe, selfDir;
	if (!getCurrentExecutablePath(selfExe, selfDir))
		return false;

	std::wstring expectedExe = selfDir + NAME EXT;

	DWORD needed = GetFullPathNameW(requestedPath.c_str(), 0, NULL, NULL);
	if (needed == 0 || needed > 32768)
		return false;
	std::vector<wchar_t> fullBuf(needed + 1, L'\0');
	DWORD written = GetFullPathNameW(requestedPath.c_str(), needed + 1, fullBuf.data(), NULL);
	if (written == 0 || written >= needed + 1)
		return false;

	if (CompareStringOrdinal(fullBuf.data(), static_cast<int>(written), expectedExe.c_str(), static_cast<int>(expectedExe.size()), TRUE) == CSTR_EQUAL) {
		allowedExeOut = expectedExe;
		return true;
	}

	// Fallback for 8.3 short-path vs long-path equivalence: verify both paths resolve to the exact same regular file object.
	HANDLE hReq = CreateFileW(fullBuf.data(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hReq == INVALID_HANDLE_VALUE)
		return false;
	HANDLE hExp = CreateFileW(expectedExe.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hExp == INVALID_HANDLE_VALUE) {
		CloseHandle(hReq);
		return false;
	}

	BY_HANDLE_FILE_INFORMATION reqInfo = {};
	BY_HANDLE_FILE_INFORMATION expInfo = {};
	bool sameFile = GetFileInformationByHandle(hReq, &reqInfo) &&
		GetFileInformationByHandle(hExp, &expInfo) &&
		(expInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
		reqInfo.dwVolumeSerialNumber == expInfo.dwVolumeSerialNumber &&
		reqInfo.nFileIndexHigh == expInfo.nFileIndexHigh &&
		reqInfo.nFileIndexLow == expInfo.nFileIndexLow;

	CloseHandle(hExp);
	CloseHandle(hReq);

	if (!sameFile)
		return false;

	allowedExeOut = expectedExe;
	return true;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hpInstance, LPTSTR nCmdLine, int iCmdShow) {
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hpInstance);
	UNREFERENCED_PARAMETER(nCmdLine);
	UNREFERENCED_PARAMETER(iCmdShow);

	// Restrict all dynamic DLL loads to C:\Windows\System32 to prevent DLL sideloading.
	SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);

	struct Args {
		int n = 0;
		LPWSTR* p = nullptr;
		~Args() { if (p) ::LocalFree(p); }
		Args() : p(::CommandLineToArgvW(::GetCommandLineW(), &n)) {}
	};

	Args args;
	if (!args.p || args.n <= 1)
		return E_ARGS;

	if (!wcscmp(args.p[1], L"install")) {
		if (!IsUserAdmin())
			return E_PRIVILEGE;
		const std::wstring hostDir = getStagingHostDir();
		DWORD dirRc = ensureLockedSystemDirectory(hostDir);
		if (dirRc != 0) {
			logError(L"Failed to lock staging directory during install");
			return dirRc;
		}
		return schedule(true);
	}
	else if (!wcscmp(args.p[1], L"uninstall")) {
		if (!IsUserAdmin())
			return E_PRIVILEGE;
		const std::wstring hostDir = getStagingHostDir();
		if (ensureLockedSystemDirectory(hostDir) == 0) {
			purgeStagingDirectory(hostDir);
			RemoveDirectoryW(hostDir.c_str());
		}
		schedule_cb(false, L"");
		return schedule(false);
	}
	else if (!wcscmp(args.p[1], L"verify-test")) {
		// Unprivileged read-only signature self-test helper: UpdateElevate.exe verify-test <pkg> <sig>
		if (args.n != 4)
			return E_ARGS;
		std::vector<BYTE> sig;
		DWORD sigRc = readSignatureFile(args.p[3], sig);
		if (sigRc != 0)
			return sigRc;
		HANDLE hPkg = CreateFileW(
			args.p[2],
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
			NULL);
		if (hPkg == INVALID_HANDLE_VALUE)
			return E_FILES_MISSING;
		DWORD verRc = verifyFileRSASignature(hPkg, sig);
		CloseHandle(hPkg);
		return verRc;
	}
	else if (!wcscmp(args.p[1], L"request")) {
		if (args.n <= 2)
			return E_ARGS;

		std::wstring normalizedPkgDir;
		if (!normalizeDirectoryArg(args.p[2], normalizedPkgDir))
			return E_ARGS;

		if (args.n > 3) {
			std::wstring allowedExe;
			if (!resolveAllowedCallbackExecutable(args.p[3], allowedExe)) {
				logError(L"Rejected untrusted callback path");
				return E_ARGS;
			}
			if (schedule_cb(true, allowedExe))
				logError(L"schedule callback");
		} else {
			schedule_cb(false, L"");
		}
		return send_request(normalizedPkgDir.c_str());
	}
	else if (!wcscmp(args.p[1], L"trigger") || !wcscmp(args.p[1], L"trigger-run")) {
		if (!IsUserAdmin()) {
			logError(L"Missing privileges");
			return E_PRIVILEGE;
		}

		if (args.n != 3) {
			logError(L"Invalid path argument count");
			return E_ARGS;
		}

		std::wstring cleanWd;
		if (!normalizeDirectoryArg(args.p[2], cleanWd)) {
			logError(L"Invalid package directory argument");
			return E_REPARSE_OR_PATH;
		}

		const std::wstring pkgname = cleanWd + L"\\" FULLID EXT;
		const std::wstring signame = cleanWd + L"\\" FULLID EXT L".sig";
		const std::wstring hostDir = getStagingHostDir();

		DWORD dirRc = ensureLockedSystemDirectory(hostDir);
		if (dirRc != 0) {
			logError(L"Secure staging directory verification failed");
			return dirRc;
		}

		if (!wcscmp(args.p[1], L"trigger")) {
			logMessage(L"Triggered");

			// Quick existence check on source files (without following symlinks)
			DWORD pkgAttr = GetFileAttributesW(pkgname.c_str());
			DWORD sigAttr = GetFileAttributesW(signame.c_str());
			if (pkgAttr == INVALID_FILE_ATTRIBUTES || sigAttr == INVALID_FILE_ATTRIBUTES ||
				(pkgAttr & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
				(sigAttr & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
			{
				logError(L"Source update files missing or invalid");
				return E_FILES_MISSING;
			}

			std::wstring selfExe, selfDir;
			if (!getCurrentExecutablePath(selfExe, selfDir)) {
				logError(L"Failed to resolve own path");
				return E_STAGE_FAIL;
			}

			purgeStagingDirectory(hostDir);

			const std::wstring stagedHostExe = hostDir + L"\\UpdateElevate.exe";
			if (!CopyFileW(selfExe.c_str(), stagedHostExe.c_str(), FALSE)) {
				logError(L"Failed to stage UpdateElevate host binary");
				return GetLastError();
			}

			std::wstring cmdline = quoteCommandLineArg(stagedHostExe) + L" trigger-run " + quoteCommandLineArg(cleanWd);
			std::vector<wchar_t> cmdvec(cmdline.begin(), cmdline.end());
			cmdvec.push_back(L'\0');

			PROCESS_INFORMATION procInfo = {};
			STARTUPINFOW startInfo = {};
			startInfo.cb = sizeof(startInfo);

			if (!CreateProcessW(
				stagedHostExe.c_str(),
				cmdvec.data(),
				NULL,
				NULL,
				FALSE,
				CREATE_NO_WINDOW,
				NULL,
				hostDir.c_str(),
				&startInfo,
				&procInfo))
			{
				logError(L"Run staged host failure");
				return GetLastError();
			}

			CloseHandle(procInfo.hThread);
			CloseHandle(procInfo.hProcess);
			return 0;
		}
		else { // "trigger-run"
			logMessage(L"Triggered to run");

			std::wstring selfExe, selfDir;
			if (!getCurrentExecutablePath(selfExe, selfDir))
				return E_STAGE_FAIL;

			std::wstring expectedHostPrefix = hostDir + L"\\";
			if (selfExe.size() <= expectedHostPrefix.size() ||
				CompareStringOrdinal(selfExe.c_str(), static_cast<int>(expectedHostPrefix.size()), expectedHostPrefix.c_str(), static_cast<int>(expectedHostPrefix.size()), TRUE) != CSTR_EQUAL)
			{
				logError(L"trigger-run must execute from secure staging directory");
				return E_PRIVILEGE;
			}

			std::vector<BYTE> sigbuffer;
			DWORD rc = readSignatureFile(signame, sigbuffer);
			if (rc != 0) {
				logError(L"Sig read failure");
				return rc;
			}

			const std::wstring stagedPkg = hostDir + L"\\VerifiedInstaller" EXT;
			rc = stageCandidateFile(pkgname, stagedPkg);
			if (rc != 0) {
				logError(L"Candidate staging failure");
				return rc;
			}

			// Hold a read-only handle sharing READ|DELETE (denying FILE_SHARE_WRITE) throughout verification + CreateProcessW.
			HANDLE hLockedPkg = CreateFileW(
				stagedPkg.c_str(),
				GENERIC_READ,
				FILE_SHARE_READ | FILE_SHARE_DELETE,
				NULL,
				OPEN_EXISTING,
				FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
				NULL);
			if (hLockedPkg == INVALID_HANDLE_VALUE) {
				DeleteFileW(stagedPkg.c_str());
				logError(L"Failed to lock staged package");
				return E_STAGE_FAIL;
			}

			rc = verifyFileRSASignature(hLockedPkg, sigbuffer);
			if (rc != 0) {
				CloseHandle(hLockedPkg);
				DeleteFileW(stagedPkg.c_str());
				logError(rc == E_SIG_FAIL ? L"Invalid signature" : L"Verification error");
				return rc;
			}

			std::wstring cmdline = quoteCommandLineArg(stagedPkg) + L" " + ARGS;
			std::vector<wchar_t> cmdvec(cmdline.begin(), cmdline.end());
			cmdvec.push_back(L'\0');

			std::wstring logmsg = L"Signature verified, executing " + cmdline;
			logMessage(logmsg.c_str());

			PROCESS_INFORMATION procInfo = {};
			STARTUPINFOW startInfo = {};
			startInfo.cb = sizeof(startInfo);

			BOOL created = CreateProcessW(
				stagedPkg.c_str(),
				cmdvec.data(),
				NULL,
				NULL,
				FALSE,
				0,
				NULL,
				hostDir.c_str(),
				&startInfo,
				&procInfo);

			if (!created) {
				DWORD err = GetLastError();
				CloseHandle(hLockedPkg);
				DeleteFileW(stagedPkg.c_str());
				logError(L"Run failure");
				return err;
			}

			DWORD waitRc = WaitForSingleObject(procInfo.hProcess, INFINITE);
			DWORD exitCode = static_cast<DWORD>(-1);
			if (waitRc == WAIT_OBJECT_0) {
				GetExitCodeProcess(procInfo.hProcess, &exitCode);
				std::wstring msg = L"Completed with exit code " + std::to_wstring(exitCode);
				logMessage(msg.c_str());
				send_completed();
			}

			CloseHandle(procInfo.hThread);
			CloseHandle(procInfo.hProcess);
			CloseHandle(hLockedPkg);

			DeleteFileW(stagedPkg.c_str());
			safeDeleteRegularFile(pkgname);
			safeDeleteRegularFile(signame);

			// Schedule staged UpdateElevate.exe for clean removal on next reboot without spawning cmd.exe.
			MoveFileExW(selfExe.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
			return (waitRc == WAIT_OBJECT_0) ? 0 : waitRc;
		}
	}
	else if (!wcscmp(args.p[1], L"completed")) {
		schedule_cb(false, L"");

		if (args.n > 2) {
			std::wstring allowedExe;
			if (!resolveAllowedCallbackExecutable(args.p[2], allowedExe)) {
				logError(L"Rejected untrusted completion executable");
				return E_ARGS;
			}

			std::wstring cmdline = quoteCommandLineArg(allowedExe);
			std::vector<wchar_t> cmdvec(cmdline.begin(), cmdline.end());
			cmdvec.push_back(L'\0');

			std::wstring workDir = allowedExe.substr(0, allowedExe.find_last_of(L"\\/") + 1);

			PROCESS_INFORMATION procInfo = {};
			STARTUPINFOW startInfo = {};
			startInfo.cb = sizeof(startInfo);

			if (!CreateProcessW(
				allowedExe.c_str(),
				cmdvec.data(),
				NULL,
				NULL,
				FALSE,
				0,
				NULL,
				workDir.c_str(),
				&startInfo,
				&procInfo))
			{
				logError(L"Completion launch failure");
				return GetLastError();
			}
			CloseHandle(procInfo.hThread);
			CloseHandle(procInfo.hProcess);
			return 0;
		}
		return E_ARGS;
	}

	return E_ARGS;
}
