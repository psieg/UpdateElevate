

#include "command.h"
#if !defined(NAME) || !defined(EXT) || !defined(ARGS)
#error "Must define NAME, EXT and ARGS before building. Overwrite command.h"
#endif

#define HOSTPATH L"C:\\Windows\\Temp\\"
#define FULLID L"PsiegUpdateElevate_" NAME
#define FULLIDCB L"PsiegUpdateElevate_" NAME L"_Completion"

#define EVT_ID_REQUEST ((DWORD)0x40000E1E0L)
#define EVT_ID_REQUEST_S L"57824"
#define EVT_ID_LOG ((DWORD)0x40000E1E1L)
#define EVT_ID_COMPLETED ((DWORD)0x40000E1E2L)
#define EVT_ID_COMPLETED_S L"57826"