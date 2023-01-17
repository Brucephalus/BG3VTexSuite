typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned long long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct _s__RTTIBaseClassDescriptor _s__RTTIBaseClassDescriptor, *P_s__RTTIBaseClassDescriptor;

typedef struct _s__RTTIBaseClassDescriptor RTTIBaseClassDescriptor;

typedef RTTIBaseClassDescriptor * RTTIBaseClassDescriptor *32 __((image-base-relative));

typedef RTTIBaseClassDescriptor *32 __((image-base-relative)) * RTTIBaseClassDescriptor *32 __((image-base-relative)) *32 __((image-base-relative));

typedef struct PMD PMD, *PPMD;

struct PMD {
    int mdisp;
    int pdisp;
    int vdisp;
};

struct _s__RTTIBaseClassDescriptor {
    ImageBaseOffset32 pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    dword numContainedBases; // count of extended classes in BaseClassArray (RTTI 2)
    struct PMD where; // member displacement structure
    dword attributes; // bit flags
    ImageBaseOffset32 pClassHierarchyDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3) for class
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct _s__RTTIClassHierarchyDescriptor _s__RTTIClassHierarchyDescriptor, *P_s__RTTIClassHierarchyDescriptor;

struct _s__RTTIClassHierarchyDescriptor {
    dword signature;
    dword attributes; // bit flags
    dword numBaseClasses; // number of base classes (i.e. rtti1Count)
    RTTIBaseClassDescriptor *32 __((image-base-relative)) *32 __((image-base-relative)) pBaseClassArray; // ref to BaseClassArray (RTTI 2)
};

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

typedef int __ehstate_t;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    ImageBaseOffset32 action;
};

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef struct _s__RTTICompleteObjectLocator _s__RTTICompleteObjectLocator, *P_s__RTTICompleteObjectLocator;

struct _s__RTTICompleteObjectLocator {
    dword signature;
    dword offset; // offset of vbtable within class
    dword cdOffset; // constructor displacement offset
    ImageBaseOffset32 pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    ImageBaseOffset32 pClassDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3)
};

typedef struct _s_IPToStateMapEntry _s_IPToStateMapEntry, *P_s_IPToStateMapEntry;

typedef struct _s_IPToStateMapEntry IPToStateMapEntry;

struct _s_IPToStateMapEntry {
    ImageBaseOffset32 Ip;
    __ehstate_t state;
};

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY _IMAGE_RUNTIME_FUNCTION_ENTRY, *P_IMAGE_RUNTIME_FUNCTION_ENTRY;

struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    ImageBaseOffset32 BeginAddress;
    ImageBaseOffset32 EndAddress;
    ImageBaseOffset32 UnwindInfoAddressOrData;
};

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void * UniqueProcess;
    void * UniqueThread;
};

typedef struct _s__RTTIClassHierarchyDescriptor RTTIClassHierarchyDescriptor;

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

typedef struct _s_FuncInfo FuncInfo;

struct _s_FuncInfo {
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    ImageBaseOffset32 dispUnwindMap;
    uint nTryBlocks;
    ImageBaseOffset32 dispTryBlockMap;
    uint nIPMapEntries;
    ImageBaseOffset32 dispIPToStateMap;
    int dispUnwindHelp;
    ImageBaseOffset32 dispESTypeList;
    int EHFlags;
};

typedef ulonglong __uint64;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

struct TypeDescriptor {
    void * pVFTable;
    void * spare;
    char name[0];
};

typedef struct _s__RTTICompleteObjectLocator RTTICompleteObjectLocator;

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulonglong ULONG_PTR;

typedef union _union_540 _union_540, *P_union_540;

typedef void * HANDLE;

typedef struct _struct_541 _struct_541, *P_struct_541;

typedef void * PVOID;

typedef ulong DWORD;

struct _struct_541 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_540 {
    struct _struct_541 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_540 u;
    HANDLE hEvent;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void * LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef wchar_t WCHAR;

typedef WCHAR * LPWSTR;

typedef ushort WORD;

typedef uchar BYTE;

typedef BYTE * LPBYTE;

struct _STARTUPINFOW {
    DWORD cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
};

typedef struct _STARTUPINFOW * LPSTARTUPINFOW;

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef DWORD (* PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef struct _PROCESS_INFORMATION _PROCESS_INFORMATION, *P_PROCESS_INFORMATION;

struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef char CHAR;

typedef CHAR * LPSTR;

struct _STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _STARTUPINFOA * LPSTARTUPINFOA;

typedef struct _PROCESS_INFORMATION * LPPROCESS_INFORMATION;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY * Flink;
    struct _LIST_ENTRY * Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION * CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (* PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT * PCONTEXT;

typedef ulonglong DWORD64;

typedef union _union_54 _union_54, *P_union_54;

typedef struct _M128A _M128A, *P_M128A;

typedef struct _M128A M128A;

typedef struct _XSAVE_FORMAT _XSAVE_FORMAT, *P_XSAVE_FORMAT;

typedef struct _XSAVE_FORMAT XSAVE_FORMAT;

typedef XSAVE_FORMAT XMM_SAVE_AREA32;

typedef struct _struct_55 _struct_55, *P_struct_55;

typedef ulonglong ULONGLONG;

typedef longlong LONGLONG;

struct _M128A {
    ULONGLONG Low;
    LONGLONG High;
};

struct _XSAVE_FORMAT {
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
};

struct _struct_55 {
    M128A Header[2];
    M128A Legacy[8];
    M128A Xmm0;
    M128A Xmm1;
    M128A Xmm2;
    M128A Xmm3;
    M128A Xmm4;
    M128A Xmm5;
    M128A Xmm6;
    M128A Xmm7;
    M128A Xmm8;
    M128A Xmm9;
    M128A Xmm10;
    M128A Xmm11;
    M128A Xmm12;
    M128A Xmm13;
    M128A Xmm14;
    M128A Xmm15;
};

union _union_54 {
    XMM_SAVE_AREA32 FltSave;
    struct _struct_55 s;
};

struct _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union _union_54 u;
    M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct _SYSTEMTIME * LPSYSTEMTIME;

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef struct _OSVERSIONINFOEXW _OSVERSIONINFOEXW, *P_OSVERSIONINFOEXW;

struct _OSVERSIONINFOEXW {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    WCHAR szCSDVersion[128];
    WORD wServicePackMajor;
    WORD wServicePackMinor;
    WORD wSuiteMask;
    BYTE wProductType;
    BYTE wReserved;
};

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct _OSVERSIONINFOEXW * LPOSVERSIONINFOEXW;

typedef struct _RUNTIME_FUNCTION _RUNTIME_FUNCTION, *P_RUNTIME_FUNCTION;

struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
};

typedef struct _RUNTIME_FUNCTION * PRUNTIME_FUNCTION;

typedef enum _EXCEPTION_DISPOSITION {
    ExceptionContinueExecution=0,
    ExceptionContinueSearch=1,
    ExceptionNestedException=2,
    ExceptionCollidedUnwind=3
} _EXCEPTION_DISPOSITION;

typedef enum _EXCEPTION_DISPOSITION EXCEPTION_DISPOSITION;

typedef EXCEPTION_DISPOSITION (EXCEPTION_ROUTINE)(struct _EXCEPTION_RECORD *, PVOID, struct _CONTEXT *, PVOID);

typedef WCHAR * LPCWSTR;

typedef struct _M128A * PM128A;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY _UNWIND_HISTORY_TABLE_ENTRY, *P_UNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY UNWIND_HISTORY_TABLE_ENTRY;

struct _UNWIND_HISTORY_TABLE_ENTRY {
    DWORD64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
};

typedef union _union_61 _union_61, *P_union_61;

typedef struct _struct_62 _struct_62, *P_struct_62;

struct _struct_62 {
    PM128A Xmm0;
    PM128A Xmm1;
    PM128A Xmm2;
    PM128A Xmm3;
    PM128A Xmm4;
    PM128A Xmm5;
    PM128A Xmm6;
    PM128A Xmm7;
    PM128A Xmm8;
    PM128A Xmm9;
    PM128A Xmm10;
    PM128A Xmm11;
    PM128A Xmm12;
    PM128A Xmm13;
    PM128A Xmm14;
    PM128A Xmm15;
};

union _union_61 {
    PM128A FloatingContext[16];
    struct _struct_62 s;
};

typedef union _union_63 _union_63, *P_union_63;

typedef ulonglong * PDWORD64;

typedef struct _struct_64 _struct_64, *P_struct_64;

struct _struct_64 {
    PDWORD64 Rax;
    PDWORD64 Rcx;
    PDWORD64 Rdx;
    PDWORD64 Rbx;
    PDWORD64 Rsp;
    PDWORD64 Rbp;
    PDWORD64 Rsi;
    PDWORD64 Rdi;
    PDWORD64 R8;
    PDWORD64 R9;
    PDWORD64 R10;
    PDWORD64 R11;
    PDWORD64 R12;
    PDWORD64 R13;
    PDWORD64 R14;
    PDWORD64 R15;
};

union _union_63 {
    PDWORD64 IntegerContext[16];
    struct _struct_64 s;
};

typedef struct _UNWIND_HISTORY_TABLE _UNWIND_HISTORY_TABLE, *P_UNWIND_HISTORY_TABLE;

typedef struct _UNWIND_HISTORY_TABLE * PUNWIND_HISTORY_TABLE;

struct _UNWIND_HISTORY_TABLE {
    DWORD Count;
    BYTE LocalHint;
    BYTE GlobalHint;
    BYTE Search;
    BYTE Once;
    DWORD64 LowAddress;
    DWORD64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[12];
};

typedef void (* PAPCFUNC)(ULONG_PTR);

typedef CHAR * LPCSTR;

typedef ULONGLONG DWORDLONG;

typedef LARGE_INTEGER * PLARGE_INTEGER;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS _KNONVOLATILE_CONTEXT_POINTERS, *P_KNONVOLATILE_CONTEXT_POINTERS;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS * PKNONVOLATILE_CONTEXT_POINTERS;

struct _KNONVOLATILE_CONTEXT_POINTERS {
    union _union_61 u;
    union _union_63 u2;
};

typedef EXCEPTION_ROUTINE * PEXCEPTION_ROUTINE;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef struct ILogManager ILogManager, *PILogManager;

struct ILogManager { // PlaceHolder Class Structure
};

typedef struct IPerformanceManager IPerformanceManager, *PIPerformanceManager;

struct IPerformanceManager { // PlaceHolder Class Structure
};

typedef struct PerformanceMonitor PerformanceMonitor, *PPerformanceMonitor;

struct PerformanceMonitor { // PlaceHolder Class Structure
};

typedef longlong INT_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[63];
};

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME * LPFILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef INT_PTR (* FARPROC)(void);

typedef HANDLE HLOCAL;

typedef DWORD * LPDWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef struct HINSTANCE__ * HINSTANCE;

typedef void * LPCVOID;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ * HWND;

struct HWND__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef uint UINT;

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER64 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    pointer64 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    qword SizeOfStackReserve;
    qword SizeOfStackCommit;
    qword SizeOfHeapReserve;
    qword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_FILE_HEADER {
    word Machine; // 34404
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

struct IMAGE_NT_HEADERS64 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Name;
    dword Base;
    dword NumberOfFunctions;
    dword NumberOfNames;
    dword AddressOfFunctions;
    dword AddressOfNames;
    dword AddressOfNameOrdinals;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY64 IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

typedef enum IMAGE_GUARD_FLAGS {
    IMAGE_GUARD_CF_INSTRUMENTED=256,
    IMAGE_GUARD_CFW_INSTRUMENTED=512,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT=1024,
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED=2048,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT=4096,
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION=8192,
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT=16384,
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION=32768,
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT=65536,
    IMAGE_GUARD_RF_INSTRUMENTED=131072,
    IMAGE_GUARD_RF_ENABLE=262144,
    IMAGE_GUARD_RF_STRICT=524288,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1=268435456,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2=536870912,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4=1073741824,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8=2147483648
} IMAGE_GUARD_FLAGS;

struct IMAGE_LOAD_CONFIG_DIRECTORY64 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    qword DeCommitFreeBlockThreshold;
    qword DeCommitTotalFreeThreshold;
    pointer64 LockPrefixTable;
    qword MaximumAllocationSize;
    qword VirtualMemoryThreshold;
    qword ProcessAffinityMask;
    dword ProcessHeapFlags;
    word CsdVersion;
    word DependentLoadFlags;
    pointer64 EditList;
    pointer64 SecurityCookie;
    pointer64 SEHandlerTable;
    qword SEHandlerCount;
    pointer64 GuardCFCCheckFunctionPointer;
    pointer64 GuardCFDispatchFunctionPointer;
    pointer64 GuardCFFunctionTable;
    qword GuardCFFunctionCount;
    enum IMAGE_GUARD_FLAGS GuardFlags;
};

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO {
    word StructLength;
    word ValueLength;
    word StructType;
    wchar16 Info[16];
    byte Padding[2];
    dword Signature;
    word StructVersion[2];
    word FileVersion[4];
    word ProductVersion[4];
    dword FileFlagsMask[2];
    dword FileFlags;
    dword FileOS;
    dword FileType;
    dword FileSubtype;
    dword FileTimestamp;
};

typedef struct IMAGE_THUNK_DATA64 IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;

struct IMAGE_THUNK_DATA64 {
    qword StartAddressOfRawData;
    qword EndAddressOfRawData;
    qword AddressOfIndex;
    qword AddressOfCallBacks;
    dword SizeOfZeroFill;
    dword Characteristics;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef ulonglong uintptr_t;


// WARNING! conflicting data type names: /Demangler/wchar_t - /wchar_t

typedef struct void_(__cdecl**___ptr64)(void) void_(__cdecl**___ptr64)(void), *Pvoid_(__cdecl**___ptr64)(void);

struct void_(__cdecl**___ptr64)(void) { // PlaceHolder Structure
};

typedef struct Allocator Allocator, *PAllocator;

struct Allocator { // PlaceHolder Structure
};

typedef struct Array<unsigned_char> Array<unsigned_char>, *PArray<unsigned_char>;

struct Array<unsigned_char> { // PlaceHolder Structure
};

typedef struct ContextInfo ContextInfo, *PContextInfo;

struct ContextInfo { // PlaceHolder Structure
};

typedef struct ILogger ILogger, *PILogger;

struct ILogger { // PlaceHolder Structure
};

typedef struct WindowsGraphicsDriver WindowsGraphicsDriver, *PWindowsGraphicsDriver;

struct WindowsGraphicsDriver { // PlaceHolder Structure
};

typedef struct IAllocator IAllocator, *PIAllocator;

struct IAllocator { // PlaceHolder Structure
};

typedef struct LogManager LogManager, *PLogManager;

struct LogManager { // PlaceHolder Structure
};

typedef enum Enum {
} Enum;

typedef struct Crc32Calculation Crc32Calculation, *PCrc32Calculation;

struct Crc32Calculation { // PlaceHolder Structure
};

typedef struct TLSVariable TLSVariable, *PTLSVariable;

struct TLSVariable { // PlaceHolder Structure
};

typedef struct CriticalSection CriticalSection, *PCriticalSection;

struct CriticalSection { // PlaceHolder Structure
};

typedef struct JobSystem JobSystem, *PJobSystem;

struct JobSystem { // PlaceHolder Structure
};

typedef struct Dynamic Dynamic, *PDynamic;

struct Dynamic { // PlaceHolder Structure
};

typedef struct StatisticGroupId StatisticGroupId, *PStatisticGroupId;

struct StatisticGroupId { // PlaceHolder Structure
};

typedef struct IMonitor IMonitor, *PIMonitor;

struct IMonitor { // PlaceHolder Structure
};

typedef struct Statistic Statistic, *PStatistic;

struct Statistic { // PlaceHolder Structure
};

typedef struct StatisticOptions StatisticOptions, *PStatisticOptions;

struct StatisticOptions { // PlaceHolder Structure
};

typedef struct StatisticId StatisticId, *PStatisticId;

struct StatisticId { // PlaceHolder Structure
};

typedef struct NoPayload NoPayload, *PNoPayload;

struct NoPayload { // PlaceHolder Structure
};

typedef int (* _onexit_t)(void);

typedef ulonglong size_t;

typedef int errno_t;

typedef size_t rsize_t;




void FUN_180001000(void)

{
  if (DAT_18007b23c == '\0') {
    InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_18007b1d0);
    DAT_18007b23c = '\x01';
  }
  return;
}



void FUN_180001030(void)

{
  DAT_18007b23c = 0;
  DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_18007b1d0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_180001060(HMODULE param_1,int param_2)

{
  int iVar1;
  code *pcVar2;
  longlong lVar3;
  undefined *puVar4;
  
  if (param_2 == 0) {
    DAT_18007b1f8 = GetProcAddress(param_1,"nvapi_QueryInterface");
    if (DAT_18007b1f8 == (FARPROC)0x0) {
      return -1;
    }
    pcVar2 = (code *)(*DAT_18007b1f8)(0x150e828);
    if (pcVar2 == (code *)0x0) {
      DAT_18007b1f8 = (FARPROC)0x0;
      return -1;
    }
    iVar1 = (*pcVar2)();
    if (iVar1 != 0) {
      DAT_18007b1f8 = (FARPROC)0x0;
      return iVar1;
    }
    DAT_18007b208 = (*DAT_18007b1f8)(0x33c7358c);
    DAT_18007b210 = (*DAT_18007b1f8)(0x593e8644);
    if ((DAT_18007b208 == 0) || (DAT_18007b210 != 0)) {
      DAT_18007b208 = 0;
      DAT_18007b210 = 0;
    }
  }
  else if ((param_2 == 1) &&
          (_DAT_18007b200 = GetProcAddress(param_1,"nvapi_pepQueryInterface"),
          _DAT_18007b200 == (FARPROC)0x0)) {
    return -1;
  }
  puVar4 = &DAT_18007b260;
  for (lVar3 = 0x828; lVar3 != 0; lVar3 = lVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  return 0;
}



int FUN_1800011a0(int param_1)

{
  int iVar1;
  HMODULE local_18;
  
  FUN_180001000();
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18007b1d0);
  if ((&DAT_18007b218)[param_1] == 0) {
    if (param_1 == 0) {
      local_18 = FUN_1800185e0(L"nvapi64.dll",0);
    }
    else {
      local_18 = FUN_180018680("nvpowerapi.dll",0);
    }
    if (local_18 == (HMODULE)0x0) {
      LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18007b1d0);
      return -2;
    }
    iVar1 = FUN_180001060(local_18,param_1);
    if (iVar1 != 0) {
      FreeLibrary(local_18);
      LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18007b1d0);
      return iVar1;
    }
    (&DAT_18007b218)[param_1] = local_18;
    (&DAT_18007b250)[param_1] = 1;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18007b1d0);
  return 0;
}



int FUN_1800012a0(int param_1)

{
  int iVar1;
  uint local_18;
  
  local_18 = 0;
  do {
    if ((&DAT_18007b238)[param_1] == '\0') {
      if ((&DAT_18007b218)[param_1] == 0) {
        iVar1 = FUN_1800011a0(param_1);
        return iVar1;
      }
      return 0;
    }
    Sleep(100);
    local_18 = local_18 + 1;
  } while (local_18 < 10);
  return -1;
}



int FUN_180001320(void)

{
  int iVar1;
  int iVar2;
  
  FUN_180001000();
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18007b1d0);
  iVar1 = DAT_18007b250;
  DAT_18007b240 = DAT_18007b240 + 1;
  iVar2 = FUN_1800012a0(0);
  if (iVar2 == 0) {
    DAT_18007b250 = iVar1 + 1;
  }
  DAT_18007b240 = DAT_18007b240 + -1;
  LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18007b1d0);
  return iVar2;
}



undefined8 FUN_1800013a0(void)

{
  int iVar1;
  undefined8 uVar2;
  code *pcVar3;
  longlong lVar4;
  undefined *puVar5;
  
  FUN_180001000();
  DAT_18007b238 = 1;
  if ((DAT_18007b218 == (HMODULE)0x0) || (DAT_18007b1f8 == (code *)0x0)) {
    DAT_18007b238 = 0;
    uVar2 = 0xfffffffc;
  }
  else if (DAT_18007b240 == 0) {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18007b1d0);
    DAT_18007b250 = DAT_18007b250 + -1;
    if (DAT_18007b250 == 0) {
      pcVar3 = (code *)(*DAT_18007b1f8)(0xd22bdd7e);
      if (pcVar3 == (code *)0x0) {
        DAT_18007b238 = 0;
        LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18007b1d0);
        uVar2 = 0xfffffffd;
      }
      else {
        iVar1 = (*pcVar3)();
        if (iVar1 == 0) {
          DAT_18007b1f8 = (code *)0x0;
          FreeLibrary(DAT_18007b218);
          DAT_18007b218 = (HMODULE)0x0;
          DAT_18007b208 = 0;
          DAT_18007b210 = 0;
          DAT_18007b240 = 0;
          DAT_18007b250 = 0;
          puVar5 = &DAT_18007b260;
          for (lVar4 = 0x828; lVar4 != 0; lVar4 = lVar4 + -1) {
            *puVar5 = 0;
            puVar5 = puVar5 + 1;
          }
          DAT_18007b238 = 0;
          LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18007b1d0);
          FUN_180001030();
          uVar2 = 0;
        }
        else {
          DAT_18007b250 = DAT_18007b250 + 1;
          DAT_18007b238 = 0;
          LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18007b1d0);
          uVar2 = 0xffffffff;
        }
      }
    }
    else {
      DAT_18007b238 = 0;
      LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18007b1d0);
      uVar2 = 0;
    }
  }
  else {
    DAT_18007b238 = 0;
    uVar2 = 0xffffffff;
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_180001530(void)

{
  undefined8 uVar1;
  
  FUN_180001000();
  DAT_18007b239 = 1;
  if ((DAT_18007b220 == (HMODULE)0x0) || (_DAT_18007b200 == 0)) {
    DAT_18007b239 = 0;
    uVar1 = 0xfffffffc;
  }
  else if (_DAT_18007b244 == 0) {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18007b1d0);
    DAT_18007b254 = DAT_18007b254 + -1;
    if (DAT_18007b254 == 0) {
      _DAT_18007b200 = 0;
      FreeLibrary(DAT_18007b220);
      DAT_18007b220 = (HMODULE)0x0;
      _DAT_18007b244 = 0;
      DAT_18007b254 = 0;
      LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18007b1d0);
      FUN_180001030();
      DAT_18007b239 = 0;
      uVar1 = 0;
    }
    else {
      LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18007b1d0);
      uVar1 = 0;
    }
  }
  else {
    DAT_18007b239 = 0;
    uVar1 = 0xffffffff;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_180001620(undefined4 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((_DAT_18007b260 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      _DAT_18007b260 = (code *)(*DAT_18007b1f8)(0x6c2d048c);
    }
    pcVar1 = _DAT_18007b260;
    if (_DAT_18007b260 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x6c2d048c,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x6c2d048c,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180001780(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b268 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b268 = (code *)(*DAT_18007b1f8)(0x1053fa5);
    }
    pcVar1 = DAT_18007b268;
    if (DAT_18007b268 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x1053fa5,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x1053fa5,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180001d30(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b288 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b288 = (code *)(*DAT_18007b1f8)(0xf951a4d1);
    }
    pcVar1 = DAT_18007b288;
    if (DAT_18007b288 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xf951a4d1,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xf951a4d1,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180001e90(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b290 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b290 = (code *)(*DAT_18007b1f8)(0x2926aaad);
    }
    pcVar1 = DAT_18007b290;
    if (DAT_18007b290 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x2926aaad,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x2926aaad,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180001ff0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b298 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b298 = (code *)(*DAT_18007b1f8)(0x7f9b368);
    }
    pcVar1 = DAT_18007b298;
    if (DAT_18007b298 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x7f9b368,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x7f9b368,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180002720(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b2c0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b2c0 = (code *)(*DAT_18007b1f8)(0xe5ac921f);
    }
    pcVar1 = DAT_18007b2c0;
    if (DAT_18007b2c0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xe5ac921f,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xe5ac921f,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180002880(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b2c8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b2c8 = (code *)(*DAT_18007b1f8)(0xd9930b07);
    }
    pcVar1 = DAT_18007b2c8;
    if (DAT_18007b2c8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xd9930b07,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xd9930b07,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800029e0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b2d0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b2d0 = (code *)(*DAT_18007b1f8)(0x48b3ea59);
    }
    pcVar1 = DAT_18007b2d0;
    if (DAT_18007b2d0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x48b3ea59,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x48b3ea59,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180002cb0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b2e0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b2e0 = (code *)(*DAT_18007b1f8)(0x5018ed61);
    }
    pcVar1 = DAT_18007b2e0;
    if (DAT_18007b2e0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x5018ed61,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x5018ed61,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180002e10(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b2e8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b2e8 = (code *)(*DAT_18007b1f8)(0xee1370cf);
    }
    pcVar1 = DAT_18007b2e8;
    if (DAT_18007b2e8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xee1370cf,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xee1370cf,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180002f70(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b2f0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b2f0 = (code *)(*DAT_18007b1f8)(0xadd604d1);
    }
    pcVar1 = DAT_18007b2f0;
    if (DAT_18007b2f0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xadd604d1,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xadd604d1,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180003240(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b300 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b300 = (code *)(*DAT_18007b1f8)(0xc7026a87);
    }
    pcVar1 = DAT_18007b300;
    if (DAT_18007b300 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xc7026a87,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xc7026a87,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800033a0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b308 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b308 = (code *)(*DAT_18007b1f8)(0x7d554f8e);
    }
    pcVar1 = DAT_18007b308;
    if (DAT_18007b308 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x7d554f8e,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x7d554f8e,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180003500(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b310 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b310 = (code *)(*DAT_18007b1f8)(0x1730bfc9);
    }
    pcVar1 = DAT_18007b310;
    if (DAT_18007b310 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x1730bfc9,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x1730bfc9,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180003660(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b318 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b318 = (code *)(*DAT_18007b1f8)(0x680de09);
    }
    pcVar1 = DAT_18007b318;
    if (DAT_18007b318 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x680de09,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x680de09,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180003ab0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b330 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b330 = (code *)(*DAT_18007b1f8)(0xcf8caf39);
    }
    pcVar1 = DAT_18007b330;
    if (DAT_18007b330 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xcf8caf39,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xcf8caf39,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180003c10(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b338 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b338 = (code *)(*DAT_18007b1f8)(0x96043cc7);
    }
    pcVar1 = DAT_18007b338;
    if (DAT_18007b338 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x96043cc7,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x96043cc7,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180003d70(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b340 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b340 = (code *)(*DAT_18007b1f8)(0xbaaabfcc);
    }
    pcVar1 = DAT_18007b340;
    if (DAT_18007b340 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xbaaabfcc,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xbaaabfcc,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180003ed0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b348 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b348 = (code *)(*DAT_18007b1f8)(0xe3e89b6f);
    }
    pcVar1 = DAT_18007b348;
    if (DAT_18007b348 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xe3e89b6f,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xe3e89b6f,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180004470(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b368 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b368 = (code *)(*DAT_18007b1f8)(0xceee8e9f);
    }
    pcVar1 = DAT_18007b368;
    if (DAT_18007b368 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xceee8e9f,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xceee8e9f,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180004760(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b378 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b378 = (code *)(*DAT_18007b1f8)(0xc33baeb1);
    }
    pcVar1 = DAT_18007b378;
    if (DAT_18007b378 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xc33baeb1,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xc33baeb1,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800048c0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b380 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b380 = (code *)(*DAT_18007b1f8)(0x1bb18724);
    }
    pcVar1 = DAT_18007b380;
    if (DAT_18007b380 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x1bb18724,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x1bb18724,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180004a20(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b388 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b388 = (code *)(*DAT_18007b1f8)(0x1be0b8e5);
    }
    pcVar1 = DAT_18007b388;
    if (DAT_18007b388 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x1be0b8e5,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x1be0b8e5,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180004b80(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b390 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b390 = (code *)(*DAT_18007b1f8)(0x2a0a350f);
    }
    pcVar1 = DAT_18007b390;
    if (DAT_18007b390 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x2a0a350f,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x2a0a350f,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180004ce0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b398 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b398 = (code *)(*DAT_18007b1f8)(0xe4715417);
    }
    pcVar1 = DAT_18007b398;
    if (DAT_18007b398 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xe4715417,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xe4715417,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180004e40(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b3a0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b3a0 = (code *)(*DAT_18007b1f8)(0xacc3da0a);
    }
    pcVar1 = DAT_18007b3a0;
    if (DAT_18007b3a0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xacc3da0a,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xacc3da0a,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180004fa0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b3a8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b3a8 = (code *)(*DAT_18007b1f8)(0x2d43fb31);
    }
    pcVar1 = DAT_18007b3a8;
    if (DAT_18007b3a8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x2d43fb31,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x2d43fb31,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180005100(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b3b0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b3b0 = (code *)(*DAT_18007b1f8)(0xa561fd7d);
    }
    pcVar1 = DAT_18007b3b0;
    if (DAT_18007b3b0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xa561fd7d,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xa561fd7d,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180005260(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b3b8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b3b8 = (code *)(*DAT_18007b1f8)(0x6e042794);
    }
    pcVar1 = DAT_18007b3b8;
    if (DAT_18007b3b8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x6e042794,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x6e042794,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800053c0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b3c0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b3c0 = (code *)(*DAT_18007b1f8)(0xc74925a0);
    }
    pcVar1 = DAT_18007b3c0;
    if (DAT_18007b3c0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xc74925a0,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xc74925a0,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180005520(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b3c8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b3c8 = (code *)(*DAT_18007b1f8)(0xd048c3b1);
    }
    pcVar1 = DAT_18007b3c8;
    if (DAT_18007b3c8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xd048c3b1,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xd048c3b1,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180005680(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b3d0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b3d0 = (code *)(*DAT_18007b1f8)(0x46fbeb03);
    }
    pcVar1 = DAT_18007b3d0;
    if (DAT_18007b3d0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x46fbeb03,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x46fbeb03,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800057e0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b3d8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b3d8 = (code *)(*DAT_18007b1f8)(0x5a04b644);
    }
    pcVar1 = DAT_18007b3d8;
    if (DAT_18007b3d8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x5a04b644,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x5a04b644,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180005940(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b3e0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b3e0 = (code *)(*DAT_18007b1f8)(0x22d54523);
    }
    pcVar1 = DAT_18007b3e0;
    if (DAT_18007b3e0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x22d54523,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x22d54523,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180005aa0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b3e8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b3e8 = (code *)(*DAT_18007b1f8)(0xdcb616c3);
    }
    pcVar1 = DAT_18007b3e8;
    if (DAT_18007b3e8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xdcb616c3,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xdcb616c3,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180005d70(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b3f8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b3f8 = (code *)(*DAT_18007b1f8)(0x6ff81213);
    }
    pcVar1 = DAT_18007b3f8;
    if (DAT_18007b3f8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x6ff81213,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x6ff81213,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180005ed0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b400 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b400 = (code *)(*DAT_18007b1f8)(0x927da4f6);
    }
    pcVar1 = DAT_18007b400;
    if (DAT_18007b400 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x927da4f6,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x927da4f6,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180006030(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b408 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b408 = (code *)(*DAT_18007b1f8)(0x60ded2ed);
    }
    pcVar1 = DAT_18007b408;
    if (DAT_18007b408 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x60ded2ed,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x60ded2ed,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180006300(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b418 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b418 = (code *)(*DAT_18007b1f8)(0x2fde12c5);
    }
    pcVar1 = DAT_18007b418;
    if (DAT_18007b418 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x2fde12c5,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x2fde12c5,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180006460(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b420 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b420 = (code *)(*DAT_18007b1f8)(0xe812eb07);
    }
    pcVar1 = DAT_18007b420;
    if (DAT_18007b420 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xe812eb07,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xe812eb07,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800068a0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b438 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b438 = (code *)(*DAT_18007b1f8)(0xf089eef5);
    }
    pcVar1 = DAT_18007b438;
    if (DAT_18007b438 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xf089eef5,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xf089eef5,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180006a00(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b440 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b440 = (code *)(*DAT_18007b1f8)(0x5f608315);
    }
    pcVar1 = DAT_18007b440;
    if (DAT_18007b440 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x5f608315,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x5f608315,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180006b60(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b448 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b448 = (code *)(*DAT_18007b1f8)(0xca1ddaf3);
    }
    pcVar1 = DAT_18007b448;
    if (DAT_18007b448 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xca1ddaf3,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xca1ddaf3,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180006cc0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b450 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b450 = (code *)(*DAT_18007b1f8)(0xc71f85a6);
    }
    pcVar1 = DAT_18007b450;
    if (DAT_18007b450 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xc71f85a6,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xc71f85a6,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180006f90(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b460 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b460 = (code *)(*DAT_18007b1f8)(0x77a796f3);
    }
    pcVar1 = DAT_18007b460;
    if (DAT_18007b460 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x77a796f3,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x77a796f3,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800073d0(undefined4 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b478 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b478 = (code *)(*DAT_18007b1f8)(0xe81ce836);
    }
    pcVar1 = DAT_18007b478;
    if (DAT_18007b478 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xe81ce836,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xe81ce836,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800076b0(undefined4 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b488 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b488 = (code *)(*DAT_18007b1f8)(0x6f5435af);
    }
    pcVar1 = DAT_18007b488;
    if (DAT_18007b488 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x6f5435af,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x6f5435af,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180007c60(undefined4 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b4a8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b4a8 = (code *)(*DAT_18007b1f8)(0xe2e1e6f0);
    }
    pcVar1 = DAT_18007b4a8;
    if (DAT_18007b4a8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xe2e1e6f0,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xe2e1e6f0,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180007dc0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b4b0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b4b0 = (code *)(*DAT_18007b1f8)(0x7f7f4600);
    }
    pcVar1 = DAT_18007b4b0;
    if (DAT_18007b4b0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x7f7f4600,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x7f7f4600,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180007f20(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b4b8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b4b8 = (code *)(*DAT_18007b1f8)(0xa629da31);
    }
    pcVar1 = DAT_18007b4b8;
    if (DAT_18007b4b8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xa629da31,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xa629da31,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180008080(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b4c0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b4c0 = (code *)(*DAT_18007b1f8)(0x9a1b9365);
    }
    pcVar1 = DAT_18007b4c0;
    if (DAT_18007b4c0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x9a1b9365,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x9a1b9365,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800081e0(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b4c8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b4c8 = (code *)(*DAT_18007b1f8)(0x254a187);
    }
    pcVar1 = DAT_18007b4c8;
    if (DAT_18007b4c8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x254a187,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x254a187,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180008340(undefined4 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b4d0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b4d0 = (code *)(*DAT_18007b1f8)(0x9abdd40d);
    }
    pcVar1 = DAT_18007b4d0;
    if (DAT_18007b4d0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x9abdd40d,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x9abdd40d,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800084a0(undefined4 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b4d8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b4d8 = (code *)(*DAT_18007b1f8)(0x20de9260);
    }
    pcVar1 = DAT_18007b4d8;
    if (DAT_18007b4d8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x20de9260,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x20de9260,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180008600(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b4e0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b4e0 = (code *)(*DAT_18007b1f8)(0x63f9799e);
    }
    pcVar1 = DAT_18007b4e0;
    if (DAT_18007b4e0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x63f9799e,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x63f9799e,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180008760(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b4e8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b4e8 = (code *)(*DAT_18007b1f8)(0x35c29134);
    }
    pcVar1 = DAT_18007b4e8;
    if (DAT_18007b4e8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x35c29134,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x35c29134,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800088c0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b4f0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b4f0 = (code *)(*DAT_18007b1f8)(0xa70503b2);
    }
    pcVar1 = DAT_18007b4f0;
    if (DAT_18007b4f0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xa70503b2,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xa70503b2,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180008a20(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b4f8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b4f8 = (code *)(*DAT_18007b1f8)(0x22a78b05);
    }
    pcVar1 = DAT_18007b4f8;
    if (DAT_18007b4f8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x22a78b05,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x22a78b05,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180008b80(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b500 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b500 = (code *)(*DAT_18007b1f8)(0x4888d790);
    }
    pcVar1 = DAT_18007b500;
    if (DAT_18007b500 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x4888d790,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x4888d790,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180008ce0(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b508 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b508 = (code *)(*DAT_18007b1f8)(0x2863148d);
    }
    pcVar1 = DAT_18007b508;
    if (DAT_18007b508 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x2863148d,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x2863148d,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180008e40(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b510 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b510 = (code *)(*DAT_18007b1f8)(0xab163097);
    }
    pcVar1 = DAT_18007b510;
    if (DAT_18007b510 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xab163097,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xab163097,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180008fa0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b518 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b518 = (code *)(*DAT_18007b1f8)(0x67b5db55);
    }
    pcVar1 = DAT_18007b518;
    if (DAT_18007b518 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x67b5db55,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x67b5db55,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180009280(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b528 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b528 = (code *)(*DAT_18007b1f8)(0xd995937e);
    }
    pcVar1 = DAT_18007b528;
    if (DAT_18007b528 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xd995937e,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xd995937e,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180009830(undefined4 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b548 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b548 = (code *)(*DAT_18007b1f8)(0x6067af3f);
    }
    pcVar1 = DAT_18007b548;
    if (DAT_18007b548 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x6067af3f,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x6067af3f,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180009990(undefined4 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b550 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b550 = (code *)(*DAT_18007b1f8)(0x92f9d80d);
    }
    pcVar1 = DAT_18007b550;
    if (DAT_18007b550 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x92f9d80d,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x92f9d80d,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180009c60(undefined4 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b560 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b560 = (code *)(*DAT_18007b1f8)(0x3b05c7e1);
    }
    pcVar1 = DAT_18007b560;
    if (DAT_18007b560 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x3b05c7e1,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x3b05c7e1,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000aad0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b5b0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b5b0 = (code *)(*DAT_18007b1f8)(0xae457190);
    }
    pcVar1 = DAT_18007b5b0;
    if (DAT_18007b5b0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xae457190,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xae457190,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000ac30(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b5b8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b5b8 = (code *)(*DAT_18007b1f8)(0x1e9d8a31);
    }
    pcVar1 = DAT_18007b5b8;
    if (DAT_18007b5b8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x1e9d8a31,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x1e9d8a31,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000ad90(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b5c0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b5c0 = (code *)(*DAT_18007b1f8)(0x11abccf8);
    }
    pcVar1 = DAT_18007b5c0;
    if (DAT_18007b5c0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x11abccf8,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x11abccf8,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000b1c0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b5d8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b5d8 = (code *)(*DAT_18007b1f8)(0xcb89381d);
    }
    pcVar1 = DAT_18007b5d8;
    if (DAT_18007b5d8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xcb89381d,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xcb89381d,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000bef0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b620 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b620 = (code *)(*DAT_18007b1f8)(0xdf2887af);
    }
    pcVar1 = DAT_18007b620;
    if (DAT_18007b620 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xdf2887af,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xdf2887af,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000c050(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b628 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b628 = (code *)(*DAT_18007b1f8)(0x410b5c25);
    }
    pcVar1 = DAT_18007b628;
    if (DAT_18007b628 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x410b5c25,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x410b5c25,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000c1b0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b630 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b630 = (code *)(*DAT_18007b1f8)(0xf60852bd);
    }
    pcVar1 = DAT_18007b630;
    if (DAT_18007b630 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xf60852bd,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xf60852bd,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000c310(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b638 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b638 = (code *)(*DAT_18007b1f8)(0xd54b8989);
    }
    pcVar1 = DAT_18007b638;
    if (DAT_18007b638 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xd54b8989,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xd54b8989,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000c5d0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b648 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b648 = (code *)(*DAT_18007b1f8)(0xd9639601);
    }
    pcVar1 = DAT_18007b648;
    if (DAT_18007b648 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xd9639601,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xd9639601,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000c730(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b650 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b650 = (code *)(*DAT_18007b1f8)(0x44a3f1d1);
    }
    pcVar1 = DAT_18007b650;
    if (DAT_18007b650 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x44a3f1d1,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x44a3f1d1,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000cb90(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b668 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b668 = (code *)(*DAT_18007b1f8)(0x16de1c6a);
    }
    pcVar1 = DAT_18007b668;
    if (DAT_18007b668 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x16de1c6a,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x16de1c6a,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000ccf0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b670 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b670 = (code *)(*DAT_18007b1f8)(0x8bbff88b);
    }
    pcVar1 = DAT_18007b670;
    if (DAT_18007b670 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x8bbff88b,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x8bbff88b,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000d140(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b688 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b688 = (code *)(*DAT_18007b1f8)(0x70d404ec);
    }
    pcVar1 = DAT_18007b688;
    if (DAT_18007b688 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x70d404ec,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x70d404ec,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000d2a0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b690 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b690 = (code *)(*DAT_18007b1f8)(0x4b708b54);
    }
    pcVar1 = DAT_18007b690;
    if (DAT_18007b690 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x4b708b54,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x4b708b54,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000d400(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b698 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b698 = (code *)(*DAT_18007b1f8)(0xa064bdfc);
    }
    pcVar1 = DAT_18007b698;
    if (DAT_18007b698 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xa064bdfc,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xa064bdfc,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000d560(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b6a0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b6a0 = (code *)(*DAT_18007b1f8)(0xbb2b17aa);
    }
    pcVar1 = DAT_18007b6a0;
    if (DAT_18007b6a0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xbb2b17aa,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xbb2b17aa,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000e160(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b6e0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b6e0 = (code *)(*DAT_18007b1f8)(0xf2dd3f2);
    }
    pcVar1 = DAT_18007b6e0;
    if (DAT_18007b6e0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xf2dd3f2,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xf2dd3f2,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000e2c0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b6e8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b6e8 = (code *)(*DAT_18007b1f8)(0xb852f4db);
    }
    pcVar1 = DAT_18007b6e8;
    if (DAT_18007b6e8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xb852f4db,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xb852f4db,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000ede0(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b720 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b720 = (code *)(*DAT_18007b1f8)(0x65b93ca8);
    }
    pcVar1 = DAT_18007b720;
    if (DAT_18007b720 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x65b93ca8,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x65b93ca8,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000ef40(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b728 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b728 = (code *)(*DAT_18007b1f8)(0x2216a357);
    }
    pcVar1 = DAT_18007b728;
    if (DAT_18007b728 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x2216a357,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x2216a357,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000f7c0(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b758 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b758 = (code *)(*DAT_18007b1f8)(0xd0cbca7d);
    }
    pcVar1 = DAT_18007b758;
    if (DAT_18007b758 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xd0cbca7d,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xd0cbca7d,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000f920(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b760 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b760 = (code *)(*DAT_18007b1f8)(0x1dc91303);
    }
    pcVar1 = DAT_18007b760;
    if (DAT_18007b760 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x1dc91303,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x1dc91303,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000fd50(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b778 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b778 = (code *)(*DAT_18007b1f8)(0xe6ce4f1);
    }
    pcVar1 = DAT_18007b778;
    if (DAT_18007b778 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xe6ce4f1,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xe6ce4f1,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_18000feb0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b780 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b780 = (code *)(*DAT_18007b1f8)(0x118d48a3);
    }
    pcVar1 = DAT_18007b780;
    if (DAT_18007b780 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x118d48a3,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x118d48a3,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180010010(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b788 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b788 = (code *)(*DAT_18007b1f8)(0xd34a789b);
    }
    pcVar1 = DAT_18007b788;
    if (DAT_18007b788 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xd34a789b,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xd34a789b,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180010170(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b790 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b790 = (code *)(*DAT_18007b1f8)(0xe4eec07);
    }
    pcVar1 = DAT_18007b790;
    if (DAT_18007b790 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xe4eec07,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xe4eec07,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800102d0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b798 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b798 = (code *)(*DAT_18007b1f8)(0xa1ec8d74);
    }
    pcVar1 = DAT_18007b798;
    if (DAT_18007b798 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xa1ec8d74,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xa1ec8d74,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180010430(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b7a0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b7a0 = (code *)(*DAT_18007b1f8)(0x7b0d72a3);
    }
    pcVar1 = DAT_18007b7a0;
    if (DAT_18007b7a0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x7b0d72a3,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x7b0d72a3,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180010590(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b7a8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b7a8 = (code *)(*DAT_18007b1f8)(0x964bf452);
    }
    pcVar1 = DAT_18007b7a8;
    if (DAT_18007b7a8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x964bf452,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x964bf452,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800106f0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b7b0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b7b0 = (code *)(*DAT_18007b1f8)(0x51d53d06);
    }
    pcVar1 = DAT_18007b7b0;
    if (DAT_18007b7b0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x51d53d06,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x51d53d06,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180010850(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b7b8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b7b8 = (code *)(*DAT_18007b1f8)(0x2697a8d1);
    }
    pcVar1 = DAT_18007b7b8;
    if (DAT_18007b7b8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x2697a8d1,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x2697a8d1,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800109b0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b7c0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b7c0 = (code *)(*DAT_18007b1f8)(0x462214a9);
    }
    pcVar1 = DAT_18007b7c0;
    if (DAT_18007b7c0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x462214a9,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x462214a9,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180010b10(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b7c8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b7c8 = (code *)(*DAT_18007b1f8)(0xb981d935);
    }
    pcVar1 = DAT_18007b7c8;
    if (DAT_18007b7c8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xb981d935,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xb981d935,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180010c70(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b7d0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b7d0 = (code *)(*DAT_18007b1f8)(0x96bd040e);
    }
    pcVar1 = DAT_18007b7d0;
    if (DAT_18007b7d0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x96bd040e,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x96bd040e,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180010dd0(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b7d8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b7d8 = (code *)(*DAT_18007b1f8)(0xcde8e1a3);
    }
    pcVar1 = DAT_18007b7d8;
    if (DAT_18007b7d8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xcde8e1a3,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xcde8e1a3,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180010f30(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b7e0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b7e0 = (code *)(*DAT_18007b1f8)(0x6ba2a5d6);
    }
    pcVar1 = DAT_18007b7e0;
    if (DAT_18007b7e0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x6ba2a5d6,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x6ba2a5d6,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180011210(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b7f0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b7f0 = (code *)(*DAT_18007b1f8)(0xfd7c5557);
    }
    pcVar1 = DAT_18007b7f0;
    if (DAT_18007b7f0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xfd7c5557,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xfd7c5557,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180011370(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b7f8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b7f8 = (code *)(*DAT_18007b1f8)(0x869534e2);
    }
    pcVar1 = DAT_18007b7f8;
    if (DAT_18007b7f8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x869534e2,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x869534e2,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180011d40(void)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b830 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b830 = (code *)(*DAT_18007b1f8)(0x239c4545);
    }
    pcVar1 = DAT_18007b830;
    if (DAT_18007b830 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x239c4545,&local_20);
      }
      local_18 = (*pcVar1)();
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x239c4545,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180011e90(void)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b838 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b838 = (code *)(*DAT_18007b1f8)(0x2ec50c2b);
    }
    pcVar1 = DAT_18007b838;
    if (DAT_18007b838 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x2ec50c2b,&local_20);
      }
      local_18 = (*pcVar1)();
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x2ec50c2b,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180011fe0(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b840 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b840 = (code *)(*DAT_18007b1f8)(0x348ff8e1);
    }
    pcVar1 = DAT_18007b840;
    if (DAT_18007b840 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x348ff8e1,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x348ff8e1,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180012140(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b848 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b848 = (code *)(*DAT_18007b1f8)(0x296c434d);
    }
    pcVar1 = DAT_18007b848;
    if (DAT_18007b848 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x296c434d,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x296c434d,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800122a0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b850 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b850 = (code *)(*DAT_18007b1f8)(0xac7e37f4);
    }
    pcVar1 = DAT_18007b850;
    if (DAT_18007b850 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xac7e37f4,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xac7e37f4,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180012400(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b858 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b858 = (code *)(*DAT_18007b1f8)(0x3a153134);
    }
    pcVar1 = DAT_18007b858;
    if (DAT_18007b858 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x3a153134,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x3a153134,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180012560(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b860 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b860 = (code *)(*DAT_18007b1f8)(0xf6a1ad68);
    }
    pcVar1 = DAT_18007b860;
    if (DAT_18007b860 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xf6a1ad68,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xf6a1ad68,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800126c0(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b868 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b868 = (code *)(*DAT_18007b1f8)(0x2d68de96);
    }
    pcVar1 = DAT_18007b868;
    if (DAT_18007b868 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x2d68de96,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x2d68de96,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180012820(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b870 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b870 = (code *)(*DAT_18007b1f8)(0x1fb0bc30);
    }
    pcVar1 = DAT_18007b870;
    if (DAT_18007b870 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x1fb0bc30,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x1fb0bc30,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180012980(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b878 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b878 = (code *)(*DAT_18007b1f8)(0x451f2134);
    }
    pcVar1 = DAT_18007b878;
    if (DAT_18007b878 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x451f2134,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x451f2134,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180012c50(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b888 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b888 = (code *)(*DAT_18007b1f8)(0xda044458);
    }
    pcVar1 = DAT_18007b888;
    if (DAT_18007b888 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xda044458,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xda044458,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180012db0(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b890 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b890 = (code *)(*DAT_18007b1f8)(0xc9a8ecec);
    }
    pcVar1 = DAT_18007b890;
    if (DAT_18007b890 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xc9a8ecec,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xc9a8ecec,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180012f10(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b898 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b898 = (code *)(*DAT_18007b1f8)(0x4ab00934);
    }
    pcVar1 = DAT_18007b898;
    if (DAT_18007b898 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x4ab00934,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x4ab00934,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800131e0(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b8a8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b8a8 = (code *)(*DAT_18007b1f8)(0x4c87e317);
    }
    pcVar1 = DAT_18007b8a8;
    if (DAT_18007b8a8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x4c87e317,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x4c87e317,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180013340(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b8b0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b8b0 = (code *)(*DAT_18007b1f8)(0xa17daabe);
    }
    pcVar1 = DAT_18007b8b0;
    if (DAT_18007b8b0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xa17daabe,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xa17daabe,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800134a0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b8b8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b8b8 = (code *)(*DAT_18007b1f8)(0xe6839b43);
    }
    pcVar1 = DAT_18007b8b8;
    if (DAT_18007b8b8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xe6839b43,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xe6839b43,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180013a20(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b8d8 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b8d8 = (code *)(*DAT_18007b1f8)(0xd6c6cd2);
    }
    pcVar1 = DAT_18007b8d8;
    if (DAT_18007b8d8 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xd6c6cd2,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xd6c6cd2,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180013b80(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b8e0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b8e0 = (code *)(*DAT_18007b1f8)(0x8b7e99b5);
    }
    pcVar1 = DAT_18007b8e0;
    if (DAT_18007b8e0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x8b7e99b5,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x8b7e99b5,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180014270(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b908 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b908 = (code *)(*DAT_18007b1f8)(0xce653127);
    }
    pcVar1 = DAT_18007b908;
    if (DAT_18007b908 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xce653127,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xce653127,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800143d0(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b910 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b910 = (code *)(*DAT_18007b1f8)(0x40c8ed5e);
    }
    pcVar1 = DAT_18007b910;
    if (DAT_18007b910 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x40c8ed5e,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x40c8ed5e,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180014690(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b920 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b920 = (code *)(*DAT_18007b1f8)(0x36f1c736);
    }
    pcVar1 = DAT_18007b920;
    if (DAT_18007b920 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x36f1c736,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x36f1c736,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800147f0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b928 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b928 = (code *)(*DAT_18007b1f8)(0xed4416c5);
    }
    pcVar1 = DAT_18007b928;
    if (DAT_18007b928 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xed4416c5,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xed4416c5,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180014950(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b930 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b930 = (code *)(*DAT_18007b1f8)(0x44f0ecd1);
    }
    pcVar1 = DAT_18007b930;
    if (DAT_18007b930 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x44f0ecd1,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x44f0ecd1,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180014f20(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b950 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b950 = (code *)(*DAT_18007b1f8)(0x694d52e);
    }
    pcVar1 = DAT_18007b950;
    if (DAT_18007b950 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x694d52e,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x694d52e,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180015080(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b958 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b958 = (code *)(*DAT_18007b1f8)(0xdad9cff8);
    }
    pcVar1 = DAT_18007b958;
    if (DAT_18007b958 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xdad9cff8,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xdad9cff8,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800151e0(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b960 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b960 = (code *)(*DAT_18007b1f8)(0x375dbd6b);
    }
    pcVar1 = DAT_18007b960;
    if (DAT_18007b960 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x375dbd6b,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x375dbd6b,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180015340(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b968 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b968 = (code *)(*DAT_18007b1f8)(0xfcbc7e14);
    }
    pcVar1 = DAT_18007b968;
    if (DAT_18007b968 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xfcbc7e14,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xfcbc7e14,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800154a0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b970 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b970 = (code *)(*DAT_18007b1f8)(0xd3ede889);
    }
    pcVar1 = DAT_18007b970;
    if (DAT_18007b970 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xd3ede889,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xd3ede889,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180015600(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b978 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b978 = (code *)(*DAT_18007b1f8)(0x2be25df8);
    }
    pcVar1 = DAT_18007b978;
    if (DAT_18007b978 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x2be25df8,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x2be25df8,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800158d0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b988 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b988 = (code *)(*DAT_18007b1f8)(0x17093206);
    }
    pcVar1 = DAT_18007b988;
    if (DAT_18007b988 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x17093206,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x17093206,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180015a30(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b990 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b990 = (code *)(*DAT_18007b1f8)(0x1c89c5df);
    }
    pcVar1 = DAT_18007b990;
    if (DAT_18007b990 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x1c89c5df,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x1c89c5df,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180015b90(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b998 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b998 = (code *)(*DAT_18007b1f8)(0x617bff9f);
    }
    pcVar1 = DAT_18007b998;
    if (DAT_18007b998 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x617bff9f,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x617bff9f,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800162b0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007b9c0 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007b9c0 = (code *)(*DAT_18007b1f8)(0x1dae4fbc);
    }
    pcVar1 = DAT_18007b9c0;
    if (DAT_18007b9c0 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x1dae4fbc,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x1dae4fbc,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180017170(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007ba10 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007ba10 = (code *)(*DAT_18007b1f8)(0xf020614a);
    }
    pcVar1 = DAT_18007ba10;
    if (DAT_18007ba10 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xf020614a,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xf020614a,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180017440(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007ba20 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007ba20 = (code *)(*DAT_18007b1f8)(0xcb7309cd);
    }
    pcVar1 = DAT_18007ba20;
    if (DAT_18007ba20 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xcb7309cd,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xcb7309cd,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800175a0(undefined4 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007ba28 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007ba28 = (code *)(*DAT_18007b1f8)(0xd61cbe6e);
    }
    pcVar1 = DAT_18007ba28;
    if (DAT_18007ba28 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xd61cbe6e,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xd61cbe6e,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180017870(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007ba38 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007ba38 = (code *)(*DAT_18007b1f8)(0x5927b094);
    }
    pcVar1 = DAT_18007ba38;
    if (DAT_18007ba38 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x5927b094,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x5927b094,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800179d0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007ba40 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007ba40 = (code *)(*DAT_18007b1f8)(0xfa5f6134);
    }
    pcVar1 = DAT_18007ba40;
    if (DAT_18007ba40 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xfa5f6134,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xfa5f6134,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180017ca0(undefined8 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007ba50 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007ba50 = (code *)(*DAT_18007b1f8)(0xda8466a0);
    }
    pcVar1 = DAT_18007ba50;
    if (DAT_18007ba50 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xda8466a0,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xda8466a0,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180017e00(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007ba58 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007ba58 = (code *)(*DAT_18007b1f8)(0x53dabbca);
    }
    pcVar1 = DAT_18007ba58;
    if (DAT_18007ba58 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x53dabbca,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x53dabbca,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_180017f60(undefined8 param_1)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007ba60 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007ba60 = (code *)(*DAT_18007b1f8)(0xcda14d8a);
    }
    pcVar1 = DAT_18007ba60;
    if (DAT_18007ba60 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0xcda14d8a,&local_20);
      }
      local_18 = (*pcVar1)(param_1);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0xcda14d8a,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



int FUN_1800183a0(undefined4 param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 local_20;
  int local_18;
  int local_14;
  
  local_14 = 0;
  DAT_18007b240 = DAT_18007b240 + 1;
  local_18 = FUN_1800012a0(0);
  if (local_18 == 0) {
    if ((DAT_18007ba78 == (code *)0x0) && (DAT_18007b1f8 != (code *)0x0)) {
      DAT_18007ba78 = (code *)(*DAT_18007b1f8)(0x9ea74659);
    }
    pcVar1 = DAT_18007ba78;
    if (DAT_18007ba78 == (code *)0x0) {
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
      local_18 = -3;
    }
    else {
      local_20 = 0;
      if (DAT_18007b208 != (code *)0x0) {
        (*DAT_18007b208)(0x9ea74659,&local_20);
      }
      local_18 = (*pcVar1)(param_1,param_2);
      if (DAT_18007b210 != (code *)0x0) {
        (*DAT_18007b210)(0x9ea74659,local_20,local_18);
      }
      (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
    }
  }
  else {
    (&DAT_18007b240)[local_14] = (&DAT_18007b240)[local_14] + -1;
  }
  return local_18;
}



HMODULE FUN_180018500(short *param_1)

{
  undefined8 uVar1;
  LPWSTR lpModuleName;
  HMODULE local_18;
  
  local_18 = (HMODULE)0x0;
  SetLastError(0);
  uVar1 = FUN_1800199d0(param_1);
  if ((int)uVar1 == 0) {
    lpModuleName = FUN_1800197e0(param_1);
    if ((param_1 == (short *)0x0) || (lpModuleName != (LPWSTR)0x0)) {
      local_18 = GetModuleHandleW(lpModuleName);
    }
    LocalFree(lpModuleName);
  }
  else {
    SetLastError(0xa0);
  }
  return local_18;
}



HMODULE FUN_180018580(char *param_1)

{
  short *hMem;
  HMODULE local_18;
  
  local_18 = (HMODULE)0x0;
  hMem = (short *)FUN_180019910(param_1);
  if ((param_1 == (char *)0x0) || (hMem != (short *)0x0)) {
    local_18 = FUN_180018500(hMem);
  }
  LocalFree(hMem);
  return local_18;
}



HMODULE FUN_1800185e0(short *param_1,uint param_2)

{
  undefined8 uVar1;
  LPWSTR lpLibFileName;
  HMODULE local_18;
  
  local_18 = (HMODULE)0x0;
  SetLastError(0);
  uVar1 = FUN_1800199d0(param_1);
  if ((int)uVar1 == 0) {
    lpLibFileName = FUN_1800197e0(param_1);
    if ((param_1 == (short *)0x0) || (lpLibFileName != (LPWSTR)0x0)) {
      local_18 = LoadLibraryExW(lpLibFileName,(HANDLE)0x0,param_2 & 0xffffe0f7);
    }
    LocalFree(lpLibFileName);
  }
  else {
    SetLastError(0xa0);
  }
  return local_18;
}



HMODULE FUN_180018680(char *param_1,uint param_2)

{
  short *hMem;
  HMODULE local_18;
  
  local_18 = (HMODULE)0x0;
  hMem = (short *)FUN_180019910(param_1);
  if ((param_1 == (char *)0x0) || (hMem != (short *)0x0)) {
    local_18 = FUN_1800185e0(hMem,param_2);
  }
  LocalFree(hMem);
  return local_18;
}



HMODULE FUN_1800186f0(LPCWSTR param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  uint uVar1;
  undefined8 uVar2;
  HMODULE pHVar3;
  uint uVar4;
  
  uVar4 = (uint)param_2;
  SetLastError(0);
  uVar2 = FUN_180019a50((ushort *)param_1);
  if ((int)uVar2 == 0) {
    SetLastError(0xa0);
    pHVar3 = (HMODULE)0x0;
  }
  else {
    uVar1 = FUN_180019b70(param_1,param_2,param_3,param_4);
    if (uVar1 == 0) {
      SetLastError(0xa1);
      pHVar3 = (HMODULE)0x0;
    }
    else {
      pHVar3 = LoadLibraryExW(param_1,(HANDLE)0x0,uVar4 & 0xffffe0f7);
    }
  }
  return pHVar3;
}



HMODULE FUN_1800187e0(LPCWSTR param_1,uint param_2,undefined8 param_3,undefined8 param_4)

{
  DWORD DVar1;
  int iVar2;
  LPWSTR lpLibFileName;
  HANDLE hObject;
  HMODULE local_38;
  int local_20;
  uint local_1c;
  DWORD local_18;
  uint *local_10;
  
  iVar2 = (int)param_3;
  local_38 = (HMODULE)0x0;
  SetLastError(0);
  lpLibFileName = FUN_18001a200(param_1,param_2,param_3,param_4);
  if (lpLibFileName == (LPWSTR)0x0) {
    DVar1 = GetLastError();
    if (DVar1 == 0x20) {
      return (HMODULE)0x0;
    }
    SetLastError(0x7e);
    return (HMODULE)0x0;
  }
  hObject = (HANDLE)FUN_180019b20(lpLibFileName);
  if (hObject == (HANDLE)0xffffffffffffffff) {
    LocalFree(lpLibFileName);
    SetLastError(0x20);
    return (HMODULE)0x0;
  }
  local_1c = 0;
  if (iVar2 == 0) {
    local_10 = (uint *)0x0;
  }
  else {
    local_10 = &local_1c;
  }
  local_20 = FUN_18001a3c0(lpLibFileName,local_10);
  if (((local_20 != 0) && (iVar2 != 0)) && (local_1c == 0)) {
    SetLastError(0x80092009);
    local_20 = 0;
  }
  if (local_20 == 0) {
    DVar1 = GetLastError();
    iVar2 = FUN_18001afd0(lpLibFileName,DVar1);
    if (iVar2 == 0) goto LAB_180018917;
  }
  local_38 = LoadLibraryExW(lpLibFileName,(HANDLE)0x0,param_2 & 0xffffe0f7);
LAB_180018917:
  LocalFree(lpLibFileName);
  if ((hObject != (HANDLE)0x0) && (hObject != (HANDLE)0xffffffffffffffff)) {
    local_18 = GetLastError();
    CloseHandle(hObject);
    SetLastError(local_18);
  }
  return local_38;
}



HMODULE FUN_1800189e0(LPCWSTR param_1,uint param_2,undefined8 param_3,undefined8 param_4)

{
  DWORD DVar1;
  uint uVar2;
  int iVar3;
  LPWSTR lpLibFileName;
  HANDLE hObject;
  ulonglong uVar4;
  HMODULE local_30;
  int local_20;
  uint local_1c;
  DWORD local_18;
  DWORD local_14;
  uint *local_10;
  
  iVar3 = (int)param_3;
  local_30 = (HMODULE)0x0;
  SetLastError(0);
  uVar4 = (ulonglong)param_2;
  lpLibFileName = FUN_18001a200(param_1,param_2,param_3,param_4);
  if (lpLibFileName == (LPWSTR)0x0) {
    DVar1 = GetLastError();
    if (DVar1 != 0x20) {
      SetLastError(0x7e);
    }
  }
  else {
    hObject = (HANDLE)FUN_180019b20(lpLibFileName);
    if (hObject == (HANDLE)0xffffffffffffffff) {
      LocalFree(lpLibFileName);
      SetLastError(0x20);
    }
    else {
      uVar2 = FUN_180019b70(lpLibFileName,uVar4,param_3,param_4);
      if (uVar2 == 0) {
        local_1c = 0;
        if (iVar3 == 0) {
          local_10 = (uint *)0x0;
        }
        else {
          local_10 = &local_1c;
        }
        local_20 = FUN_18001a3c0(lpLibFileName,local_10);
        if (((local_20 != 0) && (iVar3 != 0)) && (local_1c == 0)) {
          SetLastError(0x80092009);
          local_20 = 0;
        }
        if (local_20 == 0) {
          DVar1 = GetLastError();
          iVar3 = FUN_18001afd0(lpLibFileName,DVar1);
          if (iVar3 == 0) {
            LocalFree(lpLibFileName);
            if ((hObject != (HANDLE)0x0) && (hObject != (HANDLE)0xffffffffffffffff)) {
              local_18 = GetLastError();
              CloseHandle(hObject);
              SetLastError(local_18);
            }
            return (HMODULE)0x0;
          }
        }
      }
      local_30 = LoadLibraryExW(lpLibFileName,(HANDLE)0x0,param_2);
      LocalFree(lpLibFileName);
      if ((hObject != (HANDLE)0x0) && (hObject != (HANDLE)0xffffffffffffffff)) {
        local_14 = GetLastError();
        CloseHandle(hObject);
        SetLastError(local_14);
      }
    }
  }
  return local_30;
}



int FUN_180018d00(LPCWSTR param_1,short *param_2,undefined8 param_3,undefined8 param_4)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  undefined8 uVar4;
  ulonglong uVar5;
  SIZE_T uBytes;
  short *psVar6;
  wchar_t *pwVar7;
  DWORD local_30;
  wchar_t *local_28;
  LPCWSTR local_20;
  
  iVar3 = (int)param_3;
  local_28 = (wchar_t *)0x0;
  local_30 = 0;
  SetLastError(0);
  local_20 = param_1;
  if (param_1 == (LPCWSTR)0x0) {
    if (param_2 == (short *)0x0) {
      SetLastError(0x57);
      return 0;
    }
    uVar5 = 0xffffffffffffffff;
    psVar6 = param_2;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      sVar1 = *psVar6;
      psVar6 = psVar6 + 1;
    } while (sVar1 != 0);
    uBytes = ~uVar5 * 2;
    local_28 = (wchar_t *)LocalAlloc(0x40,uBytes);
    pwVar7 = local_28;
    if (local_28 == (wchar_t *)0x0) {
      return 0;
    }
    for (; uBytes != 0; uBytes = uBytes - 1) {
      *(undefined *)pwVar7 = *(undefined *)param_2;
      param_2 = (short *)((longlong)param_2 + 1);
      pwVar7 = (wchar_t *)((longlong)pwVar7 + 1);
    }
    uVar4 = FUN_180019ae0(local_28,0x22);
    if ((int)uVar4 == 0) {
      param_1 = (LPCWSTR)&DAT_180032314;
      local_20 = wcstok(local_28,(wchar_t *)&DAT_180032314);
    }
    else {
      param_1 = (LPCWSTR)&DAT_180032310;
      local_20 = wcstok(local_28,(wchar_t *)&DAT_180032310);
    }
  }
  if (local_20 == (LPCWSTR)0x0) {
    LocalFree(local_28);
    SetLastError(0x57);
    iVar3 = 0;
  }
  else {
    uVar4 = FUN_180019a50((ushort *)local_20);
    if ((int)uVar4 == 0) {
      LocalFree(local_28);
      SetLastError(0xa0);
      iVar3 = 0;
    }
    else {
      uVar2 = FUN_180019b70(local_20,param_1,param_3,param_4);
      if (uVar2 == 0) {
        uVar4 = FUN_180018ee0(local_20,iVar3);
        iVar3 = (int)uVar4;
        if (iVar3 == 0) {
          local_30 = GetLastError();
        }
        LocalFree(local_28);
        if (iVar3 == 0) {
          SetLastError(local_30);
        }
      }
      else {
        LocalFree(local_28);
        iVar3 = 1;
      }
    }
  }
  return iVar3;
}



undefined8 FUN_180018ee0(LPCWSTR param_1,int param_2)

{
  DWORD DVar1;
  int iVar2;
  int local_18;
  uint local_14;
  uint *local_10;
  
  local_14 = 0;
  if (param_2 == 0) {
    local_10 = (uint *)0x0;
  }
  else {
    local_10 = &local_14;
  }
  local_18 = FUN_18001a3c0(param_1,local_10);
  if (((local_18 != 0) && (param_2 != 0)) && (local_14 == 0)) {
    SetLastError(0x80092009);
    local_18 = 0;
  }
  if (local_18 == 0) {
    DVar1 = GetLastError();
    iVar2 = FUN_18001afd0(param_1,DVar1);
    if (iVar2 == 0) {
      return 0;
    }
  }
  return 1;
}



LPWSTR FUN_1800197e0(short *param_1)

{
  short sVar1;
  UINT uSize;
  LPWSTR lpBuffer;
  ulonglong uVar2;
  short *psVar3;
  uint local_28;
  UINT local_18;
  
  if (param_1 != (short *)0x0) {
    uSize = GetSystemDirectoryW((LPWSTR)0x0,0);
    uVar2 = 0xffffffffffffffff;
    psVar3 = param_1;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      sVar1 = *psVar3;
      psVar3 = psVar3 + 1;
    } while (sVar1 != 0);
    lpBuffer = (LPWSTR)LocalAlloc(0x40,((ulonglong)(uSize + 1) + (~uVar2 - 1)) * 2);
    if (lpBuffer != (LPWSTR)0x0) {
      local_18 = GetSystemDirectoryW(lpBuffer,uSize);
      if (lpBuffer[local_18 - 1] != L'\\') {
        lpBuffer[local_18] = L'\\';
        local_18 = local_18 + 1;
      }
      local_28 = 0;
      do {
        uVar2 = 0xffffffffffffffff;
        psVar3 = param_1;
        do {
          if (uVar2 == 0) break;
          uVar2 = uVar2 - 1;
          sVar1 = *psVar3;
          psVar3 = psVar3 + 1;
        } while (sVar1 != 0);
        if (~uVar2 - 1 <= (ulonglong)local_28) {
          return lpBuffer;
        }
        lpBuffer[local_18 + local_28] = param_1[local_28];
        local_28 = local_28 + 1;
      } while( true );
    }
  }
  return (LPWSTR)0x0;
}



HLOCAL FUN_180019910(char *param_1)

{
  char cVar1;
  ulonglong uVar2;
  char *pcVar3;
  uint local_18;
  HLOCAL local_10;
  
  local_10 = (HLOCAL)0x0;
  if (param_1 != (char *)0x0) {
    uVar2 = 0xffffffffffffffff;
    pcVar3 = param_1;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    local_10 = LocalAlloc(0x40,~uVar2 * 2);
    if (local_10 != (HLOCAL)0x0) {
      local_18 = 0;
      do {
        uVar2 = 0xffffffffffffffff;
        pcVar3 = param_1;
        do {
          if (uVar2 == 0) break;
          uVar2 = uVar2 - 1;
          cVar1 = *pcVar3;
          pcVar3 = pcVar3 + 1;
        } while (cVar1 != '\0');
        if (~uVar2 - 1 <= (ulonglong)local_18) {
          return local_10;
        }
        *(short *)((longlong)local_10 + (ulonglong)local_18 * 2) = (short)param_1[local_18];
        local_18 = local_18 + 1;
      } while( true );
    }
  }
  return local_10;
}



undefined8 FUN_1800199d0(short *param_1)

{
  short sVar1;
  ulonglong uVar2;
  short *psVar3;
  uint local_18;
  
  if (param_1 == (short *)0x0) {
    return 0;
  }
  local_18 = 0;
  do {
    uVar2 = 0xffffffffffffffff;
    psVar3 = param_1;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      sVar1 = *psVar3;
      psVar3 = psVar3 + 1;
    } while (sVar1 != 0);
    if (~uVar2 - 1 <= (ulonglong)local_18) {
      return 0;
    }
    if ((param_1[local_18] == 0x5c) || (param_1[local_18] == 0x2f)) {
      return 1;
    }
    local_18 = local_18 + 1;
  } while( true );
}



undefined8 FUN_180019a50(ushort *param_1)

{
  int iVar1;
  undefined8 uVar2;
  
  if (param_1 == (ushort *)0x0) {
    uVar2 = 0;
  }
  else if ((*param_1 == 0x5c) || (*param_1 == 0x2f)) {
    uVar2 = 1;
  }
  else {
    iVar1 = isalpha((uint)*param_1);
    if (((iVar1 == 0) || (param_1[1] != 0x3a)) || ((param_1[2] != 0x5c && (param_1[2] != 0x2f)))) {
      uVar2 = 0;
    }
    else {
      uVar2 = 1;
    }
  }
  return uVar2;
}



undefined8 FUN_180019ae0(short *param_1,short param_2)

{
  undefined8 uVar1;
  
  if ((param_1 == (short *)0x0) || (*param_1 != param_2)) {
    uVar1 = 0;
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}



void FUN_180019b20(LPCWSTR param_1)

{
  CreateFileW(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_180019b70(LPCWSTR param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  wchar_t wVar1;
  BOOL BVar2;
  DWORD DVar3;
  int iVar4;
  undefined8 uVar5;
  ulonglong uVar6;
  wchar_t *pwVar7;
  int local_54;
  uint local_50 [4];
  uint local_40;
  LPWSTR local_38;
  int local_30;
  DWORD local_2c;
  wchar_t *local_28;
  DWORDLONG local_20;
  uint local_18;
  uint local_14;
  
  local_2c = 0;
  local_38 = (LPWSTR)0x0;
  local_28 = (wchar_t *)0x0;
  local_40 = 0;
  local_50[0] = 0x24;
  local_50[1] = 0x26;
  local_50[2] = 0x2a;
  local_30 = 3;
  if (_DAT_18007bb70 == 0) {
    uVar5 = VerSetConditionMask(0,2,3,param_4,0);
    uVar5 = VerSetConditionMask(uVar5,1,3);
    local_20 = VerSetConditionMask(uVar5,0x20,3);
    _DAT_18007bb70 = 0x11c;
    _DAT_18007bb74 = 6;
    _DAT_18007bb78 = 1;
    _DAT_18007bc84 = 0;
    BVar2 = VerifyVersionInfoW((LPOSVERSIONINFOEXW)&DAT_18007bb70,0x23,local_20);
    local_18 = (uint)(BVar2 == 0);
    _DAT_180032458 = local_18;
  }
  if (_DAT_180032458 == 0) {
    if ((((param_1 != (LPCWSTR)0x0) &&
         (local_2c = GetFullPathNameW(param_1,0,(LPWSTR)0x0,(LPWSTR *)0x0), local_2c != 0)) &&
        (local_38 = (LPWSTR)LocalAlloc(0x40,(ulonglong)local_2c << 1), local_38 != (LPWSTR)0x0)) &&
       (DVar3 = GetFullPathNameW(param_1,local_2c,local_38,(LPWSTR *)0x0), DVar3 < local_2c)) {
      local_54 = 0;
      while ((local_54 < local_30 &&
             (local_28 = (wchar_t *)FUN_180019de0(local_50[local_54],(short *)&DAT_18007bb68),
             local_28 != (wchar_t *)0x0))) {
        uVar6 = 0xffffffffffffffff;
        pwVar7 = local_28;
        do {
          if (uVar6 == 0) break;
          uVar6 = uVar6 - 1;
          wVar1 = *pwVar7;
          pwVar7 = pwVar7 + 1;
        } while (wVar1 != L'\0');
        iVar4 = _wcsnicmp(local_38,local_28,~uVar6 - 1);
        local_14 = (uint)(iVar4 == 0);
        local_40 = local_14;
        if (local_14 != 0) break;
        LocalFree(local_28);
        local_28 = (wchar_t *)0x0;
        local_54 = local_54 + 1;
      }
    }
    LocalFree(local_28);
    LocalFree(local_38);
  }
  else {
    local_40 = 1;
  }
  return local_40;
}



void FUN_180019de0(uint param_1,short *param_2)

{
  short sVar1;
  INT_PTR IVar2;
  longlong lVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  short *psVar6;
  undefined auStack_278 [32];
  short *local_258;
  short *local_248;
  int local_240;
  short local_228 [264];
  ulonglong local_18;
  ulonglong local_10;
  
  local_10 = DAT_180032820 ^ (ulonglong)auStack_278;
  local_248 = (short *)0x0;
  if (param_2 != (short *)0x0) {
    psVar6 = local_228;
    for (lVar3 = 0x20a; lVar3 != 0; lVar3 = lVar3 + -1) {
      *(undefined *)psVar6 = 0;
      psVar6 = (short *)((longlong)psVar6 + 1);
    }
    if ((DAT_18007ba98 == (HMODULE)0x0) &&
       (DAT_18007ba98 = FUN_1800185e0(u_Shell32_dll_180032428,0), DAT_18007ba98 != (HMODULE)0x0)) {
      DAT_18007baa0 = GetProcAddress(DAT_18007ba98,s_SHGetFolderPathW_180032440);
    }
    if (DAT_18007baa0 != (FARPROC)0x0) {
      local_258 = local_228;
      IVar2 = (*DAT_18007baa0)(0,(ulonglong)param_1,0,0);
      local_240 = (int)IVar2;
      if (local_240 == 0) {
        uVar4 = 0xffffffffffffffff;
        psVar6 = local_228;
        do {
          if (uVar4 == 0) break;
          uVar4 = uVar4 - 1;
          sVar1 = *psVar6;
          psVar6 = psVar6 + 1;
        } while (sVar1 != 0);
        uVar5 = 0xffffffffffffffff;
        psVar6 = param_2;
        do {
          if (uVar5 == 0) break;
          uVar5 = uVar5 - 1;
          sVar1 = *psVar6;
          psVar6 = psVar6 + 1;
        } while (sVar1 != 0);
        local_18 = ~uVar4 + ~uVar5;
        local_248 = (short *)LocalAlloc(0x40,local_18 * 2);
        if (local_248 != (short *)0x0) {
          FUN_18001b530(local_248,local_18,local_228);
          FUN_18001b590((wchar_t *)local_248,local_18,(short *)&DAT_180032454);
          FUN_18001b590((wchar_t *)local_248,local_18,param_2);
        }
      }
    }
  }
  __security_check_cookie(local_10 ^ (ulonglong)auStack_278);
  return;
}



undefined4 FUN_180019f90(undefined8 param_1,ulonglong param_2,ulonglong param_3)

{
  undefined4 local_18;
  
  local_18 = 0;
  if ((param_2 == 0) || (param_3 < param_2)) {
    local_18 = 0x80070057;
  }
  return local_18;
}



int FUN_180019fe0(wchar_t *param_1,ulonglong param_2,__uint64 *param_3,ulonglong param_4)

{
  long local_18;
  
  local_18 = FUN_180019f90(param_1,param_2,param_4);
  if (local_18 < 0) {
    *param_3 = 0;
  }
  else {
    local_18 = StringLengthWorkerW(param_1,param_2,param_3);
  }
  return local_18;
}



// Library Function - Single Match
//  long __cdecl StringLengthWorkerW(wchar_t const * __ptr64,unsigned __int64,unsigned __int64 *
// __ptr64)
// 
// Library: Visual Studio 2008 Debug

long __cdecl StringLengthWorkerW(wchar_t *param_1,__uint64 param_2,__uint64 *param_3)

{
  short *local_res8;
  __uint64 local_res10;
  int local_10;
  
  local_10 = 0;
  local_res10 = param_2;
  for (local_res8 = (short *)param_1; (local_res10 != 0 && (*local_res8 != 0));
      local_res8 = local_res8 + 1) {
    local_res10 = local_res10 - 1;
  }
  if (local_res10 == 0) {
    local_10 = -0x7ff8ffa9;
  }
  if (param_3 != (__uint64 *)0x0) {
    if (local_10 < 0) {
      *param_3 = 0;
    }
    else {
      *param_3 = param_2 - local_res10;
    }
  }
  return local_10;
}



undefined4
FUN_18001a100(short *param_1,longlong param_2,longlong *param_3,short *param_4,longlong param_5)

{
  short *local_res8;
  longlong local_res10;
  short *local_res20;
  longlong local_18;
  undefined4 local_10;
  
  local_10 = 0;
  local_18 = 0;
  local_res8 = param_1;
  local_res10 = param_2;
  for (local_res20 = param_4; ((local_res10 != 0 && (param_5 != 0)) && (*local_res20 != 0));
      local_res20 = local_res20 + 1) {
    *local_res8 = *local_res20;
    local_res8 = local_res8 + 1;
    local_res10 = local_res10 + -1;
    param_5 = param_5 + -1;
    local_18 = local_18 + 1;
  }
  if (local_res10 == 0) {
    local_res8 = local_res8 + -1;
    local_18 = local_18 + -1;
    local_10 = 0x8007007a;
  }
  *local_res8 = 0;
  if (param_3 != (longlong *)0x0) {
    *param_3 = local_18;
  }
  return local_10;
}



LPWSTR FUN_18001a200(LPCWSTR param_1,uint param_2,undefined8 param_3,undefined8 param_4)

{
  DWORD DVar1;
  INT_PTR IVar2;
  HMODULE hModule;
  LPWSTR local_38;
  undefined8 local_20;
  uint local_18;
  uint local_14;
  DWORD local_10;
  
  local_20 = 0;
  local_38 = (LPWSTR)0x0;
  if ((DAT_18007baa8 == (HMODULE)0x0) &&
     (DAT_18007baa8 = FUN_1800185e0(u_ntdll_dll_180032460,0), DAT_18007baa8 != (HMODULE)0x0)) {
    DAT_18007bab0 = GetProcAddress(DAT_18007baa8,s_LdrLockLoaderLock_180032478);
    DAT_18007bab8 = GetProcAddress(DAT_18007baa8,s_LdrUnlockLoaderLock_180032490);
  }
  if ((DAT_18007bab0 == (FARPROC)0x0) || (DAT_18007bab8 == (FARPROC)0x0)) {
    local_38 = (LPWSTR)0x0;
  }
  else {
    IVar2 = (*DAT_18007bab0)(0,0,&local_20);
    if ((int)IVar2 == 0) {
      hModule = LoadLibraryExW(param_1,(HANDLE)0x0,param_2 | 1);
      if (hModule != (HMODULE)0x0) {
        local_14 = 0x1000;
        local_18 = 0x80;
        while ((local_38 == (LPWSTR)0x0 && (local_18 < local_14))) {
          local_18 = local_18 << 1;
          local_38 = (LPWSTR)LocalAlloc(0x40,(ulonglong)local_18 << 1);
          if (local_38 == (LPWSTR)0x0) break;
          local_10 = GetModuleFileNameW(hModule,local_38,local_18);
          if ((local_10 == local_18) || (DVar1 = GetLastError(), DVar1 == 0x7a)) {
            SetLastError(0);
            LocalFree(local_38);
            local_38 = (LPWSTR)0x0;
          }
        }
        FreeLibrary(hModule);
      }
      (*DAT_18007bab8)(0,local_20);
    }
  }
  return local_38;
}



int FUN_18001a3c0(LPCWSTR param_1,uint *param_2)

{
  int iVar1;
  uint uVar2;
  INT_PTR IVar3;
  longlong lVar4;
  undefined *puVar5;
  undefined *puVar6;
  ulonglong in_stack_fffffffffffffe28;
  INT_PTR local_198;
  uint local_190 [2];
  HLOCAL local_188;
  longlong local_180;
  undefined8 local_178;
  longlong local_170;
  int local_168;
  undefined local_164 [4];
  undefined local_160 [8];
  HLOCAL local_158 [2];
  undefined local_148 [8];
  undefined local_140 [40];
  undefined local_118 [160];
  undefined local_78 [4];
  DWORD local_74;
  DWORD local_70;
  DWORD local_6c;
  DWORD local_68;
  DWORD local_64;
  DWORD local_60;
  DWORD local_5c;
  undefined local_58 [16];
  undefined local_48 [16];
  undefined local_38 [16];
  undefined local_28 [24];
  
  local_178 = 0;
  local_170 = 0;
  local_180 = 0;
  local_188 = (HLOCAL)0x0;
  local_198 = 0;
  local_158[0] = (HLOCAL)0x0;
  local_168 = 0;
  SetLastError(0);
  iVar1 = FUN_18001a930(param_1);
  if (iVar1 == 0) {
    SetLastError(0x7e);
  }
  else {
    if ((DAT_18007bac0 == (HMODULE)0x0) &&
       (DAT_18007bac0 = FUN_1800185e0(u_crypt32_dll_1800324a8,0), DAT_18007bac0 != (HMODULE)0x0)) {
      DAT_18007bac8 = GetProcAddress(DAT_18007bac0,s_CryptMsgClose_1800324c0);
      DAT_18007bad0 = GetProcAddress(DAT_18007bac0,s_CertCloseStore_1800324d0);
      DAT_18007bad8 = GetProcAddress(DAT_18007bac0,s_CertFreeCertificateContext_1800324e0);
      DAT_18007bae0 = GetProcAddress(DAT_18007bac0,s_CertFindCertificateInStore_180032500);
      DAT_18007bae8 = GetProcAddress(DAT_18007bac0,s_CryptMsgGetParam_180032520);
      DAT_18007baf0 = GetProcAddress(DAT_18007bac0,s_CryptQueryObject_180032538);
      DAT_18007baf8 = GetProcAddress(DAT_18007bac0,s_CertGetNameStringA_180032550);
      DAT_18007bb00 = GetProcAddress(DAT_18007bac0,s_CryptDecodeObject_180032568);
    }
    if (((((DAT_18007bac8 == (FARPROC)0x0) || (DAT_18007bad0 == (FARPROC)0x0)) ||
         (DAT_18007bad8 == (FARPROC)0x0)) ||
        ((DAT_18007bae0 == (FARPROC)0x0 || (DAT_18007bae8 == (FARPROC)0x0)))) ||
       ((DAT_18007baf0 == (FARPROC)0x0 ||
        ((DAT_18007baf8 == (FARPROC)0x0 || (DAT_18007bb00 == (FARPROC)0x0)))))) {
      return 0;
    }
    IVar3 = (*DAT_18007baf0)(1,param_1,0x400,2,in_stack_fffffffffffffe28 & 0xffffffff00000000,
                             local_160,local_78,local_164,&local_170,&local_180,0);
    local_168 = (int)IVar3;
    if (local_168 == 0) {
      local_74 = GetLastError();
    }
    else {
      IVar3 = (*DAT_18007bae8)(local_180,6,0,0,local_190);
      local_168 = (int)IVar3;
      if (local_168 == 0) {
        local_70 = GetLastError();
      }
      else {
        local_188 = LocalAlloc(0x40,(ulonglong)local_190[0]);
        if (local_188 == (HLOCAL)0x0) {
          local_6c = GetLastError();
        }
        else {
          IVar3 = (*DAT_18007bae8)(local_180,6,0,local_188,local_190);
          local_168 = (int)IVar3;
          if (local_168 == 0) {
            local_68 = GetLastError();
          }
          else {
            puVar5 = (undefined *)((longlong)local_188 + 8);
            puVar6 = local_28;
            for (lVar4 = 0x10; lVar4 != 0; lVar4 = lVar4 + -1) {
              *puVar6 = *puVar5;
              puVar5 = puVar5 + 1;
              puVar6 = puVar6 + 1;
            }
            puVar5 = local_28;
            puVar6 = local_118;
            for (lVar4 = 0x10; lVar4 != 0; lVar4 = lVar4 + -1) {
              *puVar6 = *puVar5;
              puVar5 = puVar5 + 1;
              puVar6 = puVar6 + 1;
            }
            puVar5 = (undefined *)((longlong)local_188 + 0x18);
            puVar6 = local_38;
            for (lVar4 = 0x10; lVar4 != 0; lVar4 = lVar4 + -1) {
              *puVar6 = *puVar5;
              puVar5 = puVar5 + 1;
              puVar6 = puVar6 + 1;
            }
            puVar5 = local_38;
            puVar6 = local_140;
            for (lVar4 = 0x10; lVar4 != 0; lVar4 = lVar4 + -1) {
              *puVar6 = *puVar5;
              puVar5 = puVar5 + 1;
              puVar6 = puVar6 + 1;
            }
            local_198 = (*DAT_18007bae0)(local_170,0x10001,0,0xb0000,local_148,0);
            if (local_198 == 0) {
              local_64 = GetLastError();
            }
            else {
              if (param_2 != (uint *)0x0) {
                uVar2 = FUN_18001aba0(local_198);
                *param_2 = uVar2;
                local_60 = GetLastError();
                if (local_60 != 0) goto LAB_18001a8b1;
              }
              iVar1 = FUN_18001ae00((longlong)local_188,local_158);
              if (iVar1 != 0) {
                puVar5 = (undefined *)((longlong)local_158[0] + 8);
                puVar6 = local_48;
                for (lVar4 = 0x10; lVar4 != 0; lVar4 = lVar4 + -1) {
                  *puVar6 = *puVar5;
                  puVar5 = puVar5 + 1;
                  puVar6 = puVar6 + 1;
                }
                puVar5 = local_48;
                puVar6 = local_118;
                for (lVar4 = 0x10; lVar4 != 0; lVar4 = lVar4 + -1) {
                  *puVar6 = *puVar5;
                  puVar5 = puVar5 + 1;
                  puVar6 = puVar6 + 1;
                }
                puVar5 = (undefined *)((longlong)local_158[0] + 0x18);
                puVar6 = local_58;
                for (lVar4 = 0x10; lVar4 != 0; lVar4 = lVar4 + -1) {
                  *puVar6 = *puVar5;
                  puVar5 = puVar5 + 1;
                  puVar6 = puVar6 + 1;
                }
                puVar5 = local_58;
                puVar6 = local_140;
                for (lVar4 = 0x10; lVar4 != 0; lVar4 = lVar4 + -1) {
                  *puVar6 = *puVar5;
                  puVar5 = puVar5 + 1;
                  puVar6 = puVar6 + 1;
                }
                local_198 = (*DAT_18007bae0)(local_170,0x10001,0,0xb0000,local_148,0);
                if (local_198 == 0) {
                  local_5c = GetLastError();
                }
                else {
                  local_168 = 1;
                }
              }
            }
          }
        }
      }
    }
  }
LAB_18001a8b1:
  LocalFree(local_188);
  LocalFree(local_158[0]);
  if (local_198 != 0) {
    (*DAT_18007bad8)(local_198);
  }
  if (local_170 != 0) {
    (*DAT_18007bad0)(local_170,0);
  }
  if (local_180 != 0) {
    (*DAT_18007bac8)(local_180);
  }
  return local_168;
}



undefined4 FUN_18001a930(LPCWSTR param_1)

{
  DWORD DVar1;
  undefined4 local_10;
  
  DVar1 = GetFileAttributesW(param_1);
  if ((DVar1 == 0xffffffff) || ((DVar1 & 0x50) != 0)) {
    local_10 = 0;
  }
  else {
    local_10 = 1;
  }
  return local_10;
}



int FUN_18001a990(char *param_1,uint *param_2)

{
  LPCWSTR hMem;
  int local_10;
  
  local_10 = 0;
  hMem = (LPCWSTR)FUN_180019910(param_1);
  if ((param_1 == (char *)0x0) || (hMem != (LPCWSTR)0x0)) {
    local_10 = FUN_18001a3c0(hMem,param_2);
  }
  LocalFree(hMem);
  return local_10;
}



void FUN_18001aa00(void)

{
  if (DAT_18007ba98 != (HMODULE)0x0) {
    DAT_18007baa0 = 0;
    DAT_18007bb48 = 0;
    DAT_18007bb50 = 0;
    DAT_18007bb58 = 0;
    DAT_18007bb60 = 0;
    FreeLibrary(DAT_18007ba98);
    DAT_18007ba98 = (HMODULE)0x0;
  }
  if (DAT_18007baa8 != (HMODULE)0x0) {
    DAT_18007bab8 = 0;
    DAT_18007bab0 = 0;
    FreeLibrary(DAT_18007baa8);
    DAT_18007baa8 = (HMODULE)0x0;
  }
  if (DAT_18007bb08 != (HMODULE)0x0) {
    DAT_18007bb10 = 0;
    DAT_18007bb18 = 0;
    DAT_18007bb20 = 0;
    DAT_18007bb38 = 0;
    DAT_18007bb40 = 0;
    FreeLibrary(DAT_18007bb08);
    DAT_18007bb08 = (HMODULE)0x0;
  }
  if (DAT_18007bb28 != (HMODULE)0x0) {
    DAT_18007bb30 = 0;
    FreeLibrary(DAT_18007bb28);
    DAT_18007bb28 = (HMODULE)0x0;
  }
  if (DAT_18007bac0 != (HMODULE)0x0) {
    DAT_18007bac8 = 0;
    DAT_18007bad0 = 0;
    DAT_18007bad8 = 0;
    DAT_18007bae0 = 0;
    DAT_18007bae8 = 0;
    DAT_18007baf0 = 0;
    DAT_18007baf8 = 0;
    DAT_18007bb00 = 0;
    FreeLibrary(DAT_18007bac0);
    DAT_18007bac0 = (HMODULE)0x0;
  }
  return;
}



uint FUN_18001aba0(undefined8 param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  uint local_54;
  uint local_50;
  byte *local_48;
  char *local_40 [3];
  DWORD local_28;
  DWORD local_24;
  DWORD local_20;
  DWORD local_1c;
  DWORD local_18;
  DWORD local_14;
  uint local_10;
  
  local_40[0] = s_NVIDIA_Subordinate_CA_180032598;
  local_40[1] = s_VeriSign_Class_3_Code_Signing_20_1800325d8;
  local_40[2] = (char *)0x0;
  local_48 = (byte *)0x0;
  local_50 = 0;
  uVar2 = (*DAT_18007baf8)(param_1,4,1,0,0,0);
  if (uVar2 == 0) {
    local_28 = GetLastError();
  }
  else {
    local_48 = (byte *)LocalAlloc(0x40,(ulonglong)uVar2);
    if (local_48 == (byte *)0x0) {
      local_24 = GetLastError();
    }
    else {
      iVar3 = (*DAT_18007baf8)(param_1,4,1,0,local_48,uVar2);
      if (iVar3 == 0) {
        local_20 = GetLastError();
      }
      else {
        for (local_54 = 0; local_40[local_54] != (char *)0x0; local_54 = local_54 + 1) {
          pbVar4 = local_48;
          do {
            bVar1 = *pbVar4;
            if (bVar1 != pbVar4[(longlong)local_40[local_54] - (longlong)local_48]) {
              uVar2 = (uint)(bVar1 < pbVar4[(longlong)local_40[local_54] - (longlong)local_48]);
              iVar3 = (1 - uVar2) - (uint)(uVar2 != 0);
              goto LAB_18001ace8;
            }
            pbVar4 = pbVar4 + 1;
          } while (bVar1 != 0);
          iVar3 = 0;
LAB_18001ace8:
          if (iVar3 == 0) {
            LocalFree(local_48);
            local_48 = (byte *)0x0;
            uVar2 = (*DAT_18007baf8)(param_1,4,0,0,0,0);
            if (uVar2 == 0) {
              local_1c = GetLastError();
            }
            else {
              local_48 = (byte *)LocalAlloc(0x40,(ulonglong)uVar2);
              if (local_48 == (byte *)0x0) {
                local_18 = GetLastError();
              }
              else {
                iVar3 = (*DAT_18007baf8)(param_1,4,0,0,local_48,uVar2);
                if (iVar3 == 0) {
                  local_14 = GetLastError();
                }
                else {
                  iVar3 = _stricmp((char *)local_48,s_NVIDIA_Corporation_180032600);
                  local_10 = (uint)(iVar3 == 0);
                  local_50 = local_10;
                }
              }
            }
            break;
          }
        }
      }
    }
  }
  LocalFree(local_48);
  return local_50;
}



int FUN_18001ae00(longlong param_1,HLOCAL *param_2)

{
  int iVar1;
  HLOCAL pvVar2;
  uint local_28;
  uint local_24;
  int local_20;
  int local_1c;
  
  local_20 = 0;
  *param_2 = (HLOCAL)0x0;
  local_24 = 0;
  do {
    if (*(uint *)(param_1 + 0x78) <= local_24) {
      return local_20;
    }
    if (local_20 != 0) {
      return local_20;
    }
    iVar1 = lstrcmpA(*(LPCSTR *)(*(longlong *)(param_1 + 0x80) + (ulonglong)local_24 * 0x18),
                     s_1_2_840_113549_1_9_6_180032618);
    if (iVar1 == 0) {
      local_1c = (*DAT_18007bb00)(0x10001,500,
                                  *(undefined8 *)
                                   (*(longlong *)
                                     (*(longlong *)(param_1 + 0x80) + 0x10 +
                                     (ulonglong)local_24 * 0x18) + 8),
                                  **(undefined4 **)
                                    (*(longlong *)(param_1 + 0x80) + 0x10 +
                                    (ulonglong)local_24 * 0x18),0,0,&local_28);
      if (local_1c == 0) {
        GetLastError();
        return local_20;
      }
      pvVar2 = LocalAlloc(0x40,(ulonglong)local_28);
      *param_2 = pvVar2;
      if (*param_2 == (HLOCAL)0x0) {
        GetLastError();
        return local_20;
      }
      local_1c = (*DAT_18007bb00)(0x10001,500,
                                  *(undefined8 *)
                                   (*(longlong *)
                                     (*(longlong *)(param_1 + 0x80) + 0x10 +
                                     (ulonglong)local_24 * 0x18) + 8),
                                  **(undefined4 **)
                                    (*(longlong *)(param_1 + 0x80) + 0x10 +
                                    (ulonglong)local_24 * 0x18),0,*param_2,&local_28);
      if (local_1c == 0) {
        GetLastError();
        return local_20;
      }
      local_20 = 1;
    }
    local_24 = local_24 + 1;
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_18001afd0(LPCWSTR param_1,uint param_2)

{
  ushort *puVar1;
  ushort uVar2;
  uint uVar3;
  int iVar4;
  INT_PTR IVar5;
  longlong lVar6;
  ulonglong uVar7;
  ushort *puVar8;
  wchar_t *pwVar9;
  WCHAR *pWVar10;
  undefined auStack_228 [32];
  undefined8 *local_208;
  undefined8 local_200;
  int *local_1f8;
  undefined4 *local_1f0;
  int local_1e8;
  uint local_1e4;
  WCHAR local_1d8 [12];
  undefined4 local_1c0;
  undefined2 local_1bc;
  undefined2 local_1ba;
  undefined local_1b8;
  undefined local_1b7;
  undefined local_1b6;
  undefined local_1b5;
  undefined local_1b4;
  undefined local_1b3;
  undefined local_1b2;
  undefined local_1b1;
  ushort local_1b0 [4];
  ushort local_1a8 [40];
  undefined8 local_158;
  int local_150;
  uint local_14c;
  uint local_148;
  undefined4 local_144;
  uint local_140;
  int local_13c;
  ushort local_138 [128];
  undefined4 local_38;
  uint local_34;
  uint local_30;
  uint local_2c;
  ulonglong local_28;
  
  local_28 = DAT_180032820 ^ (ulonglong)auStack_228;
  local_1e4 = DAT_18007bc8c;
  pwVar9 = u_0x00000000_180032630;
  pWVar10 = local_1d8;
  for (lVar6 = 0x18; lVar6 != 0; lVar6 = lVar6 + -1) {
    *(undefined *)pWVar10 = *(undefined *)pwVar9;
    pwVar9 = (wchar_t *)((longlong)pwVar9 + 1);
    pWVar10 = (WCHAR *)((longlong)pWVar10 + 1);
  }
  OutputDebugStringW(u_____WARNING___PE_SIGNATURE_VERIF_180032650);
  OutputDebugStringW(param_1);
  OutputDebugStringW(u______Error__1800326d8);
  for (local_1e8 = 0; local_1e8 < 8; local_1e8 = local_1e8 + 1) {
    local_1d8[local_1e8 + 2] =
         (ushort)(param_2 >> (('\a' - (char)local_1e8) * '\x04' & 0x1fU)) & 0xf;
    if ((ushort)local_1d8[local_1e8 + 2] < 10) {
      local_38 = 0x30;
    }
    else {
      local_38 = 0x37;
    }
    local_1d8[local_1e8 + 2] = local_1d8[local_1e8 + 2] + (short)local_38;
  }
  OutputDebugStringW(local_1d8);
  if ((local_1e4 == 0) && (_DAT_18003245c != 0)) {
    local_1b0[0] = 0x100;
    local_1b0[1] = 0x200;
    local_1b0[2] = 0;
    local_1c0 = 0x41fcc608;
    local_1bc = 0x8496;
    local_1ba = 0x4def;
    local_1b8 = 0xb4;
    local_1b7 = 0x3e;
    local_1b6 = 0x7d;
    local_1b5 = 0x9b;
    local_1b4 = 0xd6;
    local_1b3 = 0x75;
    local_1b2 = 0xa6;
    local_1b1 = 0xff;
    _DAT_18003245c = 0;
    if ((DAT_18007bb08 == (HMODULE)0x0) &&
       (DAT_18007bb08 = FUN_1800185e0(u_Advapi32_dll_1800326f8,0), DAT_18007bb08 != (HMODULE)0x0)) {
      DAT_18007bb10 = GetProcAddress(DAT_18007bb08,s_RegOpenKeyExW_180032718);
      DAT_18007bb18 = GetProcAddress(DAT_18007bb08,s_RegEnumValueW_180032728);
      DAT_18007bb20 = GetProcAddress(DAT_18007bb08,s_RegCloseKey_180032738);
    }
    if (((DAT_18007bb10 == (FARPROC)0x0) || (DAT_18007bb18 == (FARPROC)0x0)) ||
       (DAT_18007bb20 == (FARPROC)0x0)) goto LAB_18001b511;
    if ((DAT_18007bb28 == (HMODULE)0x0) &&
       (DAT_18007bb28 = FUN_1800185e0(u_Ole32_dll_180032748,0), DAT_18007bb28 != (HMODULE)0x0)) {
      DAT_18007bb30 = GetProcAddress(DAT_18007bb28,s_StringFromGUID2_180032760);
    }
    if (DAT_18007bb30 == (FARPROC)0x0) goto LAB_18001b511;
    puVar8 = local_1a8;
    for (lVar6 = 0x4e; lVar6 != 0; lVar6 = lVar6 + -1) {
      *(undefined *)puVar8 = 0;
      puVar8 = (ushort *)((longlong)puVar8 + 1);
    }
    IVar5 = (*DAT_18007bb30)(&local_1c0,local_1a8,0x27);
    if ((int)IVar5 != 0x27) goto LAB_18001b511;
    for (local_1e8 = 0; (local_1e4 == 0 && (local_1b0[local_1e8] != 0)); local_1e8 = local_1e8 + 1)
    {
      local_158 = 0;
      local_208 = &local_158;
      IVar5 = (*DAT_18007bb10)(0xffffffff80000002,u_SOFTWARE_NVIDIA_Corporation_Glob_180032770,0,
                               (ulonglong)(local_1b0[local_1e8] | 0x20019));
      local_150 = (int)IVar5;
      if ((int)IVar5 == 0) {
        local_148 = 0;
        local_14c = 0;
        do {
          local_140 = 0x80;
          local_144 = 4;
          puVar8 = local_138;
          for (lVar6 = 0x100; lVar6 != 0; lVar6 = lVar6 + -1) {
            *(undefined *)puVar8 = 0;
            puVar8 = (ushort *)((longlong)puVar8 + 1);
          }
          local_34 = local_148;
          local_1f0 = &local_144;
          local_1f8 = &local_13c;
          local_200 = 0;
          local_208 = (undefined8 *)0x0;
          IVar5 = (*DAT_18007bb18)(local_158,(ulonglong)local_148,local_138,&local_140);
          local_150 = (int)IVar5;
          local_148 = local_148 + 1;
          if (local_150 == 0) {
            uVar7 = 0xffffffffffffffff;
            puVar8 = local_1a8;
            do {
              if (uVar7 == 0) break;
              uVar7 = uVar7 - 1;
              uVar2 = *puVar8;
              puVar8 = puVar8 + 1;
            } while (uVar2 != 0);
            if (~uVar7 - 1 == (ulonglong)local_140) {
              puVar8 = local_1a8;
              lVar6 = (longlong)local_138 - (longlong)puVar8;
              do {
                uVar2 = *puVar8;
                puVar1 = (ushort *)((longlong)puVar8 + lVar6);
                if (uVar2 != *puVar1) {
                  uVar3 = (uint)(uVar2 < *puVar1);
                  iVar4 = (1 - uVar3) - (uint)(uVar3 != 0);
                  goto LAB_18001b42c;
                }
                puVar8 = puVar8 + 1;
              } while (uVar2 != 0);
              iVar4 = 0;
LAB_18001b42c:
              if (iVar4 == 0) {
                local_30 = (uint)(local_13c != 0);
                local_14c = local_14c | local_30;
              }
            }
          }
        } while (local_150 != 0x103);
        (*DAT_18007bb20)(local_158);
        if (local_14c == 0) {
          local_2c = 0;
        }
        else {
          local_2c = 1;
        }
        local_2c = (uint)(local_14c != 0);
        DAT_18007bc8c = local_2c;
        local_1e4 = local_2c;
      }
    }
  }
  if ((local_1e4 == 0) && (DAT_18007bc8c == 0)) {
    SetLastError(param_2);
  }
  else {
    OutputDebugStringW(u_____Signature_override_detected__1800327c0);
    SetLastError(0);
  }
LAB_18001b511:
  __security_check_cookie(local_28 ^ (ulonglong)auStack_228);
  return;
}



int FUN_18001b530(short *param_1,ulonglong param_2,short *param_3)

{
  int local_18;
  
  local_18 = FUN_180019f90(param_1,param_2,0x7fffffff);
  if (-1 < local_18) {
    local_18 = FUN_18001a100(param_1,param_2,(longlong *)0x0,param_3,0x7ffffffe);
  }
  return local_18;
}



int FUN_18001b590(wchar_t *param_1,ulonglong param_2,short *param_3)

{
  int local_18;
  __uint64 local_10 [2];
  
  local_18 = FUN_180019fe0(param_1,param_2,local_10,0x7fffffff);
  if (-1 < local_18) {
    local_18 = FUN_18001a100((short *)(param_1 + local_10[0] * 2),param_2 - local_10[0],
                             (longlong *)0x0,param_3,0x7fffffff);
  }
  return local_18;
}



void FUN_18001b610(void)

{
  PerformanceMonitor *this;
  
  this = Graphine::Performance::GetPerformanceMonitor();
  Graphine::Performance::PerformanceMonitor::RegisterGroup(this,(wchar_t *)&DAT_180032a4c);
  return;
}



void FUN_18001b640(void)

{
  PerformanceMonitor *this;
  
  this = Graphine::Performance::GetPerformanceMonitor();
  Graphine::Performance::PerformanceMonitor::RegisterStatistic
            (this,(wchar_t *)&DAT_180032a48,0x80025490,(StatisticOptions *)0x2);
  return;
}



void FUN_18001b6b0(void)

{
  undefined8 *puVar1;
  longlong lVar2;
  
  lVar2 = 0x40;
  puVar1 = (undefined8 *)
           (*(longlong *)((longlong)ThreadLocalStoragePointer + (ulonglong)_tls_index * 8) + 0x20);
  do {
    *puVar1 = 0;
    *(undefined4 *)(puVar1 + 1) = 0;
    puVar1 = puVar1 + 2;
    lVar2 = lVar2 + -1;
  } while (lVar2 != 0);
  return;
}



void FUN_18001b6f0(void)

{
  PerformanceMonitor *this;
  
  this = Graphine::Performance::GetPerformanceMonitor();
  Graphine::Performance::PerformanceMonitor::RegisterStatistic
            (this,(wchar_t *)&DAT_18007b1a8,0x8002ae28,(StatisticOptions *)0x2);
  return;
}



void FUN_18001b760(void)

{
  PerformanceMonitor *this;
  
  this = Graphine::Performance::GetPerformanceMonitor();
  Graphine::Performance::PerformanceMonitor::RegisterStatistic
            (this,(wchar_t *)&DAT_18007b1c4,0x8002a9a0,(StatisticOptions *)0x2);
  return;
}



void FUN_18001b7d0(void)

{
  PerformanceMonitor *this;
  
  this = Graphine::Performance::GetPerformanceMonitor();
  Graphine::Performance::PerformanceMonitor::RegisterStatistic
            (this,(wchar_t *)&DAT_18007b1b0,0x8002ae70,(StatisticOptions *)0x2);
  return;
}



void FUN_18001b840(void)

{
  PerformanceMonitor *this;
  
  this = Graphine::Performance::GetPerformanceMonitor();
  Graphine::Performance::PerformanceMonitor::RegisterStatistic
            (this,(wchar_t *)&DAT_18007b1bc,0x8002ab50,(StatisticOptions *)0x2);
  return;
}



void FUN_18001b8b0(void)

{
  PerformanceMonitor *this;
  
  this = Graphine::Performance::GetPerformanceMonitor();
  Graphine::Performance::PerformanceMonitor::RegisterStatistic
            (this,(wchar_t *)&DAT_18007b1ac,0x8002adf8,(StatisticOptions *)0x2);
  return;
}



void FUN_18001b920(void)

{
  PerformanceMonitor *this;
  
  this = Graphine::Performance::GetPerformanceMonitor();
  Graphine::Performance::PerformanceMonitor::RegisterStatistic
            (this,(wchar_t *)&DAT_18007b1a0,0x8002a910,(StatisticOptions *)0x2);
  return;
}



void FUN_18001b990(void)

{
  PerformanceMonitor *this;
  
  this = Graphine::Performance::GetPerformanceMonitor();
  Graphine::Performance::PerformanceMonitor::RegisterGroup(this,(wchar_t *)&DAT_18007b1b8);
  return;
}



void FUN_18001b9c0(void)

{
  PerformanceMonitor *this;
  
  this = Graphine::Performance::GetPerformanceMonitor();
  Graphine::Performance::PerformanceMonitor::RegisterGroup(this,(wchar_t *)&DAT_18007b1c0);
  return;
}



void FUN_18001b9f0(void)

{
  PerformanceMonitor *this;
  
  this = Graphine::Performance::GetPerformanceMonitor();
  Graphine::Performance::PerformanceMonitor::RegisterStatistic
            (this,(wchar_t *)&DAT_18007b1a4,0x8002ac58,(StatisticOptions *)0x2);
  return;
}



void FUN_18001ba60(void)

{
  PerformanceMonitor *this;
  
  this = Graphine::Performance::GetPerformanceMonitor();
  Graphine::Performance::PerformanceMonitor::RegisterStatistic
            (this,(wchar_t *)&DAT_18007b1b4,0x8002ad78,(StatisticOptions *)0x2);
  return;
}



// public: __cdecl Graphine::Allocator::Allocator(void) __ptr64

Allocator * __thiscall Graphine::Allocator::Allocator(Allocator *this)

{
                    // 0x1bad0  1  ??0Allocator@Graphine@@QEAA@XZ
  *(undefined8 *)this = 0;
  return this;
}



// public: __cdecl Graphine::ILogManager::ILogManager(class Graphine::ILogManager const & __ptr64)
// __ptr64

ILogManager * __thiscall Graphine::ILogManager::ILogManager(ILogManager *this,ILogManager *param_1)

{
                    // 0x1bae0  3  ??0ILogManager@Graphine@@QEAA@AEBV01@@Z
                    // 0x1bae0  4  ??0ILogManager@Graphine@@QEAA@XZ
  *(undefined ***)this = vftable;
  return this;
}



// public: __cdecl Graphine::Performance::IPerformanceManager::IPerformanceManager(class
// Graphine::Performance::IPerformanceManager const & __ptr64) __ptr64

IPerformanceManager * __thiscall
Graphine::Performance::IPerformanceManager::IPerformanceManager
          (IPerformanceManager *this,IPerformanceManager *param_1)

{
                    // 0x1baf0  5  ??0IPerformanceManager@Performance@Graphine@@QEAA@AEBV012@@Z
                    // 0x1baf0  6  ??0IPerformanceManager@Performance@Graphine@@QEAA@XZ
  *(undefined ***)this = vftable;
  return this;
}



// protected: virtual __cdecl Graphine::ILogManager::~ILogManager(void) __ptr64

void __thiscall Graphine::ILogManager::_ILogManager(ILogManager *this)

{
                    // 0x1bb00  12  ??1ILogManager@Graphine@@MEAA@XZ
  *(undefined ***)this = vftable;
  return;
}



// public: virtual __cdecl Graphine::Performance::IPerformanceManager::~IPerformanceManager(void)
// __ptr64

void __thiscall
Graphine::Performance::IPerformanceManager::_IPerformanceManager(IPerformanceManager *this)

{
                    // 0x1bb10  13  ??1IPerformanceManager@Performance@Graphine@@UEAA@XZ
  *(undefined ***)this = vftable;
  return;
}



void FUN_18001bb20(CriticalSection **param_1)

{
  Graphine::Platform::CriticalSection::Leave(*param_1);
  return;
}



// public: static void * __ptr64 __cdecl Graphine::Platform::JobSystem::operator new(unsigned
// __int64)

void * __cdecl Graphine::Platform::JobSystem::operator_new(__uint64 param_1)

{
  bool bVar1;
  undefined4 *puVar2;
  PerformanceMonitor *pPVar3;
  __uint64 *p_Var4;
  undefined4 local_res8 [2];
  char *local_28;
  undefined4 local_20;
  char *local_18;
  
                    // 0x1bb40  17  ??2JobSystem@Platform@Graphine@@SAPEAX_K@Z
  local_20 = 0x1e0;
  local_28 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Platform.h";
  local_18 = "Graphine::Platform::JobSystem::operator new";
  bVar1 = IsCoreInitialized();
  if ((bVar1) && (DAT_180032a40 == (undefined **)0x0)) {
    DAT_180032a40 = &PTR_vftable_180032090;
  }
  if (param_1 != 0) {
    puVar2 = FUN_18001c700(local_res8,0);
    pPVar3 = Performance::GetPerformanceMonitor();
    Performance::PerformanceMonitor::CounterAdd(pPVar3,SUB41(*puVar2,0),(int)param_1);
    pPVar3 = Performance::GetPerformanceMonitor();
    Performance::PerformanceMonitor::CounterAdd(pPVar3,SUB41(DAT_180032a48,0),(int)param_1);
    p_Var4 = (__uint64 *)(**(code **)*DAT_180032a40)(DAT_180032a40,param_1 + 0x10,0,&local_28);
    if (p_Var4 != (__uint64 *)0x0) {
      *p_Var4 = param_1;
      *(undefined4 *)(p_Var4 + 1) = 0;
      return p_Var4 + 2;
    }
  }
  return (void *)0x0;
}



// public: static void * __ptr64 __cdecl Graphine::Platform::JobSystem::operator new(unsigned
// __int64,enum Graphine::AllocationCategory::Enum)

void * __cdecl Graphine::Platform::JobSystem::operator_new(__uint64 param_1,Enum param_2)

{
  bool bVar1;
  undefined4 *puVar2;
  PerformanceMonitor *pPVar3;
  __uint64 *p_Var4;
  undefined4 local_res8 [2];
  char *local_28;
  undefined4 local_20;
  char *local_18;
  
                    // 0x1bc10  18
                    // ??2JobSystem@Platform@Graphine@@SAPEAX_KW4Enum@AllocationCategory@2@@Z
  local_20 = 0x1e0;
  local_28 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Platform.h";
  local_18 = "Graphine::Platform::JobSystem::operator new";
  bVar1 = IsCoreInitialized();
  if ((bVar1) && (DAT_180032a40 == (undefined **)0x0)) {
    DAT_180032a40 = &PTR_vftable_180032090;
  }
  if (param_1 != 0) {
    puVar2 = FUN_18001c700(local_res8,param_2);
    pPVar3 = Performance::GetPerformanceMonitor();
    Performance::PerformanceMonitor::CounterAdd(pPVar3,SUB41(*puVar2,0),(int)param_1);
    pPVar3 = Performance::GetPerformanceMonitor();
    Performance::PerformanceMonitor::CounterAdd(pPVar3,SUB41(DAT_180032a48,0),(int)param_1);
    p_Var4 = (__uint64 *)(**(code **)*DAT_180032a40)(DAT_180032a40,param_1 + 0x10,param_2,&local_28)
    ;
    if (p_Var4 != (__uint64 *)0x0) {
      *(short *)(p_Var4 + 1) = (short)param_2;
      *(undefined2 *)((longlong)p_Var4 + 10) = 0;
      *p_Var4 = param_1;
      return p_Var4 + 2;
    }
  }
  return (void *)0x0;
}



// public: static void __cdecl Graphine::Platform::JobSystem::operator delete(void * __ptr64)

void __cdecl Graphine::Platform::JobSystem::operator_delete(void *param_1)

{
  bool bVar1;
  undefined4 *puVar2;
  PerformanceMonitor *pPVar3;
  undefined4 local_res8 [2];
  char *local_20;
  undefined4 local_18;
  char *local_10;
  
                    // 0x1bcf0  19  ??3JobSystem@Platform@Graphine@@SAXPEAX@Z
  local_20 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Platform.h";
  local_18 = 0x1e0;
  local_10 = "Graphine::Platform::JobSystem::operator delete";
  bVar1 = IsCoreInitialized();
  if ((bVar1) && (DAT_180032a40 == (undefined **)0x0)) {
    DAT_180032a40 = &PTR_vftable_180032090;
  }
  puVar2 = FUN_18001c700(local_res8,(uint)*(ushort *)((longlong)param_1 + -8));
  pPVar3 = Performance::GetPerformanceMonitor();
  Performance::PerformanceMonitor::CounterSub
            (pPVar3,SUB41(*puVar2,0),*(int *)((longlong)param_1 + -0x10));
  pPVar3 = Performance::GetPerformanceMonitor();
  Performance::PerformanceMonitor::CounterSub
            (pPVar3,SUB41(DAT_180032a48,0),*(int *)((longlong)param_1 + -0x10));
  (**(code **)(*DAT_180032a40 + 8))(DAT_180032a40,(longlong)param_1 + -0x10,&local_20);
  return;
}



// public: static void __cdecl Graphine::Platform::JobSystem::operator delete(void * __ptr64,enum
// Graphine::AllocationCategory::Enum)

void __cdecl Graphine::Platform::JobSystem::operator_delete(void *param_1,Enum param_2)

{
  bool bVar1;
  undefined4 *puVar2;
  PerformanceMonitor *pPVar3;
  undefined4 local_res8 [2];
  char *local_20;
  undefined4 local_18;
  char *local_10;
  
                    // 0x1bdb0  20
                    // ??3JobSystem@Platform@Graphine@@SAXPEAXW4Enum@AllocationCategory@2@@Z
  local_20 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Platform.h";
  local_18 = 0x1e0;
  local_10 = "Graphine::Platform::JobSystem::operator delete";
  bVar1 = IsCoreInitialized();
  if ((bVar1) && (DAT_180032a40 == (undefined **)0x0)) {
    DAT_180032a40 = &PTR_vftable_180032090;
  }
  puVar2 = FUN_18001c700(local_res8,(uint)*(ushort *)((longlong)param_1 + -8));
  pPVar3 = Performance::GetPerformanceMonitor();
  Performance::PerformanceMonitor::CounterSub
            (pPVar3,SUB41(*puVar2,0),*(int *)((longlong)param_1 + -0x10));
  pPVar3 = Performance::GetPerformanceMonitor();
  Performance::PerformanceMonitor::CounterSub
            (pPVar3,SUB41(DAT_180032a48,0),*(int *)((longlong)param_1 + -0x10));
  (**(code **)(*DAT_180032a40 + 8))(DAT_180032a40,(longlong)param_1 + -0x10,&local_20);
  return;
}



// public: class Graphine::Allocator & __ptr64 __cdecl Graphine::Allocator::operator=(class
// Graphine::Allocator && __ptr64) __ptr64

Allocator * __thiscall Graphine::Allocator::operator_(Allocator *this,Allocator *param_1)

{
                    // 0x1be70  21  ??4Allocator@Graphine@@QEAAAEAV01@$$QEAV01@@Z
                    // 0x1be70  22  ??4Allocator@Graphine@@QEAAAEAV01@AEBV01@@Z
  *(undefined8 *)this = *(undefined8 *)param_1;
  return this;
}



// public: class Graphine::ILogManager & __ptr64 __cdecl Graphine::ILogManager::operator=(class
// Graphine::ILogManager const & __ptr64) __ptr64

ILogManager * __thiscall Graphine::ILogManager::operator_(ILogManager *this,ILogManager *param_1)

{
                    // 0x1be80  23  ??4ILogManager@Graphine@@QEAAAEAV01@AEBV01@@Z
                    // 0x1be80  24
                    // ??4IPerformanceManager@Performance@Graphine@@QEAAAEAV012@AEBV012@@Z
  return this;
}



// public: class Graphine::Platform::JobSystem & __ptr64 __cdecl
// Graphine::Platform::JobSystem::operator=(class Graphine::Platform::JobSystem const & __ptr64)
// __ptr64

JobSystem * __thiscall Graphine::Platform::JobSystem::operator_(JobSystem *this,JobSystem *param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  longlong lVar7;
  
                    // 0x1be90  25  ??4JobSystem@Platform@Graphine@@QEAAAEAV012@AEBV012@@Z
  lVar7 = 2;
  puVar4 = (undefined4 *)this;
  do {
    puVar6 = (undefined4 *)param_1;
    puVar5 = puVar4;
    uVar1 = puVar6[1];
    uVar2 = puVar6[2];
    uVar3 = puVar6[3];
    *puVar5 = *puVar6;
    puVar5[1] = uVar1;
    puVar5[2] = uVar2;
    puVar5[3] = uVar3;
    uVar1 = puVar6[5];
    uVar2 = puVar6[6];
    uVar3 = puVar6[7];
    puVar5[4] = puVar6[4];
    puVar5[5] = uVar1;
    puVar5[6] = uVar2;
    puVar5[7] = uVar3;
    uVar1 = puVar6[9];
    uVar2 = puVar6[10];
    uVar3 = puVar6[0xb];
    puVar5[8] = puVar6[8];
    puVar5[9] = uVar1;
    puVar5[10] = uVar2;
    puVar5[0xb] = uVar3;
    uVar1 = puVar6[0xd];
    uVar2 = puVar6[0xe];
    uVar3 = puVar6[0xf];
    puVar5[0xc] = puVar6[0xc];
    puVar5[0xd] = uVar1;
    puVar5[0xe] = uVar2;
    puVar5[0xf] = uVar3;
    uVar1 = puVar6[0x11];
    uVar2 = puVar6[0x12];
    uVar3 = puVar6[0x13];
    puVar5[0x10] = puVar6[0x10];
    puVar5[0x11] = uVar1;
    puVar5[0x12] = uVar2;
    puVar5[0x13] = uVar3;
    uVar1 = puVar6[0x15];
    uVar2 = puVar6[0x16];
    uVar3 = puVar6[0x17];
    puVar5[0x14] = puVar6[0x14];
    puVar5[0x15] = uVar1;
    puVar5[0x16] = uVar2;
    puVar5[0x17] = uVar3;
    uVar1 = puVar6[0x19];
    uVar2 = puVar6[0x1a];
    uVar3 = puVar6[0x1b];
    puVar5[0x18] = puVar6[0x18];
    puVar5[0x19] = uVar1;
    puVar5[0x1a] = uVar2;
    puVar5[0x1b] = uVar3;
    uVar1 = puVar6[0x1d];
    uVar2 = puVar6[0x1e];
    uVar3 = puVar6[0x1f];
    puVar5[0x1c] = puVar6[0x1c];
    puVar5[0x1d] = uVar1;
    puVar5[0x1e] = uVar2;
    puVar5[0x1f] = uVar3;
    lVar7 = lVar7 + -1;
    puVar4 = puVar5 + 0x20;
    param_1 = (JobSystem *)(puVar6 + 0x20);
  } while (lVar7 != 0);
  uVar1 = puVar6[0x21];
  uVar2 = puVar6[0x22];
  uVar3 = puVar6[0x23];
  puVar5[0x20] = puVar6[0x20];
  puVar5[0x21] = uVar1;
  puVar5[0x22] = uVar2;
  puVar5[0x23] = uVar3;
  uVar1 = puVar6[0x25];
  uVar2 = puVar6[0x26];
  uVar3 = puVar6[0x27];
  puVar5[0x24] = puVar6[0x24];
  puVar5[0x25] = uVar1;
  puVar5[0x26] = uVar2;
  puVar5[0x27] = uVar3;
  uVar1 = puVar6[0x29];
  uVar2 = puVar6[0x2a];
  uVar3 = puVar6[0x2b];
  puVar5[0x28] = puVar6[0x28];
  puVar5[0x29] = uVar1;
  puVar5[0x2a] = uVar2;
  puVar5[0x2b] = uVar3;
  uVar1 = puVar6[0x2d];
  uVar2 = puVar6[0x2e];
  uVar3 = puVar6[0x2f];
  puVar5[0x2c] = puVar6[0x2c];
  puVar5[0x2d] = uVar1;
  puVar5[0x2e] = uVar2;
  puVar5[0x2f] = uVar3;
  return this;
}



// public: class Graphine::Platform::TLSVariable & __ptr64 __cdecl
// Graphine::Platform::TLSVariable::operator=(class Graphine::Platform::TLSVariable && __ptr64)
// __ptr64

TLSVariable * __thiscall
Graphine::Platform::TLSVariable::operator_(TLSVariable *this,TLSVariable *param_1)

{
                    // 0x1bf20  26  ??4TLSVariable@Platform@Graphine@@QEAAAEAV012@$$QEAV012@@Z
  *this = *param_1;
  this[1] = param_1[1];
  this[2] = param_1[2];
  this[3] = param_1[3];
  return this;
}



// public: class Graphine::Platform::TLSVariable & __ptr64 __cdecl
// Graphine::Platform::TLSVariable::operator=(class Graphine::Platform::TLSVariable const & __ptr64)
// __ptr64

TLSVariable * __thiscall
Graphine::Platform::TLSVariable::operator_(TLSVariable *this,TLSVariable *param_1)

{
                    // 0x1bf40  27  ??4TLSVariable@Platform@Graphine@@QEAAAEAV012@AEBV012@@Z
  *(undefined4 *)this = *(undefined4 *)param_1;
  return this;
}



undefined8 * FUN_18001bf50(undefined8 *param_1,uint param_2)

{
  if ((param_2 & 2) == 0) {
    *param_1 = Graphine::ILogManager::vftable;
    if ((param_2 & 1) != 0) {
      free(param_1);
    }
  }
  else {
    _eh_vector_destructor_iterator_(param_1,8,param_1[-1],Graphine::ILogManager::_ILogManager);
    if ((param_2 & 1) != 0) {
      free(param_1 + -1);
    }
    param_1 = param_1 + -1;
  }
  return param_1;
}



undefined8 * FUN_18001bfe0(undefined8 *param_1,uint param_2)

{
  if ((param_2 & 2) == 0) {
    *param_1 = Graphine::Performance::IPerformanceManager::vftable;
    if ((param_2 & 1) != 0) {
      free(param_1);
    }
  }
  else {
    _eh_vector_destructor_iterator_
              (param_1,8,param_1[-1],
               Graphine::Performance::IPerformanceManager::_IPerformanceManager);
    if ((param_2 & 1) != 0) {
      free(param_1 + -1);
    }
    param_1 = param_1 + -1;
  }
  return param_1;
}



// public: static void * __ptr64 __cdecl Graphine::Platform::JobSystem::operator new[](unsigned
// __int64)

void * __cdecl Graphine::Platform::JobSystem::operator_new__(__uint64 param_1)

{
  bool bVar1;
  undefined4 *puVar2;
  PerformanceMonitor *pPVar3;
  __uint64 *p_Var4;
  undefined4 local_res8 [2];
  char *local_28;
  undefined4 local_20;
  char *local_18;
  
                    // 0x1c070  32  ??_UJobSystem@Platform@Graphine@@SAPEAX_K@Z
  local_20 = 0x1e0;
  local_28 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Platform.h";
  local_18 = "Graphine::Platform::JobSystem::operator new[]";
  bVar1 = IsCoreInitialized();
  if ((bVar1) && (DAT_180032a40 == (undefined **)0x0)) {
    DAT_180032a40 = &PTR_vftable_180032090;
  }
  if (param_1 != 0) {
    puVar2 = FUN_18001c700(local_res8,0);
    pPVar3 = Performance::GetPerformanceMonitor();
    Performance::PerformanceMonitor::CounterAdd(pPVar3,SUB41(*puVar2,0),(int)param_1);
    pPVar3 = Performance::GetPerformanceMonitor();
    Performance::PerformanceMonitor::CounterAdd(pPVar3,SUB41(DAT_180032a48,0),(int)param_1);
    p_Var4 = (__uint64 *)(**(code **)*DAT_180032a40)(DAT_180032a40,param_1 + 0x10,0,&local_28);
    if (p_Var4 != (__uint64 *)0x0) {
      *p_Var4 = param_1;
      *(undefined4 *)(p_Var4 + 1) = 0;
      return p_Var4 + 2;
    }
  }
  return (void *)0x0;
}



// public: static void * __ptr64 __cdecl Graphine::Platform::JobSystem::operator new[](unsigned
// __int64,enum Graphine::AllocationCategory::Enum)

void * __cdecl Graphine::Platform::JobSystem::operator_new__(__uint64 param_1,Enum param_2)

{
  bool bVar1;
  undefined4 *puVar2;
  PerformanceMonitor *pPVar3;
  __uint64 *p_Var4;
  undefined4 local_res8 [2];
  char *local_28;
  undefined4 local_20;
  char *local_18;
  
                    // 0x1c140  33
                    // ??_UJobSystem@Platform@Graphine@@SAPEAX_KW4Enum@AllocationCategory@2@@Z
  local_20 = 0x1e0;
  local_28 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Platform.h";
  local_18 = "Graphine::Platform::JobSystem::operator new[]";
  bVar1 = IsCoreInitialized();
  if ((bVar1) && (DAT_180032a40 == (undefined **)0x0)) {
    DAT_180032a40 = &PTR_vftable_180032090;
  }
  if (param_1 != 0) {
    puVar2 = FUN_18001c700(local_res8,param_2);
    pPVar3 = Performance::GetPerformanceMonitor();
    Performance::PerformanceMonitor::CounterAdd(pPVar3,SUB41(*puVar2,0),(int)param_1);
    pPVar3 = Performance::GetPerformanceMonitor();
    Performance::PerformanceMonitor::CounterAdd(pPVar3,SUB41(DAT_180032a48,0),(int)param_1);
    p_Var4 = (__uint64 *)(**(code **)*DAT_180032a40)(DAT_180032a40,param_1 + 0x10,param_2,&local_28)
    ;
    if (p_Var4 != (__uint64 *)0x0) {
      *(short *)(p_Var4 + 1) = (short)param_2;
      *(undefined2 *)((longlong)p_Var4 + 10) = 0;
      *p_Var4 = param_1;
      return p_Var4 + 2;
    }
  }
  return (void *)0x0;
}



// public: static void __cdecl Graphine::Platform::JobSystem::operator delete[](void * __ptr64)

void __cdecl Graphine::Platform::JobSystem::operator_delete__(void *param_1)

{
  bool bVar1;
  undefined4 *puVar2;
  PerformanceMonitor *pPVar3;
  undefined4 local_res8 [2];
  char *local_20;
  undefined4 local_18;
  char *local_10;
  
                    // 0x1c220  34  ??_VJobSystem@Platform@Graphine@@SAXPEAX@Z
  local_20 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Platform.h";
  local_18 = 0x1e0;
  local_10 = "Graphine::Platform::JobSystem::operator delete[]";
  bVar1 = IsCoreInitialized();
  if ((bVar1) && (DAT_180032a40 == (undefined **)0x0)) {
    DAT_180032a40 = &PTR_vftable_180032090;
  }
  puVar2 = FUN_18001c700(local_res8,(uint)*(ushort *)((longlong)param_1 + -8));
  pPVar3 = Performance::GetPerformanceMonitor();
  Performance::PerformanceMonitor::CounterSub
            (pPVar3,SUB41(*puVar2,0),*(int *)((longlong)param_1 + -0x10));
  pPVar3 = Performance::GetPerformanceMonitor();
  Performance::PerformanceMonitor::CounterSub
            (pPVar3,SUB41(DAT_180032a48,0),*(int *)((longlong)param_1 + -0x10));
  (**(code **)(*DAT_180032a40 + 8))(DAT_180032a40,(longlong)param_1 + -0x10,&local_20);
  return;
}



// public: static void __cdecl Graphine::Platform::JobSystem::operator delete[](void * __ptr64,enum
// Graphine::AllocationCategory::Enum)

void __cdecl Graphine::Platform::JobSystem::operator_delete__(void *param_1,Enum param_2)

{
  bool bVar1;
  undefined4 *puVar2;
  PerformanceMonitor *pPVar3;
  undefined4 local_res8 [2];
  char *local_20;
  undefined4 local_18;
  char *local_10;
  
                    // 0x1c2e0  35
                    // ??_VJobSystem@Platform@Graphine@@SAXPEAXW4Enum@AllocationCategory@2@@Z
  local_20 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Platform.h";
  local_18 = 0x1e0;
  local_10 = "Graphine::Platform::JobSystem::operator delete[]";
  bVar1 = IsCoreInitialized();
  if ((bVar1) && (DAT_180032a40 == (undefined **)0x0)) {
    DAT_180032a40 = &PTR_vftable_180032090;
  }
  puVar2 = FUN_18001c700(local_res8,(uint)*(ushort *)((longlong)param_1 + -8));
  pPVar3 = Performance::GetPerformanceMonitor();
  Performance::PerformanceMonitor::CounterSub
            (pPVar3,SUB41(*puVar2,0),*(int *)((longlong)param_1 + -0x10));
  pPVar3 = Performance::GetPerformanceMonitor();
  Performance::PerformanceMonitor::CounterSub
            (pPVar3,SUB41(DAT_180032a48,0),*(int *)((longlong)param_1 + -0x10));
  (**(code **)(*DAT_180032a40 + 8))(DAT_180032a40,(longlong)param_1 + -0x10,&local_20);
  return;
}



// public: void * __ptr64 __cdecl Graphine::Allocator::Alloc(unsigned __int64,enum
// Graphine::AllocationCategory::Enum,struct Graphine::ContextInfo const & __ptr64) __ptr64

void * __thiscall
Graphine::Allocator::Alloc(Allocator *this,__uint64 param_1,Enum param_2,ContextInfo *param_3)

{
  undefined4 *puVar1;
  PerformanceMonitor *pPVar2;
  __uint64 *p_Var3;
  undefined4 local_res10 [2];
  
                    // 0x1c3a0  40
                    // ?Alloc@Allocator@Graphine@@QEAAPEAX_KW4Enum@AllocationCategory@2@AEBUContextInfo@2@@Z
  if (param_1 != 0) {
    puVar1 = FUN_18001c700(local_res10,param_2);
    pPVar2 = Performance::GetPerformanceMonitor();
    Performance::PerformanceMonitor::CounterAdd(pPVar2,SUB41(*puVar1,0),(int)param_1);
    pPVar2 = Performance::GetPerformanceMonitor();
    Performance::PerformanceMonitor::CounterAdd(pPVar2,SUB41(DAT_180032a48,0),(int)param_1);
    p_Var3 = (__uint64 *)
             (**(code **)**(undefined8 **)this)(*(undefined8 **)this,param_1 + 0x10,param_2,param_3)
    ;
    if (p_Var3 != (__uint64 *)0x0) {
      *(undefined2 *)((longlong)p_Var3 + 10) = 0;
      *(short *)(p_Var3 + 1) = (short)param_2;
      *p_Var3 = param_1;
      return p_Var3 + 2;
    }
  }
  return (void *)0x0;
}



void FUN_18001c450(undefined8 param_1,undefined8 param_2)

{
                    // WARNING: Could not recover jumptable at 0x00018001c453. Too many branches
                    // WARNING: Treating indirect jump as call
  malloc(param_2);
  return;
}



// public: void * __ptr64 __cdecl Graphine::Allocator::AllocAligned(unsigned __int64,unsigned
// int,enum Graphine::AllocationCategory::Enum,struct Graphine::ContextInfo const & __ptr64) __ptr64

void * __thiscall
Graphine::Allocator::AllocAligned
          (Allocator *this,__uint64 param_1,uint param_2,Enum param_3,ContextInfo *param_4)

{
  ulonglong uVar1;
  undefined4 *puVar2;
  PerformanceMonitor *pPVar3;
  void *pvVar4;
  longlong lVar5;
  undefined4 local_res10 [2];
  
                    // 0x1c460  41
                    // ?AllocAligned@Allocator@Graphine@@QEAAPEAX_KIW4Enum@AllocationCategory@2@AEBUContextInfo@2@@Z
  uVar1 = (ulonglong)param_2;
  if (param_1 == 0) {
    return (void *)0x0;
  }
  puVar2 = FUN_18001c700(local_res10,param_3);
  pPVar3 = Performance::GetPerformanceMonitor();
  Performance::PerformanceMonitor::CounterAdd(pPVar3,SUB41(*puVar2,0),(int)param_1);
  pPVar3 = Performance::GetPerformanceMonitor();
  Performance::PerformanceMonitor::CounterAdd(pPVar3,SUB41(DAT_180032a48,0),(int)param_1);
  lVar5 = ((uVar1 + 0xf) / uVar1) * uVar1;
  pvVar4 = (void *)(**(code **)(**(longlong **)this + 0x10))
                             (*(longlong **)this,lVar5 + param_1,uVar1,param_3,param_4);
  if (pvVar4 != (void *)0x0) {
    pvVar4 = (void *)((longlong)pvVar4 + lVar5);
    *(short *)((longlong)pvVar4 + -6) = (short)param_2;
    *(short *)((longlong)pvVar4 + -8) = (short)param_3;
    *(__uint64 *)((longlong)pvVar4 + -0x10) = param_1;
  }
  return pvVar4;
}



// public: void __cdecl Graphine::Performance::PerformanceMonitor::CounterSet(class
// Graphine::Performance::StatisticId,int) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::CounterSet
          (PerformanceMonitor *this,StatisticId param_1,int param_2)

{
  undefined7 in_register_00000011;
  uint local_res18 [4];
  
                    // 0x1c530  55
                    // ?CounterSet@PerformanceMonitor@Performance@Graphine@@QEAAXVStatisticId@23@H@Z
  *(longlong *)(this + (CONCAT71(in_register_00000011,param_1) & 0xffffffff) * 0xc0 + 0x8150) =
       (longlong)param_2;
  Platform::CriticalSection::Enter((CriticalSection *)(this + 0xc));
  local_res18[0] = (int)CONCAT71(in_register_00000011,param_1) << 8 | 0xe;
  Write(this,local_res18,4);
  local_res18[0] = param_2;
  Write(this,local_res18,4);
  Platform::CriticalSection::Leave((CriticalSection *)(this + 0xc));
  return;
}



// public: void __cdecl Graphine::Allocator::Free(void * __ptr64,struct Graphine::ContextInfo const
// & __ptr64) __ptr64

void __thiscall Graphine::Allocator::Free(Allocator *this,void *param_1,ContextInfo *param_2)

{
  int *piVar1;
  undefined4 *puVar2;
  PerformanceMonitor *pPVar3;
  undefined4 local_res8 [2];
  
                    // 0x1c5c0  69  ?Free@Allocator@Graphine@@QEAAXPEAXAEBUContextInfo@2@@Z
  piVar1 = (int *)((longlong)param_1 + -0x10);
  puVar2 = FUN_18001c700(local_res8,(uint)*(ushort *)((longlong)param_1 + -8));
  pPVar3 = Performance::GetPerformanceMonitor();
  Performance::PerformanceMonitor::CounterSub(pPVar3,SUB41(*puVar2,0),*piVar1);
  pPVar3 = Performance::GetPerformanceMonitor();
  Performance::PerformanceMonitor::CounterSub(pPVar3,SUB41(DAT_180032a48,0),*piVar1);
                    // WARNING: Could not recover jumptable at 0x00018001c637. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)this + 8))(*(longlong **)this,piVar1,param_2);
  return;
}



void FUN_18001c640(undefined8 param_1,void *param_2)

{
                    // WARNING: Could not recover jumptable at 0x00018001c643. Too many branches
                    // WARNING: Treating indirect jump as call
  free(param_2);
  return;
}



// public: void __cdecl Graphine::Allocator::FreeAligned(void * __ptr64,struct Graphine::ContextInfo
// const & __ptr64) __ptr64

void __thiscall Graphine::Allocator::FreeAligned(Allocator *this,void *param_1,ContextInfo *param_2)

{
  undefined4 *puVar1;
  PerformanceMonitor *pPVar2;
  ulonglong uVar3;
  undefined4 local_res8 [2];
  
                    // 0x1c650  70  ?FreeAligned@Allocator@Graphine@@QEAAXPEAXAEBUContextInfo@2@@Z
  puVar1 = FUN_18001c700(local_res8,(uint)*(ushort *)((longlong)param_1 + -8));
  pPVar2 = Performance::GetPerformanceMonitor();
  Performance::PerformanceMonitor::CounterSub
            (pPVar2,SUB41(*puVar1,0),*(int *)((longlong)param_1 + -0x10));
  pPVar2 = Performance::GetPerformanceMonitor();
  Performance::PerformanceMonitor::CounterSub
            (pPVar2,SUB41(DAT_180032a48,0),*(int *)((longlong)param_1 + -0x10));
  uVar3 = (ulonglong)*(ushort *)((longlong)param_1 + -6);
                    // WARNING: Could not recover jumptable at 0x00018001c6dd. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)this + 0x18))
            (*(longlong **)this,(longlong)param_1 - ((uVar3 + 0xf) / uVar3) * uVar3,param_2);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * FUN_18001c700(undefined4 *param_1,int param_2)

{
  longlong lVar1;
  StatisticId SVar2;
  PerformanceMonitor *this;
  undefined7 extraout_var;
  undefined **ppuVar3;
  undefined4 *puVar4;
  wchar_t local_res10 [8];
  
  lVar1 = *(longlong *)((longlong)ThreadLocalStoragePointer + (ulonglong)_tls_index * 8);
  if (*(int *)(lVar1 + 0x420) < _DAT_180032a74) {
    _Init_thread_header((int *)&DAT_180032a74);
    if (_DAT_180032a74 == -1) {
      _DAT_180032a50 = 0xffffffffffffffff;
      _DAT_180032a58 = 0xffffffffffffffff;
      _DAT_180032a60 = 0xffffffffffffffff;
      _DAT_180032a68 = 0xffffffffffffffff;
      _DAT_180032a70 = 0xffffffff;
      _Init_thread_footer((int *)&DAT_180032a74);
    }
  }
  if (DAT_180032a78 == '\0') {
    if (*(int *)(lVar1 + 0x420) < _DAT_180032aa0) {
      _Init_thread_header((int *)&DAT_180032aa0);
      if (_DAT_180032aa0 == -1) {
        _DAT_180032a80 = &DAT_180025ab4;
        uRam0000000180032a88 = 0x80025ab8;
        uRam0000000180032a8c = 1;
        _DAT_180032a90 = 0;
        uRam0000000180032a94 = 0x3eb00000;
        uRam0000000180032a98 = 1;
        uRam0000000180032a9c = DAT_180032a4c;
        _Init_thread_footer((int *)&DAT_180032aa0);
      }
    }
    ppuVar3 = &PTR_u_Generic_180032000;
    puVar4 = &DAT_180032a50;
    do {
      _DAT_180032a80 = ppuVar3[1];
      this = Graphine::Performance::GetPerformanceMonitor();
      SVar2 = Graphine::Performance::PerformanceMonitor::RegisterStatistic
                        (this,local_res10,(Enum)*ppuVar3,(StatisticOptions *)0x2);
      ppuVar3 = ppuVar3 + 2;
      *puVar4 = *(undefined4 *)CONCAT71(extraout_var,SVar2);
      puVar4 = puVar4 + 1;
    } while ((longlong)ppuVar3 < 0x180032090);
    DAT_180032a78 = '\x01';
  }
  *param_1 = (&DAT_180032a50)[param_2];
  return param_1;
}



// class Graphine::Allocator * __ptr64 __cdecl Graphine::GetAllocator(void)

Allocator * __cdecl Graphine::GetAllocator(void)

{
  bool bVar1;
  
                    // 0x1c8e0  71  ?GetAllocator@Graphine@@YAPEAVAllocator@1@XZ
  bVar1 = IsCoreInitialized();
  if ((bVar1) && (DAT_180032a40 == (undefined **)0x0)) {
    DAT_180032a40 = &PTR_vftable_180032090;
  }
  return (Allocator *)&DAT_180032a40;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// class Graphine::LogManager * __ptr64 __cdecl Graphine::GetLogManagerPrivate(void)

LogManager * __cdecl Graphine::GetLogManagerPrivate(void)

{
                    // 0x1c920  79  ?GetLogManagerPrivate@Graphine@@YAPEAVLogManager@1@XZ
  if (*(int *)(*(longlong *)((longlong)ThreadLocalStoragePointer + (ulonglong)_tls_index * 8) +
              0x420) < _DAT_180032aa8) {
    _Init_thread_header((int *)&DAT_180032aa8);
    if (_DAT_180032aa8 == -1) {
      Platform::CriticalSection::CriticalSection((CriticalSection *)&DAT_180032150);
      atexit(FUN_180024890);
      _Init_thread_footer((int *)&DAT_180032aa8);
    }
  }
  return (LogManager *)&PTR_vftable_1800320a0;
}



// public: virtual enum Graphine::Performance::PerformanceCaptureMode::Enum __cdecl
// Graphine::Performance::PerformanceMonitor::GetMode(void) __ptr64

Enum __thiscall Graphine::Performance::PerformanceMonitor::GetMode(PerformanceMonitor *this)

{
                    // 0x1c930  80
                    // ?GetMode@PerformanceMonitor@Performance@Graphine@@UEAA?AW4Enum@PerformanceCaptureMode@23@XZ
  return *(Enum *)(this + 8);
}



// enum Graphine::Error::Enum __cdecl Graphine::RegisterAllocator(class Graphine::IAllocator *
// __ptr64)

Enum __cdecl Graphine::RegisterAllocator(IAllocator *param_1)

{
  bool bVar1;
  
                    // 0x1c940  129
                    // ?RegisterAllocator@Graphine@@YA?AW4Enum@Error@1@PEAVIAllocator@1@@Z
  bVar1 = IsCoreInitialized();
  if (bVar1) {
    return 2;
  }
  DAT_180032a40 = param_1;
  return 0;
}



// public: virtual void __cdecl Graphine::Performance::PerformanceMonitor::SetMode(enum
// Graphine::Performance::PerformanceCaptureMode::Enum) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::SetMode(PerformanceMonitor *this,Enum param_1)

{
                    // 0x1c970  138
                    // ?SetMode@PerformanceMonitor@Performance@Graphine@@UEAAXW4Enum@PerformanceCaptureMode@23@@Z
  *(Enum *)(this + 8) = param_1;
  return;
}



// public: void __cdecl Graphine::Allocator::ValidateHeap(void) __ptr64

void __thiscall Graphine::Allocator::ValidateHeap(Allocator *this)

{
                    // 0x1c980  161  ?ValidateHeap@Allocator@Graphine@@QEAAXXZ
                    // WARNING: Could not recover jumptable at 0x00018001c986. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)this + 0x20))();
  return;
}



// protected: void __cdecl Graphine::Performance::PerformanceMonitor::Write64(unsigned __int64)
// __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::Write64(PerformanceMonitor *this,__uint64 param_1)

{
  __uint64 local_res10 [3];
  
                    // 0x1c990  164  ?Write64@PerformanceMonitor@Performance@Graphine@@IEAAX_K@Z
  local_res10[0] = param_1;
  Write(this,local_res10,8);
  return;
}



// protected: void __cdecl Graphine::Performance::PerformanceMonitor::Write(unsigned int) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::Write(PerformanceMonitor *this,uint param_1)

{
  uint local_res10 [6];
  
                    // 0x1c9b0  165  ?Write@PerformanceMonitor@Performance@Graphine@@IEAAXI@Z
  local_res10[0] = param_1;
  Write(this,local_res10,4);
  return;
}



// protected: void __cdecl Graphine::Performance::PerformanceMonitor::Write(wchar_t const * __ptr64)
// __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::Write(PerformanceMonitor *this,wchar_t *param_1)

{
  short sVar1;
  int iVar2;
  ushort local_res10 [4];
  undefined2 local_res18 [8];
  
                    // 0x1c9d0  167  ?Write@PerformanceMonitor@Performance@Graphine@@IEAAXPEB_W@Z
  if (param_1 != (wchar_t *)0x0) {
    iVar2 = 0;
    sVar1 = *(short *)param_1;
    while (sVar1 != 0) {
      iVar2 = iVar2 + 1;
      sVar1 = *(short *)(param_1 + (longlong)iVar2 * 2);
    }
    local_res10[0] = 0xffff;
    if (iVar2 < 0xffff) {
      local_res10[0] = (ushort)iVar2;
    }
    Write(this,local_res10,2);
    Write(this,param_1,(ulonglong)local_res10[0] * 2);
    return;
  }
  local_res18[0] = 0;
  Write(this,local_res18,2);
  return;
}



// protected: void __cdecl Graphine::Performance::PerformanceMonitor::Write(enum
// Graphine::Performance::PayloadType::Enum) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::Write(PerformanceMonitor *this,Enum param_1)

{
  undefined local_res10 [24];
  
                    // 0x1ca60  168
                    // ?Write@PerformanceMonitor@Performance@Graphine@@IEAAXW4Enum@PayloadType@23@@Z
  local_res10[0] = (undefined)param_1;
  Write(this,local_res10,1);
  return;
}



// protected: void __cdecl Graphine::Performance::PerformanceMonitor::WriteDouble(double) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::WriteDouble(PerformanceMonitor *this,double param_1)

{
  double local_res10 [3];
  
                    // 0x1ca80  172  ?WriteDouble@PerformanceMonitor@Performance@Graphine@@IEAAXN@Z
  local_res10[0] = param_1;
  Write(this,local_res10,8);
  return;
}



// protected: void __cdecl Graphine::Performance::PerformanceMonitor::WriteHeader(enum
// Graphine::Performance::MessageType::Enum,class Graphine::Performance::StatisticId) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::WriteHeader
          (PerformanceMonitor *this,Enum param_1,StatisticId param_2)

{
  undefined7 in_register_00000081;
  uint local_res10 [6];
  
                    // 0x1caa0  174
                    // ?WriteHeader@PerformanceMonitor@Performance@Graphine@@IEAAXW4Enum@MessageType@23@VStatisticId@23@@Z
  local_res10[0] = (int)CONCAT71(in_register_00000081,param_2) << 8 | param_1;
  Write(this,local_res10,4);
  return;
}



// protected: void __cdecl Graphine::Performance::PerformanceMonitor::WritePayload(int const &
// __ptr64) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::WritePayload(PerformanceMonitor *this,int *param_1)

{
  undefined4 local_res10;
  
                    // 0x1cad0  175
                    // ?WritePayload@PerformanceMonitor@Performance@Graphine@@IEAAXAEBH@Z
                    // 0x1cad0  176
                    // ?WritePayload@PerformanceMonitor@Performance@Graphine@@IEAAXAEBI@Z
  local_res10 = CONCAT31(local_res10._1_3_,2);
  Write(this,&local_res10,1);
  local_res10 = *param_1;
  Write(this,&local_res10,4);
  return;
}



// protected: void __cdecl Graphine::Performance::PerformanceMonitor::WritePayload(struct
// Graphine::Performance::PerformanceMonitor::NoPayload const & __ptr64) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::WritePayload(PerformanceMonitor *this,NoPayload *param_1)

{
  undefined local_res18 [16];
  
                    // 0x1cb20  177
                    // ?WritePayload@PerformanceMonitor@Performance@Graphine@@IEAAXAEBUNoPayload@123@@Z
  local_res18[0] = 0;
  Write(this,local_res18,1);
  return;
}



// protected: void __cdecl Graphine::Performance::PerformanceMonitor::WritePayload(wchar_t const *
// __ptr64) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::WritePayload(PerformanceMonitor *this,wchar_t *param_1)

{
  undefined local_res18 [16];
  
                    // 0x1cb40  178
                    // ?WritePayload@PerformanceMonitor@Performance@Graphine@@IEAAXPEB_W@Z
  local_res18[0] = 3;
  Write(this,local_res18,1);
  Write(this,param_1);
  return;
}



// protected: void __cdecl Graphine::Performance::PerformanceMonitor::WriteTime(unsigned __int64)
// __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::WriteTime(PerformanceMonitor *this,__uint64 param_1)

{
  longlong local_res10 [3];
  
                    // 0x1cb80  180  ?WriteTime@PerformanceMonitor@Performance@Graphine@@IEAAX_K@Z
  local_res10[0] = param_1 - *(longlong *)(this + 0x80a8);
  Write(this,local_res10,8);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// enum Graphine::Error::Enum __cdecl Graphine::InitializeCore(__int64)

Enum __cdecl Graphine::InitializeCore(__int64 param_1)

{
                    // 0x1cbb0  100  ?InitializeCore@Graphine@@YA?AW4Enum@Error@1@_J@Z
  _DAT_180032aa4 = _DAT_180032aa4 + 1;
  WindowsGraphicsDriver::Initialize(&GlobalGraphicsDriver);
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// bool __cdecl Graphine::IsCoreInitialized(void)

bool __cdecl Graphine::IsCoreInitialized(void)

{
                    // 0x1cbd0  107  ?IsCoreInitialized@Graphine@@YA_NXZ
  return _DAT_180032aa4 != 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// bool __cdecl Graphine::ReleaseCore(void)

bool __cdecl Graphine::ReleaseCore(void)

{
                    // 0x1cbe0  134  ?ReleaseCore@Graphine@@YA_NXZ
  _DAT_180032aa4 = _DAT_180032aa4 + -1;
  return _DAT_180032aa4 == 0;
}



// private: __cdecl Graphine::LogManager::LogManager(void) __ptr64

LogManager * __thiscall Graphine::LogManager::LogManager(LogManager *this)

{
                    // 0x1cbf0  8  ??0LogManager@Graphine@@AEAA@XZ
  *(undefined ***)this = vftable;
  *(undefined4 *)(this + 0x88) = 0;
  *(undefined4 *)(this + 0x90) = 0;
  *(undefined8 *)(this + 0x98) = 0;
  *(undefined4 *)(this + 0xa0) = 0;
  Platform::CriticalSection::CriticalSection((CriticalSection *)(this + 0xb0));
  return this;
}



void FUN_18001cc50(undefined4 *param_1)

{
  FUN_18001cdf0(param_1);
  FUN_18001d780((void **)(param_1 + 2));
  return;
}



void FUN_18001cc80(undefined8 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  *(undefined4 *)(param_1 + 2) = 0;
  return;
}



// private: virtual __cdecl Graphine::LogManager::~LogManager(void) __ptr64

void __thiscall Graphine::LogManager::_LogManager(LogManager *this)

{
                    // 0x1cc90  15  ??1LogManager@Graphine@@EEAA@XZ
  *(undefined ***)this = vftable;
  Platform::CriticalSection::_CriticalSection((CriticalSection *)(this + 0xb0));
  FUN_18001cdf0((undefined4 *)(this + 0x90));
  FUN_18001d780((void **)(this + 0x98));
  *(undefined ***)this = ILogManager::vftable;
  return;
}



LogManager * FUN_18001ccf0(LogManager *param_1,uint param_2)

{
  if ((param_2 & 2) == 0) {
    Graphine::LogManager::_LogManager(param_1);
    if ((param_2 & 1) != 0) {
      free(param_1);
    }
  }
  else {
    _eh_vector_destructor_iterator_
              (param_1,0xd8,*(__uint64 *)(param_1 + -8),Graphine::LogManager::_LogManager);
    if ((param_2 & 1) != 0) {
      free(param_1 + -8);
    }
    param_1 = param_1 + -8;
  }
  return param_1;
}



// public: virtual enum Graphine::Error::Enum __cdecl Graphine::LogManager::AddLogger(class
// Graphine::ILogger * __ptr64) __ptr64

Enum __thiscall Graphine::LogManager::AddLogger(LogManager *this,ILogger *param_1)

{
  Enum EVar1;
  
                    // 0x1cd80  37
                    // ?AddLogger@LogManager@Graphine@@UEAA?AW4Enum@Error@2@PEAVILogger@2@@Z
  Platform::CriticalSection::Enter((CriticalSection *)(this + 0xb0));
  if (param_1 == (ILogger *)0x0) {
    EVar1 = 1;
  }
  else if (*(uint *)(this + 0x88) == 0x10) {
    EVar1 = 3;
  }
  else {
    *(ILogger **)(this + (ulonglong)*(uint *)(this + 0x88) * 8 + 8) = param_1;
    *(int *)(this + 0x88) = *(int *)(this + 0x88) + 1;
    EVar1 = 0;
  }
  Platform::CriticalSection::Leave((CriticalSection *)(this + 0xb0));
  return EVar1;
}



void FUN_18001cdf0(undefined4 *param_1)

{
  longlong lVar1;
  int *piVar2;
  int iVar3;
  longlong lVar4;
  void *pvVar5;
  longlong lVar6;
  Allocator *this;
  uint uVar7;
  char *local_30;
  undefined4 local_28;
  char *local_20;
  ulonglong uVar8;
  
  uVar8 = 0;
  if (param_1[4] == 0) {
    *param_1 = 0;
  }
  else {
    do {
      lVar1 = uVar8 * 0x18;
      iVar3 = *(int *)(*(longlong *)(param_1 + 2) + 0x10 + lVar1);
      while (iVar3 != 0) {
        lVar4 = *(longlong *)(param_1 + 2);
        pvVar5 = *(void **)(lVar1 + lVar4);
        if (pvVar5 == *(void **)(lVar1 + 8 + lVar4)) {
          *(undefined8 *)(lVar1 + 8 + lVar4) = 0;
          *(undefined8 *)(lVar1 + lVar4) = 0;
          *(undefined4 *)(lVar1 + 0x10 + lVar4) = 0;
          *(undefined8 *)((longlong)pvVar5 + 8) = 0;
          *(undefined8 *)((longlong)pvVar5 + 0x10) = 0;
        }
        else {
          lVar6 = *(longlong *)((longlong)pvVar5 + 8);
          *(longlong *)(lVar1 + lVar4) = lVar6;
          *(undefined8 *)(lVar6 + 0x10) = 0;
          if (*(longlong *)(*(longlong *)(lVar1 + lVar4) + 8) == 0) {
            *(longlong *)(lVar1 + 8 + lVar4) = *(longlong *)(lVar1 + lVar4);
          }
          *(undefined8 *)((longlong)pvVar5 + 8) = 0;
          *(undefined8 *)((longlong)pvVar5 + 0x10) = 0;
          piVar2 = (int *)(lVar1 + 0x10 + lVar4);
          *piVar2 = *piVar2 + -1;
        }
        local_30 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Dictionary.h";
        local_28 = 0xb7;
        local_20 = 
        "Graphine::Dictionary<unsigned int,bool,struct Graphine::DefaultTypeHelper<unsigned int> >::Pair::operator delete"
        ;
        this = Graphine::GetAllocator();
        Graphine::Allocator::Free(this,pvVar5,(ContextInfo *)&local_30);
        iVar3 = *(int *)(*(longlong *)(param_1 + 2) + 0x10 + lVar1);
      }
      lVar4 = *(longlong *)(param_1 + 2);
      *(undefined8 *)(lVar1 + lVar4) = 0;
      *(undefined8 *)(lVar1 + 8 + lVar4) = 0;
      *(undefined4 *)(lVar1 + 0x10 + lVar4) = 0;
      uVar7 = (int)uVar8 + 1;
      uVar8 = (ulonglong)uVar7;
    } while (uVar7 < (uint)param_1[4]);
    *param_1 = 0;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// class Graphine::ILogManager * __ptr64 __cdecl Graphine::GetLogManager(void)

ILogManager * __cdecl Graphine::GetLogManager(void)

{
                    // 0x1cf30  78  ?GetLogManager@Graphine@@YAPEAVILogManager@1@XZ
  if (*(int *)(*(longlong *)((longlong)ThreadLocalStoragePointer + (ulonglong)_tls_index * 8) +
              0x420) < _DAT_180032aa8) {
    _Init_thread_header((int *)&DAT_180032aa8);
    if (_DAT_180032aa8 == -1) {
      Platform::CriticalSection::CriticalSection((CriticalSection *)&DAT_180032150);
      atexit(FUN_180024890);
      _Init_thread_footer((int *)&DAT_180032aa8);
    }
  }
  return (ILogManager *)&PTR_vftable_1800320a0;
}



undefined8 FUN_18001cfb0(void **param_1,uint param_2,uint param_3,Enum param_4)

{
  undefined8 *puVar1;
  uint uVar2;
  Allocator *pAVar3;
  void *pvVar4;
  char *local_38;
  undefined4 local_30;
  char *local_28;
  ulonglong uVar5;
  
  if (*param_1 != (void *)0x0) {
    return 2;
  }
  if (param_2 != 0) {
    local_38 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Array.h";
    local_28 = 
    "Graphine::ArrayBase<class Graphine::LinkedList<struct Graphine::Dictionary<unsigned int,bool,struct Graphine::DefaultTypeHelper<unsigned int> >::Pair>,1>::InitializeInternal"
    ;
    if (param_3 == 0) {
      local_30 = 0xb1;
      pAVar3 = Graphine::GetAllocator();
      pvVar4 = Graphine::Allocator::Alloc
                         (pAVar3,(ulonglong)param_2 * 0x18,param_4,(ContextInfo *)&local_38);
    }
    else {
      local_30 = 0xad;
      pAVar3 = Graphine::GetAllocator();
      pvVar4 = Graphine::Allocator::AllocAligned
                         (pAVar3,(ulonglong)param_2 * 0x18,param_3,param_4,(ContextInfo *)&local_38)
      ;
    }
    *param_1 = pvVar4;
    if (pvVar4 == (void *)0x0) {
      return 3;
    }
    uVar5 = 0;
    *(uint *)(param_1 + 1) = param_2;
    if (param_2 != 0) {
      do {
        puVar1 = (undefined8 *)((longlong)*param_1 + uVar5 * 0x18);
        if (puVar1 != (undefined8 *)0x0) {
          *puVar1 = 0;
          puVar1[1] = 0;
          *(undefined4 *)(puVar1 + 2) = 0;
        }
        uVar2 = (int)uVar5 + 1;
        uVar5 = (ulonglong)uVar2;
      } while (uVar2 < *(uint *)(param_1 + 1));
    }
  }
  return 0;
}



undefined8 FUN_18001d0e0(uint *param_1,uint *param_2,undefined *param_3)

{
  undefined8 *puVar1;
  int *piVar2;
  longlong lVar3;
  longlong lVar4;
  Allocator *pAVar5;
  void *pvVar6;
  uint *puVar7;
  uint uVar8;
  char *local_38;
  undefined4 local_30;
  char *local_28;
  ulonglong uVar9;
  
  uVar9 = 0;
  if (param_1[4] == 0) {
    if (*(longlong *)(param_1 + 2) != 0) {
      return 2;
    }
    local_30 = 0xb1;
    local_38 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Array.h";
    local_28 = 
    "Graphine::ArrayBase<class Graphine::LinkedList<struct Graphine::Dictionary<unsigned int,bool,struct Graphine::DefaultTypeHelper<unsigned int> >::Pair>,1>::InitializeInternal"
    ;
    pAVar5 = Graphine::GetAllocator();
    pvVar6 = Graphine::Allocator::Alloc(pAVar5,0x180,0,(ContextInfo *)&local_38);
    *(void **)(param_1 + 2) = pvVar6;
    if (pvVar6 == (void *)0x0) {
      return 3;
    }
    param_1[4] = 0x10;
    do {
      puVar1 = (undefined8 *)(*(longlong *)(param_1 + 2) + uVar9 * 0x18);
      if (puVar1 != (undefined8 *)0x0) {
        *puVar1 = 0;
        puVar1[1] = 0;
        *(undefined4 *)(puVar1 + 2) = 0;
      }
      uVar8 = (int)uVar9 + 1;
      uVar9 = (ulonglong)uVar8;
    } while (uVar8 < param_1[4]);
  }
  uVar8 = *param_1;
  if (2.0 < (double)(ulonglong)uVar8 / (double)(ulonglong)param_1[4]) {
    uVar8 = (uVar8 >> 1) + uVar8;
    if (uVar8 < 0x10) {
      uVar8 = 0x10;
    }
    FUN_18001da50((longlong)param_1,uVar8 >> 1);
  }
  if (param_1[4] != 0) {
    for (puVar7 = *(uint **)(*(longlong *)(param_1 + 2) +
                            ((ulonglong)*param_2 % (ulonglong)param_1[4]) * 0x18);
        puVar7 != (uint *)0x0; puVar7 = *(uint **)(puVar7 + 2)) {
      if (*puVar7 == *param_2) {
        *(undefined *)(puVar7 + 1) = *param_3;
        return 0;
      }
    }
  }
  local_30 = 0xb7;
  local_38 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Dictionary.h";
  local_28 = 
  "Graphine::Dictionary<unsigned int,bool,struct Graphine::DefaultTypeHelper<unsigned int> >::Pair::operator new"
  ;
  pAVar5 = Graphine::GetAllocator();
  puVar7 = (uint *)Graphine::Allocator::Alloc(pAVar5,0x18,0,(ContextInfo *)&local_38);
  if (puVar7 == (uint *)0x0) {
    return 3;
  }
  *(undefined8 *)(puVar7 + 2) = 0;
  *(undefined8 *)(puVar7 + 4) = 0;
  *puVar7 = *param_2;
  *(undefined *)(puVar7 + 1) = *param_3;
  uVar9 = (ulonglong)*param_2 % (ulonglong)param_1[4];
  lVar3 = *(longlong *)(param_1 + 2);
  lVar4 = *(longlong *)(lVar3 + 8 + uVar9 * 0x18);
  if (lVar4 != 0) {
    *(uint **)(lVar4 + 8) = puVar7;
    *(undefined8 *)(puVar7 + 4) = *(undefined8 *)(lVar3 + 8 + uVar9 * 0x18);
    *(undefined8 *)(puVar7 + 2) = 0;
    piVar2 = (int *)(lVar3 + 0x10 + uVar9 * 0x18);
    *piVar2 = *piVar2 + 1;
    *(uint **)(lVar3 + 8 + uVar9 * 0x18) = puVar7;
    *param_1 = *param_1 + 1;
    return 0;
  }
  *(uint **)(lVar3 + 8 + uVar9 * 0x18) = puVar7;
  *(uint **)(lVar3 + uVar9 * 0x18) = puVar7;
  *(undefined8 *)(puVar7 + 2) = 0;
  *(undefined8 *)(puVar7 + 4) = 0;
  *(undefined4 *)(lVar3 + 0x10 + uVar9 * 0x18) = 1;
  *param_1 = *param_1 + 1;
  return 0;
}



// public: virtual bool __cdecl Graphine::LogManager::IsWarningMuted(unsigned int) __ptr64

bool __thiscall Graphine::LogManager::IsWarningMuted(LogManager *this,uint param_1)

{
  uint *puVar1;
  
                    // 0x1d2f0  109  ?IsWarningMuted@LogManager@Graphine@@UEAA_NI@Z
  if (*(uint *)(this + 0xa0) != 0) {
    for (puVar1 = *(uint **)(*(longlong *)(this + 0x98) +
                            ((ulonglong)param_1 % (ulonglong)*(uint *)(this + 0xa0)) * 0x18);
        puVar1 != (uint *)0x0; puVar1 = *(uint **)(puVar1 + 2)) {
      if (*puVar1 == param_1) goto LAB_18001d330;
    }
  }
  puVar1 = (uint *)0x0;
LAB_18001d330:
  return puVar1 != (uint *)0x0;
}



// WARNING: Function: _alloca_probe replaced with injection: alloca_probe
// public: void __cdecl Graphine::LogManager::LogError(enum Graphine::Error::Enum,struct
// Graphine::ContextInfo const & __ptr64,wchar_t const * __ptr64,...) __ptr64

void __thiscall
Graphine::LogManager::LogError
          (LogManager *this,Enum param_1,ContextInfo *param_2,wchar_t *param_3,...)

{
  CriticalSection *this_00;
  uint uVar1;
  ulonglong uVar2;
  wchar_t *local_res20;
  undefined auStack_1070 [32];
  undefined8 local_1050;
  CriticalSection *local_1048;
  wchar_t local_1040 [4096];
  ulonglong local_40;
  undefined8 uStack_30;
  
                    // 0x1d340  115
                    // ?LogError@LogManager@Graphine@@QEAAXW4Enum@Error@2@AEBUContextInfo@2@PEB_WZZ
  uStack_30 = 0x18001d355;
  local_1050 = 0xfffffffffffffffe;
  local_40 = DAT_180032820 ^ (ulonglong)auStack_1070;
  local_res20 = param_3;
  if (*(int *)(this + 0x88) != 0) {
    String::FormatStringTruncVA(local_1040,0x800,param_3,(char *)&local_res20);
    this_00 = (CriticalSection *)(this + 0xb0);
    local_1048 = this_00;
    Platform::CriticalSection::Enter(this_00);
    uVar2 = 0;
    if (*(int *)(this + 0x88) != 0) {
      do {
        (**(code **)**(undefined8 **)(this + uVar2 * 8 + 8))
                  (*(undefined8 **)(this + uVar2 * 8 + 8),param_1,local_1040,param_2);
        uVar1 = (int)uVar2 + 1;
        uVar2 = (ulonglong)uVar1;
      } while (uVar1 < *(uint *)(this + 0x88));
    }
    Platform::CriticalSection::Leave(this_00);
  }
  __security_check_cookie(local_40 ^ (ulonglong)auStack_1070);
  return;
}



// public: void __cdecl Graphine::LogManager::LogError(enum Graphine::Error::Enum,wchar_t const *
// __ptr64,struct Graphine::ContextInfo const & __ptr64) __ptr64

void __thiscall
Graphine::LogManager::LogError(LogManager *this,Enum param_1,wchar_t *param_2,ContextInfo *param_3)

{
  uint uVar1;
  ulonglong uVar2;
  undefined8 uVar3;
  
                    // 0x1d410  116
                    // ?LogError@LogManager@Graphine@@QEAAXW4Enum@Error@2@PEB_WAEBUContextInfo@2@@Z
  uVar3 = 0xfffffffffffffffe;
  Platform::CriticalSection::Enter((CriticalSection *)(this + 0xb0));
  uVar2 = 0;
  if (*(int *)(this + 0x88) != 0) {
    do {
      (**(code **)**(undefined8 **)(this + uVar2 * 8 + 8))
                (*(undefined8 **)(this + uVar2 * 8 + 8),param_1,param_2,param_3,uVar3);
      uVar1 = (int)uVar2 + 1;
      uVar2 = (ulonglong)uVar1;
    } while (uVar1 < *(uint *)(this + 0x88));
  }
  Platform::CriticalSection::Leave((CriticalSection *)(this + 0xb0));
  return;
}



// WARNING: Function: _alloca_probe replaced with injection: alloca_probe
// public: void __cdecl Graphine::LogManager::LogMessage(wchar_t const * __ptr64,...) __ptr64

void __thiscall Graphine::LogManager::LogMessage(LogManager *this,wchar_t *param_1,...)

{
  CriticalSection *this_00;
  uint uVar1;
  ulonglong uVar2;
  undefined8 in_R8;
  undefined8 in_R9;
  wchar_t *local_res10;
  undefined8 local_res18;
  undefined8 local_res20;
  undefined auStack_1060 [32];
  undefined8 local_1040;
  CriticalSection *local_1038;
  wchar_t local_1030 [4096];
  ulonglong local_30;
  undefined8 uStack_20;
  
                    // 0x1d4a0  117  ?LogMessage@LogManager@Graphine@@QEAAXPEB_WZZ
  uStack_20 = 0x18001d4bc;
  local_1040 = 0xfffffffffffffffe;
  local_30 = DAT_180032820 ^ (ulonglong)auStack_1060;
  local_res10 = param_1;
  local_res18 = in_R8;
  local_res20 = in_R9;
  if (*(int *)(this + 0x88) != 0) {
    String::FormatStringTruncVA(local_1030,0x800,param_1,(char *)&local_res10);
    this_00 = (CriticalSection *)(this + 0xb0);
    local_1038 = this_00;
    Platform::CriticalSection::Enter(this_00);
    uVar2 = 0;
    if (*(int *)(this + 0x88) != 0) {
      do {
        (**(code **)(**(longlong **)(this + uVar2 * 8 + 8) + 0x10))
                  (*(longlong **)(this + uVar2 * 8 + 8),local_1030);
        uVar1 = (int)uVar2 + 1;
        uVar2 = (ulonglong)uVar1;
      } while (uVar1 < *(uint *)(this + 0x88));
    }
    Platform::CriticalSection::Leave(this_00);
  }
  __security_check_cookie(local_30 ^ (ulonglong)auStack_1060);
  return;
}



// WARNING: Function: _alloca_probe replaced with injection: alloca_probe
// public: void __cdecl Graphine::LogManager::LogWarning(wchar_t const * __ptr64,...) __ptr64

void __thiscall Graphine::LogManager::LogWarning(LogManager *this,wchar_t *param_1,...)

{
  CriticalSection *this_00;
  uint uVar1;
  ulonglong uVar2;
  undefined8 in_R8;
  undefined8 in_R9;
  wchar_t *local_res10;
  undefined8 local_res18;
  undefined8 local_res20;
  undefined auStack_1060 [32];
  undefined8 local_1040;
  CriticalSection *local_1038;
  wchar_t local_1030 [4096];
  ulonglong local_30;
  undefined8 uStack_20;
  
                    // 0x1d560  118  ?LogWarning@LogManager@Graphine@@QEAAXPEB_WZZ
  uStack_20 = 0x18001d57c;
  local_1040 = 0xfffffffffffffffe;
  local_30 = DAT_180032820 ^ (ulonglong)auStack_1060;
  local_res10 = param_1;
  local_res18 = in_R8;
  local_res20 = in_R9;
  if (*(int *)(this + 0x88) != 0) {
    String::FormatStringTruncVA(local_1030,0x800,param_1,(char *)&local_res10);
    this_00 = (CriticalSection *)(this + 0xb0);
    local_1038 = this_00;
    Platform::CriticalSection::Enter(this_00);
    uVar2 = 0;
    if (*(int *)(this + 0x88) != 0) {
      do {
        (**(code **)(**(longlong **)(this + uVar2 * 8 + 8) + 8))
                  (*(longlong **)(this + uVar2 * 8 + 8),local_1030);
        uVar1 = (int)uVar2 + 1;
        uVar2 = (ulonglong)uVar1;
      } while (uVar1 < *(uint *)(this + 0x88));
    }
    Platform::CriticalSection::Leave(this_00);
  }
  __security_check_cookie(local_30 ^ (ulonglong)auStack_1060);
  return;
}



// WARNING: Function: _alloca_probe replaced with injection: alloca_probe
// public: virtual void __cdecl Graphine::LogManager::LogWarning(unsigned int,wchar_t const *
// __ptr64,...) __ptr64

void __thiscall Graphine::LogManager::LogWarning(LogManager *this,uint param_1,wchar_t *param_2,...)

{
  CriticalSection *this_00;
  uint *puVar1;
  uint uVar2;
  ulonglong uVar3;
  undefined8 in_R9;
  wchar_t *local_res18;
  undefined8 local_res20;
  undefined auStack_2070 [32];
  wchar_t *local_2050;
  undefined8 local_2040;
  CriticalSection *local_2038;
  wchar_t local_2030 [4096];
  wchar_t local_1030 [4096];
  ulonglong local_30;
  undefined8 uStack_20;
  
                    // 0x1d620  119  ?LogWarning@LogManager@Graphine@@UEAAXIPEB_WZZ
  uStack_20 = 0x18001d637;
  local_2040 = 0xfffffffffffffffe;
  local_30 = DAT_180032820 ^ (ulonglong)auStack_2070;
  local_res18 = param_2;
  local_res20 = in_R9;
  if (*(int *)(this + 0x88) != 0) {
    if (*(uint *)(this + 0xa0) != 0) {
      for (puVar1 = *(uint **)(*(longlong *)(this + 0x98) +
                              ((ulonglong)param_1 % (ulonglong)*(uint *)(this + 0xa0)) * 0x18);
          puVar1 != (uint *)0x0; puVar1 = *(uint **)(puVar1 + 2)) {
        if (*puVar1 == param_1) goto LAB_18001d726;
      }
    }
    String::FormatStringTruncVA(local_2030,0x800,param_2,(char *)&local_res18);
    local_2050 = local_2030;
    String::FormatStringTrunc(local_1030,0x800,(wchar_t *)L"W%u: %ls",(ulonglong)param_1);
    this_00 = (CriticalSection *)(this + 0xb0);
    local_2038 = this_00;
    Platform::CriticalSection::Enter(this_00);
    uVar3 = 0;
    if (*(int *)(this + 0x88) != 0) {
      do {
        (**(code **)(**(longlong **)(this + uVar3 * 8 + 8) + 8))
                  (*(longlong **)(this + uVar3 * 8 + 8),local_1030);
        uVar2 = (int)uVar3 + 1;
        uVar3 = (ulonglong)uVar2;
      } while (uVar2 < *(uint *)(this + 0x88));
    }
    Platform::CriticalSection::Leave(this_00);
  }
LAB_18001d726:
  __security_check_cookie(local_30 ^ (ulonglong)auStack_2070);
  return;
}



// public: virtual void __cdecl Graphine::LogManager::MuteWarning(unsigned int) __ptr64

void __thiscall Graphine::LogManager::MuteWarning(LogManager *this,uint param_1)

{
  undefined local_res8 [8];
  uint local_res10 [6];
  
                    // 0x1d750  123  ?MuteWarning@LogManager@Graphine@@UEAAXI@Z
  local_res8[0] = 1;
  local_res10[0] = param_1;
  FUN_18001d0e0((uint *)(this + 0x90),local_res10,local_res8);
  return;
}



void FUN_18001d780(void **param_1)

{
  void *pvVar1;
  Allocator *this;
  uint uVar2;
  ulonglong uVar3;
  char *local_28;
  undefined4 local_20;
  char *local_18;
  
  uVar3 = 0;
  if (*(int *)(param_1 + 1) != 0) {
    do {
      uVar2 = (int)uVar3 + 1;
      pvVar1 = *param_1;
      *(undefined8 *)((longlong)pvVar1 + uVar3 * 0x18) = 0;
      *(undefined8 *)((longlong)pvVar1 + uVar3 * 0x18 + 8) = 0;
      *(undefined4 *)((longlong)pvVar1 + uVar3 * 0x18 + 0x10) = 0;
      uVar3 = (ulonglong)uVar2;
    } while (uVar2 < *(uint *)(param_1 + 1));
  }
  pvVar1 = *param_1;
  if (pvVar1 != (void *)0x0) {
    local_20 = 0xd3;
    local_28 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Array.h";
    local_18 = 
    "Graphine::ArrayBase<class Graphine::LinkedList<struct Graphine::Dictionary<unsigned int,bool,struct Graphine::DefaultTypeHelper<unsigned int> >::Pair>,1>::ReleaseInternal"
    ;
    this = Graphine::GetAllocator();
    Graphine::Allocator::Free(this,pvVar1,(ContextInfo *)&local_28);
  }
  *(undefined4 *)(param_1 + 1) = 0;
  *param_1 = (void *)0x0;
  return;
}



ulonglong FUN_18001d810(int *param_1,uint *param_2)

{
  uint **ppuVar1;
  uint *puVar2;
  ulonglong in_RAX;
  Allocator *this;
  undefined8 extraout_RAX;
  char *local_20;
  undefined4 local_18;
  char *local_10;
  
  if (param_1[4] != 0) {
    in_RAX = *(ulonglong *)(param_1 + 2);
    ppuVar1 = (uint **)(in_RAX + ((ulonglong)*param_2 % (ulonglong)(uint)param_1[4]) * 0x18);
    for (puVar2 = *ppuVar1; puVar2 != (uint *)0x0; puVar2 = *(uint **)(puVar2 + 2)) {
      if (*puVar2 == *param_2) {
        FUN_18001d8c0((longlong *)ppuVar1,(longlong)puVar2);
        local_20 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Dictionary.h";
        local_18 = 0xb7;
        local_10 = 
        "Graphine::Dictionary<unsigned int,bool,struct Graphine::DefaultTypeHelper<unsigned int> >::Pair::operator delete"
        ;
        this = Graphine::GetAllocator();
        Graphine::Allocator::Free(this,puVar2,(ContextInfo *)&local_20);
        *param_1 = *param_1 + -1;
        return CONCAT71((int7)((ulonglong)extraout_RAX >> 8),1);
      }
    }
  }
  return in_RAX & 0xffffffffffffff00;
}



longlong FUN_18001d8c0(longlong *param_1,longlong param_2)

{
  longlong lVar1;
  longlong in_RAX;
  longlong lVar2;
  
  lVar2 = *param_1;
  if (param_2 == lVar2) {
    if (lVar2 == param_1[1]) {
      param_1[1] = 0;
      *param_1 = 0;
      *(undefined4 *)(param_1 + 2) = 0;
      *(undefined8 *)(lVar2 + 8) = 0;
      *(undefined8 *)(lVar2 + 0x10) = 0;
      return in_RAX;
    }
    lVar1 = *(longlong *)(lVar2 + 8);
    *param_1 = lVar1;
    *(undefined8 *)(lVar1 + 0x10) = 0;
    lVar1 = *param_1;
    if (*(longlong *)(lVar1 + 8) == 0) {
      param_1[1] = lVar1;
    }
    *(undefined8 *)(lVar2 + 8) = 0;
    *(undefined8 *)(lVar2 + 0x10) = 0;
    *(int *)(param_1 + 2) = *(int *)(param_1 + 2) + -1;
    return lVar1;
  }
  if (param_2 != param_1[1]) {
    *(undefined8 *)(*(longlong *)(param_2 + 0x10) + 8) = *(undefined8 *)(param_2 + 8);
    lVar2 = *(longlong *)(param_2 + 0x10);
    *(longlong *)(*(longlong *)(param_2 + 8) + 0x10) = lVar2;
    *(undefined8 *)(param_2 + 8) = 0;
    *(undefined8 *)(param_2 + 0x10) = 0;
    *(int *)(param_1 + 2) = *(int *)(param_1 + 2) + -1;
    return lVar2;
  }
  lVar2 = *param_1;
  lVar1 = param_1[1];
  if (lVar2 == lVar1) {
    param_1[1] = 0;
    *param_1 = 0;
    *(undefined4 *)(param_1 + 2) = 0;
    *(undefined8 *)(lVar2 + 8) = 0;
    *(undefined8 *)(lVar2 + 0x10) = 0;
    return lVar2;
  }
  lVar2 = *(longlong *)(lVar1 + 0x10);
  param_1[1] = lVar2;
  *(undefined8 *)(lVar2 + 8) = 0;
  lVar2 = param_1[1];
  if (*(longlong *)(*param_1 + 8) == 0) {
    lVar2 = *param_1;
  }
  param_1[1] = lVar2;
  *(undefined8 *)(lVar1 + 8) = 0;
  *(undefined8 *)(lVar1 + 0x10) = 0;
  *(int *)(param_1 + 2) = *(int *)(param_1 + 2) + -1;
  return lVar1;
}



// public: virtual enum Graphine::Error::Enum __cdecl Graphine::LogManager::RemoveLogger(class
// Graphine::ILogger * __ptr64) __ptr64

Enum __thiscall Graphine::LogManager::RemoveLogger(LogManager *this,ILogger *param_1)

{
  uint uVar1;
  uint uVar2;
  Enum EVar3;
  
                    // 0x1d9a0  135
                    // ?RemoveLogger@LogManager@Graphine@@UEAA?AW4Enum@Error@2@PEAVILogger@2@@Z
  Platform::CriticalSection::Enter((CriticalSection *)(this + 0xb0));
  uVar2 = 0;
  uVar1 = *(uint *)(this + 0x88);
  if (uVar1 != 0) {
    do {
      if (*(ILogger **)(this + (ulonglong)uVar2 * 8 + 8) == param_1) {
        *(uint *)(this + 0x88) = uVar1 - 1;
        EVar3 = 0;
        if (uVar2 < uVar1 - 1) {
          do {
            uVar1 = uVar2 + 1;
            *(undefined8 *)(this + (ulonglong)uVar2 * 8 + 8) =
                 *(undefined8 *)(this + (ulonglong)uVar1 * 8 + 8);
            uVar2 = uVar1;
            EVar3 = 0;
          } while (uVar1 < *(uint *)(this + 0x88));
        }
        goto LAB_18001da23;
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 < uVar1);
  }
  EVar3 = 1;
LAB_18001da23:
  Platform::CriticalSection::Leave((CriticalSection *)(this + 0xb0));
  return EVar3;
}



uint * FUN_18001da50(longlong param_1,uint param_2)

{
  longlong lVar1;
  uint *puVar2;
  uint *puVar3;
  longlong lVar4;
  uint *puVar5;
  uint **ppuVar6;
  int iVar7;
  uint *puVar8;
  uint uVar9;
  uint *puVar10;
  uint *local_30;
  uint *puStack_28;
  
  if (param_2 == *(uint *)(param_1 + 0x10)) {
    puVar5 = (uint *)0x0;
  }
  else {
    puVar10 = (uint *)0x0;
    puStack_28 = (uint *)0x0;
    local_30 = (uint *)0x0;
    puVar8 = puVar10;
    puVar5 = puVar10;
    if (*(uint *)(param_1 + 0x10) != 0) {
      do {
        lVar1 = (longlong)puVar5 * 0x18;
        ppuVar6 = (uint **)(*(longlong *)(param_1 + 8) + lVar1);
        iVar7 = *(int *)(ppuVar6 + 2);
        while (iVar7 != 0) {
          puVar2 = *ppuVar6;
          if (puVar2 == ppuVar6[1]) {
            ppuVar6[1] = (uint *)0x0;
            *ppuVar6 = (uint *)0x0;
            *(undefined4 *)(ppuVar6 + 2) = 0;
            *(undefined8 *)(puVar2 + 2) = 0;
            *(undefined8 *)(puVar2 + 4) = 0;
          }
          else {
            puVar3 = *(uint **)(puVar2 + 2);
            *ppuVar6 = puVar3;
            *(undefined8 *)(puVar3 + 4) = 0;
            if (*(longlong *)(*ppuVar6 + 2) == 0) {
              ppuVar6[1] = *ppuVar6;
            }
            *(undefined8 *)(puVar2 + 2) = 0;
            *(undefined8 *)(puVar2 + 4) = 0;
            *(int *)(ppuVar6 + 2) = *(int *)(ppuVar6 + 2) + -1;
          }
          if (puStack_28 == (uint *)0x0) {
            *(undefined8 *)(puVar2 + 4) = 0;
            iVar7 = 0;
            local_30 = puVar2;
          }
          else {
            *(uint **)(puStack_28 + 2) = puVar2;
            *(uint **)(puVar2 + 4) = puStack_28;
            iVar7 = (int)puVar8;
          }
          puVar8 = (uint *)(ulonglong)(iVar7 + 1);
          *(undefined8 *)(puVar2 + 2) = 0;
          ppuVar6 = (uint **)(*(longlong *)(param_1 + 8) + lVar1);
          puStack_28 = puVar2;
          iVar7 = *(int *)(ppuVar6 + 2);
        }
        lVar4 = *(longlong *)(param_1 + 8);
        *(undefined8 *)(lVar1 + lVar4) = 0;
        *(undefined8 *)(lVar1 + 8 + lVar4) = 0;
        *(undefined4 *)(lVar1 + 0x10 + lVar4) = 0;
        uVar9 = (int)puVar5 + 1;
        puVar5 = (uint *)(ulonglong)uVar9;
      } while (uVar9 < *(uint *)(param_1 + 0x10));
    }
    FUN_18001d780((void **)(param_1 + 8));
    puVar5 = (uint *)FUN_18001cfb0((void **)(param_1 + 8),param_2,0,0);
    if ((int)puVar5 == 0) {
      iVar7 = (int)puVar8;
      while (puVar5 = puVar10, iVar7 != 0) {
        if (local_30 == puStack_28) {
          *(undefined8 *)(local_30 + 2) = 0;
          puStack_28 = puVar10;
          puVar8 = puVar10;
        }
        else {
          puVar5 = *(uint **)(local_30 + 2);
          *(undefined8 *)(puVar5 + 4) = 0;
          if (*(longlong *)(puVar5 + 2) == 0) {
            puStack_28 = puVar5;
          }
          *(uint **)(local_30 + 2) = (uint *)0x0;
          puVar8 = (uint *)(ulonglong)((int)puVar8 - 1);
        }
        *(undefined8 *)(local_30 + 4) = 0;
        ppuVar6 = (uint **)(*(longlong *)(param_1 + 8) +
                           ((ulonglong)*local_30 % (ulonglong)*(uint *)(param_1 + 0x10)) * 0x18);
        if (ppuVar6[1] == (uint *)0x0) {
          ppuVar6[1] = local_30;
          *ppuVar6 = local_30;
          *(undefined8 *)(local_30 + 2) = 0;
          *(undefined8 *)(local_30 + 4) = 0;
          *(undefined4 *)(ppuVar6 + 2) = 1;
        }
        else {
          *(uint **)(ppuVar6[1] + 2) = local_30;
          *(uint **)(local_30 + 4) = ppuVar6[1];
          *(undefined8 *)(local_30 + 2) = 0;
          ppuVar6[1] = local_30;
          *(int *)(ppuVar6 + 2) = *(int *)(ppuVar6 + 2) + 1;
        }
        local_30 = puVar5;
        iVar7 = (int)puVar8;
      }
    }
  }
  return puVar5;
}



// public: virtual void __cdecl Graphine::LogManager::UnMuteWarning(unsigned int) __ptr64

void __thiscall Graphine::LogManager::UnMuteWarning(LogManager *this,uint param_1)

{
  uint local_res10 [6];
  
                    // 0x1dc60  159  ?UnMuteWarning@LogManager@Graphine@@UEAAXI@Z
  local_res10[0] = param_1;
  FUN_18001d810((int *)(this + 0x90),local_res10);
  return;
}



// double __cdecl Graphine::Math::Log10(double)

double __cdecl Graphine::Math::Log10(double param_1)

{
  double dVar1;
  
                    // 0x1dc80  113  ?Log10@Math@Graphine@@YANN@Z
                    // WARNING: Could not recover jumptable at 0x00018002455c. Too many branches
                    // WARNING: Treating indirect jump as call
  dVar1 = log10(param_1);
  return dVar1;
}



// float __cdecl Graphine::Math::Log2(float)

float __cdecl Graphine::Math::Log2(float param_1)

{
  double dVar1;
  double dVar2;
  
                    // 0x1dc90  114  ?Log2@Math@Graphine@@YAMM@Z
  dVar1 = log((double)param_1);
  dVar2 = log(2.0);
  return (float)(dVar1 / dVar2);
}



// float __cdecl Graphine::Math::Pow2(float)

float __cdecl Graphine::Math::Pow2(float param_1)

{
  double dVar1;
  
                    // 0x1dcd0  126  ?Pow2@Math@Graphine@@YAMM@Z
  dVar1 = pow(2.0,(double)param_1);
  return (float)dVar1;
}



// float __cdecl Graphine::Math::Sqrt(float)

float __cdecl Graphine::Math::Sqrt(float param_1)

{
  double dVar1;
  
                    // 0x1dd00  142  ?Sqrt@Math@Graphine@@YAMM@Z
  dVar1 = sqrt((double)param_1);
  return (float)dVar1;
}



longlong FUN_18001dd20(longlong param_1)

{
  undefined8 *puVar1;
  longlong lVar2;
  
  lVar2 = 0x400;
  puVar1 = (undefined8 *)(param_1 + 0xb0);
  do {
    *(undefined4 *)(puVar1 + -6) = 2;
    puVar1[-5] = 0;
    puVar1[-4] = 0;
    puVar1[-2] = &DAT_180025ab4;
    puVar1[-1] = &DAT_180025ab4;
    *puVar1 = 0x3ff0000000000000;
    puVar1[1] = 1;
    *(undefined2 *)(puVar1 + -0x16) = 0;
    puVar1 = puVar1 + 0x18;
    lVar2 = lVar2 + -1;
  } while (lVar2 != 0);
  *(undefined4 *)(param_1 + 0x30000) = 0;
  return param_1;
}



// WARNING: Function: _alloca_probe replaced with injection: alloca_probe
// public: __cdecl Graphine::Performance::PerformanceMonitor::PerformanceMonitor(void) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::PerformanceMonitor(PerformanceMonitor *this)

{
  CriticalSection *this_00;
  DWORD DVar1;
  Enum EVar2;
  longlong lVar3;
  undefined2 *puVar4;
  __int64 _Var5;
  ILogManager *this_01;
  LogManager *this_02;
  longlong lVar6;
  wchar_t *pwVar7;
  undefined auStack_2090 [32];
  WCHAR *local_2070;
  char *local_2060;
  undefined4 local_2058;
  char *local_2050;
  wchar_t local_2048 [8];
  undefined8 local_2040;
  PerformanceMonitor *local_2038;
  CriticalSection *local_2030;
  WCHAR local_2020 [4095];
  undefined2 local_22;
  ulonglong local_20;
  undefined8 local_10;
  
                    // 0x1dd90  9  ??0PerformanceMonitor@Performance@Graphine@@QEAA@XZ
  local_10 = 0x18001dd9c;
  local_2040 = 0xfffffffffffffffe;
  local_20 = DAT_180032820 ^ (ulonglong)auStack_2090;
  *(undefined ***)this = vftable;
  *(undefined4 *)(this + 8) = 1;
  this_00 = (CriticalSection *)(this + 0xc);
  local_2038 = this;
  Platform::CriticalSection::CriticalSection(this_00);
  *(undefined8 *)(this + 0x38) = 0xffffffffff;
  *(undefined8 *)(this + 0x40) = 0;
  FUN_180022de0((undefined8 *)(this + 0x48));
  FUN_18001dd20((longlong)(this + 0x80c8));
  lVar6 = 0x100;
  lVar3 = 0x100;
  puVar4 = (undefined2 *)(this + 0x380d0);
  do {
    *puVar4 = 0;
    puVar4 = puVar4 + 0x40;
    lVar3 = lVar3 + -1;
  } while (lVar3 != 0);
  *(undefined4 *)(this + 0x400d0) = 0;
  puVar4 = (undefined2 *)(this + 0x400d4);
  do {
    *(undefined4 *)(puVar4 + 0x40) = 0;
    *puVar4 = 0;
    puVar4 = puVar4 + 0x42;
    lVar6 = lVar6 + -1;
  } while (lVar6 != 0);
  *(undefined4 *)(this + 0x484d4) = 0;
  *(undefined4 *)(this + 0x486d8) = 0;
  local_2030 = this_00;
  Platform::CriticalSection::Enter(this_00);
  _Var5 = Platform::GetTicksPerSecond();
  *(__int64 *)(this + 0x80b0) = _Var5;
  _Var5 = Platform::GetTimeTicks();
  *(__int64 *)(this + 0x80b8) = _Var5;
  *(undefined8 *)(this + 0x80c0) = 0x3ff0000000000000;
  *(PerformanceMonitor **)(this + 0x8088) = this + 0x88;
  *(undefined8 *)(this + 0x80a0) = 0x4000;
  *(PerformanceMonitor **)(this + 0x8090) = this + 0x4088;
  *(undefined8 *)(this + 0x8098) = 0;
  RegisterGroup(this,local_2048);
  Platform::MemoryClear(local_2020,0x2000);
  DVar1 = GetEnvironmentVariableW(L"GRAPHINE_DEBUGGER",local_2020,0x1000);
  if (DVar1 == 0) {
    local_2060 = "D:\\Git\\graphine\\graphine\\GraphineCore\\src\\PerformanceMonitor.cpp";
    local_2058 = 0x59;
    local_2050 = "Graphine::Performance::PerformanceMonitor::PerformanceMonitor";
    this_02 = (LogManager *)GetLogManager();
    pwVar7 = L"Performance env var not found ";
  }
  else {
    DVar1 = GetEnvironmentVariableW(L"GRAPHINE_DEBUG_LOG",local_2020,0x1000);
    if (DVar1 != 0) {
      local_22 = 0;
      EVar2 = StartLogging(this,(wchar_t *)local_2020);
      if (EVar2 != 0) {
        local_2060 = "D:\\Git\\graphine\\graphine\\GraphineCore\\src\\PerformanceMonitor.cpp";
        local_2058 = 0x4f;
        local_2050 = "Graphine::Performance::PerformanceMonitor::PerformanceMonitor";
        this_01 = GetLogManager();
        local_2070 = local_2020;
        LogManager::LogError
                  ((LogManager *)this_01,EVar2,(ContextInfo *)&local_2060,
                   (wchar_t *)L"Error writing to performance log \'%s\'");
      }
      goto LAB_18001e009;
    }
    local_2060 = "D:\\Git\\graphine\\graphine\\GraphineCore\\src\\PerformanceMonitor.cpp";
    local_2058 = 0x54;
    local_2050 = "Graphine::Performance::PerformanceMonitor::PerformanceMonitor";
    this_02 = (LogManager *)GetLogManager();
    pwVar7 = L"Log file env var not found ";
  }
  LogManager::LogError(this_02,2,(ContextInfo *)&local_2060,(wchar_t *)pwVar7);
LAB_18001e009:
  Platform::CriticalSection::Leave(this_00);
  __security_check_cookie(local_20 ^ (ulonglong)auStack_2090);
  return;
}



void FUN_18001e040(undefined8 *param_1)

{
  *param_1 = Graphine::IAsyncWriter<class_Graphine::AsyncWriter_Windows>::vftable;
  FUN_180022ea0((longlong)param_1);
  return;
}



void FUN_18001e070(undefined8 *param_1)

{
  *param_1 = Graphine::IAsyncWriter<class_Graphine::AsyncWriter_Windows>::vftable;
  FUN_180022ea0((longlong)param_1);
  return;
}



// public: virtual __cdecl Graphine::Performance::PerformanceMonitor::~PerformanceMonitor(void)
// __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::_PerformanceMonitor(PerformanceMonitor *this)

{
                    // 0x1e0a0  16  ??1PerformanceMonitor@Performance@Graphine@@UEAA@XZ
  *(undefined ***)this = vftable;
  Platform::CriticalSection::Enter((CriticalSection *)(this + 0xc));
  StopLogging(this);
  Platform::CriticalSection::Leave((CriticalSection *)(this + 0xc));
  *(undefined ***)(this + 0x48) = IAsyncWriter<class_Graphine::AsyncWriter_Windows>::vftable;
  FUN_180022ea0((longlong)(this + 0x48));
  Platform::CriticalSection::_CriticalSection((CriticalSection *)(this + 0xc));
  *(undefined ***)this = IPerformanceManager::vftable;
  return;
}



PerformanceMonitor * FUN_18001e120(PerformanceMonitor *param_1,uint param_2)

{
  if ((param_2 & 2) == 0) {
    Graphine::Performance::PerformanceMonitor::_PerformanceMonitor(param_1);
    if ((param_2 & 1) != 0) {
      free(param_1);
    }
  }
  else {
    _eh_vector_destructor_iterator_
              (param_1,0x486e0,*(__uint64 *)(param_1 + -8),
               Graphine::Performance::PerformanceMonitor::_PerformanceMonitor);
    if ((param_2 & 1) != 0) {
      free(param_1 + -8);
    }
    param_1 = param_1 + -8;
  }
  return param_1;
}



undefined8 * FUN_18001e1b0(undefined8 *param_1,uint param_2)

{
  *param_1 = Graphine::IAsyncWriter<class_Graphine::AsyncWriter_Windows>::vftable;
  FUN_180022ea0((longlong)param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



// public: unsigned __int64 __cdecl Graphine::Performance::PerformanceMonitor::BeginRange(class
// Graphine::Performance::StatisticId) __ptr64

__uint64 __thiscall
Graphine::Performance::PerformanceMonitor::BeginRange(PerformanceMonitor *this,StatisticId param_1)

{
  CriticalSection *this_00;
  __uint64 _Var1;
  __int64 _Var2;
  undefined7 in_register_00000011;
  undefined8 local_res8;
  uint local_res10;
  CriticalSection *local_res18;
  
                    // 0x1e200  42
                    // ?BeginRange@PerformanceMonitor@Performance@Graphine@@QEAA_KVStatisticId@23@@Z
  local_res10 = (uint)CONCAT71(in_register_00000011,param_1);
  this_00 = (CriticalSection *)(this + 0xc);
  local_res18 = this_00;
  Platform::CriticalSection::Enter(this_00);
  *(longlong *)(this + (ulonglong)local_res10 * 0xc0 + 0x8150) =
       *(longlong *)(this + (ulonglong)local_res10 * 0xc0 + 0x8150) + 1;
  if (*(longlong **)(this + 0x40) == (longlong *)0x0) {
    _Var1 = Platform::InterlockedInc64((__int64 *)(this + 0x38));
  }
  else {
    _Var1 = (**(code **)(**(longlong **)(this + 0x40) + 8))();
  }
  local_res8 = CONCAT44(local_res8._4_4_,local_res10 << 8) | 3;
  Write(this,&local_res8,4);
  local_res8 = _Var1;
  Write(this,&local_res8,8);
  _Var2 = Platform::GetTimeTicks();
  local_res8 = _Var2 - *(longlong *)(this + 0x80a8);
  Write(this,&local_res8,8);
  Platform::CriticalSection::Leave(this_00);
  return _Var1;
}



// public: void __cdecl Graphine::Performance::PerformanceMonitor::CounterAdd(class
// Graphine::Performance::StatisticId,int) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::CounterAdd
          (PerformanceMonitor *this,StatisticId param_1,int param_2)

{
  undefined7 in_register_00000011;
  uint local_res18 [4];
  
                    // 0x1e2e0  52
                    // ?CounterAdd@PerformanceMonitor@Performance@Graphine@@QEAAXVStatisticId@23@H@Z
  *(longlong *)(this + (CONCAT71(in_register_00000011,param_1) & 0xffffffff) * 0xc0 + 0x8150) =
       *(longlong *)(this + (CONCAT71(in_register_00000011,param_1) & 0xffffffff) * 0xc0 + 0x8150) +
       (longlong)param_2;
  Platform::CriticalSection::Enter((CriticalSection *)(this + 0xc));
  local_res18[0] = (int)CONCAT71(in_register_00000011,param_1) << 8 | 0xc;
  Write(this,local_res18,4);
  local_res18[0] = param_2;
  Write(this,local_res18,4);
  Platform::CriticalSection::Leave((CriticalSection *)(this + 0xc));
  return;
}



// public: void __cdecl Graphine::Performance::PerformanceMonitor::CounterDec(class
// Graphine::Performance::StatisticId) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::CounterDec(PerformanceMonitor *this,StatisticId param_1)

{
  CriticalSection *this_00;
  undefined7 in_register_00000011;
  uint local_res8 [2];
  int local_res10;
  CriticalSection *local_res18;
  
                    // 0x1e370  53
                    // ?CounterDec@PerformanceMonitor@Performance@Graphine@@QEAAXVStatisticId@23@@Z
  local_res10 = (int)CONCAT71(in_register_00000011,param_1);
  *(longlong *)(this + (CONCAT71(in_register_00000011,param_1) & 0xffffffff) * 0xc0 + 0x8150) =
       *(longlong *)(this + (CONCAT71(in_register_00000011,param_1) & 0xffffffff) * 0xc0 + 0x8150) +
       -1;
  this_00 = (CriticalSection *)(this + 0xc);
  local_res18 = this_00;
  Platform::CriticalSection::Enter(this_00);
  local_res8[0] = local_res10 << 8 | 0xb;
  Write(this,local_res8,4);
  Platform::CriticalSection::Leave(this_00);
  return;
}



// public: void __cdecl Graphine::Performance::PerformanceMonitor::CounterInc(class
// Graphine::Performance::StatisticId) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::CounterInc(PerformanceMonitor *this,StatisticId param_1)

{
  CriticalSection *this_00;
  undefined7 in_register_00000011;
  uint local_res8 [2];
  int local_res10;
  CriticalSection *local_res18;
  
                    // 0x1e3f0  54
                    // ?CounterInc@PerformanceMonitor@Performance@Graphine@@QEAAXVStatisticId@23@@Z
  local_res10 = (int)CONCAT71(in_register_00000011,param_1);
  *(longlong *)(this + (CONCAT71(in_register_00000011,param_1) & 0xffffffff) * 0xc0 + 0x8150) =
       *(longlong *)(this + (CONCAT71(in_register_00000011,param_1) & 0xffffffff) * 0xc0 + 0x8150) +
       1;
  this_00 = (CriticalSection *)(this + 0xc);
  local_res18 = this_00;
  Platform::CriticalSection::Enter(this_00);
  local_res8[0] = local_res10 << 8 | 10;
  Write(this,local_res8,4);
  Platform::CriticalSection::Leave(this_00);
  return;
}



// public: void __cdecl Graphine::Performance::PerformanceMonitor::CounterSub(class
// Graphine::Performance::StatisticId,int) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::CounterSub
          (PerformanceMonitor *this,StatisticId param_1,int param_2)

{
  undefined7 in_register_00000011;
  uint local_res18 [4];
  
                    // 0x1e470  56
                    // ?CounterSub@PerformanceMonitor@Performance@Graphine@@QEAAXVStatisticId@23@H@Z
  *(longlong *)(this + (CONCAT71(in_register_00000011,param_1) & 0xffffffff) * 0xc0 + 0x8150) =
       *(longlong *)(this + (CONCAT71(in_register_00000011,param_1) & 0xffffffff) * 0xc0 + 0x8150) -
       (longlong)param_2;
  Platform::CriticalSection::Enter((CriticalSection *)(this + 0xc));
  local_res18[0] = (int)CONCAT71(in_register_00000011,param_1) << 8 | 0xd;
  Write(this,local_res18,4);
  local_res18[0] = param_2;
  Write(this,local_res18,4);
  Platform::CriticalSection::Leave((CriticalSection *)(this + 0xc));
  return;
}



// public: void __cdecl Graphine::Performance::PerformanceMonitor::EndRange(unsigned __int64)
// __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::EndRange(PerformanceMonitor *this,__uint64 param_1)

{
  CriticalSection *this_00;
  longlong *plVar1;
  __int64 _Var2;
  undefined8 local_res8;
  CriticalSection *local_res10;
  
                    // 0x1e500  60  ?EndRange@PerformanceMonitor@Performance@Graphine@@QEAAX_K@Z
  this_00 = (CriticalSection *)(this + 0xc);
  local_res10 = this_00;
  Platform::CriticalSection::Enter(this_00);
  plVar1 = *(longlong **)(this + 0x40);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x10))(plVar1,param_1);
  }
  local_res8 = CONCAT44(local_res8._4_4_,4);
  Write(this,&local_res8,4);
  local_res8 = param_1;
  Write(this,&local_res8,8);
  _Var2 = Platform::GetTimeTicks();
  local_res8 = _Var2 - *(longlong *)(this + 0x80a8);
  Write(this,&local_res8,8);
  Platform::CriticalSection::Leave(this_00);
  return;
}



// public: virtual bool __cdecl Graphine::Performance::PerformanceMonitor::FindStatistic(wchar_t
// const * __ptr64,wchar_t const * __ptr64,unsigned int & __ptr64) __ptr64

bool __thiscall
Graphine::Performance::PerformanceMonitor::FindStatistic
          (PerformanceMonitor *this,wchar_t *param_1,wchar_t *param_2,uint *param_3)

{
  int iVar1;
  uint uVar2;
  ulonglong uVar3;
  
                    // 0x1e5c0  64
                    // ?FindStatistic@PerformanceMonitor@Performance@Graphine@@UEAA_NPEB_W0AEAI@Z
  if ((param_2 == (wchar_t *)0x0) || (param_1 == (wchar_t *)0x0)) {
    return false;
  }
  uVar3 = 0;
  if (*(int *)(this + 0x380c8) != 0) {
    do {
      uVar2 = *(uint *)(this + uVar3 * 0xc0 + 0x8184);
      iVar1 = String::StringCompare((wchar_t *)(this + uVar3 * 0xc0 + 0x80c8),param_2);
      if ((iVar1 == 0) &&
         (iVar1 = String::StringCompare
                            ((wchar_t *)(this + (ulonglong)uVar2 * 0x80 + 0x380d0),param_1),
         iVar1 == 0)) {
        *param_3 = (uint)uVar3;
        return true;
      }
      uVar2 = (uint)uVar3 + 1;
      uVar3 = (ulonglong)uVar2;
    } while (uVar2 < *(uint *)(this + 0x380c8));
  }
  return false;
}



// public: virtual bool __cdecl Graphine::Performance::PerformanceMonitor::FindStatistic(wchar_t
// const * __ptr64,unsigned int & __ptr64) __ptr64

bool __thiscall
Graphine::Performance::PerformanceMonitor::FindStatistic
          (PerformanceMonitor *this,wchar_t *param_1,uint *param_2)

{
  int iVar1;
  uint uVar2;
  ulonglong uVar3;
  
                    // 0x1e680  65
                    // ?FindStatistic@PerformanceMonitor@Performance@Graphine@@UEAA_NPEB_WAEAI@Z
  if (param_1 == (wchar_t *)0x0) {
    return false;
  }
  uVar3 = 0;
  if (*(int *)(this + 0x380c8) != 0) {
    do {
      iVar1 = String::StringCompare((wchar_t *)(this + uVar3 * 0xc0 + 0x80c8),param_1);
      if (iVar1 == 0) {
        *param_2 = (uint)uVar3;
        return true;
      }
      uVar2 = (uint)uVar3 + 1;
      uVar3 = (ulonglong)uVar2;
    } while (uVar2 < *(uint *)(this + 0x380c8));
  }
  return false;
}



// protected: void __cdecl Graphine::Performance::PerformanceMonitor::Flush(void) __ptr64

void __thiscall Graphine::Performance::PerformanceMonitor::Flush(PerformanceMonitor *this)

{
  LPCVOID pvVar1;
  
                    // 0x1e710  66  ?Flush@PerformanceMonitor@Performance@Graphine@@IEAAXXZ
  pvVar1 = *(LPCVOID *)(this + 0x8088);
  *(undefined8 *)(this + 0x8088) = *(undefined8 *)(this + 0x8090);
  *(LPCVOID *)(this + 0x8090) = pvVar1;
  FUN_180023020((longlong)(this + 0x48),pvVar1,*(longlong *)(this + 0x8098));
  *(undefined8 *)(this + 0x8098) = 0;
  return;
}



// public: virtual unsigned int __cdecl
// Graphine::Performance::PerformanceMonitor::GetNumStatistics(void) __ptr64

uint __thiscall
Graphine::Performance::PerformanceMonitor::GetNumStatistics(PerformanceMonitor *this)

{
                    // 0x1e760  81
                    // ?GetNumStatistics@PerformanceMonitor@Performance@Graphine@@UEAAIXZ
  return *(uint *)(this + 0x380c8);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// class Graphine::Performance::IPerformanceManager * __ptr64 __cdecl
// Graphine::Performance::GetPerformanceManager(void)

IPerformanceManager * __cdecl Graphine::Performance::GetPerformanceManager(void)

{
                    // 0x1e770  82
                    // ?GetPerformanceManager@Performance@Graphine@@YAPEAVIPerformanceManager@12@XZ
  if ((*(int *)(*(longlong *)((longlong)ThreadLocalStoragePointer + (ulonglong)_tls_index * 8) +
               0x420) < _DAT_18007b190) &&
     (_Init_thread_header((int *)&DAT_18007b190), _DAT_18007b190 == -1)) {
    PerformanceMonitor::PerformanceMonitor((PerformanceMonitor *)&DAT_180032ab0);
    atexit(FUN_1800248f0);
    _Init_thread_footer((int *)&DAT_18007b190);
  }
  return (IPerformanceManager *)&DAT_180032ab0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// class Graphine::Performance::PerformanceMonitor * __ptr64 __cdecl
// Graphine::Performance::GetPerformanceMonitor(void)

PerformanceMonitor * __cdecl Graphine::Performance::GetPerformanceMonitor(void)

{
                    // 0x1e780  83
                    // ?GetPerformanceMonitor@Performance@Graphine@@YAPEAVPerformanceMonitor@12@XZ
  if ((*(int *)(*(longlong *)((longlong)ThreadLocalStoragePointer + (ulonglong)_tls_index * 8) +
               0x420) < _DAT_18007b190) &&
     (_Init_thread_header((int *)&DAT_18007b190), _DAT_18007b190 == -1)) {
    PerformanceMonitor::PerformanceMonitor((PerformanceMonitor *)&DAT_180032ab0);
    atexit(FUN_1800248f0);
    _Init_thread_footer((int *)&DAT_18007b190);
  }
  return (PerformanceMonitor *)&DAT_180032ab0;
}



// public: virtual wchar_t const * __ptr64 __cdecl
// Graphine::Performance::PerformanceMonitor::GetStatisticDescription(unsigned int) __ptr64

wchar_t * __thiscall
Graphine::Performance::PerformanceMonitor::GetStatisticDescription
          (PerformanceMonitor *this,uint param_1)

{
                    // 0x1e810  85
                    // ?GetStatisticDescription@PerformanceMonitor@Performance@Graphine@@UEAAPEB_WI@Z
  if (*(uint *)(this + 0x380c8) <= param_1) {
    return (wchar_t *)0x0;
  }
  return *(wchar_t **)(this + (ulonglong)param_1 * 0xc0 + 0x8168);
}



// public: virtual wchar_t const * __ptr64 __cdecl
// Graphine::Performance::PerformanceMonitor::GetStatisticName(unsigned int) __ptr64

wchar_t * __thiscall
Graphine::Performance::PerformanceMonitor::GetStatisticName(PerformanceMonitor *this,uint param_1)

{
                    // 0x1e830  86
                    // ?GetStatisticName@PerformanceMonitor@Performance@Graphine@@UEAAPEB_WI@Z
  if (*(uint *)(this + 0x380c8) <= param_1) {
    return (wchar_t *)0x0;
  }
  return (wchar_t *)(this + (ulonglong)param_1 * 0xc0 + 0x80c8);
}



// public: virtual wchar_t const * __ptr64 __cdecl
// Graphine::Performance::PerformanceMonitor::GetStatisticUnit(unsigned int,enum
// Graphine::Performance::StatisticValueMethod::Enum) __ptr64

wchar_t * __thiscall
Graphine::Performance::PerformanceMonitor::GetStatisticUnit
          (PerformanceMonitor *this,uint param_1,Enum param_2)

{
  wchar_t *pwVar1;
  
                    // 0x1e860  87
                    // ?GetStatisticUnit@PerformanceMonitor@Performance@Graphine@@UEAAPEB_WIW4Enum@StatisticValueMethod@23@@Z
  if (*(uint *)(this + 0x380c8) <= param_1) {
    return (wchar_t *)0x0;
  }
  if (param_2 == 0) {
    param_2 = *(Enum *)(this + (ulonglong)param_1 * 0xc0 + 0x8180);
  }
  if (param_2 == 2) {
    pwVar1 = L"/frame";
  }
  else {
    if (param_2 != 3) {
      return *(wchar_t **)(this + (ulonglong)param_1 * 0xc0 + 0x8170);
    }
    pwVar1 = L"/s";
  }
  String::FormatStringTrunc
            ((wchar_t *)(this + 0x484d8),0x100,(wchar_t *)L"%s%s",
             *(undefined8 *)(this + (ulonglong)param_1 * 0xc0 + 0x8170),pwVar1);
  return (wchar_t *)(this + 0x484d8);
}



// public: virtual double __cdecl
// Graphine::Performance::PerformanceMonitor::GetStatisticValue(unsigned int,enum
// Graphine::Performance::StatisticValueMethod::Enum) __ptr64

double __thiscall
Graphine::Performance::PerformanceMonitor::GetStatisticValue
          (PerformanceMonitor *this,uint param_1,Enum param_2)

{
  double dVar1;
  longlong lVar2;
  double dVar3;
  
                    // 0x1e910  88
                    // ?GetStatisticValue@PerformanceMonitor@Performance@Graphine@@UEAANIW4Enum@StatisticValueMethod@23@@Z
  if (*(uint *)(this + 0x380c8) <= param_1) {
    return 0.0;
  }
  lVar2 = (ulonglong)param_1 * 0xc0;
  dVar1 = *(double *)(this + lVar2 + 0x8178);
  if (param_2 == 0) {
    param_2 = *(Enum *)(this + lVar2 + 0x8180);
  }
  dVar3 = 0.0;
  if (param_2 == 1) {
    dVar3 = (double)*(longlong *)(this + lVar2 + 0x8150) * dVar1;
  }
  else {
    if (param_2 == 2) {
      return (double)*(longlong *)(this + lVar2 + 0x8160) * dVar1;
    }
    if (param_2 == 3) {
      return (double)*(longlong *)(this + lVar2 + 0x8160) * dVar1 * *(double *)(this + 0x80c0);
    }
  }
  return dVar3;
}



// public: virtual bool __cdecl Graphine::Performance::PerformanceMonitor::IsCapturing(void) __ptr64

bool __thiscall Graphine::Performance::PerformanceMonitor::IsCapturing(PerformanceMonitor *this)

{
  bool bVar1;
  
                    // 0x1e990  106  ?IsCapturing@PerformanceMonitor@Performance@Graphine@@UEAA_NXZ
  bVar1 = FUN_180022f00((longlong)(this + 0x48));
  return bVar1;
}



// WARNING: Could not reconcile some variable overlaps
// public: void __cdecl Graphine::Performance::PerformanceMonitor::PopRange(void) __ptr64

void __thiscall Graphine::Performance::PerformanceMonitor::PopRange(PerformanceMonitor *this)

{
  CriticalSection *this_00;
  longlong lVar1;
  __int64 _Var2;
  longlong lVar3;
  __int64 _Var4;
  __uint64 _Var5;
  int iVar6;
  uint uVar7;
  int *piVar8;
  undefined8 local_res8;
  CriticalSection *local_res10;
  
                    // 0x1e9a0  125  ?PopRange@PerformanceMonitor@Performance@Graphine@@QEAAXXZ
  this_00 = (CriticalSection *)(this + 0xc);
  local_res10 = this_00;
  Platform::CriticalSection::Enter(this_00);
  if (*(longlong **)(this + 0x40) != (longlong *)0x0) {
    (**(code **)(**(longlong **)(this + 0x40) + 0x20))();
  }
  _Var2 = Platform::GetTimeTicks();
  uVar7 = 0;
  lVar3 = *(longlong *)((longlong)ThreadLocalStoragePointer + (ulonglong)_tls_index * 8);
  piVar8 = (int *)(lVar3 + 0x10);
  iVar6 = *piVar8;
  if (0 < iVar6) {
    iVar6 = iVar6 + -1;
    lVar3 = lVar3 + (longlong)iVar6 * 0x10;
    lVar1 = *(longlong *)(lVar3 + 0x20);
    uVar7 = *(uint *)(lVar3 + 0x28);
    *piVar8 = iVar6;
    _Var4 = Platform::GetTimeTicks();
    *(longlong *)(this + (ulonglong)uVar7 * 0xc0 + 0x8150) =
         *(longlong *)(this + (ulonglong)uVar7 * 0xc0 + 0x8150) + (_Var4 - lVar1);
  }
  local_res8._0_4_ = uVar7 << 8 | 6;
  Write(this,&local_res8,4);
  _Var5 = Platform::GetThreadId();
  local_res8 = _Var5 & 0xffffffff | (ulonglong)local_res8._4_4_ << 0x20;
  Write(this,&local_res8,4);
  local_res8 = _Var2 - *(longlong *)(this + 0x80a8);
  Write(this,&local_res8,8);
  Platform::CriticalSection::Leave(this_00);
  return;
}



// WARNING: Could not reconcile some variable overlaps
// public: void __cdecl Graphine::Performance::PerformanceMonitor::PushRange(class
// Graphine::Performance::StatisticId) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::PushRange(PerformanceMonitor *this,StatisticId param_1)

{
  CriticalSection *this_00;
  int iVar1;
  longlong *plVar2;
  longlong lVar3;
  __int64 _Var4;
  __uint64 _Var5;
  longlong lVar6;
  undefined7 in_register_00000011;
  undefined8 local_res8;
  uint local_res10;
  CriticalSection *local_res18;
  undefined4 local_30;
  undefined4 uStack_2c;
  undefined4 uStack_24;
  
                    // 0x1eac0  127
                    // ?PushRange@PerformanceMonitor@Performance@Graphine@@QEAAXVStatisticId@23@@Z
  local_res10 = (uint)CONCAT71(in_register_00000011,param_1);
  this_00 = (CriticalSection *)(this + 0xc);
  local_res18 = this_00;
  Platform::CriticalSection::Enter(this_00);
  plVar2 = *(longlong **)(this + 0x40);
  if (plVar2 != (longlong *)0x0) {
    (**(code **)(*plVar2 + 0x18))(plVar2,this + (ulonglong)local_res10 * 0xc0 + 0x80c8);
  }
  _Var4 = Platform::GetTimeTicks();
  local_res8._0_4_ = local_res10 << 8 | 5;
  Write(this,&local_res8,4);
  _Var5 = Platform::GetThreadId();
  local_res8 = _Var5 & 0xffffffff | (ulonglong)local_res8._4_4_ << 0x20;
  Write(this,&local_res8,4);
  local_res8 = _Var4 - *(longlong *)(this + 0x80a8);
  Write(this,&local_res8,8);
  lVar3 = *(longlong *)((longlong)ThreadLocalStoragePointer + (ulonglong)_tls_index * 8);
  iVar1 = *(int *)(lVar3 + 0x10);
  if (iVar1 < 0x40) {
    lVar6 = (longlong)iVar1 * 0x10 + lVar3;
    local_30 = (undefined4)_Var4;
    uStack_2c = (undefined4)((ulonglong)_Var4 >> 0x20);
    *(undefined4 *)(lVar6 + 0x20) = local_30;
    *(undefined4 *)(lVar6 + 0x24) = uStack_2c;
    *(uint *)(lVar6 + 0x28) = local_res10;
    *(undefined4 *)(lVar6 + 0x2c) = uStack_24;
    *(int *)(lVar3 + 0x10) = iVar1 + 1;
  }
  Platform::CriticalSection::Leave(this_00);
  return;
}



// public: void __cdecl Graphine::Performance::PerformanceMonitor::RegisterCurrentThread(wchar_t
// const * __ptr64) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::RegisterCurrentThread
          (PerformanceMonitor *this,wchar_t *param_1)

{
  CriticalSection *this_00;
  undefined4 *puVar1;
  __uint64 _Var2;
  uint *puVar3;
  longlong lVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  undefined auStack_118 [32];
  ushort local_f8 [4];
  uint local_f0 [2];
  uint local_e8 [2];
  undefined8 local_e0;
  CriticalSection *local_d8;
  undefined4 local_c8;
  undefined4 uStack_c4;
  undefined4 uStack_c0;
  undefined4 uStack_bc;
  undefined4 local_b8;
  undefined4 uStack_b4;
  undefined4 uStack_b0;
  undefined4 uStack_ac;
  undefined4 local_a8;
  undefined4 uStack_a4;
  undefined4 uStack_a0;
  undefined4 uStack_9c;
  undefined4 local_98;
  undefined4 uStack_94;
  undefined4 uStack_90;
  undefined4 uStack_8c;
  undefined4 local_88;
  undefined4 uStack_84;
  undefined4 uStack_80;
  undefined4 uStack_7c;
  undefined4 local_78;
  undefined4 uStack_74;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  undefined4 local_68;
  undefined4 uStack_64;
  undefined4 uStack_60;
  undefined4 uStack_5c;
  undefined4 local_58;
  undefined4 uStack_54;
  undefined4 uStack_50;
  undefined4 uStack_4c;
  int local_48;
  ulonglong local_38;
  
                    // 0x1ebe0  130
                    // ?RegisterCurrentThread@PerformanceMonitor@Performance@Graphine@@QEAAXPEB_W@Z
  local_e0 = 0xfffffffffffffffe;
  local_38 = DAT_180032820 ^ (ulonglong)auStack_118;
  this_00 = (CriticalSection *)(this + 0xc);
  local_d8 = this_00;
  Platform::CriticalSection::Enter(this_00);
  _Var2 = Platform::GetThreadId();
  uVar5 = 0;
  uVar6 = 0;
  iVar7 = (int)_Var2;
  if (*(int *)(this + 0x484d4) != 0) {
    do {
      if (*(int *)(this + (ulonglong)uVar6 * 0x84 + 0x40154) == iVar7) goto LAB_18001ed9d;
      uVar6 = uVar6 + 1;
    } while (uVar6 < *(uint *)(this + 0x484d4));
  }
  local_48 = iVar7;
  String::CopyStringTruncate((wchar_t *)&local_c8,0x40,param_1);
  if (*(uint *)(this + 0x484d4) != 0x100) {
    lVar4 = (ulonglong)*(uint *)(this + 0x484d4) * 0x84;
    puVar1 = (undefined4 *)(this + lVar4 + 0x400d4);
    *puVar1 = local_c8;
    puVar1[1] = uStack_c4;
    puVar1[2] = uStack_c0;
    puVar1[3] = uStack_bc;
    puVar1 = (undefined4 *)(this + lVar4 + 0x400e4);
    *puVar1 = local_b8;
    puVar1[1] = uStack_b4;
    puVar1[2] = uStack_b0;
    puVar1[3] = uStack_ac;
    puVar1 = (undefined4 *)(this + lVar4 + 0x400f4);
    *puVar1 = local_a8;
    puVar1[1] = uStack_a4;
    puVar1[2] = uStack_a0;
    puVar1[3] = uStack_9c;
    puVar1 = (undefined4 *)(this + lVar4 + 0x40104);
    *puVar1 = local_98;
    puVar1[1] = uStack_94;
    puVar1[2] = uStack_90;
    puVar1[3] = uStack_8c;
    puVar1 = (undefined4 *)(this + lVar4 + 0x40114);
    *puVar1 = local_88;
    puVar1[1] = uStack_84;
    puVar1[2] = uStack_80;
    puVar1[3] = uStack_7c;
    puVar1 = (undefined4 *)(this + lVar4 + 0x40124);
    *puVar1 = local_78;
    puVar1[1] = uStack_74;
    puVar1[2] = uStack_70;
    puVar1[3] = uStack_6c;
    puVar1 = (undefined4 *)(this + lVar4 + 0x40134);
    *puVar1 = local_68;
    puVar1[1] = uStack_64;
    puVar1[2] = uStack_60;
    puVar1[3] = uStack_5c;
    puVar1 = (undefined4 *)(this + lVar4 + 0x40144);
    *puVar1 = local_58;
    puVar1[1] = uStack_54;
    puVar1[2] = uStack_50;
    puVar1[3] = uStack_4c;
    *(int *)(this + lVar4 + 0x40154) = local_48;
    *(int *)(this + 0x484d4) = *(int *)(this + 0x484d4) + 1;
  }
  local_f0[0] = iVar7 << 8 | 7;
  Write(this,local_f0,4);
  if (param_1 == (wchar_t *)0x0) {
    local_f0[0] = local_f0[0] & 0xffff0000;
    _Var2 = 2;
    param_1 = (wchar_t *)local_f0;
  }
  else {
    local_f0[0] = 0;
    if (*(short *)param_1 != 0) {
      do {
        uVar5 = uVar5 + 1;
      } while (*(short *)(param_1 + (longlong)(int)uVar5 * 2) != 0);
      local_f0[0] = uVar5;
    }
    local_e8[0] = 0xffff;
    puVar3 = local_f0;
    if (0xfffe < (int)local_f0[0]) {
      puVar3 = local_e8;
    }
    local_f8[0] = *(ushort *)puVar3;
    Write(this,local_f8,2);
    _Var2 = (ulonglong)local_f8[0] * 2;
  }
  Write(this,param_1,_Var2);
LAB_18001ed9d:
  Platform::CriticalSection::Leave(this_00);
  __security_check_cookie(local_38 ^ (ulonglong)auStack_118);
  return;
}



// public: class Graphine::Performance::StatisticGroupId __cdecl
// Graphine::Performance::PerformanceMonitor::RegisterGroup(wchar_t const * __ptr64) __ptr64

StatisticGroupId __thiscall
Graphine::Performance::PerformanceMonitor::RegisterGroup(PerformanceMonitor *this,wchar_t *param_1)

{
  CriticalSection *this_00;
  undefined4 *puVar1;
  StatisticGroupId extraout_AL;
  int iVar2;
  longlong lVar3;
  uint *puVar4;
  uint uVar5;
  uint *puVar6;
  uint uVar7;
  wchar_t *in_R8;
  __uint64 _Var8;
  undefined auStack_118 [32];
  ushort local_f8 [4];
  uint local_f0 [2];
  uint local_e8 [2];
  undefined8 local_e0;
  CriticalSection *local_d8;
  undefined4 local_c8;
  undefined4 uStack_c4;
  undefined4 uStack_c0;
  undefined4 uStack_bc;
  undefined4 local_b8;
  undefined4 uStack_b4;
  undefined4 uStack_b0;
  undefined4 uStack_ac;
  undefined4 local_a8;
  undefined4 uStack_a4;
  undefined4 uStack_a0;
  undefined4 uStack_9c;
  undefined4 local_98;
  undefined4 uStack_94;
  undefined4 uStack_90;
  undefined4 uStack_8c;
  undefined4 local_88;
  undefined4 uStack_84;
  undefined4 uStack_80;
  undefined4 uStack_7c;
  undefined4 local_78;
  undefined4 uStack_74;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  undefined4 local_68;
  undefined4 uStack_64;
  undefined4 uStack_60;
  undefined4 uStack_5c;
  undefined4 local_58;
  undefined4 uStack_54;
  undefined4 uStack_50;
  undefined4 uStack_4c;
  ulonglong local_48;
  
                    // 0x1edd0  131
                    // ?RegisterGroup@PerformanceMonitor@Performance@Graphine@@QEAA?AVStatisticGroupId@23@PEB_W@Z
  local_e0 = 0xfffffffffffffffe;
  local_48 = DAT_180032820 ^ (ulonglong)auStack_118;
  this_00 = (CriticalSection *)(this + 0xc);
  local_d8 = this_00;
  Platform::CriticalSection::Enter(this_00);
  uVar7 = 0;
  uVar5 = 0;
  if (*(int *)(this + 0x400d0) != 0) {
    do {
      iVar2 = String::StringCompare(in_R8,(wchar_t *)(this + (ulonglong)uVar5 * 0x80 + 0x380d0));
      if (iVar2 == 0) {
        *(uint *)param_1 = uVar5;
        Platform::CriticalSection::Leave(this_00);
        goto LAB_18001efca;
      }
      uVar5 = uVar5 + 1;
    } while (uVar5 < *(uint *)(this + 0x400d0));
  }
  uVar5 = *(uint *)(this + 0x400d0);
  String::CopyStringTruncate((wchar_t *)&local_c8,0x40,in_R8);
  if (*(uint *)(this + 0x400d0) != 0x100) {
    lVar3 = (ulonglong)*(uint *)(this + 0x400d0) * 0x80;
    puVar1 = (undefined4 *)(this + lVar3 + 0x380d0);
    *puVar1 = local_c8;
    puVar1[1] = uStack_c4;
    puVar1[2] = uStack_c0;
    puVar1[3] = uStack_bc;
    puVar1 = (undefined4 *)(this + lVar3 + 0x380e0);
    *puVar1 = local_b8;
    puVar1[1] = uStack_b4;
    puVar1[2] = uStack_b0;
    puVar1[3] = uStack_ac;
    puVar1 = (undefined4 *)(this + lVar3 + 0x380f0);
    *puVar1 = local_a8;
    puVar1[1] = uStack_a4;
    puVar1[2] = uStack_a0;
    puVar1[3] = uStack_9c;
    puVar1 = (undefined4 *)(this + lVar3 + 0x38100);
    *puVar1 = local_98;
    puVar1[1] = uStack_94;
    puVar1[2] = uStack_90;
    puVar1[3] = uStack_8c;
    puVar1 = (undefined4 *)(this + lVar3 + 0x38110);
    *puVar1 = local_88;
    puVar1[1] = uStack_84;
    puVar1[2] = uStack_80;
    puVar1[3] = uStack_7c;
    puVar1 = (undefined4 *)(this + lVar3 + 0x38120);
    *puVar1 = local_78;
    puVar1[1] = uStack_74;
    puVar1[2] = uStack_70;
    puVar1[3] = uStack_6c;
    puVar1 = (undefined4 *)(this + lVar3 + 0x38130);
    *puVar1 = local_68;
    puVar1[1] = uStack_64;
    puVar1[2] = uStack_60;
    puVar1[3] = uStack_5c;
    puVar1 = (undefined4 *)(this + lVar3 + 0x38140);
    *puVar1 = local_58;
    puVar1[1] = uStack_54;
    puVar1[2] = uStack_50;
    puVar1[3] = uStack_4c;
    *(int *)(this + 0x400d0) = *(int *)(this + 0x400d0) + 1;
  }
  puVar6 = (uint *)(this + (ulonglong)uVar5 * 0x80 + 0x380d0);
  local_f0[0] = uVar5 << 8 | 9;
  Write(this,local_f0,4);
  if (puVar6 == (uint *)0x0) {
    local_f0[0] = local_f0[0] & 0xffff0000;
    _Var8 = 2;
    puVar6 = local_f0;
  }
  else {
    local_f0[0] = 0;
    if (*(short *)puVar6 != 0) {
      do {
        uVar7 = uVar7 + 1;
      } while (*(short *)((longlong)puVar6 + (longlong)(int)uVar7 * 2) != 0);
      local_f0[0] = uVar7;
    }
    local_e8[0] = 0xffff;
    puVar4 = local_f0;
    if (0xfffe < (int)local_f0[0]) {
      puVar4 = local_e8;
    }
    local_f8[0] = *(ushort *)puVar4;
    Write(this,local_f8,2);
    _Var8 = (ulonglong)local_f8[0] * 2;
  }
  Write(this,puVar6,_Var8);
  *(uint *)param_1 = uVar5;
  Platform::CriticalSection::Leave(this_00);
LAB_18001efca:
  __security_check_cookie(local_48 ^ (ulonglong)auStack_118);
  return extraout_AL;
}



// public: virtual enum Graphine::Error::Enum __cdecl
// Graphine::Performance::PerformanceMonitor::RegisterMonitor(class Graphine::Performance::IMonitor
// * __ptr64) __ptr64

Enum __thiscall
Graphine::Performance::PerformanceMonitor::RegisterMonitor
          (PerformanceMonitor *this,IMonitor *param_1)

{
                    // 0x1eff0  132
                    // ?RegisterMonitor@PerformanceMonitor@Performance@Graphine@@UEAA?AW4Enum@Error@3@PEAVIMonitor@23@@Z
  *(IMonitor **)(this + 0x40) = param_1;
  return 0;
}



// public: class Graphine::Performance::StatisticId __cdecl
// Graphine::Performance::PerformanceMonitor::RegisterStatistic(wchar_t const * __ptr64,enum
// Graphine::Performance::StatisticType::Enum,struct Graphine::Performance::StatisticOptions const &
// __ptr64) __ptr64

StatisticId __thiscall
Graphine::Performance::PerformanceMonitor::RegisterStatistic
          (PerformanceMonitor *this,wchar_t *param_1,Enum param_2,StatisticOptions *param_3)

{
  CriticalSection *this_00;
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  StatisticId extraout_AL;
  int iVar9;
  uint *puVar10;
  ulonglong uVar11;
  uint uVar12;
  undefined4 in_register_00000084;
  undefined8 *in_stack_00000028;
  undefined auStack_158 [32];
  undefined8 local_138;
  CriticalSection *local_130;
  uint local_128;
  uint uStack_124;
  uint uStack_120;
  uint uStack_11c;
  uint local_118;
  uint uStack_114;
  uint uStack_110;
  uint uStack_10c;
  uint local_108;
  uint uStack_104;
  uint uStack_100;
  uint uStack_fc;
  uint local_f8;
  uint uStack_f4;
  uint uStack_f0;
  uint uStack_ec;
  uint local_e8;
  uint uStack_e4;
  uint uStack_e0;
  uint uStack_dc;
  uint local_d8;
  uint uStack_d4;
  uint uStack_d0;
  uint uStack_cc;
  uint local_c8;
  uint uStack_c4;
  uint uStack_c0;
  uint uStack_bc;
  uint local_b8;
  uint uStack_b4;
  uint uStack_b0;
  uint uStack_ac;
  uint local_a8;
  uint uStack_a4;
  undefined8 uStack_a0;
  undefined8 local_98;
  uint uStack_90;
  uint uStack_8c;
  undefined *local_88;
  undefined *puStack_80;
  undefined8 local_78;
  undefined8 uStack_70;
  ulonglong local_58;
  
                    // 0x1f000  133
                    // ?RegisterStatistic@PerformanceMonitor@Performance@Graphine@@QEAA?AVStatisticId@23@PEB_WW4Enum@StatisticType@23@AEBUStatisticOptions@23@@Z
  local_138 = 0xfffffffffffffffe;
  local_58 = DAT_180032820 ^ (ulonglong)auStack_158;
  this_00 = (CriticalSection *)(this + 0xc);
  local_130 = this_00;
  Platform::CriticalSection::Enter(this_00);
  uVar11 = 0;
  if (*(int *)(this + 0x380c8) != 0) {
    do {
      iVar9 = String::StringCompare
                        ((wchar_t *)CONCAT44(in_register_00000084,param_2),
                         (wchar_t *)(this + uVar11 * 0xc0 + 0x80c8));
      if ((iVar9 == 0) &&
         (*(int *)(this + uVar11 * 0xc0 + 0x8184) == *(int *)((longlong)in_stack_00000028 + 0x1c)))
      {
        *(int *)param_1 = (int)uVar11;
        Platform::CriticalSection::Leave(this_00);
        goto LAB_18001f206;
      }
      uVar12 = (int)uVar11 + 1;
      uVar11 = (ulonglong)uVar12;
    } while (uVar12 < *(uint *)(this + 0x380c8));
  }
  local_a8 = 2;
  uStack_a0 = 0;
  local_98 = 0;
  local_88 = &DAT_180025ab4;
  puStack_80 = &DAT_180025ab4;
  local_78 = 0x3ff0000000000000;
  uStack_70 = 1;
  local_128 = local_128 & 0xffff0000;
  String::CopyStringTruncate
            ((wchar_t *)&local_128,0x40,(wchar_t *)CONCAT44(in_register_00000084,param_2));
  local_98 = 0;
  uStack_a0 = 0;
  uVar1 = *(uint *)in_stack_00000028;
  uVar2 = *(uint *)((longlong)in_stack_00000028 + 4);
  local_88 = (undefined *)*in_stack_00000028;
  uVar3 = *(uint *)(in_stack_00000028 + 1);
  uVar4 = *(uint *)((longlong)in_stack_00000028 + 0xc);
  puStack_80 = (undefined *)in_stack_00000028[1];
  uVar5 = *(uint *)(in_stack_00000028 + 2);
  uVar6 = *(uint *)((longlong)in_stack_00000028 + 0x14);
  local_78 = in_stack_00000028[2];
  uVar7 = *(uint *)(in_stack_00000028 + 3);
  uVar8 = *(uint *)((longlong)in_stack_00000028 + 0x1c);
  uStack_70 = in_stack_00000028[3];
  uVar12 = *(uint *)(this + 0x380c8);
  if (uVar12 != 0x400) {
    puVar10 = (uint *)(this + (ulonglong)uVar12 * 0xc0 + 0x80c8);
    *puVar10 = local_128;
    puVar10[1] = uStack_124;
    puVar10[2] = uStack_120;
    puVar10[3] = uStack_11c;
    puVar10[4] = local_118;
    puVar10[5] = uStack_114;
    puVar10[6] = uStack_110;
    puVar10[7] = uStack_10c;
    puVar10[8] = local_108;
    puVar10[9] = uStack_104;
    puVar10[10] = uStack_100;
    puVar10[0xb] = uStack_fc;
    puVar10[0xc] = local_f8;
    puVar10[0xd] = uStack_f4;
    puVar10[0xe] = uStack_f0;
    puVar10[0xf] = uStack_ec;
    puVar10[0x10] = local_e8;
    puVar10[0x11] = uStack_e4;
    puVar10[0x12] = uStack_e0;
    puVar10[0x13] = uStack_dc;
    puVar10[0x14] = local_d8;
    puVar10[0x15] = uStack_d4;
    puVar10[0x16] = uStack_d0;
    puVar10[0x17] = uStack_cc;
    puVar10[0x18] = local_c8;
    puVar10[0x19] = uStack_c4;
    puVar10[0x1a] = uStack_c0;
    puVar10[0x1b] = uStack_bc;
    puVar10[0x1c] = local_b8;
    puVar10[0x1d] = uStack_b4;
    puVar10[0x1e] = uStack_b0;
    puVar10[0x1f] = uStack_ac;
    puVar10[0x20] = (uint)param_3;
    puVar10[0x21] = uStack_a4;
    puVar10[0x22] = 0;
    puVar10[0x23] = 0;
    puVar10[0x24] = 0;
    puVar10[0x25] = 0;
    puVar10[0x26] = uStack_90;
    puVar10[0x27] = uStack_8c;
    puVar10[0x28] = uVar1;
    puVar10[0x29] = uVar2;
    puVar10[0x2a] = uVar3;
    puVar10[0x2b] = uVar4;
    puVar10[0x2c] = uVar5;
    puVar10[0x2d] = uVar6;
    puVar10[0x2e] = uVar7;
    puVar10[0x2f] = uVar8;
    *(int *)(this + 0x380c8) = *(int *)(this + 0x380c8) + 1;
  }
  local_a8 = (uint)param_3;
  WriteStatisticCreate(this,(Statistic *)&local_128,uVar12);
  *(uint *)param_1 = uVar12;
  Platform::CriticalSection::Leave(this_00);
LAB_18001f206:
  __security_check_cookie(local_58 ^ (ulonglong)auStack_158);
  return extraout_AL;
}



// WARNING: Type propagation algorithm not settling
// public: enum Graphine::Error::Enum __cdecl
// Graphine::Performance::PerformanceMonitor::StartLogging(wchar_t const * __ptr64) __ptr64

Enum __thiscall
Graphine::Performance::PerformanceMonitor::StartLogging(PerformanceMonitor *this,wchar_t *param_1)

{
  CriticalSection *this_00;
  short sVar1;
  LPCVOID pvVar2;
  CriticalSection *pCVar3;
  char cVar4;
  undefined8 uVar5;
  __int64 _Var6;
  undefined8 *puVar7;
  uint *puVar8;
  CriticalSection **ppCVar9;
  ulonglong uVar10;
  uint uVar11;
  Enum EVar12;
  CriticalSection **ppCVar14;
  ulonglong uVar15;
  __uint64 _Var16;
  longlong lVar17;
  undefined8 local_res8;
  CriticalSection *local_res18;
  undefined8 local_res20;
  undefined8 local_68;
  CriticalSection *local_60;
  uint local_58 [2];
  undefined8 local_50;
  CriticalSection *local_48;
  ulonglong uVar13;
  
                    // 0x1f230  143
                    // ?StartLogging@PerformanceMonitor@Performance@Graphine@@QEAA?AW4Enum@Error@3@PEB_W@Z
  local_50 = 0xfffffffffffffffe;
  this_00 = (CriticalSection *)(this + 0xc);
  local_48 = this_00;
  Platform::CriticalSection::Enter(this_00);
  uVar5 = FUN_180022f10((longlong)(this + 0x48),(LPCWSTR)param_1);
  uVar15 = 0;
  *(undefined8 *)(this + 0x8098) = 0;
  EVar12 = (Enum)uVar5;
  if ((Enum)uVar5 == 0) {
    local_res8 = CONCAT44(local_res8._4_4_,0x200);
    Write(this,&local_res8,4);
    Write(this,&DAT_180026640,4);
    local_res8 = *(ulonglong *)(this + 0x80b0);
    Write(this,&local_res8,8);
    Write(this,(wchar_t *)L"TODO");
    _Var6 = Platform::GetTimeTicks();
    *(__int64 *)(this + 0x80a8) = _Var6;
    uVar13 = uVar15;
    if (*(int *)(this + 0x380c8) != 0) {
      do {
        WriteStatisticCreate(this,(Statistic *)(this + uVar13 * 0xc0 + 0x80c8),(uint)uVar13);
        uVar11 = (uint)uVar13 + 1;
        uVar13 = (ulonglong)uVar11;
      } while (uVar11 < *(uint *)(this + 0x380c8));
    }
    uVar13 = uVar15;
    if (*(int *)(this + 0x400d0) != 0) {
      do {
        ppCVar14 = (CriticalSection **)(this + uVar13 * 0x80 + 0x380d0);
        local_res18 = (CriticalSection *)
                      ((ulonglong)local_res18 & 0xffffffff00000000 |
                       (ulonglong)(uint)((int)uVar13 << 8) | 9);
        Write(this,&local_res18,4);
        if (ppCVar14 == (CriticalSection **)0x0) {
          local_res18 = (CriticalSection *)((ulonglong)local_res18 & 0xffffffffffff0000);
          _Var16 = 2;
          ppCVar14 = &local_res18;
        }
        else {
          local_res20._0_4_ = 0;
          sVar1 = *(short *)ppCVar14;
          uVar10 = uVar15;
          while (sVar1 != 0) {
            local_res20._0_4_ = (int)uVar10 + 1;
            uVar10 = (ulonglong)(uint)local_res20;
            sVar1 = *(short *)((longlong)ppCVar14 + (longlong)(int)(uint)local_res20 * 2);
          }
          local_68 = (CriticalSection *)CONCAT44(local_68._4_4_,0xffff);
          puVar7 = &local_res20;
          if (0xfffe < (int)(uint)local_res20) {
            puVar7 = &local_68;
          }
          local_res8 = local_res8 & 0xffffffffffff0000 | (ulonglong)*(ushort *)puVar7;
          Write(this,&local_res8,2);
          _Var16 = (local_res8 & 0xffff) * 2;
        }
        Write(this,ppCVar14,_Var16);
        uVar11 = (int)uVar13 + 1;
        uVar13 = (ulonglong)uVar11;
      } while (uVar11 < *(uint *)(this + 0x400d0));
    }
    uVar13 = uVar15;
    if (*(int *)(this + 0x484d4) != 0) {
      do {
        ppCVar14 = (CriticalSection **)(this + uVar13 * 0x84 + 0x400d4);
        local_res18 = (CriticalSection *)
                      ((ulonglong)local_res18 & 0xffffffff00000000 |
                       (ulonglong)(uint)(*(int *)(this + uVar13 * 0x84 + 0x40154) << 8) | 7);
        Write(this,&local_res18,4);
        if (ppCVar14 == (CriticalSection **)0x0) {
          local_res18 = (CriticalSection *)((ulonglong)local_res18 & 0xffffffffffff0000);
          local_60 = (CriticalSection *)0x2;
          cVar4 = (**(code **)(*(longlong *)this + 0x50))(this);
          if (cVar4 != '\0') {
            lVar17 = *(longlong *)(this + 0x8098);
            local_68 = (CriticalSection *)(*(longlong *)(this + 0x80a0) - lVar17);
            if (local_68 == (CriticalSection *)0x0) {
              pvVar2 = *(LPCVOID *)(this + 0x8088);
              *(undefined8 *)(this + 0x8088) = *(undefined8 *)(this + 0x8090);
              *(LPCVOID *)(this + 0x8090) = pvVar2;
              FUN_180023020((longlong)(this + 0x48),pvVar2,lVar17);
              *(undefined8 *)(this + 0x8098) = 0;
              _Var16 = 2;
              ppCVar14 = &local_res18;
            }
            else {
              ppCVar14 = (CriticalSection **)&local_68;
              if ((CriticalSection *)0x1 < local_68) {
                ppCVar14 = &local_60;
              }
              pCVar3 = *ppCVar14;
              Platform::MemoryCopy
                        ((void *)(*(longlong *)(this + 0x8088) + lVar17),&local_res18,
                         (__uint64)pCVar3);
              *(CriticalSection **)(this + 0x8098) =
                   *(CriticalSection **)(this + 0x8098) + (longlong)pCVar3;
              if ((CriticalSection *)0x1 < pCVar3) goto LAB_18001f5f8;
              _Var16 = 2 - (longlong)pCVar3;
              ppCVar14 = (CriticalSection **)((longlong)&local_res18 + (longlong)pCVar3);
            }
            goto LAB_18001f5f0;
          }
        }
        else {
          local_res20._0_4_ = 0;
          sVar1 = *(short *)ppCVar14;
          uVar10 = uVar15;
          while (sVar1 != 0) {
            local_res20._0_4_ = (int)uVar10 + 1;
            uVar10 = (ulonglong)(uint)local_res20;
            sVar1 = *(short *)((longlong)ppCVar14 + (longlong)(int)(uint)local_res20 * 2);
          }
          local_58[0] = 0xffff;
          puVar8 = (uint *)&local_res20;
          if (0xfffe < (int)(uint)local_res20) {
            puVar8 = local_58;
          }
          local_res8 = local_res8 & 0xffffffffffff0000 | (ulonglong)*(ushort *)puVar8;
          local_60 = (CriticalSection *)0x2;
          cVar4 = (**(code **)(*(longlong *)this + 0x50))(this);
          if (cVar4 != '\0') {
            lVar17 = *(longlong *)(this + 0x8098);
            local_res18 = (CriticalSection *)(*(longlong *)(this + 0x80a0) - lVar17);
            if (local_res18 == (CriticalSection *)0x0) {
              pvVar2 = *(LPCVOID *)(this + 0x8088);
              *(undefined8 *)(this + 0x8088) = *(undefined8 *)(this + 0x8090);
              *(LPCVOID *)(this + 0x8090) = pvVar2;
              FUN_180023020((longlong)(this + 0x48),pvVar2,lVar17);
              *(undefined8 *)(this + 0x8098) = 0;
              _Var16 = 2;
              puVar7 = &local_res8;
            }
            else {
              ppCVar9 = &local_res18;
              if ((CriticalSection *)0x1 < local_res18) {
                ppCVar9 = &local_60;
              }
              pCVar3 = *ppCVar9;
              Platform::MemoryCopy
                        ((void *)(*(longlong *)(this + 0x8088) + lVar17),&local_res8,
                         (__uint64)pCVar3);
              *(longlong *)(this + 0x8098) = *(longlong *)(this + 0x8098) + (longlong)pCVar3;
              if ((CriticalSection *)0x1 < pCVar3) goto LAB_18001f5e5;
              _Var16 = 2 - (longlong)pCVar3;
              puVar7 = (undefined8 *)((longlong)&local_res8 + (longlong)pCVar3);
            }
            Write(this,puVar7,_Var16);
          }
LAB_18001f5e5:
          _Var16 = (local_res8 & 0xffff) * 2;
LAB_18001f5f0:
          Write(this,ppCVar14,_Var16);
        }
LAB_18001f5f8:
        uVar11 = (int)uVar13 + 1;
        uVar13 = (ulonglong)uVar11;
      } while (uVar11 < *(uint *)(this + 0x484d4));
    }
    local_res18 = this_00;
    Platform::CriticalSection::Enter(this_00);
    if (*(int *)(this + 0x380c8) != 0) {
      do {
        lVar17 = uVar15 * 0xc0;
        if ((*(int *)(this + lVar17 + 0x8148) == 2) && (*(int *)(this + lVar17 + 0x8180) == 1)) {
          local_res8 = local_res8 & 0xffffffff00000000 | (ulonglong)(uint)((int)uVar15 << 8) | 0xe;
          Write(this,&local_res8,4);
          local_res8 = local_res8 & 0xffffffff00000000 |
                       (ulonglong)*(uint *)(this + lVar17 + 0x8150);
          Write(this,&local_res8,4);
        }
        uVar11 = (int)uVar15 + 1;
        uVar15 = (ulonglong)uVar11;
      } while (uVar11 < *(uint *)(this + 0x380c8));
    }
    Platform::CriticalSection::Leave(this_00);
    EVar12 = 0;
  }
  Platform::CriticalSection::Leave(this_00);
  return EVar12;
}



// public: virtual enum Graphine::Error::Enum __cdecl
// Graphine::Performance::PerformanceMonitor::StartRecord(wchar_t const * __ptr64) __ptr64

Enum __thiscall
Graphine::Performance::PerformanceMonitor::StartRecord(PerformanceMonitor *this,wchar_t *param_1)

{
  Enum EVar1;
  
                    // 0x1f6c0  144
                    // ?StartRecord@PerformanceMonitor@Performance@Graphine@@UEAA?AW4Enum@Error@3@PEB_W@Z
  if (param_1 == (wchar_t *)0x0) {
    return 1;
  }
  EVar1 = StartLogging(this,param_1);
  return EVar1;
}



// public: enum Graphine::Error::Enum __cdecl
// Graphine::Performance::PerformanceMonitor::StopLogging(void) __ptr64

Enum __thiscall Graphine::Performance::PerformanceMonitor::StopLogging(PerformanceMonitor *this)

{
  bool bVar1;
  byte bVar2;
  undefined7 extraout_var;
  Enum EVar3;
  
                    // 0x1f6d0  146
                    // ?StopLogging@PerformanceMonitor@Performance@Graphine@@QEAA?AW4Enum@Error@3@XZ
  Platform::CriticalSection::Enter((CriticalSection *)(this + 0xc));
  bVar1 = FUN_180022f00((longlong)(this + 0x48));
  if (bVar1) {
    if ((this[0x50] == (PerformanceMonitor)0x0) && (*(longlong *)(this + 0x8098) != 0)) {
      Flush(this);
      FUN_180022fe0((longlong)(this + 0x48));
    }
    bVar2 = FUN_180022ea0((longlong)(this + 0x48));
    EVar3 = (Enum)CONCAT71(extraout_var,bVar2);
  }
  else {
    EVar3 = 2;
  }
  Platform::CriticalSection::Leave((CriticalSection *)(this + 0xc));
  return EVar3;
}



// public: virtual enum Graphine::Error::Enum __cdecl
// Graphine::Performance::PerformanceMonitor::StopRecord(void) __ptr64

Enum __thiscall Graphine::Performance::PerformanceMonitor::StopRecord(PerformanceMonitor *this)

{
  bool bVar1;
  byte bVar2;
  undefined7 extraout_var;
  Enum EVar3;
  
  Platform::CriticalSection::Enter((CriticalSection *)(this + 0xc));
  bVar1 = FUN_180022f00((longlong)(this + 0x48));
  if (bVar1) {
    if ((this[0x50] == (PerformanceMonitor)0x0) && (*(longlong *)(this + 0x8098) != 0)) {
      Flush(this);
      FUN_180022fe0((longlong)(this + 0x48));
    }
    bVar2 = FUN_180022ea0((longlong)(this + 0x48));
    EVar3 = (Enum)CONCAT71(extraout_var,bVar2);
  }
  else {
    EVar3 = 2;
  }
  Platform::CriticalSection::Leave((CriticalSection *)(this + 0xc));
  return EVar3;
}



// public: void __cdecl Graphine::Performance::PerformanceMonitor::Tick(void) __ptr64

void __thiscall Graphine::Performance::PerformanceMonitor::Tick(PerformanceMonitor *this)

{
  CriticalSection *this_00;
  __int64 _Var1;
  longlong lVar2;
  uint uVar3;
  ulonglong uVar4;
  undefined8 local_res8;
  CriticalSection *local_res10;
  
                    // 0x1f770  151  ?Tick@PerformanceMonitor@Performance@Graphine@@QEAAXXZ
  this_00 = (CriticalSection *)(this + 0xc);
  local_res10 = this_00;
  Platform::CriticalSection::Enter(this_00);
  _Var1 = Platform::GetTimeTicks();
  *(double *)(this + 0x80c0) =
       (double)*(longlong *)(this + 0x80b0) / (double)(_Var1 - *(longlong *)(this + 0x80b8));
  uVar4 = 0;
  if (*(int *)(this + 0x380c8) != 0) {
    do {
      lVar2 = uVar4 * 0xc0;
      *(longlong *)(this + lVar2 + 0x8160) =
           *(longlong *)(this + lVar2 + 0x8150) - *(longlong *)(this + lVar2 + 0x8158);
      *(longlong *)(this + lVar2 + 0x8158) = *(longlong *)(this + lVar2 + 0x8150);
      uVar3 = (int)uVar4 + 1;
      uVar4 = (ulonglong)uVar3;
    } while (uVar3 < *(uint *)(this + 0x380c8));
  }
  *(__int64 *)(this + 0x80b8) = _Var1;
  local_res8 = CONCAT44(local_res8._4_4_,1);
  Write(this,&local_res8,4);
  _Var1 = Platform::GetTimeTicks();
  local_res8 = _Var1 - *(longlong *)(this + 0x80a8);
  Write(this,&local_res8,8);
  Platform::CriticalSection::Leave(this_00);
  return;
}



// protected: void __cdecl Graphine::Performance::PerformanceMonitor::Write(void const *
// __ptr64,unsigned __int64) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::Write
          (PerformanceMonitor *this,void *param_1,__uint64 param_2)

{
  longlong lVar1;
  LPCVOID pvVar2;
  char cVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  
                    // 0x1f880  166  ?Write@PerformanceMonitor@Performance@Graphine@@IEAAXPEBX_K@Z
  cVar3 = (**(code **)(*(longlong *)this + 0x50))();
  do {
    if (cVar3 == '\0') {
      return;
    }
    lVar1 = *(longlong *)(this + 0x8098);
    uVar4 = *(longlong *)(this + 0x80a0) - lVar1;
    if (uVar4 == 0) {
      pvVar2 = *(LPCVOID *)(this + 0x8088);
      *(undefined8 *)(this + 0x8088) = *(undefined8 *)(this + 0x8090);
      *(LPCVOID *)(this + 0x8090) = pvVar2;
      FUN_180023020((longlong)(this + 0x48),pvVar2,lVar1);
      *(undefined8 *)(this + 0x8098) = 0;
    }
    else {
      uVar5 = param_2;
      if (uVar4 < param_2) {
        uVar5 = uVar4;
      }
      Platform::MemoryCopy((void *)(*(longlong *)(this + 0x8088) + lVar1),param_1,uVar5);
      *(ulonglong *)(this + 0x8098) = *(longlong *)(this + 0x8098) + uVar5;
      if (param_2 <= uVar5) {
        return;
      }
      param_2 = param_2 - uVar5;
      param_1 = (void *)((longlong)param_1 + uVar5);
    }
    cVar3 = (**(code **)(*(longlong *)this + 0x50))(this);
  } while( true );
}



// protected: void __cdecl Graphine::Performance::PerformanceMonitor::WriteCreateEvent(enum
// Graphine::Performance::MessageType::Enum,unsigned int,wchar_t const * __ptr64) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::WriteCreateEvent
          (PerformanceMonitor *this,Enum param_1,uint param_2,wchar_t *param_3)

{
  uint local_res10 [6];
  
                    // 0x1f960  171
                    // ?WriteCreateEvent@PerformanceMonitor@Performance@Graphine@@IEAAXW4Enum@MessageType@23@IPEB_W@Z
  local_res10[0] = param_2 << 8 | param_1;
  Write(this,local_res10,4);
  Write(this,param_3);
  return;
}



// protected: void __cdecl Graphine::Performance::PerformanceMonitor::WriteStatisticCreate(struct
// Graphine::Performance::Statistic & __ptr64,unsigned int) __ptr64

void __thiscall
Graphine::Performance::PerformanceMonitor::WriteStatisticCreate
          (PerformanceMonitor *this,Statistic *param_1,uint param_2)

{
  undefined8 local_res10;
  uint local_res18 [4];
  
                    // 0x1f9b0  179
                    // ?WriteStatisticCreate@PerformanceMonitor@Performance@Graphine@@IEAAXAEAUStatistic@23@I@Z
  local_res18[0] = param_2 << 8 | 8;
  Write(this,local_res18,4);
  Write(this,(wchar_t *)param_1);
  local_res18[0] = *(uint *)(param_1 + 0x80);
  Write(this,local_res18,4);
  Write(this,*(wchar_t **)(param_1 + 0xa0));
  Write(this,*(wchar_t **)(param_1 + 0xa8));
  local_res10 = *(undefined8 *)(param_1 + 0xb0);
  Write(this,&local_res10,8);
  local_res18[0] = *(uint *)(param_1 + 0xb8);
  Write(this,local_res18,4);
  local_res18[0] = *(uint *)(param_1 + 0xbc);
  Write(this,local_res18,4);
  return;
}



// public: unsigned int __cdecl Graphine::Utilities::Crc32Calculation::AddBytes(void const *
// __ptr64,unsigned __int64) __ptr64

uint __thiscall
Graphine::Utilities::Crc32Calculation::AddBytes
          (Crc32Calculation *this,void *param_1,__uint64 param_2)

{
  uint uVar1;
  
                    // 0x1fa90  36  ?AddBytes@Crc32Calculation@Utilities@Graphine@@QEAAIPEBX_K@Z
  if ((param_1 != (void *)0x0) && (param_2 != 0)) {
    uVar1 = FUN_18001fae0((uint *)param_1,param_2,~*(uint *)this,0x100);
    *(uint *)(this + 4) = uVar1;
    *(uint *)this = ~uVar1;
    return uVar1;
  }
  return 0;
}



uint FUN_18001fae0(uint *param_1,ulonglong param_2,uint param_3,longlong param_4)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  longlong lVar7;
  longlong lVar8;
  
  uVar5 = ~param_3;
  if (param_4 + 0x40U <= param_2) {
    lVar7 = (param_2 - (param_4 + 0x40U) >> 6) + 1;
    param_2 = param_2 + lVar7 * -0x40;
    do {
      lVar8 = 4;
      do {
        uVar2 = param_1[1];
        uVar3 = param_1[2];
        uVar4 = param_1[3];
        uVar6 = *param_1;
        param_1 = param_1 + 4;
        uVar6 = uVar6 ^ uVar5;
        uVar5 = *(uint *)(&DAT_180029a90 + (ulonglong)(byte)(uVar6 >> 0x10) * 4) ^
                *(uint *)(&DAT_180029e90 + (ulonglong)(byte)(uVar6 >> 8) * 4) ^
                *(uint *)(&DAT_180028a90 + (ulonglong)(byte)(uVar2 >> 0x10) * 4) ^
                *(uint *)(&DAT_180028e90 + (ulonglong)(byte)(uVar2 >> 8) * 4) ^
                *(uint *)(&DAT_180027a90 + (ulonglong)(byte)(uVar3 >> 0x10) * 4) ^
                *(uint *)(&DAT_180027e90 + (ulonglong)(byte)(uVar3 >> 8) * 4) ^
                *(uint *)(&DAT_180026a90 + (ulonglong)(byte)(uVar4 >> 0x10) * 4) ^
                *(uint *)(&DAT_180026e90 + (ulonglong)(byte)(uVar4 >> 8) * 4) ^
                *(uint *)(&DAT_180029690 + (ulonglong)(uVar6 >> 0x18) * 4) ^
                *(uint *)(&DAT_180028690 + (ulonglong)(uVar2 >> 0x18) * 4) ^
                *(uint *)(&DAT_180027690 + (ulonglong)(uVar3 >> 0x18) * 4) ^
                *(uint *)(&DAT_180026690 + (ulonglong)(uVar4 >> 0x18) * 4) ^
                *(uint *)(&DAT_18002a290 + (ulonglong)(uVar6 & 0xff) * 4) ^
                *(uint *)(&DAT_180029290 + (ulonglong)(uVar2 & 0xff) * 4) ^
                *(uint *)(&DAT_180028290 + (ulonglong)(uVar3 & 0xff) * 4) ^
                *(uint *)(&DAT_180027290 + (ulonglong)(uVar4 & 0xff) * 4);
        lVar8 = lVar8 + -1;
      } while (lVar8 != 0);
      lVar7 = lVar7 + -1;
    } while (lVar7 != 0);
  }
  for (; param_2 != 0; param_2 = param_2 - 1) {
    bVar1 = *(byte *)param_1;
    param_1 = (uint *)((longlong)param_1 + 1);
    uVar5 = *(uint *)(&DAT_180026690 + ((ulonglong)(uVar5 & 0xff) ^ (ulonglong)bVar1) * 4) ^
            uVar5 >> 8;
  }
  return ~uVar5;
}



// unsigned __int64 __cdecl Graphine::Utilities::Compressor::CalculateBufferSize(unsigned __int64)

__uint64 __cdecl Graphine::Utilities::Compressor::CalculateBufferSize(__uint64 param_1)

{
  __uint64 _Var1;
  ulonglong uVar2;
  
                    // 0x1fcc0  43  ?CalculateBufferSize@Compressor@Utilities@Graphine@@YA_K_K@Z
  uVar2 = (param_1 + 0x13) / 0x14 + param_1;
  _Var1 = 0x42;
  if (0x42 < uVar2) {
    _Var1 = uVar2;
  }
  return _Var1;
}



// unsigned __int64 __cdecl Graphine::Utilities::Compressor::Compress_level(int,void const *
// __ptr64,unsigned __int64,void * __ptr64)

__uint64 __cdecl
Graphine::Utilities::Compressor::Compress_level
          (int param_1,void *param_2,__uint64 param_3,void *param_4)

{
  int iVar1;
  
                    // 0x1fcf0  47  ?Compress_level@Compressor@Utilities@Graphine@@YA_KHPEBX_KPEAX@Z
  if (param_1 == 1) {
    iVar1 = FUN_18001fd80((char *)param_2,(int)param_3,(char *)param_4);
    return (longlong)iVar1;
  }
  if (param_1 == 2) {
    iVar1 = FUN_180020330((byte *)param_2,(int)param_3,(byte *)param_4);
    return (longlong)iVar1;
  }
  return 0;
}



// unsigned __int64 __cdecl Graphine::Utilities::Compressor::Decompress(void const *
// __ptr64,unsigned __int64,void * __ptr64,unsigned __int64)

__uint64 __cdecl
Graphine::Utilities::Compressor::Decompress
          (void *param_1,__uint64 param_2,void *param_3,__uint64 param_4)

{
  ulonglong uVar1;
  
                    // 0x1fd40  57  ?Decompress@Compressor@Utilities@Graphine@@YA_KPEBX_KPEAX1@Z
                    // WARNING: Load size is inaccurate
  if (*param_1 >> 5 == 0) {
    uVar1 = FUN_1800201a0((byte *)param_1,(int)param_2,(byte *)param_3,(int)param_4);
    return (longlong)(int)uVar1;
  }
  if (*param_1 >> 5 == 1) {
    uVar1 = FUN_180020810((byte *)param_1,(int)param_2,(byte *)param_3,(int)param_4);
    return (longlong)(int)uVar1;
  }
  return 0;
}



// WARNING: Function: _alloca_probe replaced with injection: alloca_probe

void FUN_18001fd80(char *param_1,int param_2,char *param_3)

{
  ushort *puVar1;
  char cVar2;
  char cVar3;
  ushort uVar4;
  ulonglong uVar5;
  ushort **ppuVar6;
  longlong lVar7;
  char *pcVar8;
  ushort *puVar9;
  ulonglong uVar10;
  ushort *puVar11;
  uint uVar12;
  char *pcVar13;
  ulonglong uVar14;
  int iVar15;
  ushort *puVar16;
  ushort *puVar17;
  ushort *apuStack_10040 [8194];
  
  uVar5 = DAT_180032820 ^ (ulonglong)apuStack_10040;
  puVar9 = (ushort *)(param_1 + (longlong)param_2 + -2);
  if (param_2 < 4) {
    if (param_2 != 0) {
      *param_3 = (char)param_2 + -1;
      if (param_1 <= (char *)((longlong)puVar9 + 1)) {
        pcVar13 = param_1;
        do {
          pcVar13[(longlong)(param_3 + (1 - (longlong)param_1))] = *pcVar13;
          pcVar13 = pcVar13 + 1;
        } while (pcVar13 <= (char *)((longlong)puVar9 + 1));
      }
    }
  }
  else {
    lVar7 = 0x400;
    ppuVar6 = apuStack_10040;
    do {
      *ppuVar6 = (ushort *)param_1;
      ((char **)ppuVar6)[1] = param_1;
      ((char **)ppuVar6)[2] = param_1;
      ((char **)ppuVar6)[3] = param_1;
      ((char **)ppuVar6)[4] = param_1;
      ((char **)ppuVar6)[5] = param_1;
      ((char **)ppuVar6)[6] = param_1;
      ((char **)ppuVar6)[7] = param_1;
      lVar7 = lVar7 + -1;
      ppuVar6 = (ushort **)((char **)ppuVar6 + 8);
    } while (lVar7 != 0);
    *param_3 = '\x1f';
    uVar10 = 2;
    param_3[1] = *param_1;
    puVar11 = (ushort *)(param_1 + 2);
    param_3[2] = param_1[1];
    pcVar13 = param_3 + 3;
    while (pcVar8 = pcVar13, puVar11 < param_1 + (longlong)param_2 + -0xc) {
      cVar2 = *(char *)puVar11;
      uVar12 = *(ushort *)((longlong)puVar11 + 1) & 0x1fff ^
               (ushort)(*puVar11 >> 3 ^ *puVar11) & 0x1fff;
      puVar17 = apuStack_10040[uVar12];
      iVar15 = (int)puVar11 - (int)puVar17;
      apuStack_10040[uVar12] = puVar11;
      if ((((iVar15 - 1U < 0x1fff) && (*(char *)puVar17 == cVar2)) &&
          (*(char *)((longlong)puVar17 + 1) == *(char *)((longlong)puVar11 + 1))) &&
         (pcVar13 = (char *)((longlong)puVar17 + 3),
         *(char *)(puVar17 + 1) == *(char *)(puVar11 + 1))) {
        puVar16 = (ushort *)((longlong)puVar11 + 3);
        iVar15 = iVar15 + -1;
        if (iVar15 == 0) {
          while ((puVar16 < puVar9 &&
                 (cVar2 = *pcVar13, pcVar13 = pcVar13 + 1, cVar2 == *(char *)(puVar11 + 1)))) {
            puVar16 = (ushort *)((longlong)puVar16 + 1);
          }
        }
        else {
          cVar2 = *(char *)puVar16;
          puVar16 = puVar11 + 2;
          if (((((*pcVar13 == cVar2) &&
                (cVar2 = *(char *)puVar16, puVar16 = (ushort *)((longlong)puVar11 + 5),
                *(char *)(puVar17 + 2) == cVar2)) &&
               ((cVar2 = *(char *)puVar16, puVar16 = puVar11 + 3,
                *(char *)((longlong)puVar17 + 5) == cVar2 &&
                ((cVar2 = *(char *)puVar16, puVar16 = (ushort *)((longlong)puVar11 + 7),
                 *(char *)(puVar17 + 3) == cVar2 &&
                 (cVar2 = *(char *)puVar16, puVar16 = puVar11 + 4,
                 *(char *)((longlong)puVar17 + 7) == cVar2)))))) &&
              (cVar2 = *(char *)puVar16, puVar16 = (ushort *)((longlong)puVar11 + 9),
              *(char *)(puVar17 + 4) == cVar2)) &&
             (cVar2 = *(char *)puVar16, puVar16 = puVar11 + 5,
             *(char *)((longlong)puVar17 + 9) == cVar2)) {
            pcVar13 = (char *)((longlong)puVar17 + 0xb);
            cVar2 = *(char *)puVar16;
            puVar16 = (ushort *)((longlong)puVar11 + 0xb);
            if (*(char *)(puVar17 + 5) == cVar2) {
              do {
                if (puVar9 <= puVar16) break;
                cVar2 = *(char *)puVar16;
                puVar16 = (ushort *)((longlong)puVar16 + 1);
                cVar3 = *pcVar13;
                pcVar13 = pcVar13 + 1;
              } while (cVar3 == cVar2);
            }
          }
        }
        if ((int)uVar10 == 0) {
          pcVar8 = pcVar8 + -1;
        }
        else {
          pcVar8[-1 - uVar10] = (char)uVar10 + -1;
        }
        puVar17 = (ushort *)((longlong)puVar16 + -3);
        uVar10 = 0;
        uVar12 = (int)puVar17 - (int)puVar11;
        cVar2 = (char)((uint)iVar15 >> 8);
        if (0x106 < uVar12) {
          uVar14 = (ulonglong)((uVar12 - 0x107) / 0x106 + 1);
          do {
            uVar12 = uVar12 - 0x106;
            *pcVar8 = cVar2 + -0x20;
            pcVar8[1] = -3;
            pcVar8[2] = (char)iVar15;
            pcVar8 = pcVar8 + 3;
            uVar14 = uVar14 - 1;
          } while (uVar14 != 0);
        }
        if (uVar12 < 7) {
          *pcVar8 = cVar2 + (char)uVar12 * ' ';
          pcVar8 = pcVar8 + 1;
        }
        else {
          *pcVar8 = cVar2 + -0x20;
          pcVar8[1] = (char)uVar12 + -7;
          pcVar8 = pcVar8 + 2;
        }
        *pcVar8 = (char)iVar15;
        puVar1 = puVar16 + -1;
        puVar11 = (ushort *)((longlong)puVar16 + -1);
        cVar2 = *(char *)puVar11;
        uVar4 = *puVar1;
        apuStack_10040[(ushort)(*puVar1 ^ *puVar17 >> 3 ^ *puVar17) & 0x1fff] = puVar17;
        cVar3 = *(char *)puVar16;
        pcVar8[1] = '\x1f';
        apuStack_10040[(ushort)(CONCAT11(cVar3,cVar2) ^ uVar4 >> 3 ^ uVar4) & 0x1fff] = puVar1;
        pcVar13 = pcVar8 + 2;
      }
      else {
        uVar12 = (int)uVar10 + 1;
        uVar10 = (ulonglong)uVar12;
        *pcVar8 = *(char *)puVar11;
        puVar11 = (ushort *)((longlong)puVar11 + 1);
        pcVar13 = pcVar8 + 1;
        if (uVar12 == 0x20) {
          uVar10 = 0;
          pcVar8[1] = '\x1f';
          pcVar13 = pcVar8 + 2;
        }
      }
    }
    while (pcVar13 = pcVar8, puVar11 <= (ushort *)((longlong)puVar9 + 1)) {
      uVar12 = (int)uVar10 + 1;
      uVar10 = (ulonglong)uVar12;
      *pcVar13 = *(char *)puVar11;
      puVar11 = (ushort *)((longlong)puVar11 + 1);
      pcVar8 = pcVar13 + 1;
      if (uVar12 == 0x20) {
        uVar10 = 0;
        pcVar13[1] = '\x1f';
        pcVar8 = pcVar13 + 2;
      }
    }
    if ((int)uVar10 != 0) {
      pcVar13[-1 - uVar10] = (char)uVar10 + -1;
    }
  }
  __security_check_cookie(uVar5 ^ (ulonglong)apuStack_10040);
  return;
}



ulonglong FUN_1800201a0(byte *param_1,int param_2,byte *param_3,int param_4)

{
  byte bVar1;
  ulonglong uVar2;
  byte *pbVar3;
  byte *pbVar4;
  uint uVar5;
  byte *pbVar6;
  byte *pbVar7;
  byte *pbVar8;
  uint uVar9;
  bool bVar10;
  
  bVar10 = true;
  pbVar4 = param_1 + param_2;
  uVar9 = *param_1 & 0x1f;
  pbVar3 = param_3;
  pbVar7 = param_1 + 1;
  do {
    if (uVar9 < 0x20) {
      if (param_3 + param_4 < pbVar3 + (uVar9 + 1)) {
        return 0;
      }
      if (pbVar4 < pbVar7 + (uVar9 + 1)) {
        return 0;
      }
      *pbVar3 = *pbVar7;
      pbVar8 = pbVar7;
      while( true ) {
        pbVar3 = pbVar3 + 1;
        pbVar8 = pbVar8 + 1;
        if (uVar9 == 0) break;
        *pbVar3 = *pbVar8;
        uVar9 = uVar9 - 1;
      }
      bVar10 = pbVar8 < pbVar4;
      if (pbVar8 < pbVar4) {
        uVar9 = (uint)*pbVar8;
        pbVar8 = pbVar8 + 1;
      }
    }
    else {
      uVar5 = (uVar9 >> 5) - 1;
      if (uVar5 == 6) {
        uVar5 = *pbVar7 + 6;
        pbVar7 = pbVar7 + 1;
      }
      pbVar8 = pbVar7 + 1;
      pbVar6 = pbVar3 + (-(ulonglong)*pbVar7 - (ulonglong)((uVar9 & 0x1f) << 8));
      uVar2 = (ulonglong)uVar5;
      if ((param_3 + param_4 < pbVar3 + uVar2 + 3) || (pbVar6 + -1 < param_3)) {
        return 0;
      }
      if (pbVar8 < pbVar4) {
        uVar9 = (uint)*pbVar8;
        pbVar8 = pbVar7 + 2;
      }
      else {
        bVar10 = false;
      }
      bVar1 = pbVar6[-1];
      *pbVar3 = bVar1;
      if (pbVar6 == pbVar3) {
        pbVar3[1] = bVar1;
        pbVar3[2] = bVar1;
        pbVar7 = pbVar3 + 3;
        pbVar3 = pbVar7;
        if (uVar5 != 0) {
          pbVar3 = pbVar7 + uVar2;
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *pbVar7 = bVar1;
            pbVar7 = pbVar7 + 1;
          }
        }
      }
      else {
        pbVar3[1] = *pbVar6;
        pbVar7 = pbVar6 + 2;
        pbVar3[2] = pbVar6[1];
        pbVar3 = pbVar3 + 3;
        for (; uVar5 != 0; uVar5 = uVar5 - 1) {
          bVar1 = *pbVar7;
          pbVar7 = pbVar7 + 1;
          *pbVar3 = bVar1;
          pbVar3 = pbVar3 + 1;
        }
      }
    }
    pbVar7 = pbVar8;
    if (!bVar10) {
      return (longlong)pbVar3 - (longlong)param_3 & 0xffffffff;
    }
  } while( true );
}



// WARNING: Function: _alloca_probe replaced with injection: alloca_probe

void FUN_180020330(byte *param_1,int param_2,byte *param_3)

{
  byte bVar1;
  byte bVar2;
  ushort *puVar3;
  ushort uVar4;
  char cVar5;
  ulonglong uVar6;
  ushort **ppuVar7;
  ushort *puVar8;
  byte *pbVar9;
  ulonglong uVar10;
  longlong lVar11;
  uint uVar12;
  uint uVar13;
  ulonglong uVar14;
  byte *pbVar15;
  uint uVar16;
  byte *pbVar17;
  byte *pbVar18;
  ushort *puVar19;
  ulonglong uVar20;
  ushort *puVar21;
  ushort *apuStack_10040 [8194];
  
  uVar6 = DAT_180032820 ^ (ulonglong)apuStack_10040;
  pbVar15 = param_1 + (longlong)param_2 + -2;
  if (param_2 < 4) {
    if (param_2 != 0) {
      *param_3 = (char)param_2 - 1;
      if (param_1 <= pbVar15 + 1) {
        pbVar9 = param_1;
        do {
          pbVar9[(longlong)(param_3 + (1 - (longlong)param_1))] = *pbVar9;
          pbVar9 = pbVar9 + 1;
        } while (pbVar9 <= pbVar15 + 1);
      }
    }
  }
  else {
    lVar11 = 0x400;
    ppuVar7 = apuStack_10040;
    do {
      *ppuVar7 = (ushort *)param_1;
      ((byte **)ppuVar7)[1] = param_1;
      ((byte **)ppuVar7)[2] = param_1;
      ((byte **)ppuVar7)[3] = param_1;
      ((byte **)ppuVar7)[4] = param_1;
      ((byte **)ppuVar7)[5] = param_1;
      ((byte **)ppuVar7)[6] = param_1;
      ((byte **)ppuVar7)[7] = param_1;
      lVar11 = lVar11 + -1;
      ppuVar7 = (ushort **)((byte **)ppuVar7 + 8);
    } while (lVar11 != 0);
    *param_3 = 0x1f;
    param_3[1] = *param_1;
    uVar14 = 2;
    param_3[2] = param_1[1];
    puVar21 = (ushort *)(param_1 + 2);
    pbVar9 = param_3 + 3;
    while (pbVar17 = pbVar9, puVar21 < param_1 + (longlong)param_2 + -0xc) {
      lVar11 = 3;
      bVar1 = *(byte *)puVar21;
      if ((bVar1 == *(byte *)((longlong)puVar21 + -1)) &&
         (puVar19 = puVar21 + 1,
         CONCAT11(bVar1,*(byte *)((longlong)puVar21 + -1)) == *(short *)((longlong)puVar21 + 1))) {
        uVar12 = 1;
LAB_180020515:
        pbVar9 = (byte *)((longlong)puVar21 + lVar11);
        uVar13 = uVar12 - 1;
        if (uVar13 == 0) {
          pbVar18 = pbVar9;
          while ((pbVar18 < pbVar15 &&
                 (bVar1 = *(byte *)puVar19, puVar19 = (ushort *)((longlong)puVar19 + 1),
                 bVar1 == pbVar9[-1]))) {
            pbVar18 = pbVar18 + 1;
          }
        }
        else {
          pbVar18 = pbVar9 + 1;
          if (((*(byte *)puVar19 == *pbVar9) &&
              (bVar1 = *pbVar18, pbVar18 = pbVar9 + 2, *(byte *)((longlong)puVar19 + 1) == bVar1))
             && ((bVar1 = *pbVar18, pbVar18 = pbVar9 + 3, *(byte *)(puVar19 + 1) == bVar1 &&
                 ((((bVar1 = *pbVar18, pbVar18 = pbVar9 + 4,
                    *(byte *)((longlong)puVar19 + 3) == bVar1 &&
                    (bVar1 = *pbVar18, pbVar18 = pbVar9 + 5, *(byte *)(puVar19 + 2) == bVar1)) &&
                   (bVar1 = *pbVar18, pbVar18 = pbVar9 + 6,
                   *(byte *)((longlong)puVar19 + 5) == bVar1)) &&
                  (bVar1 = *pbVar18, pbVar18 = pbVar9 + 7, *(byte *)(puVar19 + 3) == bVar1)))))) {
            puVar8 = puVar19 + 4;
            bVar1 = *pbVar18;
            pbVar18 = pbVar9 + 8;
            if (*(byte *)((longlong)puVar19 + 7) == bVar1) {
              do {
                if (pbVar15 <= pbVar18) break;
                bVar1 = *pbVar18;
                pbVar18 = pbVar18 + 1;
                bVar2 = *(byte *)puVar8;
                puVar8 = (ushort *)((longlong)puVar8 + 1);
              } while (bVar2 == bVar1);
            }
          }
        }
        if ((int)uVar14 == 0) {
          pbVar17 = pbVar17 + -1;
        }
        else {
          pbVar17[-1 - uVar14] = (char)uVar14 - 1;
        }
        puVar19 = (ushort *)(pbVar18 + -3);
        uVar14 = 0;
        uVar16 = (int)puVar19 - (int)puVar21;
        if (uVar13 < 0x1fff) {
          cVar5 = (char)(uVar13 >> 8);
          if (uVar16 < 7) {
            *pbVar17 = cVar5 + (char)uVar16 * ' ';
            pbVar17 = pbVar17 + 1;
          }
          else {
            uVar16 = uVar16 - 7;
            *pbVar17 = cVar5 - 0x20;
            pbVar17 = pbVar17 + 1;
            pbVar9 = pbVar17;
            if (0xfe < uVar16) {
              uVar20 = (ulonglong)uVar16 / 0xff;
              pbVar9 = pbVar17 + uVar20;
              for (uVar10 = uVar20; uVar10 != 0; uVar10 = uVar10 - 1) {
                *pbVar17 = 0xff;
                pbVar17 = pbVar17 + 1;
              }
              do {
                uVar16 = uVar16 - 0xff;
                uVar20 = uVar20 - 1;
              } while (uVar20 != 0);
            }
            *pbVar9 = (byte)uVar16;
            pbVar17 = pbVar9 + 1;
          }
        }
        else {
          uVar13 = uVar12 - 0x2000;
          if (uVar16 < 7) {
            uVar16 = (uint)(byte)((char)uVar16 * ' ' + 0x1f);
          }
          else {
            *pbVar17 = 0xff;
            uVar16 = uVar16 - 7;
            pbVar9 = pbVar17 + 1;
            pbVar17 = pbVar9;
            if (0xfe < uVar16) {
              uVar20 = (ulonglong)uVar16 / 0xff;
              pbVar17 = pbVar9 + uVar20;
              for (uVar10 = uVar20; uVar10 != 0; uVar10 = uVar10 - 1) {
                *pbVar9 = 0xff;
                pbVar9 = pbVar9 + 1;
              }
              do {
                uVar16 = uVar16 - 0xff;
                uVar20 = uVar20 - 1;
              } while (uVar20 != 0);
            }
          }
          *pbVar17 = (byte)uVar16;
          pbVar17[1] = 0xff;
          pbVar17[2] = (byte)(uVar13 >> 8);
          pbVar17 = pbVar17 + 3;
        }
        *pbVar17 = (byte)uVar13;
        puVar21 = (ushort *)(pbVar18 + -2);
        bVar1 = pbVar18[-1];
        uVar4 = *puVar21;
        apuStack_10040[(ushort)(*puVar21 ^ *puVar19 >> 3 ^ *puVar19) & 0x1fff] = puVar19;
        bVar2 = *pbVar18;
        pbVar17[1] = 0x1f;
        apuStack_10040[(ushort)(CONCAT11(bVar2,bVar1) ^ uVar4 >> 3 ^ uVar4) & 0x1fff] = puVar21;
        puVar21 = (ushort *)(pbVar18 + -1);
        pbVar9 = pbVar17 + 2;
      }
      else {
        puVar8 = (ushort *)((longlong)puVar21 + 1);
        uVar4 = CONCAT11(*(char *)(ushort *)((longlong)puVar21 + 1),bVar1);
        uVar13 = *(ushort *)((longlong)puVar21 + 1) & 0x1fff ^ (ushort)(uVar4 >> 3 ^ uVar4) & 0x1fff
        ;
        puVar3 = apuStack_10040[uVar13];
        uVar12 = (int)puVar21 - (int)puVar3;
        apuStack_10040[uVar13] = puVar21;
        if ((uVar12 - 1 < 0x11ffc) &&
           (((*(byte *)puVar3 == bVar1 && (*(byte *)((longlong)puVar3 + 1) == *(byte *)puVar8)) &&
            (puVar19 = (ushort *)((longlong)puVar3 + 3),
            *(byte *)(puVar3 + 1) == *(byte *)(puVar21 + 1))))) {
          if (0x1ffe < uVar12) {
            if ((*(byte *)((longlong)puVar21 + 3) != *(byte *)puVar19) ||
               (puVar19 = (ushort *)((longlong)puVar3 + 5),
               *(byte *)(puVar21 + 2) != *(byte *)(puVar3 + 2))) goto LAB_180020750;
            lVar11 = 5;
          }
          goto LAB_180020515;
        }
LAB_180020750:
        uVar13 = (int)uVar14 + 1;
        uVar14 = (ulonglong)uVar13;
        *pbVar17 = *(byte *)puVar21;
        puVar21 = puVar8;
        pbVar9 = pbVar17 + 1;
        if (uVar13 == 0x20) {
          uVar14 = 0;
          pbVar17[1] = 0x1f;
          pbVar9 = pbVar17 + 2;
        }
      }
    }
    while (pbVar9 = pbVar17, puVar21 <= pbVar15 + 1) {
      uVar13 = (int)uVar14 + 1;
      uVar14 = (ulonglong)uVar13;
      *pbVar9 = *(byte *)puVar21;
      puVar21 = (ushort *)((longlong)puVar21 + 1);
      pbVar17 = pbVar9 + 1;
      if (uVar13 == 0x20) {
        uVar14 = 0;
        pbVar9[1] = 0x1f;
        pbVar17 = pbVar9 + 2;
      }
    }
    if ((int)uVar14 != 0) {
      pbVar9[-1 - uVar14] = (char)uVar14 - 1;
    }
    *param_3 = *param_3 | 0x20;
  }
  __security_check_cookie(uVar6 ^ (ulonglong)apuStack_10040);
  return;
}



ulonglong FUN_180020810(byte *param_1,int param_2,byte *param_3,int param_4)

{
  byte bVar1;
  ulonglong uVar2;
  byte *pbVar3;
  byte *pbVar4;
  uint uVar5;
  byte *pbVar6;
  byte *pbVar7;
  byte *pbVar8;
  uint uVar9;
  bool bVar10;
  
  bVar10 = true;
  pbVar4 = param_1 + param_2;
  uVar9 = *param_1 & 0x1f;
  pbVar3 = param_3;
  pbVar7 = param_1 + 1;
  do {
    if (uVar9 < 0x20) {
      if (param_3 + param_4 < pbVar3 + (uVar9 + 1)) {
        return 0;
      }
      if (pbVar4 < pbVar7 + (uVar9 + 1)) {
        return 0;
      }
      *pbVar3 = *pbVar7;
      pbVar8 = pbVar7;
      while( true ) {
        pbVar3 = pbVar3 + 1;
        pbVar8 = pbVar8 + 1;
        if (uVar9 == 0) break;
        *pbVar3 = *pbVar8;
        uVar9 = uVar9 - 1;
      }
      bVar10 = pbVar8 < pbVar4;
      if (pbVar8 < pbVar4) {
        uVar9 = (uint)*pbVar8;
        pbVar8 = pbVar8 + 1;
      }
    }
    else {
      uVar5 = (uVar9 >> 5) - 1;
      if (uVar5 == 6) {
        do {
          bVar1 = *pbVar7;
          pbVar7 = pbVar7 + 1;
          uVar5 = uVar5 + bVar1;
        } while (bVar1 == 0xff);
      }
      pbVar8 = pbVar7 + 1;
      pbVar6 = pbVar3 + (-(ulonglong)*pbVar7 - (ulonglong)((uVar9 & 0x1f) << 8));
      if ((*pbVar7 == 0xff) && ((uVar9 & 0x1f) == 0x1f)) {
        bVar1 = *pbVar8;
        pbVar8 = pbVar7 + 3;
        pbVar6 = pbVar3 + ((ulonglong)bVar1 * -0x100 - (ulonglong)pbVar7[2]) + -0x1fff;
      }
      uVar2 = (ulonglong)uVar5;
      if ((param_3 + param_4 < pbVar3 + uVar2 + 3) || (pbVar6 + -1 < param_3)) {
        return 0;
      }
      if (pbVar8 < pbVar4) {
        uVar9 = (uint)*pbVar8;
        pbVar8 = pbVar8 + 1;
      }
      else {
        bVar10 = false;
      }
      bVar1 = pbVar6[-1];
      *pbVar3 = bVar1;
      if (pbVar6 == pbVar3) {
        pbVar3[1] = bVar1;
        pbVar3[2] = bVar1;
        pbVar7 = pbVar3 + 3;
        pbVar3 = pbVar7;
        if (uVar5 != 0) {
          pbVar3 = pbVar7 + uVar2;
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *pbVar7 = bVar1;
            pbVar7 = pbVar7 + 1;
          }
        }
      }
      else {
        pbVar3[1] = *pbVar6;
        pbVar7 = pbVar6 + 2;
        pbVar3[2] = pbVar6[1];
        pbVar3 = pbVar3 + 3;
        for (; uVar5 != 0; uVar5 = uVar5 - 1) {
          bVar1 = *pbVar7;
          pbVar7 = pbVar7 + 1;
          *pbVar3 = bVar1;
          pbVar3 = pbVar3 + 1;
        }
      }
    }
    pbVar7 = pbVar8;
    if (!bVar10) {
      return (longlong)pbVar3 - (longlong)param_3 & 0xffffffff;
    }
  } while( true );
}



// void __cdecl Graphine::String::Convert2ByteWideTo4ByteWide(wchar_t const * __ptr64,unsigned
// __int64,unsigned __int64,wchar_t * __ptr64)

void __cdecl
Graphine::String::Convert2ByteWideTo4ByteWide
          (wchar_t *param_1,__uint64 param_2,__uint64 param_3,wchar_t *param_4)

{
  int iVar1;
  
                    // 0x209d0  48  ?Convert2ByteWideTo4ByteWide@String@Graphine@@YAXPEB_W_K1PEA_W@Z
  if (param_2 < param_3) {
    param_3 = param_2;
  }
  iVar1 = 0;
  if (param_3 != 0) {
    do {
      *param_4 = *param_1;
      iVar1 = iVar1 + 1;
      param_4[1] = param_1[1];
      *(undefined2 *)(param_4 + 2) = 0;
      param_1 = param_1 + 2;
      param_4 = param_4 + 4;
    } while ((ulonglong)(longlong)iVar1 < param_3);
  }
  return;
}



// void __cdecl Graphine::String::Convert4ByteWideTo2ByteWide(wchar_t const * __ptr64,unsigned
// __int64,unsigned __int64,wchar_t * __ptr64)

void __cdecl
Graphine::String::Convert4ByteWideTo2ByteWide
          (wchar_t *param_1,__uint64 param_2,__uint64 param_3,wchar_t *param_4)

{
  wchar_t *pwVar1;
  int iVar2;
  
                    // 0x20a10  49  ?Convert4ByteWideTo2ByteWide@String@Graphine@@YAXPEB_W_K1PEA_W@Z
  if (param_2 < param_3) {
    param_3 = param_2;
  }
  iVar2 = 0;
  if (param_3 != 0) {
    do {
      iVar2 = iVar2 + 1;
      *param_4 = *param_1;
      pwVar1 = param_1 + 1;
      param_1 = param_1 + 4;
      param_4[1] = *pwVar1;
      param_4 = param_4 + 2;
    } while ((ulonglong)(longlong)iVar2 < param_3);
  }
  return;
}



// unsigned __int64 __cdecl Graphine::String::CopyStringTruncate(wchar_t * __ptr64,unsigned
// __int64,wchar_t const * __ptr64)

__uint64 __cdecl
Graphine::String::CopyStringTruncate(wchar_t *param_1,__uint64 param_2,wchar_t *param_3)

{
  ulonglong uVar1;
  undefined2 *puVar2;
  ulonglong uVar3;
  
                    // 0x20a50  50  ?CopyStringTruncate@String@Graphine@@YA_KPEA_W_KPEB_W@Z
  uVar3 = 0xffffffffffffffff;
  do {
    uVar3 = uVar3 + 1;
  } while (*(short *)(param_3 + uVar3 * 2) != 0);
  if (param_2 - 1 < uVar3) {
    uVar3 = param_2 - 1;
  }
  if (uVar3 != 0) {
    uVar1 = uVar3;
    puVar2 = (undefined2 *)param_1;
    do {
      *puVar2 = *(undefined2 *)(((longlong)param_3 - (longlong)param_1) + (longlong)puVar2);
      puVar2 = puVar2 + 1;
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
  }
  *(undefined2 *)(param_1 + uVar3 * 2) = 0;
  return uVar3;
}



// unsigned __int64 __cdecl Graphine::String::CopyStringTruncateMultiByte(char * __ptr64,unsigned
// __int64,char const * __ptr64)

__uint64 __cdecl
Graphine::String::CopyStringTruncateMultiByte(char *param_1,__uint64 param_2,char *param_3)

{
  ulonglong uVar1;
  char *pcVar2;
  __uint64 _Var3;
  
                    // 0x20ab0  51  ?CopyStringTruncateMultiByte@String@Graphine@@YA_KPEAD_KPEBD@Z
  uVar1 = 0xffffffffffffffff;
  do {
    uVar1 = uVar1 + 1;
  } while (param_3[uVar1] != '\0');
  if (param_2 - 1 < uVar1) {
    uVar1 = param_2 - 1;
  }
  if (uVar1 != 0) {
    pcVar2 = param_1;
    _Var3 = uVar1;
    do {
      *pcVar2 = pcVar2[(longlong)param_3 - (longlong)param_1];
      pcVar2 = pcVar2 + 1;
      _Var3 = _Var3 - 1;
    } while (_Var3 != 0);
  }
  param_1[uVar1] = '\0';
  return uVar1;
}



// wchar_t * __ptr64 __cdecl Graphine::String::DuplicateString(wchar_t const * __ptr64,enum
// Graphine::AllocationCategory::Enum,struct Graphine::ContextInfo const & __ptr64)

wchar_t * __cdecl
Graphine::String::DuplicateString(wchar_t *param_1,Enum param_2,ContextInfo *param_3)

{
  short *psVar1;
  __uint64 _Size;
  short sVar2;
  Allocator *this;
  wchar_t *_Dst;
  int iVar3;
  
                    // 0x20b10  59
                    // ?DuplicateString@String@Graphine@@YAPEA_WPEB_WW4Enum@AllocationCategory@2@AEBUContextInfo@2@@Z
  if (param_1 == (wchar_t *)0x0) {
    return (wchar_t *)0x0;
  }
  iVar3 = 0;
  sVar2 = *(short *)param_1;
  psVar1 = (short *)param_1;
  while (sVar2 != 0) {
    iVar3 = iVar3 + 1;
    psVar1 = psVar1 + 1;
    sVar2 = *psVar1;
  }
  _Size = (longlong)iVar3 * 2 + 2;
  this = GetAllocator();
  _Dst = (wchar_t *)Allocator::Alloc(this,_Size,param_2,param_3);
  memcpy(_Dst,param_1,_Size);
  return _Dst;
}



// void __cdecl Graphine::String::FormatStringTrunc(wchar_t * __ptr64,int,wchar_t const *
// __ptr64,...)

void __cdecl Graphine::String::FormatStringTrunc(wchar_t *param_1,int param_2,wchar_t *param_3,...)

{
  undefined8 *puVar1;
  undefined8 in_R9;
  undefined8 local_res20;
  
                    // 0x20bb0  67  ?FormatStringTrunc@String@Graphine@@YAXPEA_WHPEB_WZZ
  local_res20 = in_R9;
  puVar1 = (undefined8 *)FUN_180020f90();
  __stdio_common_vswprintf(*puVar1,param_1,(longlong)param_2,param_3,0,&local_res20);
  *(undefined2 *)(param_1 + (longlong)(param_2 + -1) * 2) = 0;
  return;
}



// void __cdecl Graphine::String::FormatStringTruncVA(wchar_t * __ptr64,int,wchar_t const *
// __ptr64,char * __ptr64)

void __cdecl
Graphine::String::FormatStringTruncVA(wchar_t *param_1,int param_2,wchar_t *param_3,char *param_4)

{
  undefined8 *puVar1;
  
                    // 0x20c10  68  ?FormatStringTruncVA@String@Graphine@@YAXPEA_WHPEB_WPEAD@Z
  puVar1 = (undefined8 *)FUN_180020f90();
  __stdio_common_vswprintf(*puVar1,param_1,(longlong)param_2,param_3,0,param_4);
  *(undefined2 *)(param_1 + (longlong)(param_2 + -1) * 2) = 0;
  return;
}



// public: enum Graphine::Error::Enum __cdecl Graphine::String::Dynamic::Initialize(class
// Graphine::String::Dynamic const & __ptr64,enum Graphine::AllocationCategory::Enum) __ptr64

Enum __thiscall Graphine::String::Dynamic::Initialize(Dynamic *this,Dynamic *param_1,Enum param_2)

{
  uint uVar1;
  Enum EVar2;
  undefined8 uVar3;
  
                    // 0x20c80  96
                    // ?Initialize@Dynamic@String@Graphine@@QEAA?AW4Enum@Error@3@AEBV123@W44AllocationCategory@3@@Z
  uVar1 = *(uint *)(param_1 + 8);
  uVar3 = FUN_180020d50((void **)this,uVar1,0,0);
  EVar2 = (Enum)uVar3;
  if (EVar2 == 0) {
    Platform::MemoryCopy(*(void **)this,*(void **)param_1,(ulonglong)uVar1 * 2);
    EVar2 = 0;
  }
  return EVar2;
}



// public: enum Graphine::Error::Enum __cdecl Graphine::String::Dynamic::Initialize(wchar_t const *
// __ptr64,enum Graphine::AllocationCategory::Enum) __ptr64

Enum __thiscall Graphine::String::Dynamic::Initialize(Dynamic *this,wchar_t *param_1,Enum param_2)

{
  short *psVar1;
  short sVar2;
  Enum EVar3;
  undefined8 uVar4;
  uint uVar5;
  ulonglong uVar6;
  
                    // 0x20cd0  97
                    // ?Initialize@Dynamic@String@Graphine@@QEAA?AW4Enum@Error@3@PEB_WW44AllocationCategory@3@@Z
  uVar6 = 0;
  uVar5 = 0;
  if (param_1 != (wchar_t *)0x0) {
    sVar2 = *(short *)param_1;
    psVar1 = (short *)param_1;
    while (sVar2 != 0) {
      uVar5 = (int)uVar6 + 1;
      uVar6 = (ulonglong)uVar5;
      psVar1 = psVar1 + 1;
      sVar2 = *psVar1;
    }
    uVar6 = (ulonglong)(int)uVar5;
  }
  uVar4 = FUN_180020d50((void **)this,(uint)(uVar6 + 1),0,0);
  EVar3 = (Enum)uVar4;
  if (EVar3 == 0) {
    Platform::MemoryCopy(*(void **)this,param_1,(uVar6 + 1) * 2);
    EVar3 = 0;
  }
  return EVar3;
}



undefined8 FUN_180020d50(void **param_1,uint param_2,uint param_3,Enum param_4)

{
  undefined2 *puVar1;
  uint uVar2;
  undefined8 uVar3;
  Allocator *pAVar4;
  void *pvVar5;
  ulonglong uVar6;
  char *local_28;
  undefined4 local_20;
  char *local_18;
  
  if (*param_1 == (void *)0x0) {
    if (param_2 != 0) {
      local_28 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Array.h";
      local_18 = "Graphine::ArrayBase<wchar_t,1>::InitializeInternal";
      if (param_3 == 0) {
        local_20 = 0xb1;
        pAVar4 = Graphine::GetAllocator();
        pvVar5 = Graphine::Allocator::Alloc
                           (pAVar4,(ulonglong)param_2 * 2,param_4,(ContextInfo *)&local_28);
      }
      else {
        local_20 = 0xad;
        pAVar4 = Graphine::GetAllocator();
        pvVar5 = Graphine::Allocator::AllocAligned
                           (pAVar4,(ulonglong)param_2 * 2,param_3,param_4,(ContextInfo *)&local_28);
      }
      *param_1 = pvVar5;
      if (pvVar5 == (void *)0x0) {
        return 3;
      }
      uVar6 = 0;
      *(uint *)(param_1 + 1) = param_2;
      if (param_2 != 0) {
        do {
          puVar1 = (undefined2 *)((longlong)*param_1 + uVar6 * 2);
          if (puVar1 != (undefined2 *)0x0) {
            *puVar1 = 0;
          }
          uVar2 = (int)uVar6 + 1;
          uVar6 = (ulonglong)uVar2;
        } while (uVar2 < *(uint *)(param_1 + 1));
      }
    }
    uVar3 = 0;
  }
  else {
    uVar3 = 2;
  }
  return uVar3;
}



// int __cdecl Graphine::String::StringCompare(char const * __ptr64,char const * __ptr64,unsigned
// __int64)

int __cdecl Graphine::String::StringCompare(char *param_1,char *param_2,__uint64 param_3)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180020e60. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x20e60  149  ?StringCompare@String@Graphine@@YAHPEBD0_K@Z
  iVar1 = strncmp(param_1,param_2,param_3);
  return iVar1;
}



// int __cdecl Graphine::String::StringCompare(wchar_t const * __ptr64,wchar_t const * __ptr64)

int __cdecl Graphine::String::StringCompare(wchar_t *param_1,wchar_t *param_2)

{
  ushort *puVar1;
  ushort uVar2;
  longlong lVar3;
  
                    // 0x20e70  150  ?StringCompare@String@Graphine@@YAHPEB_W0@Z
  lVar3 = (longlong)param_2 - (longlong)param_1;
  do {
    uVar2 = *(ushort *)param_1;
    puVar1 = (ushort *)((longlong)param_1 + lVar3);
    if (uVar2 != *puVar1) {
      return -(uint)(uVar2 < *puVar1) | 1;
    }
    param_1 = (wchar_t *)((longlong)param_1 + 2);
  } while (uVar2 != 0);
  return 0;
}



// bool __cdecl Graphine::String::UTF16ToUTF32(unsigned short const * __ptr64,unsigned
// __int64,unsigned __int64,unsigned int * __ptr64)

bool __cdecl
Graphine::String::UTF16ToUTF32(ushort *param_1,__uint64 param_2,__uint64 param_3,uint *param_4)

{
  ushort *puVar1;
  ushort uVar2;
  ushort *puVar3;
  int iVar4;
  
                    // 0x20e90  158  ?UTF16ToUTF32@String@Graphine@@YA_NPEBG_K1PEAI@Z
  iVar4 = 0;
  puVar1 = param_1 + param_2;
  if (param_1 < puVar1) {
    do {
      if (param_3 <= (ulonglong)(longlong)iVar4) break;
      uVar2 = *param_1;
      puVar3 = param_1 + 1;
      if (uVar2 < 0xe000) {
        if ((((uVar2 & 0xfffffc00) != 0xd800) || (puVar1 <= puVar3)) ||
           ((*puVar3 & 0xfffffc00) != 0xdc00)) {
          return false;
        }
        *param_4 = *puVar3 + 0xfca02400 + (uint)uVar2 * 0x400;
        puVar3 = param_1 + 2;
      }
      else {
        *param_4 = (uint)uVar2;
      }
      param_4 = param_4 + 1;
      iVar4 = iVar4 + 1;
      param_1 = puVar3;
    } while (puVar3 < puVar1);
  }
  if ((ulonglong)(longlong)iVar4 < param_3) {
    param_4[iVar4] = 0;
    return true;
  }
  param_4[param_3 - 1] = 0;
  return true;
}



// bool __cdecl Graphine::String::WideCharToMultiByteTruncate(char * __ptr64,unsigned
// __int64,unsigned __int64 & __ptr64,wchar_t const * __ptr64)

bool __cdecl
Graphine::String::WideCharToMultiByteTruncate
          (char *param_1,__uint64 param_2,__uint64 *param_3,wchar_t *param_4)

{
  size_t sVar1;
  uint7 extraout_var;
  
                    // 0x20f40  162
                    // ?WideCharToMultiByteTruncate@String@Graphine@@YA_NPEAD_KAEA_KPEB_W@Z
  sVar1 = wcstombs(param_1,(wchar_t *)param_4,param_2 - 1);
  if ((sVar1 & 0xff | (ulonglong)extraout_var << 8) == 0xffffffffffffffff) {
    return false;
  }
  param_1[sVar1 & 0xff | (ulonglong)extraout_var << 8] = '\0';
  *param_3 = sVar1 & 0xff | (ulonglong)extraout_var << 8;
  return true;
}



undefined * FUN_180020f90(void)

{
  return &DAT_18007b198;
}



// unsigned int __cdecl Graphine::Graphics::CalculateRectanglePitch(enum
// Graphine::Graphics::TextureFormat::Enum,unsigned int)

uint __cdecl Graphine::Graphics::CalculateRectanglePitch(Enum param_1,uint param_2)

{
  uint local_res18 [2];
  uint local_res20 [2];
  
                    // 0x20fa0  44
                    // ?CalculateRectanglePitch@Graphics@Graphine@@YAIW4Enum@TextureFormat@12@I@Z
  local_res18[0] = 0;
  CalculateSubrectangleOffsetAndPitch(param_1,param_2,0x80,0,0,local_res20,local_res18);
  return local_res18[0];
}



// void __cdecl Graphine::Graphics::CalculateSubrectangleOffsetAndPitch(enum
// Graphine::Graphics::TextureFormat::Enum,unsigned int,unsigned int,unsigned int,unsigned
// int,unsigned int & __ptr64,unsigned int & __ptr64)

void __cdecl
Graphine::Graphics::CalculateSubrectangleOffsetAndPitch
          (Enum param_1,uint param_2,uint param_3,uint param_4,uint param_5,uint *param_6,
          uint *param_7)

{
  uint uVar1;
  uint uVar2;
  
                    // 0x20fe0  45
                    // ?CalculateSubrectangleOffsetAndPitch@Graphics@Graphine@@YAXW4Enum@TextureFormat@12@IIIIAEAI1@Z
  uVar1 = 0;
  uVar2 = 0;
  switch(param_1) {
  case 0:
  case 0xb:
    *param_6 = (param_2 * param_5 + param_4) * 4;
    *param_7 = param_2 * 4;
    return;
  case 1:
  case 0xc:
    *param_6 = (param_2 * param_5 + param_4) * 8;
    *param_7 = param_2 * 8;
    return;
  case 2:
    *param_6 = (param_2 * param_5 + param_4) * 0x10;
    *param_7 = param_2 << 4;
    return;
  case 3:
  case 8:
    *param_6 = ((param_2 >> 2) * (param_5 >> 2) + (param_4 >> 2)) * 8;
    *param_7 = (param_2 + 3 >> 2) << 3;
    return;
  case 4:
  case 5:
  case 6:
  case 7:
  case 9:
    *param_6 = ((param_2 >> 2) * (param_5 >> 2) + (param_4 >> 2)) * 0x10;
    *param_7 = (param_2 + 3 >> 2) << 4;
    return;
  case 10:
    *param_6 = ((param_2 >> 3) * (param_5 >> 3) + (param_4 >> 3)) * 0x10;
    *param_7 = (param_2 + 7 >> 3) << 4;
    return;
  case 0xd:
    uVar1 = (param_2 * param_5 + param_4) * 0xc;
    uVar2 = param_2 * 0xc;
  }
  *param_6 = uVar1;
  *param_7 = uVar2;
  return;
}



// enum Graphine::Error::Enum __cdecl Graphine::Graphics::ExtractRectangle(enum
// Graphine::Graphics::TextureFormat::Enum,void * __ptr64,unsigned int,unsigned int,void *
// __ptr64,unsigned int,unsigned int,unsigned int,unsigned int)

Enum __cdecl
Graphine::Graphics::ExtractRectangle
          (Enum param_1,void *param_2,uint param_3,uint param_4,void *param_5,uint param_6,
          uint param_7,uint param_8,uint param_9)

{
  ulonglong uVar1;
  ulonglong uVar2;
  __uint64 _Var3;
  void *pvVar4;
  int iVar5;
  int iVar6;
  Enum EVar7;
  
                    // 0x211a0  63
                    // ?ExtractRectangle@Graphics@Graphine@@YA?AW4Enum@Error@2@W43TextureFormat@12@PEAXII1IIII@Z
  if (((((param_2 == (void *)0x0) || (param_5 == (void *)0x0)) || (param_3 == 0)) ||
      ((param_4 == 0 || (param_6 < param_3)))) || (param_7 < param_4)) {
    return 1;
  }
  switch(param_1) {
  case 0:
  case 0xb:
    iVar5 = 4;
    break;
  case 1:
  case 0xc:
    iVar5 = 8;
    break;
  case 2:
    iVar5 = 0x10;
    break;
  case 3:
  case 8:
    uVar1 = 4;
    iVar5 = 8;
    goto LAB_18002125d;
  case 4:
  case 5:
  case 6:
  case 7:
    uVar1 = 4;
    iVar5 = 0x10;
    goto LAB_18002125d;
  default:
    goto switchD_180021222_caseD_9;
  case 0xd:
    iVar5 = 0xc;
  }
  uVar1 = 1;
LAB_18002125d:
  if (((int)((ulonglong)param_8 % uVar1) == 0) && ((int)((ulonglong)param_9 % uVar1) == 0)) {
    uVar2 = param_4 / uVar1;
    iVar6 = (int)(param_6 / uVar1) * iVar5;
    pvVar4 = (void *)((longlong)param_5 +
                     (ulonglong)(uint)((int)(param_8 / uVar1) * iVar5) +
                     (ulonglong)(uint)((int)(param_9 / uVar1) * iVar6));
    EVar7 = 0;
    if (0 < (int)uVar2) {
      _Var3 = (__uint64)((int)(param_3 / uVar1) * iVar5);
      do {
        Platform::MemoryCopy(param_2,pvVar4,_Var3);
        pvVar4 = (void *)((longlong)pvVar4 + (longlong)iVar6);
        param_2 = (void *)((longlong)param_2 + _Var3);
        uVar2 = uVar2 - 1;
        EVar7 = 0;
      } while (uVar2 != 0);
    }
  }
  else {
switchD_180021222_caseD_9:
    EVar7 = 7;
  }
  return EVar7;
}



// unsigned int __cdecl Graphine::Graphics::GetBlockHeight(enum
// Graphine::Graphics::TextureFormat::Enum)

uint __cdecl Graphine::Graphics::GetBlockHeight(Enum param_1)

{
                    // 0x21350  72  ?GetBlockHeight@Graphics@Graphine@@YAIW4Enum@TextureFormat@12@@Z
  switch(param_1) {
  case 0:
  case 1:
  case 2:
  case 0xb:
  case 0xc:
  case 0xd:
    return 1;
  case 3:
  case 4:
  case 5:
  case 6:
  case 7:
  case 8:
  case 9:
    return 4;
  case 10:
    return 8;
  default:
    return 0;
  }
}



// unsigned int __cdecl Graphine::Graphics::GetBlockSizeBytes(enum
// Graphine::Graphics::TextureFormat::Enum)

uint __cdecl Graphine::Graphics::GetBlockSizeBytes(Enum param_1)

{
                    // 0x21360  73
                    // ?GetBlockSizeBytes@Graphics@Graphine@@YAIW4Enum@TextureFormat@12@@Z
  switch(param_1) {
  case 0:
  case 0xb:
    return 4;
  case 1:
  case 3:
  case 8:
  case 0xc:
    return 8;
  case 2:
  case 4:
  case 5:
  case 6:
  case 7:
  case 9:
  case 10:
    return 0x10;
  case 0xd:
    return 0xc;
  default:
    return 0;
  }
}



// unsigned int __cdecl Graphine::Graphics::GetBlockWidth(enum
// Graphine::Graphics::TextureFormat::Enum)

uint __cdecl Graphine::Graphics::GetBlockWidth(Enum param_1)

{
                    // 0x213d0  74  ?GetBlockWidth@Graphics@Graphine@@YAIW4Enum@TextureFormat@12@@Z
  switch(param_1) {
  case 0:
  case 1:
  case 2:
  case 0xb:
  case 0xc:
  case 0xd:
    return 1;
  case 3:
  case 4:
  case 5:
  case 6:
  case 7:
  case 8:
  case 9:
    return 4;
  case 10:
    return 8;
  default:
    return 0;
  }
}



// unsigned __int64 __cdecl Graphine::Graphics::GetRectangleSize(enum
// Graphine::Graphics::TextureFormat::Enum,int,int)

__uint64 __cdecl Graphine::Graphics::GetRectangleSize(Enum param_1,int param_2,int param_3)

{
  longlong lVar1;
  
                    // 0x21440  84
                    // ?GetRectangleSize@Graphics@Graphine@@YA_KW4Enum@TextureFormat@12@HH@Z
  lVar1 = (longlong)param_3;
  switch(param_1) {
  case 0:
  case 0xb:
    return param_2 * lVar1 * 4;
  case 1:
  case 0xc:
    return param_2 * lVar1 * 8;
  case 2:
    return param_2 * lVar1 * 0x10;
  case 3:
  case 8:
    return (longlong)((int)(param_3 + 3 + (param_3 + 3 >> 0x1f & 3U)) >> 2) *
           (longlong)((int)(param_2 + 3 + (param_2 + 3 >> 0x1f & 3U)) >> 2) * 8;
  case 4:
  case 5:
  case 6:
  case 7:
  case 9:
    return (longlong)((int)(param_3 + 3 + (param_3 + 3 >> 0x1f & 3U)) >> 2) *
           (longlong)((int)(param_2 + 3 + (param_2 + 3 >> 0x1f & 3U)) >> 2) * 0x10;
  case 10:
    return (longlong)((int)(param_3 + 7 + (param_3 + 7 >> 0x1f & 7U)) >> 3) *
           (longlong)((int)(param_2 + 7 + (param_2 + 7 >> 0x1f & 7U)) >> 3) * 0x10;
  case 0xd:
    return param_2 * lVar1 * 0xc;
  default:
    return 0;
  }
}



// wchar_t const * __ptr64 __cdecl Graphine::Graphics::TextureChannelTransform::ToString(enum
// Graphine::Graphics::TextureChannelTransform::Enum)

wchar_t * __cdecl Graphine::Graphics::TextureChannelTransform::ToString(Enum param_1)

{
  Enum EVar1;
  
                    // 0x21550  155
                    // ?ToString@TextureChannelTransform@Graphics@Graphine@@YAPEB_WW4Enum@123@@Z
  EVar1 = 7;
  if ((int)param_1 < 8) {
    EVar1 = param_1;
  }
  return (wchar_t *)(&PTR_u_UINT_180032240)[(int)EVar1];
}



// wchar_t const * __ptr64 __cdecl Graphine::Graphics::TextureFormat::ToString(enum
// Graphine::Graphics::TextureFormat::Enum)

wchar_t * __cdecl Graphine::Graphics::TextureFormat::ToString(Enum param_1)

{
  Enum EVar1;
  
                    // 0x21570  156  ?ToString@TextureFormat@Graphics@Graphine@@YAPEB_WW4Enum@123@@Z
  EVar1 = 0xe;
  if ((int)param_1 < 0xf) {
    EVar1 = param_1;
  }
  return (wchar_t *)(&PTR_u_R8G8B8A8_1800321c0)[(int)EVar1];
}



void FUN_180021590(undefined8 *param_1)

{
  int iVar1;
  undefined auStack_248 [32];
  undefined4 local_228 [4];
  undefined8 local_218;
  undefined8 local_210;
  ulonglong local_18;
  
  local_18 = DAT_180032820 ^ (ulonglong)auStack_248;
  iVar1 = FUN_180001320();
  if (iVar1 == 0) {
    memset(&local_218,0,0x200);
    local_228[0] = 0;
    iVar1 = FUN_180002720(&local_218,local_228);
    if (iVar1 == 0) {
      *param_1 = local_218;
      param_1[1] = local_210;
    }
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_248);
  return;
}



// public: void __cdecl Graphine::WindowsGraphicsDriver::Initialize(void) __ptr64

void __thiscall Graphine::WindowsGraphicsDriver::Initialize(WindowsGraphicsDriver *this)

{
  int iVar1;
  undefined auStack_248 [32];
  undefined4 auStack_228 [4];
  undefined8 uStack_218;
  undefined8 uStack_210;
  ulonglong uStack_18;
  
  uStack_18 = DAT_180032820 ^ (ulonglong)auStack_248;
  iVar1 = FUN_180001320();
  if (iVar1 == 0) {
    memset(&uStack_218,0,0x200);
    auStack_228[0] = 0;
    iVar1 = FUN_180002720(&uStack_218,auStack_228);
    if (iVar1 == 0) {
      *(undefined8 *)this = uStack_218;
      *(undefined8 *)(this + 8) = uStack_210;
    }
  }
  __security_check_cookie(uStack_18 ^ (ulonglong)auStack_248);
  return;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_180021620(longlong *param_1)

{
  char cVar1;
  int iVar2;
  longlong *plVar3;
  PerformanceMonitor *pPVar4;
  undefined auStack_48 [32];
  undefined4 local_28;
  undefined8 local_24;
  undefined8 local_1c;
  int local_14;
  ulonglong local_10;
  
  local_10 = DAT_180032820 ^ (ulonglong)auStack_48;
  local_28 = 0x20018;
  local_24 = 0;
  local_1c = 0;
  local_14 = 0;
  plVar3 = (longlong *)Graphine::Performance::GetPerformanceMonitor();
  cVar1 = (**(code **)(*plVar3 + 0x50))(plVar3);
  if (cVar1 != '\0') {
    if (*param_1 != 0) {
      iVar2 = FUN_180001ff0(*param_1,&local_28);
      if (iVar2 == 0) {
        if (*(char *)(param_1 + 2) != '\0') {
          pPVar4 = Graphine::Performance::GetPerformanceMonitor();
          Graphine::Performance::PerformanceMonitor::CounterSet
                    (pPVar4,SUB41(DAT_18007b1a0,0),(int)local_24);
          pPVar4 = Graphine::Performance::GetPerformanceMonitor();
          Graphine::Performance::PerformanceMonitor::CounterSet
                    (pPVar4,SUB41(DAT_18007b1c4,0),local_24._4_4_);
          pPVar4 = Graphine::Performance::GetPerformanceMonitor();
          Graphine::Performance::PerformanceMonitor::CounterSet
                    (pPVar4,SUB41(DAT_18007b1a4,0),local_1c._4_4_);
          pPVar4 = Graphine::Performance::GetPerformanceMonitor();
          Graphine::Performance::PerformanceMonitor::CounterSet
                    (pPVar4,SUB41(DAT_18007b1b4,0),(int)local_1c);
        }
        pPVar4 = Graphine::Performance::GetPerformanceMonitor();
        Graphine::Performance::PerformanceMonitor::CounterSet
                  (pPVar4,SUB41(DAT_18007b1bc,0),local_14);
      }
      if (*param_1 != 0) {
        iVar2 = FUN_180001ff0(param_1[1],&local_28);
        if (iVar2 == 0) {
          if (*(char *)(param_1 + 2) != '\0') {
            pPVar4 = Graphine::Performance::GetPerformanceMonitor();
            Graphine::Performance::PerformanceMonitor::CounterSet
                      (pPVar4,SUB41(DAT_18007b1ac,0),(int)local_24);
            pPVar4 = Graphine::Performance::GetPerformanceMonitor();
            Graphine::Performance::PerformanceMonitor::CounterSet
                      (pPVar4,SUB41(DAT_18007b1a8,0),local_14);
          }
          pPVar4 = Graphine::Performance::GetPerformanceMonitor();
          Graphine::Performance::PerformanceMonitor::CounterSet
                    (pPVar4,SUB41(DAT_18007b1b0,0),local_24._4_4_);
        }
      }
    }
    *(undefined *)(param_1 + 2) = 0;
  }
  __security_check_cookie(local_10 ^ (ulonglong)auStack_48);
  return;
}



// WARNING: Could not reconcile some variable overlaps
// public: void __cdecl Graphine::WindowsGraphicsDriver::Tick(void) __ptr64

void __thiscall Graphine::WindowsGraphicsDriver::Tick(WindowsGraphicsDriver *this)

{
  char cVar1;
  int iVar2;
  longlong *plVar3;
  PerformanceMonitor *pPVar4;
  undefined auStack_48 [32];
  undefined4 uStack_28;
  undefined8 uStack_24;
  undefined8 uStack_1c;
  int iStack_14;
  ulonglong uStack_10;
  
  uStack_10 = DAT_180032820 ^ (ulonglong)auStack_48;
  uStack_28 = 0x20018;
  uStack_24 = 0;
  uStack_1c = 0;
  iStack_14 = 0;
  plVar3 = (longlong *)Performance::GetPerformanceMonitor();
  cVar1 = (**(code **)(*plVar3 + 0x50))(plVar3);
  if (cVar1 != '\0') {
    if (*(longlong *)this != 0) {
      iVar2 = FUN_180001ff0(*(longlong *)this,&uStack_28);
      if (iVar2 == 0) {
        if (this[0x10] != (WindowsGraphicsDriver)0x0) {
          pPVar4 = Performance::GetPerformanceMonitor();
          Performance::PerformanceMonitor::CounterSet(pPVar4,SUB41(DAT_18007b1a0,0),(int)uStack_24);
          pPVar4 = Performance::GetPerformanceMonitor();
          Performance::PerformanceMonitor::CounterSet(pPVar4,SUB41(DAT_18007b1c4,0),uStack_24._4_4_)
          ;
          pPVar4 = Performance::GetPerformanceMonitor();
          Performance::PerformanceMonitor::CounterSet(pPVar4,SUB41(DAT_18007b1a4,0),uStack_1c._4_4_)
          ;
          pPVar4 = Performance::GetPerformanceMonitor();
          Performance::PerformanceMonitor::CounterSet(pPVar4,SUB41(DAT_18007b1b4,0),(int)uStack_1c);
        }
        pPVar4 = Performance::GetPerformanceMonitor();
        Performance::PerformanceMonitor::CounterSet(pPVar4,SUB41(DAT_18007b1bc,0),iStack_14);
      }
      if (*(longlong *)this != 0) {
        iVar2 = FUN_180001ff0(*(undefined8 *)(this + 8),&uStack_28);
        if (iVar2 == 0) {
          if (this[0x10] != (WindowsGraphicsDriver)0x0) {
            pPVar4 = Performance::GetPerformanceMonitor();
            Performance::PerformanceMonitor::CounterSet
                      (pPVar4,SUB41(DAT_18007b1ac,0),(int)uStack_24);
            pPVar4 = Performance::GetPerformanceMonitor();
            Performance::PerformanceMonitor::CounterSet(pPVar4,SUB41(DAT_18007b1a8,0),iStack_14);
          }
          pPVar4 = Performance::GetPerformanceMonitor();
          Performance::PerformanceMonitor::CounterSet(pPVar4,SUB41(DAT_18007b1b0,0),uStack_24._4_4_)
          ;
        }
      }
    }
    this[0x10] = (WindowsGraphicsDriver)0x0;
  }
  __security_check_cookie(uStack_10 ^ (ulonglong)auStack_48);
  return;
}



// wchar_t const * __ptr64 __cdecl Graphine::Error::ToString(enum Graphine::Error::Enum)

wchar_t * __cdecl Graphine::Error::ToString(Enum param_1)

{
  Enum EVar1;
  
                    // 0x21790  153  ?ToString@Error@Graphine@@YAPEB_WW4Enum@12@@Z
  EVar1 = 0xc;
  if ((int)param_1 < 0xd) {
    EVar1 = param_1;
  }
  return (wchar_t *)(&PTR_DAT_1800322a0)[(int)EVar1];
}



// bool __cdecl Graphine::LayerDataType::IsLinear(enum Graphine::LayerDataType::Enum)

bool __cdecl Graphine::LayerDataType::IsLinear(Enum param_1)

{
                    // 0x217b0  108  ?IsLinear@LayerDataType@Graphine@@YA_NW4Enum@12@@Z
  return 1 < param_1;
}



// wchar_t const * __ptr64 __cdecl Graphine::LayerDataType::ToString(enum
// Graphine::LayerDataType::Enum)

wchar_t * __cdecl Graphine::LayerDataType::ToString(Enum param_1)

{
                    // 0x217c0  154  ?ToString@LayerDataType@Graphine@@YAPEB_WW4Enum@12@@Z
  switch(param_1) {
  case 0:
    return (wchar_t *)L"R8G8B8_SRGB";
  case 1:
    return (wchar_t *)L"R8G8B8A8_SRGB";
  case 2:
    return (wchar_t *)L"X8Y8Z0_TANGENT";
  case 3:
    return (wchar_t *)L"R8G8B8_LINEAR";
  case 4:
    return (wchar_t *)L"R8G8B8A8_LINEAR";
  case 5:
    return (wchar_t *)&DAT_18002b0a0;
  case 6:
    return (wchar_t *)L"X8Y8";
  case 7:
    return (wchar_t *)L"X8Y8Z8";
  case 8:
    return (wchar_t *)L"X8Y8Z8W8";
  case 9:
    return (wchar_t *)&DAT_18002b0e0;
  case 10:
    return (wchar_t *)L"X16Y16";
  case 0xb:
    return (wchar_t *)L"X16Y16Z16";
  case 0xc:
    return (wchar_t *)L"X16Y16Z16W16";
  case 0xd:
    return (wchar_t *)&DAT_18002b130;
  case 0xe:
    return (wchar_t *)L"X32_FLOAT";
  case 0xf:
    return (wchar_t *)L"X32Y32";
  case 0x10:
    return (wchar_t *)L"X32Y32_FLOAT";
  case 0x11:
    return (wchar_t *)L"X32Y32Z32";
  case 0x12:
    return (wchar_t *)L"X32Y32Z32_FLOAT";
  case 0x13:
    return (wchar_t *)L"R32G32B32";
  case 0x14:
    return (wchar_t *)L"R32G32B32_FLOAT";
  case 0x15:
    return (wchar_t *)L"X32Y32Z32W32";
  case 0x16:
    return (wchar_t *)L"X32Y32Z32W32_FLOAT";
  case 0x17:
    return (wchar_t *)L"R32G32B32A32";
  case 0x18:
    return (wchar_t *)L"R32G32B32A32_FLOAT";
  case 0x19:
    return (wchar_t *)L"R16G16B16_FLOAT";
  case 0x1a:
    return (wchar_t *)L"R16G16B16A16_FLOAT";
  default:
    return (wchar_t *)L"Unknown";
  case 0xffffffff:
    return (wchar_t *)L"ForceUnsignedInt";
  }
}



void FUN_180021940(void **param_1)

{
  FUN_180021a10(param_1);
  return;
}



undefined8 FUN_180021960(void **param_1,uint param_2)

{
  Allocator *this;
  void *pvVar1;
  uint uVar2;
  char *local_28;
  undefined4 local_20;
  char *local_18;
  
  if (*param_1 != (void *)0x0) {
    return 2;
  }
  if (param_2 != 0) {
    local_28 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Array.h";
    local_18 = "Graphine::ArrayBase<unsigned char,1>::InitializeInternal";
    local_20 = 0xb1;
    this = Graphine::GetAllocator();
    pvVar1 = Graphine::Allocator::Alloc(this,(ulonglong)param_2,0,(ContextInfo *)&local_28);
    *param_1 = pvVar1;
    if (pvVar1 == (void *)0x0) {
      return 3;
    }
    uVar2 = 0;
    *(uint *)(param_1 + 1) = param_2;
    if (param_2 != 0) {
      do {
        if ((undefined *)((ulonglong)uVar2 + (longlong)*param_1) != (undefined *)0x0) {
          *(undefined *)((ulonglong)uVar2 + (longlong)*param_1) = 0;
        }
        uVar2 = uVar2 + 1;
      } while (uVar2 < *(uint *)(param_1 + 1));
    }
  }
  return 0;
}



void FUN_180021a10(void **param_1)

{
  void *pvVar1;
  Allocator *this;
  char *local_28;
  undefined4 local_20;
  char *local_18;
  
  pvVar1 = *param_1;
  if (pvVar1 != (void *)0x0) {
    local_20 = 0xd3;
    local_28 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Array.h";
    local_18 = "Graphine::ArrayBase<unsigned char,1>::ReleaseInternal";
    this = Graphine::GetAllocator();
    Graphine::Allocator::Free(this,pvVar1,(ContextInfo *)&local_28);
    *param_1 = (void *)0x0;
    *(undefined4 *)(param_1 + 1) = 0;
    return;
  }
  *param_1 = (void *)0x0;
  *(undefined4 *)(param_1 + 1) = 0;
  return;
}



// enum Graphine::Error::Enum __cdecl Graphine::Utilities::BmpFile::WriteBitmap(void *
// __ptr64,unsigned int,unsigned int,unsigned int,class Graphine::Array<unsigned char> & __ptr64)

Enum __cdecl
Graphine::Utilities::BmpFile::WriteBitmap
          (void *param_1,uint param_2,uint param_3,uint param_4,Array_unsigned_char_ *param_5)

{
  Enum EVar1;
  undefined8 uVar2;
  uint uVar3;
  undefined2 local_58;
  uint local_56;
  undefined4 local_52;
  undefined4 local_4e;
  undefined4 local_48;
  uint local_44;
  uint local_40;
  undefined2 local_3c;
  short local_3a;
  undefined4 local_38;
  uint local_34;
  undefined4 local_30;
  undefined8 local_2c;
  undefined4 local_24;
  
                    // 0x21a80  169
                    // ?WriteBitmap@BmpFile@Utilities@Graphine@@YA?AW4Enum@Error@3@PEAXIIIAEAV?$Array@E@3@@Z
  if ((((param_4 - 1 < 4) && (param_2 != 0)) && (param_3 != 0)) && (param_1 != (void *)0x0)) {
    uVar3 = param_2 * param_3 * param_4;
    local_56 = uVar3 + 0x36;
    uVar2 = FUN_180021960((void **)param_5,local_56);
    EVar1 = (Enum)uVar2;
    if (EVar1 == 0) {
      local_3a = (short)param_4 << 3;
      local_52 = 0;
      local_58 = 0x4d42;
      local_38 = 0;
      local_24 = 0;
      local_4e = 0x36;
      local_48 = 0x28;
      local_3c = 1;
      local_30 = 0x48;
      local_2c = 0x48;
      local_44 = param_2;
      local_40 = param_3;
      local_34 = uVar3;
      Platform::MemoryCopy(*(void **)param_5,&local_58,0xe);
      Platform::MemoryCopy((void *)(*(longlong *)param_5 + 0xe),&local_48,0x28);
      Platform::MemoryCopy((void *)(*(longlong *)param_5 + 0x36),param_1,(ulonglong)uVar3);
      EVar1 = 0;
    }
    return EVar1;
  }
  return 1;
}



// enum Graphine::Error::Enum __cdecl Graphine::Utilities::BmpFile::WriteBitmap(void *
// __ptr64,unsigned int,unsigned int,unsigned int,wchar_t const * __ptr64)

Enum __cdecl
Graphine::Utilities::BmpFile::WriteBitmap
          (void *param_1,uint param_2,uint param_3,uint param_4,wchar_t *param_5)

{
  Enum EVar1;
  Enum extraout_EAX;
  undefined8 uVar2;
  Allocator *this;
  undefined auStackY_c8 [32];
  LPCVOID local_98;
  uint local_90;
  char *local_88;
  undefined4 local_80;
  char *local_78;
  undefined8 local_70;
  undefined **local_68 [8];
  ulonglong local_28;
  
                    // 0x21bd0  170
                    // ?WriteBitmap@BmpFile@Utilities@Graphine@@YA?AW4Enum@Error@3@PEAXIIIPEB_W@Z
  local_70 = 0xfffffffffffffffe;
  local_28 = DAT_180032820 ^ (ulonglong)auStackY_c8;
  local_98 = (LPCVOID)0x0;
  local_90 = 0;
  EVar1 = WriteBitmap(param_1,param_2,param_3,param_4,(Array_unsigned_char_ *)&local_98);
  if (EVar1 == 0) {
    FUN_180022de0(local_68);
    uVar2 = FUN_180022f10((longlong)local_68,(LPCWSTR)param_5);
    if ((int)uVar2 == 0) {
      FUN_180023020((longlong)local_68,local_98,(ulonglong)local_90);
      FUN_180022fe0((longlong)local_68);
      FUN_180022ea0((longlong)local_68);
    }
    local_68[0] = IAsyncWriter<class_Graphine::AsyncWriter_Windows>::vftable;
    FUN_180022ea0((longlong)local_68);
  }
  if (local_98 != (LPCVOID)0x0) {
    local_88 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Array.h";
    local_80 = 0xd3;
    local_78 = "Graphine::ArrayBase<unsigned char,1>::ReleaseInternal";
    this = GetAllocator();
    Allocator::Free(this,local_98,(ContextInfo *)&local_88);
  }
  __security_check_cookie(local_28 ^ (ulonglong)auStackY_c8);
  return extraout_EAX;
}



undefined8 * FUN_180021ce0(undefined8 *param_1,undefined4 param_2)

{
  *param_1 = 0;
  *(undefined4 *)(param_1 + 1) = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  *(undefined4 *)(param_1 + 7) = 0;
  *(undefined4 *)(param_1 + 8) = param_2;
  InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)((longlong)param_1 + 0x44),1000);
  return param_1;
}



// public: __cdecl Graphine::Platform::CriticalSection::CriticalSection(void) __ptr64

CriticalSection * __thiscall
Graphine::Platform::CriticalSection::CriticalSection(CriticalSection *this)

{
                    // 0x21d30  2  ??0CriticalSection@Platform@Graphine@@QEAA@XZ
  InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)this,1000);
  return this;
}



// public: __cdecl Graphine::Platform::JobSystem::JobSystem(void) __ptr64

JobSystem * __thiscall Graphine::Platform::JobSystem::JobSystem(JobSystem *this)

{
                    // 0x21d50  7  ??0JobSystem@Platform@Graphine@@QEAA@XZ
  *(undefined8 *)(this + 0x118) = 0;
  this[0x120] = (JobSystem)0x0;
  *(undefined8 *)(this + 0x128) = 0;
  *(undefined8 *)(this + 0x130) = 0;
  *(undefined8 *)(this + 0x138) = 0;
  return this;
}



// public: __cdecl Graphine::Platform::TLSVariable::TLSVariable(void) __ptr64

TLSVariable * __thiscall Graphine::Platform::TLSVariable::TLSVariable(TLSVariable *this)

{
                    // 0x21d80  10  ??0TLSVariable@Platform@Graphine@@QEAA@XZ
  *(undefined4 *)this = 0xffffffff;
  return this;
}



// public: __cdecl Graphine::Platform::CriticalSection::~CriticalSection(void) __ptr64

void __thiscall Graphine::Platform::CriticalSection::_CriticalSection(CriticalSection *this)

{
                    // WARNING: Could not recover jumptable at 0x000180021d90. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x21d90  11  ??1CriticalSection@Platform@Graphine@@QEAA@XZ
  DeleteCriticalSection((LPCRITICAL_SECTION)this);
  return;
}



// public: __cdecl Graphine::Platform::JobSystem::~JobSystem(void) __ptr64

void __thiscall Graphine::Platform::JobSystem::_JobSystem(JobSystem *this)

{
  void **ppvVar1;
  
                    // 0x21da0  14  ??1JobSystem@Platform@Graphine@@QEAA@XZ
  Stop(this);
  ppvVar1 = *(void ***)(this + 0x118);
  if (ppvVar1 != (void **)0x0) {
    DeleteCriticalSection((LPCRITICAL_SECTION)((longlong)ppvVar1 + 0x44));
    ppvVar1[5] = (void *)0x0;
    ppvVar1[6] = (void *)0x0;
    *(undefined4 *)(ppvVar1 + 7) = 0;
    ppvVar1[2] = (void *)0x0;
    ppvVar1[3] = (void *)0x0;
    *(undefined4 *)(ppvVar1 + 4) = 0;
    FUN_180022ac0(ppvVar1);
    FUN_180021e60(ppvVar1);
    return;
  }
  return;
}



void FUN_180021e10(__uint64 param_1)

{
  Allocator *this;
  char *local_28;
  undefined4 local_20;
  char *local_18;
  
  local_20 = 0x18;
  local_28 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Queue.h";
  local_18 = "Graphine::Queue<void *>::operator new";
  this = Graphine::GetAllocator();
  Graphine::Allocator::Alloc(this,param_1,0,(ContextInfo *)&local_28);
  return;
}



void FUN_180021e60(void *param_1)

{
  Allocator *this;
  char *local_20;
  undefined4 local_18;
  char *local_10;
  
  local_20 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Queue.h";
  local_18 = 0x18;
  local_10 = "Graphine::Queue<void *>::operator delete";
  this = Graphine::GetAllocator();
  Graphine::Allocator::Free(this,param_1,(ContextInfo *)&local_20);
  return;
}



void FUN_180021eb0(longlong param_1)

{
  longlong lVar1;
  
  lVar1 = FUN_180022300(*(longlong *)(param_1 + 0x118),*(undefined **)(param_1 + 0x110));
  if (lVar1 != 0) {
                    // WARNING: Could not recover jumptable at 0x000180021ee0. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(param_1 + 0x100))(lVar1);
    return;
  }
  return;
}



// void * __ptr64 __cdecl Graphine::Platform::AlignedAlloc(unsigned __int64,unsigned __int64)

void * __cdecl Graphine::Platform::AlignedAlloc(__uint64 param_1,__uint64 param_2)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180021ef0. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x21ef0  38  ?AlignedAlloc@Platform@Graphine@@YAPEAX_K0@Z
  pvVar1 = _aligned_malloc(param_1,param_2);
  return pvVar1;
}



// void __cdecl Graphine::Platform::AlignedFree(void * __ptr64)

void __cdecl Graphine::Platform::AlignedFree(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x000180021f00. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x21f00  39  ?AlignedFree@Platform@Graphine@@YAXPEAX@Z
  _aligned_free(param_1);
  return;
}



// enum Graphine::Error::Enum __cdecl Graphine::Platform::CloseFile(void * __ptr64)

Enum __cdecl Graphine::Platform::CloseFile(void *param_1)

{
                    // 0x21f10  46  ?CloseFile@Platform@Graphine@@YA?AW4Enum@Error@2@PEAX@Z
  CloseHandle(param_1);
  return 0;
}



// public: void __cdecl Graphine::Platform::TLSVariable::Destroy(void) __ptr64

void __thiscall Graphine::Platform::TLSVariable::Destroy(TLSVariable *this)

{
                    // 0x21f30  58  ?Destroy@TLSVariable@Platform@Graphine@@QEAAXXZ
  TlsFree(*(DWORD *)this);
  *(undefined4 *)this = 0xffffffff;
  return;
}



// public: void __cdecl Graphine::Platform::CriticalSection::Enter(void) __ptr64

void __thiscall Graphine::Platform::CriticalSection::Enter(CriticalSection *this)

{
  BOOL BVar1;
  
                    // 0x21f50  61  ?Enter@CriticalSection@Platform@Graphine@@QEAAXXZ
  BVar1 = TryEnterCriticalSection((LPCRITICAL_SECTION)this);
  if (BVar1 == 0) {
                    // WARNING: Could not recover jumptable at 0x000180021f6b. Too many branches
                    // WARNING: Treating indirect jump as call
    EnterCriticalSection((LPCRITICAL_SECTION)this);
    return;
  }
  return;
}



// public: void __cdecl Graphine::Platform::JobSystem::ExecuteJob(void) __ptr64

void __thiscall Graphine::Platform::JobSystem::ExecuteJob(JobSystem *this)

{
  longlong lVar1;
  
                    // 0x21f80  62  ?ExecuteJob@JobSystem@Platform@Graphine@@QEAAXXZ
  lVar1 = FUN_180022300(*(longlong *)(this + 0x118),*(undefined **)(this + 0x110));
  if (lVar1 != 0) {
                    // WARNING: Could not recover jumptable at 0x000180021fb0. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(this + 0x100))(lVar1);
    return;
  }
  return;
}



// enum Graphine::Error::Enum __cdecl Graphine::Platform::GetDeviceBlockSize(wchar_t const *
// __ptr64,unsigned int & __ptr64)

Enum __cdecl Graphine::Platform::GetDeviceBlockSize(wchar_t *param_1,uint *param_2)

{
  char cVar1;
  BOOL BVar2;
  Enum extraout_EAX;
  HANDLE pvVar3;
  undefined auStackY_298 [32];
  DWORD local_258 [2];
  undefined4 local_250;
  undefined4 uStack_24c;
  undefined4 uStack_248;
  undefined8 local_244;
  uint local_23c;
  undefined local_238 [20];
  uint local_224;
  wchar_t local_218 [4];
  undefined2 local_210;
  ulonglong local_18;
  
                    // 0x21fc0  75
                    // ?GetDeviceBlockSize@Platform@Graphine@@YA?AW4Enum@Error@2@PEB_WAEAI@Z
  local_18 = DAT_180032820 ^ (ulonglong)auStackY_298;
  if (*(short *)(param_1 + 2) != 0x3a) goto LAB_18002216b;
  wcscpy_s(local_218,0x100,L"\\\\.\\c:");
  local_210 = *(undefined2 *)param_1;
  cVar1 = FUN_1800227c0();
  local_258[0] = 0;
  if (cVar1 == '\0') {
    pvVar3 = CreateFileW(local_218,0,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
    if (pvVar3 == (HANDLE)0xffffffffffffffff) goto LAB_18002216b;
    uStack_24c = 0;
    uStack_248 = 0;
    local_244 = 0;
    local_23c = 0;
    local_250 = 0;
    BVar2 = DeviceIoControl(pvVar3,0x70000,(LPVOID)0x0,0,&local_250,0x18,local_258,(LPOVERLAPPED)0x0
                           );
    CloseHandle(pvVar3);
    local_224 = local_23c;
    if (BVar2 == 0) goto LAB_18002216b;
LAB_18002215f:
    *param_2 = local_224;
  }
  else {
    local_250 = 0;
    uStack_24c = 0;
    uStack_248 = 0;
    pvVar3 = CreateFileW(local_218,0x20000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
    if (pvVar3 != (HANDLE)0xffffffffffffffff) {
      local_250 = 6;
      uStack_24c = 0;
      BVar2 = DeviceIoControl(pvVar3,0x2d1400,&local_250,0xc,local_238,0x1c,local_258,
                              (LPOVERLAPPED)0x0);
      CloseHandle(pvVar3);
      if (BVar2 != 0) goto LAB_18002215f;
    }
    GetLastError();
  }
LAB_18002216b:
  __security_check_cookie(local_18 ^ (ulonglong)auStackY_298);
  return extraout_EAX;
}



// enum Graphine::Error::Enum __cdecl Graphine::Platform::GetDynamicLibraryProcAddress(void *
// __ptr64,wchar_t const * __ptr64,void (__cdecl** __ptr64)(void))

Enum __cdecl
Graphine::Platform::GetDynamicLibraryProcAddress
          (void *param_1,wchar_t *param_2,void____cdecl_____ptr64__void_ *param_3)

{
  Enum extraout_EAX;
  FARPROC pFVar1;
  undefined auStack_848 [32];
  __uint64 local_828 [2];
  char local_818 [2048];
  ulonglong local_18;
  
                    // 0x22190  76
                    // ?GetDynamicLibraryProcAddress@Platform@Graphine@@YA?AW4Enum@Error@2@PEAXPEB_WPEAP6AXXZ@Z
  local_18 = DAT_180032820 ^ (ulonglong)auStack_848;
  String::WideCharToMultiByteTruncate(local_818,0x7ff,local_828,param_2);
  pFVar1 = GetProcAddress((HMODULE)param_1,local_818);
  *(FARPROC *)param_3 = pFVar1;
  __security_check_cookie(local_18 ^ (ulonglong)auStack_848);
  return extraout_EAX;
}



// enum Graphine::Error::Enum __cdecl Graphine::Platform::GetLocalDate(unsigned int &
// __ptr64,unsigned int & __ptr64,unsigned int & __ptr64)

Enum __cdecl Graphine::Platform::GetLocalDate(uint *param_1,uint *param_2,uint *param_3)

{
  Enum extraout_EAX;
  undefined auStack_58 [32];
  _SYSTEMTIME local_38;
  ulonglong local_28;
  
                    // 0x22210  77  ?GetLocalDate@Platform@Graphine@@YA?AW4Enum@Error@2@AEAI00@Z
  local_28 = DAT_180032820 ^ (ulonglong)auStack_58;
  GetLocalTime(&local_38);
  *param_1 = (uint)local_38.wYear;
  *param_2 = (uint)local_38.wMonth;
  *param_3 = (uint)local_38.wDay;
  __security_check_cookie(local_28 ^ (ulonglong)auStack_58);
  return extraout_EAX;
}



// unsigned __int64 __cdecl Graphine::Platform::GetThreadId(void)

__uint64 __cdecl Graphine::Platform::GetThreadId(void)

{
  DWORD DVar1;
  
                    // 0x22270  89  ?GetThreadId@Platform@Graphine@@YA_KXZ
  DVar1 = GetCurrentThreadId();
  return (ulonglong)DVar1;
}



// __int64 __cdecl Graphine::Platform::GetTicksPerSecond(void)

__int64 __cdecl Graphine::Platform::GetTicksPerSecond(void)

{
  LARGE_INTEGER local_res8 [4];
  
                    // 0x22290  90  ?GetTicksPerSecond@Platform@Graphine@@YA_JXZ
  QueryPerformanceFrequency(local_res8);
  return local_res8[0].QuadPart;
}



// __int64 __cdecl Graphine::Platform::GetTimeMs(void)

__int64 __cdecl Graphine::Platform::GetTimeMs(void)

{
  DWORD DVar1;
  
                    // 0x222b0  91  ?GetTimeMs@Platform@Graphine@@YA_JXZ
  DVar1 = GetTickCount();
  return (ulonglong)DVar1;
}



// __int64 __cdecl Graphine::Platform::GetTimeTicks(void)

__int64 __cdecl Graphine::Platform::GetTimeTicks(void)

{
  LARGE_INTEGER local_res8 [4];
  
                    // 0x222d0  92  ?GetTimeTicks@Platform@Graphine@@YA_JXZ
  QueryPerformanceCounter(local_res8);
  return local_res8[0].QuadPart;
}



// public: void * __ptr64 __cdecl Graphine::Platform::TLSVariable::GetValue(void) __ptr64

void * __thiscall Graphine::Platform::TLSVariable::GetValue(TLSVariable *this)

{
  void *pvVar1;
  
                    // 0x222f0  93  ?GetValue@TLSVariable@Platform@Graphine@@QEAAPEAXXZ
                    // WARNING: Could not recover jumptable at 0x0001800222f2. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = (void *)TlsGetValue(*(undefined4 *)this);
  return pvVar1;
}



undefined8 FUN_180022300(longlong param_1,undefined *param_2)

{
  LPCRITICAL_SECTION lpCriticalSection;
  undefined8 *puVar1;
  undefined8 *puVar2;
  undefined8 uVar3;
  BOOL BVar4;
  uint uVar5;
  uint uVar6;
  longlong lVar7;
  undefined8 *puVar8;
  
  lpCriticalSection = (LPCRITICAL_SECTION)(param_1 + 0x44);
  BVar4 = TryEnterCriticalSection(lpCriticalSection);
  if (BVar4 == 0) {
    EnterCriticalSection(lpCriticalSection);
  }
  puVar8 = *(undefined8 **)(param_1 + 0x10);
  uVar5 = (*(code *)param_2)(*puVar8);
  if ((1 < *(uint *)(param_1 + 0x20)) && (*(longlong *)(param_1 + 0x10) != 0)) {
    for (puVar1 = *(undefined8 **)(*(longlong *)(param_1 + 0x10) + 8); puVar1 != (undefined8 *)0x0;
        puVar1 = (undefined8 *)puVar1[1]) {
      uVar6 = (*(code *)param_2)(*puVar1);
      if (uVar5 < uVar6) {
        puVar8 = puVar1;
        uVar5 = uVar6;
      }
    }
  }
  puVar1 = *(undefined8 **)(param_1 + 0x10);
  if (puVar8 == puVar1) {
    if (puVar1 == *(undefined8 **)(param_1 + 0x18)) {
LAB_180022399:
      *(undefined8 *)(param_1 + 0x18) = 0;
      *(undefined8 *)(param_1 + 0x10) = 0;
      *(undefined4 *)(param_1 + 0x20) = 0;
      puVar1[1] = 0;
      puVar1[2] = 0;
      goto LAB_18002242d;
    }
    lVar7 = puVar1[1];
    *(longlong *)(param_1 + 0x10) = lVar7;
    *(undefined8 *)(lVar7 + 0x10) = 0;
    if (*(longlong *)(*(longlong *)(param_1 + 0x10) + 8) == 0) {
      *(longlong *)(param_1 + 0x18) = *(longlong *)(param_1 + 0x10);
    }
    puVar1[1] = 0;
    puVar1[2] = 0;
  }
  else {
    puVar2 = *(undefined8 **)(param_1 + 0x18);
    if (puVar8 == puVar2) {
      if (puVar1 == puVar2) goto LAB_180022399;
      lVar7 = puVar2[2];
      *(longlong *)(param_1 + 0x18) = lVar7;
      *(undefined8 *)(lVar7 + 8) = 0;
      lVar7 = *(longlong *)(param_1 + 0x18);
      if (*(longlong *)(*(longlong *)(param_1 + 0x10) + 8) == 0) {
        lVar7 = *(longlong *)(param_1 + 0x10);
      }
      *(longlong *)(param_1 + 0x18) = lVar7;
      puVar2[1] = 0;
      puVar2[2] = 0;
    }
    else {
      *(undefined8 *)(puVar8[2] + 8) = puVar8[1];
      *(undefined8 *)(puVar8[1] + 0x10) = puVar8[2];
      puVar8[1] = 0;
      puVar8[2] = 0;
    }
  }
  *(int *)(param_1 + 0x20) = *(int *)(param_1 + 0x20) + -1;
LAB_18002242d:
  if (*(longlong *)(param_1 + 0x30) == 0) {
    *(undefined8 **)(param_1 + 0x30) = puVar8;
    *(undefined8 **)(param_1 + 0x28) = puVar8;
    puVar8[1] = 0;
    puVar8[2] = 0;
    *(undefined4 *)(param_1 + 0x38) = 1;
  }
  else {
    *(undefined8 **)(*(longlong *)(param_1 + 0x30) + 8) = puVar8;
    puVar8[2] = *(undefined8 *)(param_1 + 0x30);
    puVar8[1] = 0;
    *(undefined8 **)(param_1 + 0x30) = puVar8;
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + 1;
  }
  uVar3 = *puVar8;
  LeaveCriticalSection(lpCriticalSection);
  return uVar3;
}



undefined8 FUN_180022490(void **param_1)

{
  void *pvVar1;
  undefined8 uVar2;
  uint uVar3;
  ulonglong uVar4;
  
  uVar2 = FUN_180022660(param_1,*(uint *)(param_1 + 8),0,0);
  if ((int)uVar2 == 0) {
    uVar4 = 0;
    if (*(int *)(param_1 + 1) != 0) {
      do {
        pvVar1 = (void *)((longlong)*param_1 + uVar4 * 0x18);
        if (param_1[6] == (void *)0x0) {
          param_1[6] = pvVar1;
          param_1[5] = pvVar1;
          *(undefined8 *)((longlong)pvVar1 + 8) = 0;
          *(undefined8 *)((longlong)pvVar1 + 0x10) = 0;
          *(undefined4 *)(param_1 + 7) = 1;
        }
        else {
          *(void **)((longlong)param_1[6] + 8) = pvVar1;
          *(void **)((longlong)pvVar1 + 0x10) = param_1[6];
          *(undefined8 *)((longlong)pvVar1 + 8) = 0;
          *(int *)(param_1 + 7) = *(int *)(param_1 + 7) + 1;
          param_1[6] = pvVar1;
        }
        uVar3 = (int)uVar4 + 1;
        uVar4 = (ulonglong)uVar3;
      } while (uVar3 < *(uint *)(param_1 + 1));
    }
    uVar2 = 0;
  }
  return uVar2;
}



// public: enum Graphine::Error::Enum __cdecl Graphine::Platform::JobSystem::Init(wchar_t const *
// __ptr64,void (__cdecl*)(void * __ptr64),void (__cdecl*)(void),unsigned int (__cdecl*)(void *
// __ptr64)) __ptr64

Enum __thiscall
Graphine::Platform::JobSystem::Init
          (JobSystem *this,wchar_t *param_1,_func_void_void_ptr *param_2,_func_void *param_3,
          _func_uint_void_ptr *param_4)

{
  HANDLE pvVar1;
  undefined8 *puVar2;
  void **ppvVar3;
  undefined8 uVar4;
  
                    // 0x22520  95
                    // ?Init@JobSystem@Platform@Graphine@@QEAA?AW4Enum@Error@3@PEB_WP6AXPEAX@ZP6AXXZP6AI1@Z@Z
  String::CopyStringTruncate((wchar_t *)this,0x80,param_1);
  *(_func_uint_void_ptr **)(this + 0x110) = param_4;
  *(_func_void_void_ptr **)(this + 0x100) = param_2;
  *(_func_void **)(this + 0x108) = param_3;
  pvVar1 = CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,(LPCWSTR)0x0);
  *(HANDLE *)(this + 0x128) = pvVar1;
  if (pvVar1 != (HANDLE)0x0) {
    pvVar1 = CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,(LPCWSTR)0x0);
    *(HANDLE *)(this + 0x130) = pvVar1;
    if (pvVar1 != (HANDLE)0x0) {
      ppvVar3 = (void **)0x0;
      pvVar1 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_180022d20,this
                            ,0,(LPDWORD)0x0);
      *(HANDLE *)(this + 0x138) = pvVar1;
      if (pvVar1 != (HANDLE)0x0) {
        this[0x120] = (JobSystem)0x1;
        puVar2 = (undefined8 *)FUN_180021e10(0x70);
        if (puVar2 != (undefined8 *)0x0) {
          ppvVar3 = (void **)FUN_180021ce0(puVar2,0x400);
        }
        *(void ***)(this + 0x118) = ppvVar3;
        if (ppvVar3 == (void **)0x0) {
          return 3;
        }
        uVar4 = FUN_180022490(ppvVar3);
        return (Enum)uVar4;
      }
    }
  }
  return 0xc;
}



// public: void __cdecl Graphine::Platform::TLSVariable::Initialize(void) __ptr64

void __thiscall Graphine::Platform::TLSVariable::Initialize(TLSVariable *this)

{
  DWORD DVar1;
  
                    // 0x22640  98  ?Initialize@TLSVariable@Platform@Graphine@@QEAAXXZ
  DVar1 = TlsAlloc();
  *(DWORD *)this = DVar1;
  return;
}



undefined8 FUN_180022660(void **param_1,uint param_2,uint param_3,Enum param_4)

{
  undefined8 *puVar1;
  undefined8 uVar2;
  Allocator *pAVar3;
  void *pvVar4;
  uint uVar5;
  ulonglong uVar6;
  char *local_28;
  undefined4 local_20;
  char *local_18;
  
  if (*param_1 == (void *)0x0) {
    if (param_2 != 0) {
      local_28 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Array.h";
      local_18 = 
      "Graphine::ArrayBase<struct Graphine::Queue<void *>::QueueItem,1>::InitializeInternal";
      if (param_3 == 0) {
        local_20 = 0xb1;
        pAVar3 = Graphine::GetAllocator();
        pvVar4 = Graphine::Allocator::Alloc
                           (pAVar3,(ulonglong)param_2 * 0x18,param_4,(ContextInfo *)&local_28);
      }
      else {
        local_20 = 0xad;
        pAVar3 = Graphine::GetAllocator();
        pvVar4 = Graphine::Allocator::AllocAligned
                           (pAVar3,(ulonglong)param_2 * 0x18,param_3,param_4,
                            (ContextInfo *)&local_28);
      }
      *param_1 = pvVar4;
      if (pvVar4 == (void *)0x0) {
        return 3;
      }
      uVar6 = 0;
      *(uint *)(param_1 + 1) = param_2;
      if (param_2 != 0) {
        do {
          puVar1 = (undefined8 *)((longlong)*param_1 + uVar6 * 0x18);
          if (puVar1 != (undefined8 *)0x0) {
            *puVar1 = 0;
            puVar1[1] = 0;
            puVar1[2] = 0;
          }
          uVar5 = (int)uVar6 + 1;
          uVar6 = (ulonglong)uVar5;
        } while (uVar5 < *(uint *)(param_1 + 1));
      }
    }
    uVar2 = 0;
  }
  else {
    uVar2 = 2;
  }
  return uVar2;
}



// int __cdecl Graphine::Platform::InterlockedAdd(int & __ptr64,int)

int __cdecl Graphine::Platform::InterlockedAdd(int *param_1,int param_2)

{
  int iVar1;
  
                    // 0x22770  101  ?InterlockedAdd@Platform@Graphine@@YAHAEAHH@Z
  LOCK();
  iVar1 = *param_1;
  *param_1 = *param_1 + param_2;
  return iVar1 + param_2;
}



// __int64 __cdecl Graphine::Platform::InterlockedDec64(__int64 & __ptr64)

__int64 __cdecl Graphine::Platform::InterlockedDec64(__int64 *param_1)

{
  longlong lVar1;
  
                    // 0x22780  102  ?InterlockedDec64@Platform@Graphine@@YA_JAEA_J@Z
  LOCK();
  lVar1 = *param_1;
  *param_1 = *param_1 + -1;
  return lVar1 + -1;
}



// int __cdecl Graphine::Platform::InterlockedDec(int & __ptr64)

int __cdecl Graphine::Platform::InterlockedDec(int *param_1)

{
  int iVar1;
  
                    // 0x22790  103  ?InterlockedDec@Platform@Graphine@@YAHAEAH@Z
  LOCK();
  iVar1 = *param_1;
  *param_1 = *param_1 + -1;
  return iVar1 + -1;
}



// __int64 __cdecl Graphine::Platform::InterlockedInc64(__int64 & __ptr64)

__int64 __cdecl Graphine::Platform::InterlockedInc64(__int64 *param_1)

{
  longlong lVar1;
  
                    // 0x227a0  104  ?InterlockedInc64@Platform@Graphine@@YA_JAEA_J@Z
  LOCK();
  lVar1 = *param_1;
  *param_1 = *param_1 + 1;
  return lVar1 + 1;
}



// int __cdecl Graphine::Platform::InterlockedInc(int & __ptr64)

int __cdecl Graphine::Platform::InterlockedInc(int *param_1)

{
  int iVar1;
  
                    // 0x227b0  105  ?InterlockedInc@Platform@Graphine@@YAHAEAH@Z
  LOCK();
  iVar1 = *param_1;
  *param_1 = *param_1 + 1;
  return iVar1 + 1;
}



void FUN_1800227c0(void)

{
  undefined8 uVar1;
  DWORDLONG dwlConditionMask;
  undefined auStack_158 [32];
  _OSVERSIONINFOEXW local_138;
  ulonglong local_18;
  
  local_18 = DAT_180032820 ^ (ulonglong)auStack_158;
  memset(&local_138,0,0x11c);
  local_138.dwOSVersionInfoSize = 0x11c;
  local_138._4_8_ = 6;
  local_138._276_4_ = 0;
  uVar1 = VerSetConditionMask(0,2,3);
  uVar1 = VerSetConditionMask(uVar1,1,3);
  uVar1 = VerSetConditionMask(uVar1,0x20,3);
  dwlConditionMask = VerSetConditionMask(uVar1,0x10,3);
  VerifyVersionInfoW(&local_138,0x33,dwlConditionMask);
  __security_check_cookie(local_18 ^ (ulonglong)auStack_158);
  return;
}



// public: void __cdecl Graphine::Platform::CriticalSection::Leave(void) __ptr64

void __thiscall Graphine::Platform::CriticalSection::Leave(CriticalSection *this)

{
                    // WARNING: Could not recover jumptable at 0x000180022880. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x22880  110  ?Leave@CriticalSection@Platform@Graphine@@QEAAXXZ
  LeaveCriticalSection((LPCRITICAL_SECTION)this);
  return;
}



// enum Graphine::Error::Enum __cdecl Graphine::Platform::LoadDynamicLibrary(wchar_t const *
// __ptr64,void * __ptr64 * __ptr64)

Enum __cdecl Graphine::Platform::LoadDynamicLibrary(wchar_t *param_1,void **param_2)

{
  HMODULE pHVar1;
  Enum EVar2;
  
                    // 0x22890  111
                    // ?LoadDynamicLibrary@Platform@Graphine@@YA?AW4Enum@Error@2@PEB_WPEAPEAX@Z
  pHVar1 = LoadLibraryW((LPCWSTR)param_1);
  EVar2 = 0;
  *param_2 = pHVar1;
  if (pHVar1 == (HMODULE)0x0) {
    EVar2 = 0xc;
  }
  return EVar2;
}



// void __cdecl Graphine::Platform::LoadMemoryFence(void)

void __cdecl Graphine::Platform::LoadMemoryFence(void)

{
  return;
}



// void __cdecl Graphine::Platform::MemoryClear(void * __ptr64,unsigned __int64)

void __cdecl Graphine::Platform::MemoryClear(void *param_1,__uint64 param_2)

{
                    // 0x228d0  120  ?MemoryClear@Platform@Graphine@@YAXPEAX_K@Z
  memset(param_1,0,param_2);
  return;
}



// void __cdecl Graphine::Platform::MemoryCopy(void * __ptr64,void const * __ptr64,unsigned __int64)

void __cdecl Graphine::Platform::MemoryCopy(void *param_1,void *param_2,__uint64 param_3)

{
                    // 0x228e0  121  ?MemoryCopy@Platform@Graphine@@YAXPEAXPEBX_K@Z
                    // WARNING: Could not recover jumptable at 0x000180024532. Too many branches
                    // WARNING: Treating indirect jump as call
  memcpy(param_1,param_2,param_3);
  return;
}



// void __cdecl Graphine::Platform::MemoryMove(void * __ptr64,void const * __ptr64,unsigned __int64)

void __cdecl Graphine::Platform::MemoryMove(void *param_1,void *param_2,__uint64 param_3)

{
                    // WARNING: Could not recover jumptable at 0x0001800228f0. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x228f0  122  ?MemoryMove@Platform@Graphine@@YAXPEAXPEBX_K@Z
  memmove(param_1,param_2,param_3);
  return;
}



// enum Graphine::Error::Enum __cdecl Graphine::Platform::OpenFile(wchar_t const *
// __ptr64,bool,bool,void * __ptr64 & __ptr64)

Enum __cdecl Graphine::Platform::OpenFile(wchar_t *param_1,bool param_2,bool param_3,void **param_4)

{
  DWORD dwFlagsAndAttributes;
  HANDLE pvVar1;
  DWORD dwDesiredAccess;
  Enum EVar2;
  
  dwFlagsAndAttributes = 0x10000000;
                    // 0x22900  124
                    // ?OpenFile@Platform@Graphine@@YA?AW4Enum@Error@2@PEB_W_N1AEAPEAX@Z
  if (param_2) {
    dwFlagsAndAttributes = 0x30000000;
  }
  dwDesiredAccess = 0x80000000;
  if (param_3) {
    dwDesiredAccess = 0x40000000;
  }
  EVar2 = 0;
  pvVar1 = CreateFileW((LPCWSTR)param_1,dwDesiredAccess,1,(LPSECURITY_ATTRIBUTES)0x0,3 - param_3,
                       dwFlagsAndAttributes,(HANDLE)0x0);
  *param_4 = pvVar1;
  if (pvVar1 == (HANDLE)0xffffffffffffffff) {
    EVar2 = 4;
  }
  return EVar2;
}



undefined8 FUN_180022980(longlong param_1,undefined8 param_2)

{
  undefined8 *puVar1;
  longlong lVar2;
  BOOL BVar3;
  undefined8 uVar4;
  
  BVar3 = TryEnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x44));
  if (BVar3 == 0) {
    EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x44));
  }
  if (*(int *)(param_1 + 0x38) == 0) {
    uVar4 = 2;
  }
  else {
    puVar1 = *(undefined8 **)(param_1 + 0x28);
    uVar4 = 0;
    if (puVar1 == *(undefined8 **)(param_1 + 0x30)) {
      *(undefined8 *)(param_1 + 0x30) = 0;
      *(undefined8 *)(param_1 + 0x28) = 0;
      *(undefined4 *)(param_1 + 0x38) = 0;
      puVar1[1] = 0;
      puVar1[2] = 0;
    }
    else {
      lVar2 = puVar1[1];
      *(longlong *)(param_1 + 0x28) = lVar2;
      *(undefined8 *)(lVar2 + 0x10) = 0;
      if (*(longlong *)(*(longlong *)(param_1 + 0x28) + 8) == 0) {
        *(longlong *)(param_1 + 0x30) = *(longlong *)(param_1 + 0x28);
      }
      puVar1[1] = 0;
      puVar1[2] = 0;
      *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -1;
    }
    *puVar1 = param_2;
    if (*(longlong *)(param_1 + 0x18) == 0) {
      *(undefined8 **)(param_1 + 0x18) = puVar1;
      *(undefined8 **)(param_1 + 0x10) = puVar1;
      puVar1[1] = 0;
      puVar1[2] = 0;
      *(undefined4 *)(param_1 + 0x20) = 1;
    }
    else {
      *(undefined8 **)(*(longlong *)(param_1 + 0x18) + 8) = puVar1;
      puVar1[2] = *(undefined8 *)(param_1 + 0x18);
      puVar1[1] = 0;
      *(int *)(param_1 + 0x20) = *(int *)(param_1 + 0x20) + 1;
      *(undefined8 **)(param_1 + 0x18) = puVar1;
    }
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x44));
  return uVar4;
}



// enum Graphine::Error::Enum __cdecl Graphine::Platform::ReadFile(void * __ptr64,void *
// __ptr64,unsigned int,unsigned int & __ptr64)

Enum __cdecl Graphine::Platform::ReadFile(void *param_1,void *param_2,uint param_3,uint *param_4)

{
  BOOL BVar1;
  uint local_res20 [2];
  
                    // 0x22a70  128  ?ReadFile@Platform@Graphine@@YA?AW4Enum@Error@2@PEAX0IAEAI@Z
  BVar1 = ::ReadFile(param_1,param_2,param_3,local_res20,(LPOVERLAPPED)0x0);
  *param_4 = local_res20[0];
  if ((BVar1 != 0) && (local_res20[0] == param_3)) {
    return 0;
  }
  return 4;
}



void FUN_180022ac0(void **param_1)

{
  void *pvVar1;
  Allocator *this;
  char *local_28;
  undefined4 local_20;
  char *local_18;
  
  pvVar1 = *param_1;
  if (pvVar1 != (void *)0x0) {
    local_20 = 0xd3;
    local_28 = "d:\\git\\graphine\\graphine\\graphinecore\\src\\Array.h";
    local_18 = "Graphine::ArrayBase<struct Graphine::Queue<void *>::QueueItem,1>::ReleaseInternal";
    this = Graphine::GetAllocator();
    Graphine::Allocator::Free(this,pvVar1,(ContextInfo *)&local_28);
    *param_1 = (void *)0x0;
    *(undefined4 *)(param_1 + 1) = 0;
    return;
  }
  *param_1 = (void *)0x0;
  *(undefined4 *)(param_1 + 1) = 0;
  return;
}



// public: bool __cdecl Graphine::Platform::JobSystem::Schedule(void * __ptr64) __ptr64

bool __thiscall Graphine::Platform::JobSystem::Schedule(JobSystem *this,void *param_1)

{
  DWORD DVar1;
  undefined8 uVar2;
  
                    // 0x22b30  136  ?Schedule@JobSystem@Platform@Graphine@@QEAA_NPEAX@Z
  if (this[0x120] != (JobSystem)0x0) {
    uVar2 = FUN_180022980(*(longlong *)(this + 0x118),param_1);
    if ((int)uVar2 == 0) {
      DVar1 = QueueUserAPC(FUN_180021eb0,*(HANDLE *)(this + 0x138),(ULONG_PTR)this);
      return DVar1 != 0;
    }
  }
  return false;
}



// enum Graphine::Error::Enum __cdecl Graphine::Platform::SeekFile(void * __ptr64,unsigned __int64 &
// __ptr64)

Enum __cdecl Graphine::Platform::SeekFile(void *param_1,__uint64 *param_2)

{
  BOOL BVar1;
  Enum EVar2;
  
                    // 0x22b80  137  ?SeekFile@Platform@Graphine@@YA?AW4Enum@Error@2@PEAXAEA_K@Z
  BVar1 = SetFilePointerEx(param_1,(LARGE_INTEGER)*param_2,(PLARGE_INTEGER)0x0,0);
  EVar2 = 0;
  if (BVar1 == 0) {
    EVar2 = 4;
  }
  return EVar2;
}



// public: void __cdecl Graphine::Platform::TLSVariable::SetValue(void * __ptr64) __ptr64

void __thiscall Graphine::Platform::TLSVariable::SetValue(TLSVariable *this,void *param_1)

{
                    // 0x22bb0  139  ?SetValue@TLSVariable@Platform@Graphine@@QEAAXPEAX@Z
                    // WARNING: Could not recover jumptable at 0x000180022bb2. Too many branches
                    // WARNING: Treating indirect jump as call
  TlsSetValue(*(undefined4 *)this);
  return;
}



// enum Graphine::Error::Enum __cdecl Graphine::Platform::ShowMessage(wchar_t const *
// __ptr64,wchar_t const * __ptr64)

Enum __cdecl Graphine::Platform::ShowMessage(wchar_t *param_1,wchar_t *param_2)

{
                    // 0x22bc0  140  ?ShowMessage@Platform@Graphine@@YA?AW4Enum@Error@2@PEB_W0@Z
  MessageBoxW((HWND)0x0,(LPCWSTR)param_2,(LPCWSTR)param_1,0x30);
  return 0;
}



// void __cdecl Graphine::Platform::Sleep(unsigned int)

void __cdecl Graphine::Platform::Sleep(uint param_1)

{
                    // WARNING: Could not recover jumptable at 0x000180022be0. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x22be0  141  ?Sleep@Platform@Graphine@@YAXI@Z
  ::Sleep(param_1);
  return;
}



// public: enum Graphine::Error::Enum __cdecl Graphine::Platform::JobSystem::Stop(void) __ptr64

Enum __thiscall Graphine::Platform::JobSystem::Stop(JobSystem *this)

{
                    // 0x22bf0  145  ?Stop@JobSystem@Platform@Graphine@@QEAA?AW4Enum@Error@3@XZ
  if (this[0x120] != (JobSystem)0x0) {
    if (*(HANDLE *)(this + 0x128) != (HANDLE)0x0) {
      SetEvent(*(HANDLE *)(this + 0x128));
    }
    if (*(HANDLE *)(this + 0x130) != (HANDLE)0x0) {
      WaitForSingleObject(*(HANDLE *)(this + 0x130),0xffffffff);
    }
    if (*(HANDLE *)(this + 0x138) != (HANDLE)0x0) {
      CloseHandle(*(HANDLE *)(this + 0x138));
    }
    if (*(HANDLE *)(this + 0x128) != (HANDLE)0x0) {
      CloseHandle(*(HANDLE *)(this + 0x128));
    }
    if (*(HANDLE *)(this + 0x130) != (HANDLE)0x0) {
      CloseHandle(*(HANDLE *)(this + 0x130));
    }
    this[0x120] = (JobSystem)0x0;
    return 0;
  }
  return 2;
}



// void __cdecl Graphine::Platform::StoreMemoryFence(void)

void __cdecl Graphine::Platform::StoreMemoryFence(void)

{
  return;
}



// public: bool __cdecl Graphine::Platform::CriticalSection::TryEnter(void) __ptr64

bool __thiscall Graphine::Platform::CriticalSection::TryEnter(CriticalSection *this)

{
  BOOL BVar1;
  
                    // 0x22c90  157  ?TryEnter@CriticalSection@Platform@Graphine@@QEAA_NXZ
  BVar1 = TryEnterCriticalSection((LPCRITICAL_SECTION)this);
  return BVar1 == 1;
}



// enum Graphine::Error::Enum __cdecl Graphine::Platform::UnloadDynamicLibrary(void * __ptr64)

Enum __cdecl Graphine::Platform::UnloadDynamicLibrary(void *param_1)

{
  BOOL BVar1;
  Enum EVar2;
  
                    // 0x22cb0  160
                    // ?UnloadDynamicLibrary@Platform@Graphine@@YA?AW4Enum@Error@2@PEAX@Z
  BVar1 = FreeLibrary((HMODULE)param_1);
  EVar2 = 0;
  if (BVar1 == 0) {
    EVar2 = 0xc;
  }
  return EVar2;
}



// public: void __cdecl Graphine::Platform::JobSystem::WorkerThreadMain(void) __ptr64

void __thiscall Graphine::Platform::JobSystem::WorkerThreadMain(JobSystem *this)

{
  DWORD DVar1;
  PerformanceMonitor *this_00;
  
                    // 0x22cd0  163  ?WorkerThreadMain@JobSystem@Platform@Graphine@@QEAAXXZ
  this_00 = Performance::GetPerformanceMonitor();
  Performance::PerformanceMonitor::RegisterCurrentThread(this_00,(wchar_t *)this);
  (**(code **)(this + 0x108))();
  do {
    DVar1 = WaitForSingleObjectEx(*(HANDLE *)(this + 0x128),0xffffffff,1);
  } while (DVar1 == 0xc0);
                    // WARNING: Could not recover jumptable at 0x000180022d19. Too many branches
                    // WARNING: Treating indirect jump as call
  SetEvent(*(HANDLE *)(this + 0x130));
  return;
}



// enum Graphine::Error::Enum __cdecl Graphine::Platform::WriteFile(void * __ptr64,void *
// __ptr64,unsigned __int64)

Enum __cdecl Graphine::Platform::WriteFile(void *param_1,void *param_2,__uint64 param_3)

{
  BOOL BVar1;
  uint local_res8 [8];
  
                    // 0x22d80  173  ?WriteFile@Platform@Graphine@@YA?AW4Enum@Error@2@PEAX0_K@Z
  if (((param_1 != (void *)0x0) && (param_2 != (void *)0x0)) && (param_3 != 0)) {
    local_res8[0] = 0;
    BVar1 = ::WriteFile(param_1,param_2,(DWORD)param_3,local_res8,(LPOVERLAPPED)0x0);
    if ((BVar1 != 0) && (local_res8[0] == param_3)) {
      return 0;
    }
    GetLastError();
    return 4;
  }
  return 1;
}



undefined8 * FUN_180022de0(undefined8 *param_1)

{
  *(undefined *)(param_1 + 1) = 0;
  *param_1 = Graphine::AsyncWriter_Windows::vftable;
  param_1[2] = 0xffffffffffffffff;
  param_1[3] = 0xffffffffffffffff;
  Graphine::Platform::MemoryClear(param_1 + 4,0x20);
  return param_1;
}



undefined8 * FUN_180022e30(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = Graphine::IAsyncWriter<class_Graphine::AsyncWriter_Windows>::vftable;
  if ((param_1[2] != -1) && ((HANDLE)param_1[3] != (HANDLE)0xffffffffffffffff)) {
    CloseHandle((HANDLE)param_1[3]);
    param_1[3] = 0xffffffffffffffff;
    CloseHandle((HANDLE)param_1[2]);
    param_1[2] = 0xffffffffffffffff;
  }
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



byte FUN_180022ea0(longlong param_1)

{
  if ((*(longlong *)(param_1 + 0x10) != -1) &&
     (*(HANDLE *)(param_1 + 0x18) != (HANDLE)0xffffffffffffffff)) {
    CloseHandle(*(HANDLE *)(param_1 + 0x18));
    *(undefined8 *)(param_1 + 0x18) = 0xffffffffffffffff;
    CloseHandle(*(HANDLE *)(param_1 + 0x10));
    *(undefined8 *)(param_1 + 0x10) = 0xffffffffffffffff;
    return -(*(char *)(param_1 + 8) != '\0') & 4;
  }
  return 2;
}



bool FUN_180022f00(longlong param_1)

{
  return *(longlong *)(param_1 + 0x10) != -1;
}



undefined8 FUN_180022f10(longlong param_1,LPCWSTR param_2)

{
  HANDLE pvVar1;
  
  if (*(longlong *)(param_1 + 0x10) != -1) {
    return 2;
  }
  pvVar1 = CreateFileW(param_2,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x40000000,(HANDLE)0x0);
  *(HANDLE *)(param_1 + 0x10) = pvVar1;
  if (pvVar1 == (HANDLE)0xffffffffffffffff) {
    return 4;
  }
  pvVar1 = CreateEventW((LPSECURITY_ATTRIBUTES)0x0,1,1,(LPCWSTR)0x0);
  *(HANDLE *)(param_1 + 0x18) = pvVar1;
  if (pvVar1 == (HANDLE)0xffffffffffffffff) {
    CloseHandle(*(HANDLE *)(param_1 + 0x10));
    *(undefined8 *)(param_1 + 0x10) = 0xffffffffffffffff;
    return 0xc;
  }
  *(undefined *)(param_1 + 8) = 0;
  Graphine::Platform::MemoryClear((void *)(param_1 + 0x20),0x20);
  *(undefined8 *)(param_1 + 0x38) = *(undefined8 *)(param_1 + 0x18);
  *(undefined8 *)(param_1 + 0x30) = 0xffffffffffffffff;
  return 0;
}



undefined4 FUN_180022fe0(longlong param_1)

{
  BOOL BVar1;
  undefined4 uVar2;
  DWORD local_res8 [8];
  
  local_res8[0] = 0;
  BVar1 = GetOverlappedResult(*(HANDLE *)(param_1 + 0x10),(LPOVERLAPPED)(param_1 + 0x20),local_res8,
                              1);
  uVar2 = 0;
  if (BVar1 == 0) {
    uVar2 = 4;
  }
  return uVar2;
}



undefined8 FUN_180023020(longlong param_1,LPCVOID param_2,longlong param_3)

{
  LPOVERLAPPED lpOverlapped;
  BOOL BVar1;
  DWORD DVar2;
  DWORD local_res8 [2];
  
  if ((*(longlong *)(param_1 + 0x10) != -1) && (param_3 != 0)) {
    lpOverlapped = (LPOVERLAPPED)(param_1 + 0x20);
    local_res8[0] = 0;
    GetOverlappedResult(*(HANDLE *)(param_1 + 0x10),lpOverlapped,local_res8,1);
    ResetEvent(*(HANDLE *)(param_1 + 0x38));
    Graphine::Platform::MemoryClear(lpOverlapped,0x20);
    *(undefined8 *)(param_1 + 0x38) = *(undefined8 *)(param_1 + 0x18);
    *(undefined8 *)(param_1 + 0x30) = 0xffffffffffffffff;
    BVar1 = WriteFile(*(HANDLE *)(param_1 + 0x10),param_2,(DWORD)param_3,(LPDWORD)0x0,lpOverlapped);
    if (BVar1 == 0) {
      DVar2 = GetLastError();
      if (DVar2 != 0x3e5) {
        *(undefined *)(param_1 + 8) = 1;
        return 4;
      }
    }
  }
  return 0;
}



// Library Function - Single Match
//  void __cdecl `eh vector destructor iterator'(void * __ptr64,unsigned __int64,unsigned
// __int64,void (__cdecl*)(void * __ptr64))
// 
// Library: Visual Studio 2015 Release

void __cdecl
_eh_vector_destructor_iterator_
          (void *param_1,__uint64 param_2,__uint64 param_3,_func_void_void_ptr *param_4)

{
  void *pvVar1;
  
  pvVar1 = (void *)(param_2 * param_3 + (longlong)param_1);
  while( true ) {
    if (param_3 == 0) break;
    pvVar1 = (void *)((longlong)pvVar1 - param_2);
    _guard_check_icall();
    (*param_4)(pvVar1);
    param_3 = param_3 - 1;
  }
  return;
}



// Library Function - Single Match
//  void __cdecl __ArrayUnwind(void * __ptr64,unsigned __int64,unsigned __int64,void (__cdecl*)(void
// * __ptr64))
// 
// Library: Visual Studio 2015 Release

void __cdecl
__ArrayUnwind(void *param_1,__uint64 param_2,__uint64 param_3,_func_void_void_ptr *param_4)

{
  __uint64 _Var1;
  
  for (_Var1 = 0; _Var1 != param_3; _Var1 = _Var1 + 1) {
    param_1 = (void *)((longlong)param_1 - param_2);
    _guard_check_icall();
    (*param_4)(param_1);
  }
  return;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180024550. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180024550. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_1800231d8(void)

{
  code *pcVar1;
  byte bVar2;
  HMODULE hModule;
  FARPROC pFVar3;
  FARPROC pFVar4;
  FARPROC pFVar5;
  undefined8 uVar6;
  byte bVar7;
  
  __vcrt_InitializeCriticalSectionEx(&DAT_18007bc90,4000);
  hModule = GetModuleHandleW(L"kernel32.dll");
  if (hModule == (HMODULE)0x0) {
    __scrt_fastfail(7);
    pcVar1 = (code *)swi(3);
    uVar6 = (*pcVar1)();
    return uVar6;
  }
  pFVar3 = GetProcAddress(hModule,"InitializeConditionVariable");
  pFVar4 = GetProcAddress(hModule,"SleepConditionVariableCS");
  pFVar5 = GetProcAddress(hModule,"WakeAllConditionVariable");
  if (((pFVar3 == (FARPROC)0x0) || (pFVar4 == (FARPROC)0x0)) || (pFVar5 == (FARPROC)0x0)) {
    DAT_18007bcc0 = CreateEventW((LPSECURITY_ATTRIBUTES)0x0,1,0,(LPCWSTR)0x0);
    if (DAT_18007bcc0 == (HANDLE)0x0) {
      __scrt_fastfail(7);
      pcVar1 = (code *)swi(3);
      uVar6 = (*pcVar1)();
      return uVar6;
    }
  }
  else {
    DAT_18007bcc0 = (HANDLE)0x0;
    _guard_check_icall();
    (*pFVar3)(&DAT_18007bcb8);
    bVar7 = 0x40 - ((byte)DAT_180032820 & 0x3f);
    bVar2 = bVar7 & 0x3f;
    _DAT_18007bcc8 = ((ulonglong)pFVar4 >> bVar2 | (longlong)pFVar4 << 0x40 - bVar2) ^ DAT_180032820
    ;
    bVar7 = bVar7 & 0x3f;
    _DAT_18007bcd0 = ((ulonglong)pFVar5 >> bVar7 | (longlong)pFVar5 << 0x40 - bVar7) ^ DAT_180032820
    ;
  }
  atexit(FUN_1800232f8);
  return 0;
}



void FUN_1800232f8(void)

{
  DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_18007bc90);
  if (DAT_18007bcc0 != (HANDLE)0x0) {
    CloseHandle(DAT_18007bcc0);
  }
  return;
}



// Library Function - Single Match
//  _Init_thread_abort
// 
// Library: Visual Studio 2015 Release

void _Init_thread_abort(undefined4 *param_1)

{
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18007bc90);
  *param_1 = 0;
  LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18007bc90);
  _Init_thread_notify();
  return;
}



// Library Function - Single Match
//  _Init_thread_footer
// 
// Library: Visual Studio 2015 Release

void _Init_thread_footer(int *param_1)

{
  ulonglong uVar1;
  
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18007bc90);
  uVar1 = (ulonglong)_tls_index;
  DAT_180032808 = DAT_180032808 + 1;
  *param_1 = DAT_180032808;
  *(int *)(*(longlong *)((longlong)ThreadLocalStoragePointer + uVar1 * 8) + 0x420) = DAT_180032808;
  LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18007bc90);
  _Init_thread_notify();
  return;
}



// Library Function - Single Match
//  _Init_thread_header
// 
// Library: Visual Studio 2015 Release

void _Init_thread_header(int *param_1)

{
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18007bc90);
  do {
    if (*param_1 == 0) {
      *param_1 = -1;
LAB_180023404:
                    // WARNING: Could not recover jumptable at 0x000180023410. Too many branches
                    // WARNING: Treating indirect jump as call
      LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18007bc90);
      return;
    }
    if (*param_1 != -1) {
      *(undefined4 *)
       (*(longlong *)((longlong)ThreadLocalStoragePointer + (ulonglong)_tls_index * 8) + 0x420) =
           DAT_180032808;
      goto LAB_180023404;
    }
    _Init_thread_wait(100);
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _Init_thread_notify
// 
// Library: Visual Studio 2015 Release

void _Init_thread_notify(void)

{
  byte bVar1;
  ulonglong uVar2;
  
  if (DAT_18007bcc0 == (HANDLE)0x0) {
    uVar2 = DAT_180032820 ^ _DAT_18007bcd0;
    bVar1 = (byte)DAT_180032820 & 0x3f;
    _guard_check_icall();
                    // WARNING: Could not recover jumptable at 0x000180023457. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(code *)(uVar2 >> bVar1 | uVar2 << 0x40 - bVar1))(&DAT_18007bcb8);
    return;
  }
  SetEvent(DAT_18007bcc0);
                    // WARNING: Could not recover jumptable at 0x00018002346c. Too many branches
                    // WARNING: Treating indirect jump as call
  ResetEvent(DAT_18007bcc0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _Init_thread_wait
// 
// Library: Visual Studio 2015 Release

uint _Init_thread_wait(DWORD param_1)

{
  uint uVar1;
  DWORD DVar2;
  uint extraout_EAX;
  byte bVar3;
  ulonglong uVar4;
  
  if (DAT_18007bcc0 == (HANDLE)0x0) {
    uVar4 = DAT_180032820 ^ _DAT_18007bcc8;
    bVar3 = (byte)DAT_180032820 & 0x3f;
    _guard_check_icall();
    uVar1 = (*(code *)(uVar4 >> bVar3 | uVar4 << 0x40 - bVar3))
                      (&DAT_18007bcb8,&DAT_18007bc90,param_1);
    uVar1 = uVar1 & 0xffffff00 | (uint)(uVar1 != 0);
  }
  else {
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18007bc90);
    DVar2 = WaitForSingleObjectEx(DAT_18007bcc0,param_1,0);
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18007bc90);
    uVar1 = extraout_EAX & 0xffffff00 | (uint)(DVar2 == 0);
  }
  return uVar1;
}



undefined8 * FUN_18002350c(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = type_info::vftable;
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



// Library Function - Single Match
//  __scrt_acquire_startup_lock
// 
// Library: Visual Studio 2015 Release

ulonglong __scrt_acquire_startup_lock(void)

{
  bool bVar1;
  undefined7 extraout_var;
  ulonglong uVar3;
  void *pvVar2;
  
  bVar1 = __scrt_is_ucrt_dll_in_use();
  pvVar2 = (void *)CONCAT71(extraout_var,bVar1);
  if ((int)pvVar2 == 0) {
LAB_180023566:
    uVar3 = (ulonglong)pvVar2 & 0xffffffffffffff00;
  }
  else {
    do {
      LOCK();
      bVar1 = DAT_18007bce8 == 0;
      DAT_18007bce8 = DAT_18007bce8 ^ (ulonglong)bVar1 * (DAT_18007bce8 ^ (ulonglong)StackBase);
      pvVar2 = (void *)(!bVar1 * DAT_18007bce8);
      if (bVar1) goto LAB_180023566;
    } while (StackBase != pvVar2);
    uVar3 = CONCAT71((int7)((ulonglong)pvVar2 >> 8),1);
  }
  return uVar3;
}



// Library Function - Single Match
//  __scrt_dllmain_after_initialize_c
// 
// Library: Visual Studio 2015 Release

undefined8 __scrt_dllmain_after_initialize_c(void)

{
  bool bVar1;
  undefined7 extraout_var;
  undefined8 uVar2;
  ulonglong uVar3;
  
  bVar1 = __scrt_is_ucrt_dll_in_use();
  if ((int)CONCAT71(extraout_var,bVar1) == 0) {
    uVar3 = FUN_1800241cc();
    uVar3 = _configure_narrow_argv(uVar3 & 0xffffffff);
    if ((int)uVar3 != 0) {
      return uVar3 & 0xffffffffffffff00;
    }
    uVar2 = _initialize_narrow_environment();
  }
  else {
    uVar2 = __isa_available_init();
  }
  return CONCAT71((int7)((ulonglong)uVar2 >> 8),1);
}



// Library Function - Single Match
//  __scrt_dllmain_before_initialize_c
// 
// Library: Visual Studio 2015 Release

ulonglong __scrt_dllmain_before_initialize_c(void)

{
  ulonglong uVar1;
  
  uVar1 = __scrt_initialize_onexit_tables(0);
  return uVar1 & 0xffffffffffffff00 | (ulonglong)((char)uVar1 != '\0');
}



// Library Function - Single Match
//  __scrt_dllmain_crt_thread_attach
// 
// Library: Visual Studio 2015 Release

undefined __scrt_dllmain_crt_thread_attach(void)

{
  char cVar1;
  
  cVar1 = FUN_1800245d0();
  if (cVar1 != '\0') {
    cVar1 = FUN_1800245d0();
    if (cVar1 != '\0') {
      return 1;
    }
    FUN_1800245d0();
  }
  return 0;
}



// Library Function - Single Match
//  __scrt_dllmain_crt_thread_detach
// 
// Library: Visual Studio 2015 Release

undefined __scrt_dllmain_crt_thread_detach(void)

{
  FUN_1800245d0();
  FUN_1800245d0();
  return 1;
}



// Library Function - Single Match
//  __scrt_dllmain_exception_filter
// 
// Library: Visual Studio 2015 Release

void __scrt_dllmain_exception_filter
               (undefined8 param_1,int param_2,undefined8 param_3,undefined *param_4,
               undefined4 param_5,undefined8 param_6)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = __scrt_is_ucrt_dll_in_use();
  if ((CONCAT31(extraout_var,bVar1) == 0) && (param_2 == 1)) {
    _guard_check_icall();
    (*(code *)param_4)(param_1,0,param_3);
  }
  _seh_filter_dll(param_5,param_6);
  return;
}



// Library Function - Single Match
//  __scrt_dllmain_uninitialize_c
// 
// Library: Visual Studio 2015 Release

void __scrt_dllmain_uninitialize_c(void)

{
  bool bVar1;
  undefined7 extraout_var;
  undefined8 uVar2;
  
  bVar1 = __scrt_is_ucrt_dll_in_use();
  if ((int)CONCAT71(extraout_var,bVar1) != 0) {
    _execute_onexit_table(&DAT_18007bcf0);
    return;
  }
  uVar2 = FUN_1800245d4();
  if ((int)uVar2 == 0) {
    _cexit();
  }
  return;
}



// Library Function - Single Match
//  __scrt_dllmain_uninitialize_critical
// 
// Library: Visual Studio 2015 Release

void __scrt_dllmain_uninitialize_critical(void)

{
  FUN_1800245d0();
  FUN_1800245d0();
  return;
}



// Library Function - Single Match
//  __scrt_initialize_crt
// 
// Library: Visual Studio 2015 Release

ulonglong __scrt_initialize_crt(int param_1)

{
  ulonglong uVar1;
  
  if (param_1 == 0) {
    DAT_18007bd20 = 1;
  }
  __isa_available_init();
  uVar1 = FUN_1800245d0();
  if ((char)uVar1 != '\0') {
    uVar1 = FUN_1800245d0();
    if ((char)uVar1 != '\0') {
      return uVar1 & 0xffffffffffffff00 | 1;
    }
    uVar1 = FUN_1800245d0();
  }
  return uVar1 & 0xffffffffffffff00;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __scrt_initialize_onexit_tables
// 
// Library: Visual Studio 2015 Release

ulonglong __scrt_initialize_onexit_tables(uint param_1)

{
  code *pcVar1;
  byte bVar2;
  bool bVar3;
  undefined7 extraout_var;
  ulonglong uVar4;
  undefined4 local_28;
  undefined4 uStack_24;
  
  if (param_1 < 2) {
    bVar3 = __scrt_is_ucrt_dll_in_use();
    if (((int)CONCAT71(extraout_var,bVar3) == 0) || (param_1 != 0)) {
      uVar4 = 1;
      bVar2 = 0x40 - ((byte)DAT_180032820 & 0x3f) & 0x3f;
      _DAT_18007bd00 = (0xffffffffffffffffU >> bVar2 | -1L << 0x40 - bVar2) ^ DAT_180032820;
      local_28 = (undefined4)_DAT_18007bd00;
      uStack_24 = (undefined4)(_DAT_18007bd00 >> 0x20);
      _DAT_18007bcf0 = local_28;
      uRam000000018007bcf4 = uStack_24;
      uRam000000018007bcf8 = local_28;
      uRam000000018007bcfc = uStack_24;
      _DAT_18007bd08 = local_28;
      uRam000000018007bd0c = uStack_24;
      uRam000000018007bd10 = local_28;
      uRam000000018007bd14 = uStack_24;
      _DAT_18007bd18 = _DAT_18007bd00;
    }
    else {
      uVar4 = _initialize_onexit_table(&DAT_18007bcf0);
      if ((int)uVar4 == 0) {
        uVar4 = _initialize_onexit_table(&DAT_18007bd08);
        uVar4 = uVar4 & 0xffffffffffffff00 | (ulonglong)((int)uVar4 == 0);
      }
      else {
        uVar4 = uVar4 & 0xffffffffffffff00;
      }
    }
    return uVar4;
  }
  __scrt_fastfail(5);
  pcVar1 = (code *)swi(3);
  uVar4 = (*pcVar1)();
  return uVar4;
}



// WARNING: Removing unreachable block (ram,0x00018002384e)
// Library Function - Single Match
//  __scrt_is_nonwritable_in_current_image
// 
// Library: Visual Studio 2015 Release

ulonglong __scrt_is_nonwritable_in_current_image(longlong param_1)

{
  ulonglong uVar1;
  uint7 uVar2;
  IMAGE_SECTION_HEADER *pIVar3;
  
  uVar1 = 0;
  for (pIVar3 = &IMAGE_SECTION_HEADER_180000220; pIVar3 != (IMAGE_SECTION_HEADER *)&DAT_180000360;
      pIVar3 = pIVar3 + 1) {
    if (((ulonglong)(uint)pIVar3->VirtualAddress <= param_1 - 0x180000000U) &&
       (uVar1 = (ulonglong)((pIVar3->Misc).PhysicalAddress + pIVar3->VirtualAddress),
       param_1 - 0x180000000U < uVar1)) goto LAB_180023837;
  }
  pIVar3 = (IMAGE_SECTION_HEADER *)0x0;
LAB_180023837:
  if (pIVar3 == (IMAGE_SECTION_HEADER *)0x0) {
    uVar1 = uVar1 & 0xffffffffffffff00;
  }
  else {
    uVar2 = (uint7)(uVar1 >> 8);
    if ((int)pIVar3->Characteristics < 0) {
      uVar1 = (ulonglong)uVar2 << 8;
    }
    else {
      uVar1 = CONCAT71(uVar2,1);
    }
  }
  return uVar1;
}



// Library Function - Single Match
//  __scrt_release_startup_lock
// 
// Library: Visual Studio 2015 Release

void __scrt_release_startup_lock(char param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = __scrt_is_ucrt_dll_in_use();
  if ((CONCAT31(extraout_var,bVar1) != 0) && (param_1 == '\0')) {
    DAT_18007bce8 = 0;
  }
  return;
}



// Library Function - Single Match
//  __scrt_uninitialize_crt
// 
// Library: Visual Studio 2015 Release

undefined __scrt_uninitialize_crt(undefined8 param_1,char param_2)

{
  if ((DAT_18007bd20 == '\0') || (param_2 == '\0')) {
    FUN_1800245d0();
    FUN_1800245d0();
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _onexit
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

_onexit_t __cdecl _onexit(_onexit_t _Func)

{
  int iVar1;
  byte bVar2;
  _onexit_t p_Var3;
  
  bVar2 = (byte)DAT_180032820 & 0x3f;
  if (((DAT_180032820 ^ _DAT_18007bcf0) >> bVar2 | (DAT_180032820 ^ _DAT_18007bcf0) << 0x40 - bVar2)
      == 0xffffffffffffffff) {
    iVar1 = _crt_atexit();
  }
  else {
    iVar1 = _register_onexit_function(&DAT_18007bcf0,_Func);
  }
  p_Var3 = (_onexit_t)0x0;
  if (iVar1 == 0) {
    p_Var3 = _Func;
  }
  return p_Var3;
}



// Library Function - Single Match
//  atexit
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

int __cdecl atexit(void *param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = _onexit((_onexit_t)param_1);
  return (p_Var1 != (_onexit_t)0x0) - 1;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  _alloca_probe
// 
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

void _alloca_probe(void)

{
  undefined *in_RAX;
  undefined *puVar1;
  undefined *puVar2;
  undefined local_res8 [32];
  
  puVar1 = local_res8 + -(longlong)in_RAX;
  if (local_res8 < in_RAX) {
    puVar1 = (undefined *)0x0;
  }
  if (puVar1 < StackLimit) {
    puVar2 = (undefined *)StackLimit;
    do {
      puVar2 = puVar2 + -0x1000;
      *puVar2 = 0;
    } while ((undefined *)((ulonglong)puVar1 & 0xfffffffffffff000) != puVar2);
  }
  return;
}



// Library Function - Single Match
//  __security_check_cookie
// 
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

void __cdecl __security_check_cookie(uintptr_t _StackCookie)

{
  if ((_StackCookie == DAT_180032820) && ((short)(_StackCookie >> 0x30) == 0)) {
    return;
  }
  __report_gsfailure(_StackCookie);
  return;
}



void tls_callback_0(undefined8 param_1,int param_2)

{
  code *pcVar1;
  undefined **ppuVar2;
  
  if (param_2 == 2) {
    for (ppuVar2 = &PTR_FUN_1800253f0; ppuVar2 != (undefined **)&DAT_1800253f8;
        ppuVar2 = (code **)ppuVar2 + 1) {
      pcVar1 = (code *)*ppuVar2;
      if (pcVar1 != (code *)0x0) {
        _guard_check_icall();
        (*pcVar1)();
      }
    }
  }
  return;
}



bool FUN_180023a98(int param_1)

{
  return param_1 == -0x1f928c9d;
}



// Library Function - Single Match
//  __GSHandlerCheckCommon
// 
// Library: Visual Studio 2015 Release

void __GSHandlerCheckCommon(ulonglong param_1,longlong param_2,uint *param_3)

{
  longlong lVar1;
  ulonglong uVar2;
  
  uVar2 = param_1;
  if ((*(byte *)param_3 & 4) != 0) {
    uVar2 = (longlong)(int)param_3[1] + param_1 & (longlong)(int)-param_3[2];
  }
  lVar1 = (ulonglong)*(uint *)(*(longlong *)(param_2 + 0x10) + 8) + *(longlong *)(param_2 + 8);
  if ((*(byte *)(lVar1 + 3) & 0xf) != 0) {
    param_1 = param_1 + (*(byte *)(lVar1 + 3) & 0xfffffff0);
  }
  __security_check_cookie(param_1 ^ *(ulonglong *)((longlong)(int)(*param_3 & 0xfffffff8) + uVar2));
  return;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180024550. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  int __cdecl dllmain_crt_dispatch(struct HINSTANCE__ * __ptr64 const,unsigned long,void * __ptr64
// const)
// 
// Library: Visual Studio 2015 Release

int __cdecl dllmain_crt_dispatch(HINSTANCE__ *param_1,ulong param_2,void *param_3)

{
  code *pcVar1;
  bool bVar2;
  byte bVar3;
  char cVar4;
  int iVar5;
  uint uVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  undefined8 uVar9;
  code **ppcVar10;
  
  if (param_2 == 0) {
    uVar7 = (ulonglong)param_1 & 0xffffffffffffff00;
    if (DAT_18007bd24 < 1) {
      uVar6 = 0;
    }
    else {
      DAT_18007bd24 = DAT_18007bd24 + -1;
      uVar8 = __scrt_acquire_startup_lock();
      if (_DAT_18007bce0 != 2) {
        uVar7 = 0;
        __scrt_fastfail(7);
      }
      __scrt_dllmain_uninitialize_c();
      _DAT_18007bce0 = 0;
      __scrt_dllmain_uninitialize_critical();
      uVar7 = uVar7 & 0xffffffffffffff00;
      __scrt_release_startup_lock((char)uVar8);
      cVar4 = __scrt_uninitialize_crt
                        (uVar7 & 0xffffffffffffff00 | (ulonglong)(param_3 != (void *)0x0),'\0');
      uVar6 = (uint)(cVar4 != '\0');
    }
    return uVar6;
  }
  if (param_2 == 1) {
    uVar7 = __scrt_initialize_crt(0);
    if ((char)uVar7 != '\0') {
      uVar7 = __scrt_acquire_startup_lock();
      bVar2 = true;
      if (_DAT_18007bce0 != 0) {
        __scrt_fastfail(7);
      }
      _DAT_18007bce0 = 1;
      uVar8 = __scrt_dllmain_before_initialize_c();
      if ((char)uVar8 != '\0') {
        _RTC_Initialize();
        atexit(&LAB_1800244c0);
        FUN_18002442c();
        atexit(&LAB_18002443c);
        __scrt_initialize_default_local_stdio_options();
        iVar5 = _initterm_e(&DAT_180025400,&DAT_180025410);
        if ((iVar5 == 0) && (uVar9 = __scrt_dllmain_after_initialize_c(), (char)uVar9 != '\0')) {
          _initterm(&DAT_180025378,&DAT_1800253e0);
          _DAT_18007bce0 = 2;
          bVar2 = false;
        }
      }
      __scrt_release_startup_lock((char)uVar7);
      if (!bVar2) {
        ppcVar10 = (code **)FUN_18002446c();
        if ((*ppcVar10 != (code *)0x0) &&
           (uVar7 = __scrt_is_nonwritable_in_current_image((longlong)ppcVar10), (char)uVar7 != '\0')
           ) {
          pcVar1 = *ppcVar10;
          _guard_check_icall();
          (*pcVar1)(param_1,2,param_3);
        }
        DAT_18007bd24 = DAT_18007bd24 + 1;
        return 1;
      }
    }
    return 0;
  }
  if (param_2 == 2) {
    bVar3 = __scrt_dllmain_crt_thread_attach();
  }
  else {
    if (param_2 != 3) {
      return 1;
    }
    bVar3 = __scrt_dllmain_crt_thread_detach();
  }
  return (int)bVar3;
}



int FUN_180023d28(HINSTANCE__ *param_1,ulong param_2,void *param_3)

{
  int iVar1;
  undefined8 uVar2;
  
  if ((param_2 == 0) && (DAT_18007bd24 < 1)) {
    iVar1 = 0;
  }
  else if ((1 < param_2 - 1) ||
          ((iVar1 = dllmain_raw(param_1,param_2,param_3), iVar1 != 0 &&
           (iVar1 = dllmain_crt_dispatch(param_1,param_2,param_3), iVar1 != 0)))) {
    uVar2 = FUN_180024408(param_1,param_2);
    iVar1 = (int)uVar2;
    if ((param_2 == 1) && (iVar1 == 0)) {
      FUN_180024408(param_1,0);
      dllmain_crt_dispatch(param_1,0,param_3);
      dllmain_raw(param_1,0,param_3);
    }
    if (((param_2 == 0) || (param_2 == 3)) &&
       (iVar1 = dllmain_crt_dispatch(param_1,param_2,param_3), iVar1 != 0)) {
      iVar1 = dllmain_raw(param_1,param_2,param_3);
    }
  }
  return iVar1;
}



// WARNING: Removing unreachable block (ram,0x000180023e4d)
// Library Function - Single Match
//  int __cdecl dllmain_raw(struct HINSTANCE__ * __ptr64 const,unsigned long,void * __ptr64 const)
// 
// Library: Visual Studio 2015 Release

int __cdecl dllmain_raw(HINSTANCE__ *param_1,ulong param_2,void *param_3)

{
  return 1;
}



void entry(HINSTANCE__ *param_1,ulong param_2,void *param_3)

{
  if (param_2 == 1) {
    __security_init_cookie();
  }
  FUN_180023d28(param_1,param_2,param_3);
  return;
}



void _guard_check_icall(void)

{
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __scrt_fastfail
// 
// Library: Visual Studio 2015 Release

void __scrt_fastfail(undefined4 param_1)

{
  code *pcVar1;
  BOOL BVar2;
  LONG LVar3;
  PRUNTIME_FUNCTION FunctionEntry;
  undefined *puVar4;
  undefined8 unaff_retaddr;
  DWORD64 local_res10;
  undefined local_res18 [8];
  undefined local_res20 [8];
  undefined auStack_5c8 [8];
  undefined auStack_5c0 [232];
  undefined local_4d8 [152];
  undefined *local_440;
  DWORD64 local_3e0;
  
  puVar4 = auStack_5c8;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(param_1);
    puVar4 = auStack_5c0;
  }
  _DAT_18007bd28 = 0;
  *(undefined8 *)(puVar4 + -8) = 0x180023efd;
  memset(local_4d8,0,0x4d0);
  *(undefined8 *)(puVar4 + -8) = 0x180023f07;
  RtlCaptureContext(local_4d8);
  *(undefined8 *)(puVar4 + -8) = 0x180023f21;
  FunctionEntry = RtlLookupFunctionEntry(local_3e0,&local_res10,(PUNWIND_HISTORY_TABLE)0x0);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0) {
    *(undefined8 *)(puVar4 + 0x38) = 0;
    *(undefined **)(puVar4 + 0x30) = local_res18;
    *(undefined **)(puVar4 + 0x28) = local_res20;
    *(undefined **)(puVar4 + 0x20) = local_4d8;
    *(undefined8 *)(puVar4 + -8) = 0x180023f62;
    RtlVirtualUnwind(0,local_res10,local_3e0,FunctionEntry,*(PCONTEXT *)(puVar4 + 0x20),
                     *(PVOID **)(puVar4 + 0x28),*(PDWORD64 *)(puVar4 + 0x30),
                     *(PKNONVOLATILE_CONTEXT_POINTERS *)(puVar4 + 0x38));
  }
  local_440 = &stack0x00000008;
  *(undefined8 *)(puVar4 + -8) = 0x180023f94;
  memset(puVar4 + 0x50,0,0x98);
  *(undefined8 *)(puVar4 + 0x60) = unaff_retaddr;
  *(undefined4 *)(puVar4 + 0x50) = 0x40000015;
  *(undefined4 *)(puVar4 + 0x54) = 1;
  *(undefined8 *)(puVar4 + -8) = 0x180023fb6;
  BVar2 = IsDebuggerPresent();
  *(undefined **)(puVar4 + 0x40) = puVar4 + 0x50;
  *(undefined **)(puVar4 + 0x48) = local_4d8;
  *(undefined8 *)(puVar4 + -8) = 0x180023fd7;
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  *(undefined8 *)(puVar4 + -8) = 0x180023fe2;
  LVar3 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)(puVar4 + 0x40));
  if (LVar3 == 0) {
    _DAT_18007bd28 = _DAT_18007bd28 & -(uint)(BVar2 == 1);
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x000180024121)
// WARNING: Removing unreachable block (ram,0x000180024086)
// WARNING: Removing unreachable block (ram,0x000180024028)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __isa_available_init
// 
// Library: Visual Studio 2015 Release

undefined8 __isa_available_init(void)

{
  int *piVar1;
  uint *puVar2;
  longlong lVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  byte in_XCR0;
  uint local_20;
  
  local_20 = 0;
  DAT_180032834 = 2;
  piVar1 = (int *)cpuid_basic_info(0);
  _DAT_180032830 = 1;
  puVar2 = (uint *)cpuid_Version_info(1);
  uVar4 = puVar2[3];
  uVar5 = DAT_18007bd2c;
  if ((piVar1[2] ^ 0x49656e69U | piVar1[3] ^ 0x6c65746eU | piVar1[1] ^ 0x756e6547U) == 0) {
    _DAT_180032838 = 0xffffffffffffffff;
    uVar6 = *puVar2 & 0xfff3ff0;
    if ((((uVar6 == 0x106c0) || (uVar6 == 0x20660)) || (uVar6 == 0x20670)) ||
       ((uVar5 = DAT_18007bd2c | 4, uVar6 - 0x30650 < 0x21 &&
        ((0x100010001U >> ((ulonglong)(uVar6 - 0x30650) & 0x3f) & 1) != 0)))) {
      uVar5 = DAT_18007bd2c | 5;
    }
  }
  DAT_18007bd2c = uVar5;
  if (((piVar1[1] ^ 0x68747541U | piVar1[2] ^ 0x69746e65U | piVar1[3] ^ 0x444d4163U) == 0) &&
     (0x600eff < (*puVar2 & 0xff00f00))) {
    DAT_18007bd2c = DAT_18007bd2c | 4;
  }
  if (6 < *piVar1) {
    lVar3 = cpuid_Extended_Feature_Enumeration_info(7);
    local_20 = *(uint *)(lVar3 + 4);
    if ((local_20 >> 9 & 1) != 0) {
      DAT_18007bd2c = DAT_18007bd2c | 2;
    }
  }
  if ((uVar4 >> 0x14 & 1) != 0) {
    _DAT_180032830 = 2;
    DAT_180032834 = 6;
    if ((((uVar4 >> 0x1b & 1) != 0) && ((uVar4 >> 0x1c & 1) != 0)) && ((in_XCR0 & 6) == 6)) {
      DAT_180032834 = 0xe;
      _DAT_180032830 = 3;
      if ((local_20 & 0x20) != 0) {
        _DAT_180032830 = 5;
        DAT_180032834 = 0x2e;
      }
    }
  }
  return 0;
}



undefined8 FUN_1800241cc(void)

{
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __scrt_is_ucrt_dll_in_use
// 
// Library: Visual Studio 2015 Release

bool __scrt_is_ucrt_dll_in_use(void)

{
  return _DAT_180032840 != 0;
}



// Library Function - Single Match
//  __raise_securityfailure
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __raise_securityfailure(_EXCEPTION_POINTERS *param_1)

{
  HANDLE pvVar1;
  
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter(param_1);
  pvVar1 = GetCurrentProcess();
                    // WARNING: Could not recover jumptable at 0x00018002420d. Too many branches
                    // WARNING: Treating indirect jump as call
  TerminateProcess(pvVar1,0xc0000409);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __report_gsfailure
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl __report_gsfailure(uintptr_t _StackCookie)

{
  code *pcVar1;
  BOOL BVar2;
  undefined *puVar3;
  undefined auStack_38 [8];
  undefined auStack_30 [48];
  
  puVar3 = auStack_38;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(2);
    puVar3 = auStack_30;
  }
  *(undefined8 *)(puVar3 + -8) = 0x18002423e;
  capture_previous_context((PCONTEXT)&DAT_18007bdd0);
  _DAT_18007bd40 = *(undefined8 *)(puVar3 + 0x38);
  _DAT_18007be68 = puVar3 + 0x40;
  _DAT_18007be50 = *(undefined8 *)(puVar3 + 0x40);
  _DAT_18007bd30 = 0xc0000409;
  _DAT_18007bd34 = 1;
  _DAT_18007bd48 = 1;
  DAT_18007bd50 = 2;
  *(undefined8 *)(puVar3 + 0x20) = DAT_180032820;
  *(undefined8 *)(puVar3 + 0x28) = DAT_180032828;
  *(undefined8 *)(puVar3 + -8) = 0x1800242e0;
  DAT_18007bec8 = _DAT_18007bd40;
  __raise_securityfailure((_EXCEPTION_POINTERS *)&PTR_DAT_18002b688);
  return;
}



// Library Function - Single Match
//  capture_previous_context
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void capture_previous_context(PCONTEXT param_1)

{
  DWORD64 ControlPc;
  PRUNTIME_FUNCTION FunctionEntry;
  int iVar1;
  DWORD64 local_res8;
  ulonglong local_res10;
  PVOID local_res18 [2];
  
  RtlCaptureContext();
  ControlPc = param_1->Rip;
  iVar1 = 0;
  do {
    FunctionEntry = RtlLookupFunctionEntry(ControlPc,&local_res8,(PUNWIND_HISTORY_TABLE)0x0);
    if (FunctionEntry == (PRUNTIME_FUNCTION)0x0) {
      return;
    }
    RtlVirtualUnwind(0,local_res8,ControlPc,FunctionEntry,param_1,local_res18,&local_res10,
                     (PKNONVOLATILE_CONTEXT_POINTERS)0x0);
    iVar1 = iVar1 + 1;
  } while (iVar1 < 2);
  return;
}



// Library Function - Single Match
//  __security_init_cookie
// 
// Library: Visual Studio 2015 Release

void __cdecl __security_init_cookie(void)

{
  DWORD DVar1;
  _FILETIME local_res8;
  _FILETIME local_res10;
  uint local_res18;
  undefined4 uStackX_1c;
  
  local_res10 = (_FILETIME)0x0;
  if (DAT_180032820 == 0x2b992ddfa232) {
    GetSystemTimeAsFileTime(&local_res10);
    local_res8 = local_res10;
    DVar1 = GetCurrentThreadId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    DVar1 = GetCurrentProcessId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    QueryPerformanceCounter((LARGE_INTEGER *)&local_res18);
    DAT_180032820 =
         ((ulonglong)local_res18 << 0x20 ^ CONCAT44(uStackX_1c,local_res18) ^ (ulonglong)local_res8
         ^ (ulonglong)&local_res8) & 0xffffffffffff;
    if (DAT_180032820 == 0x2b992ddfa232) {
      DAT_180032820 = 0x2b992ddfa233;
    }
  }
  DAT_180032828 = ~DAT_180032820;
  return;
}



undefined8 FUN_180024408(HMODULE param_1,int param_2)

{
  if (param_2 == 1) {
    DisableThreadLibraryCalls(param_1);
  }
  return 1;
}



void FUN_18002442c(void)

{
                    // WARNING: Could not recover jumptable at 0x000180024433. Too many branches
                    // WARNING: Treating indirect jump as call
  InitializeSListHead(&DAT_18007c2a0);
  return;
}



undefined * FUN_180024448(void)

{
  return &DAT_18007c2b0;
}



// Library Function - Single Match
//  __scrt_initialize_default_local_stdio_options
// 
// Library: Visual Studio 2015 Release

void __scrt_initialize_default_local_stdio_options(void)

{
  ulonglong *puVar1;
  
  puVar1 = (ulonglong *)FUN_180020f90();
  *puVar1 = *puVar1 | 4;
  puVar1 = (ulonglong *)FUN_180024448();
  *puVar1 = *puVar1 | 2;
  return;
}



undefined ** FUN_18002446c(void)

{
  return &PTR_tls_callback_0_18002b678;
}



// Library Function - Single Match
//  _RTC_Initialize
// 
// Library: Visual Studio 2015 Release

void _RTC_Initialize(void)

{
  code *pcVar1;
  code **ppcVar2;
  
  for (ppcVar2 = (code **)&DAT_18002bff8; ppcVar2 < &DAT_18002bff8; ppcVar2 = ppcVar2 + 1) {
    pcVar1 = *ppcVar2;
    if (pcVar1 != (code *)0x0) {
      _guard_check_icall();
      (*pcVar1)();
    }
  }
  return;
}



void _guard_check_icall(void)

{
  return;
}



void _purecall(void)

{
                    // WARNING: Could not recover jumptable at 0x000180024520. Too many branches
                    // WARNING: Treating indirect jump as call
  _purecall();
  return;
}



void Unwind_180024526(void)

{
                    // WARNING: Could not recover jumptable at 0x000180024526. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_terminate();
  return;
}



void __CxxFrameHandler3(void)

{
                    // WARNING: Could not recover jumptable at 0x00018002452c. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler3();
  return;
}



void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180024532. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180024538. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



void __vcrt_InitializeCriticalSectionEx(void)

{
                    // WARNING: Could not recover jumptable at 0x000180024544. Too many branches
                    // WARNING: Treating indirect jump as call
  __vcrt_InitializeCriticalSectionEx();
  return;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180024550. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



double __cdecl log(double _X)

{
  double dVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180024556. Too many branches
                    // WARNING: Treating indirect jump as call
  dVar1 = log(_X);
  return dVar1;
}



double __cdecl log10(double _X)

{
  double dVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018002455c. Too many branches
                    // WARNING: Treating indirect jump as call
  dVar1 = log10(_X);
  return dVar1;
}



double __cdecl pow(double _X,double _Y)

{
  double dVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180024562. Too many branches
                    // WARNING: Treating indirect jump as call
  dVar1 = pow(_X,_Y);
  return dVar1;
}



double __cdecl sqrt(double _X)

{
  double dVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180024568. Too many branches
                    // WARNING: Treating indirect jump as call
  dVar1 = sqrt(_X);
  return dVar1;
}



wchar_t * __cdecl wcstok(wchar_t *_Str,wchar_t *_Delim)

{
  wchar_t *pwVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018002456e. Too many branches
                    // WARNING: Treating indirect jump as call
  pwVar1 = wcstok(_Str,_Delim);
  return pwVar1;
}



int __cdecl isalpha(int _C)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180024574. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = isalpha(_C);
  return iVar1;
}



int __cdecl _wcsnicmp(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018002457a. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _wcsnicmp(_Str1,_Str2,_MaxCount);
  return iVar1;
}



int __cdecl _stricmp(char *_Str1,char *_Str2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180024580. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _stricmp(_Str1,_Str2);
  return iVar1;
}



void terminate(void)

{
                    // WARNING: Could not recover jumptable at 0x000180024586. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  terminate();
  return;
}



void _seh_filter_dll(void)

{
                    // WARNING: Could not recover jumptable at 0x00018002458c. Too many branches
                    // WARNING: Treating indirect jump as call
  _seh_filter_dll();
  return;
}



void _configure_narrow_argv(void)

{
                    // WARNING: Could not recover jumptable at 0x000180024592. Too many branches
                    // WARNING: Treating indirect jump as call
  _configure_narrow_argv();
  return;
}



void _initialize_narrow_environment(void)

{
                    // WARNING: Could not recover jumptable at 0x000180024598. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_narrow_environment();
  return;
}



void _initialize_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x00018002459e. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_onexit_table();
  return;
}



void _register_onexit_function(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800245a4. Too many branches
                    // WARNING: Treating indirect jump as call
  _register_onexit_function();
  return;
}



void _execute_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800245aa. Too many branches
                    // WARNING: Treating indirect jump as call
  _execute_onexit_table();
  return;
}



void _crt_atexit(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800245b0. Too many branches
                    // WARNING: Treating indirect jump as call
  _crt_atexit();
  return;
}



void __cdecl _cexit(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800245b6. Too many branches
                    // WARNING: Treating indirect jump as call
  _cexit();
  return;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800245bc. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



void _initterm_e(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800245c2. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm_e();
  return;
}



BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001800245c8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = IsProcessorFeaturePresent(ProcessorFeature);
  return BVar1;
}



undefined FUN_1800245d0(void)

{
  return 1;
}



undefined8 FUN_1800245d4(void)

{
  return 0;
}



// WARNING: This is an inlined function

void _guard_dispatch_icall(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
                    // WARNING: Could not recover jumptable at 0x0001800245f0. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void Unwind_180024600(undefined8 param_1,longlong param_2)

{
  FUN_18001bb20((CriticalSection **)(param_2 + 0x50));
  return;
}



void Unwind_180024610(undefined8 param_1,longlong param_2)

{
  Graphine::ILogManager::_ILogManager(*(ILogManager **)(param_2 + 0x40));
  return;
}



void Unwind_18002461c(undefined8 param_1,longlong param_2)

{
  FUN_18001cc50((undefined4 *)(*(longlong *)(param_2 + 0x40) + 0x90));
  return;
}



void Unwind_180024630(void)

{
  _Init_thread_abort((undefined4 *)&DAT_180032aa8);
  return;
}



void Unwind_18002463c(void)

{
  Graphine::ILogManager::_ILogManager((ILogManager *)&PTR_vftable_1800320a0);
  return;
}



void Unwind_180024648(undefined4 *param_1)

{
  FUN_18001cc50((undefined4 *)&DAT_180032130);
  return;
}



void Unwind_180024660(undefined8 param_1,longlong param_2)

{
  FUN_18001bb20((CriticalSection **)(param_2 + 0x28));
  return;
}



void Unwind_180024670(undefined8 param_1,longlong param_2)

{
  FUN_18001bb20((CriticalSection **)(param_2 + 0x38));
  return;
}



void Unwind_180024680(undefined8 param_1,longlong param_2)

{
  FUN_18001cc80((undefined8 *)(param_2 + 0x28));
  return;
}



void Unwind_180024690(undefined8 param_1,longlong param_2)

{
  Graphine::Performance::IPerformanceManager::_IPerformanceManager
            (*(IPerformanceManager **)(param_2 + 0x58));
  return;
}



void Unwind_18002469c(undefined8 param_1,longlong param_2)

{
  Graphine::Platform::CriticalSection::_CriticalSection
            ((CriticalSection *)(*(longlong *)(param_2 + 0x58) + 0xc));
  return;
}



void Unwind_1800246ac(undefined8 param_1,longlong param_2)

{
  FUN_18001e070((undefined8 *)(*(longlong *)(param_2 + 0x58) + 0x48));
  return;
}



void Unwind_1800246bc(undefined8 param_1,longlong param_2)

{
  FUN_18001bb20((CriticalSection **)(param_2 + 0x60));
  return;
}



void Unwind_1800246d0(undefined8 param_1,longlong param_2)

{
  FUN_18001bb20((CriticalSection **)(param_2 + 0x60));
  return;
}



void Unwind_1800246e0(undefined8 param_1,longlong param_2)

{
  FUN_18001bb20((CriticalSection **)(param_2 + 0x48));
  return;
}



void Unwind_1800246f0(void)

{
  _Init_thread_abort((undefined4 *)&DAT_18007b190);
  return;
}



void Unwind_180024700(undefined8 param_1,longlong param_2)

{
  FUN_18001bb20((CriticalSection **)(param_2 + 0x68));
  return;
}



void Unwind_180024710(undefined8 param_1,longlong param_2)

{
  FUN_18001bb20((CriticalSection **)(param_2 + 0x70));
  return;
}



void Unwind_180024720(undefined8 param_1,longlong param_2)

{
  FUN_18001bb20((CriticalSection **)(param_2 + 0x40));
  return;
}



void Unwind_18002472c(undefined8 param_1,longlong param_2)

{
  FUN_18001bb20((CriticalSection **)(param_2 + 0xa0));
  return;
}



void Unwind_180024740(undefined8 param_1,longlong param_2)

{
  FUN_18001bb20((CriticalSection **)(param_2 + 0x40));
  return;
}



void Unwind_180024750(undefined8 param_1,longlong param_2)

{
  FUN_180021940((void **)(param_2 + 0x30));
  return;
}



void Unwind_18002475c(undefined8 param_1,longlong param_2)

{
  FUN_18001e070((undefined8 *)(param_2 + 0x60));
  return;
}



void Unwind_180024770(undefined8 param_1,longlong param_2)

{
  FUN_18001e040(*(undefined8 **)(param_2 + 0x40));
  return;
}



// Library Function - Single Match
//  int `void __cdecl __ArrayUnwind(void * __ptr64,unsigned __int64,int,void (__cdecl*)(void *
// __ptr64))'::`1'::filt$0
// 
// Library: Visual Studio 2005 Release

undefined4
`void___cdecl___ArrayUnwind(void*___ptr64,unsigned___int64,int,void_(__cdecl*)(void*___ptr64))'::`1'
::filt_0(undefined8 param_1,longlong param_2)

{
  *(undefined8 *)(param_2 + 0x40) = param_1;
  *(undefined8 *)(param_2 + 0x30) = param_1;
  *(undefined8 *)(param_2 + 0x38) = **(undefined8 **)(param_2 + 0x30);
  if (**(int **)(param_2 + 0x38) != -0x1f928c9d) {
    *(undefined4 *)(param_2 + 0x20) = 0;
    return *(undefined4 *)(param_2 + 0x20);
  }
                    // WARNING: Subroutine does not return
  terminate();
}



void FUN_180024801(int **param_1)

{
  FUN_180023a98(**param_1);
  return;
}



void FUN_18002481c(undefined8 param_1,longlong param_2)

{
  __scrt_release_startup_lock(*(char *)(param_2 + 0x40));
  return;
}



void FUN_180024833(undefined8 param_1,longlong param_2)

{
  __scrt_dllmain_uninitialize_critical();
  __scrt_release_startup_lock(*(char *)(param_2 + 0x38));
  return;
}



void FUN_18002484f(undefined8 *param_1,longlong param_2)

{
  __scrt_dllmain_exception_filter
            (*(undefined8 *)(param_2 + 0x60),*(int *)(param_2 + 0x68),
             *(undefined8 *)(param_2 + 0x70),dllmain_crt_dispatch,*(undefined4 *)*param_1,param_1);
  return;
}



void FUN_180024890(void)

{
  PTR_vftable_1800320a0 = (undefined *)Graphine::LogManager::vftable;
  Graphine::Platform::CriticalSection::_CriticalSection((CriticalSection *)&DAT_180032150);
  FUN_18001cdf0((undefined4 *)&DAT_180032130);
  FUN_18001d780((void **)&DAT_180032138);
  PTR_vftable_1800320a0 = (undefined *)Graphine::ILogManager::vftable;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1800248f0(void)

{
  LPCVOID pvVar1;
  bool bVar2;
  
  _DAT_180032ab0 = Graphine::Performance::PerformanceMonitor::vftable;
  Graphine::Platform::CriticalSection::Enter((CriticalSection *)&DAT_180032abc);
  Graphine::Platform::CriticalSection::Enter((CriticalSection *)&DAT_180032abc);
  bVar2 = FUN_180022f00((longlong)&DAT_180032af8);
  pvVar1 = DAT_18003ab38;
  if (bVar2) {
    if ((DAT_180032b00 == '\0') && (DAT_18003ab48 != 0)) {
      DAT_18003ab38 = DAT_18003ab40;
      DAT_18003ab40 = pvVar1;
      FUN_180023020((longlong)&DAT_180032af8,pvVar1,DAT_18003ab48);
      DAT_18003ab48 = 0;
      FUN_180022fe0((longlong)&DAT_180032af8);
    }
    FUN_180022ea0((longlong)&DAT_180032af8);
    Graphine::Platform::CriticalSection::Leave((CriticalSection *)&DAT_180032abc);
  }
  else {
    Graphine::Platform::CriticalSection::Leave((CriticalSection *)&DAT_180032abc);
  }
  Graphine::Platform::CriticalSection::Leave((CriticalSection *)&DAT_180032abc);
  _DAT_180032af8 = Graphine::IAsyncWriter<class_Graphine::AsyncWriter_Windows>::vftable;
  FUN_180022ea0((longlong)&DAT_180032af8);
  Graphine::Platform::CriticalSection::_CriticalSection((CriticalSection *)&DAT_180032abc);
  _DAT_180032ab0 = Graphine::Performance::IPerformanceManager::vftable;
  return;
}


