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

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef int __ehstate_t;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    ImageBaseOffset32 action;
};

typedef struct _s_IPToStateMapEntry _s_IPToStateMapEntry, *P_s_IPToStateMapEntry;

typedef struct _s_IPToStateMapEntry IPToStateMapEntry;

struct _s_IPToStateMapEntry {
    ImageBaseOffset32 Ip;
    __ehstate_t state;
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

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

struct _s_TryBlockMapEntry {
    __ehstate_t tryLow;
    __ehstate_t tryHigh;
    __ehstate_t catchHigh;
    int nCatches;
    ImageBaseOffset32 dispHandlerArray;
};

typedef struct _s__RTTIClassHierarchyDescriptor _s__RTTIClassHierarchyDescriptor, *P_s__RTTIClassHierarchyDescriptor;

struct _s__RTTIClassHierarchyDescriptor {
    dword signature;
    dword attributes; // bit flags
    dword numBaseClasses; // number of base classes (i.e. rtti1Count)
    RTTIBaseClassDescriptor *32 __((image-base-relative)) *32 __((image-base-relative)) pBaseClassArray; // ref to BaseClassArray (RTTI 2)
};

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

typedef struct _s__RTTICompleteObjectLocator _s__RTTICompleteObjectLocator, *P_s__RTTICompleteObjectLocator;

struct _s__RTTICompleteObjectLocator {
    dword signature;
    dword offset; // offset of vbtable within class
    dword cdOffset; // constructor displacement offset
    ImageBaseOffset32 pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    ImageBaseOffset32 pClassDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3)
};

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

struct _s_HandlerType {
    uint adjectives;
    ImageBaseOffset32 dispType;
    int dispCatchObj;
    ImageBaseOffset32 dispOfHandler;
    dword dispFrame;
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

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

struct TypeDescriptor {
    void * pVFTable;
    void * spare;
    char name[0];
};

typedef struct _s__RTTICompleteObjectLocator RTTICompleteObjectLocator;

typedef ulonglong __uint64;

typedef struct _s_HandlerType HandlerType;

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Class Structure
};


// WARNING! conflicting data type names: /guiddef.h/GUID - /GUID

typedef GUID IID;

typedef struct _GUID _GUID, *P_GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef ulong DWORD;

typedef void * LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulonglong ULONG_PTR;

typedef union _union_540 _union_540, *P_union_540;

typedef void * HANDLE;

typedef struct _struct_541 _struct_541, *P_struct_541;

typedef void * PVOID;

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

typedef enum _FILE_INFO_BY_HANDLE_CLASS {
    FileBasicInfo=0,
    FileStandardInfo=1,
    FileNameInfo=2,
    FileRenameInfo=3,
    FileDispositionInfo=4,
    FileAllocationInfo=5,
    FileEndOfFileInfo=6,
    FileStreamInfo=7,
    FileCompressionInfo=8,
    FileAttributeTagInfo=9,
    FileIdBothDirectoryInfo=10,
    FileIdBothDirectoryRestartInfo=11,
    FileIoPriorityHintInfo=12,
    FileRemoteProtocolInfo=13,
    MaximumFileInfoByHandleClass=14
} _FILE_INFO_BY_HANDLE_CLASS;

typedef enum _FILE_INFO_BY_HANDLE_CLASS FILE_INFO_BY_HANDLE_CLASS;

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef long LONG;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (* PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT * PCONTEXT;

typedef ulonglong DWORD64;

typedef ushort WORD;

typedef union _union_54 _union_54, *P_union_54;

typedef struct _M128A _M128A, *P_M128A;

typedef struct _M128A M128A;

typedef struct _XSAVE_FORMAT _XSAVE_FORMAT, *P_XSAVE_FORMAT;

typedef struct _XSAVE_FORMAT XSAVE_FORMAT;

typedef XSAVE_FORMAT XMM_SAVE_AREA32;

typedef struct _struct_55 _struct_55, *P_struct_55;

typedef ulonglong ULONGLONG;

typedef longlong LONGLONG;

typedef uchar BYTE;

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

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

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

typedef wchar_t WCHAR;

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

typedef long HRESULT;

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

typedef DWORD ULONG;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME * LPFILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef DWORD * LPDWORD;

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

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 34404
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
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

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

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

struct IMAGE_NT_HEADERS64 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER64 OptionalHeader;
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

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
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

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char * _ptr;
    int _cnt;
    char * _base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char * _tmpfname;
};

typedef struct _iobuf FILE;

typedef int PMFN;

typedef struct _s_ThrowInfo _s_ThrowInfo, *P_s_ThrowInfo;

struct _s_ThrowInfo {
    uint attributes;
    PMFN pmfnUnwind;
    int pForwardCompat;
    int pCatchableTypeArray;
};

typedef struct _s_ThrowInfo ThrowInfo;

typedef ulonglong uintptr_t;

typedef struct half half, *Phalf;

struct half { // PlaceHolder Structure
};

typedef enum Enum {
} Enum;

typedef struct basic_streambuf<char,struct_std::char_traits<char>_> basic_streambuf<char,struct_std::char_traits<char>_>, *Pbasic_streambuf<char,struct_std::char_traits<char>_>;

struct basic_streambuf<char,struct_std::char_traits<char>_> { // PlaceHolder Structure
};

typedef struct basic_istream<char,struct_std::char_traits<char>_> basic_istream<char,struct_std::char_traits<char>_>, *Pbasic_istream<char,struct_std::char_traits<char>_>;

struct basic_istream<char,struct_std::char_traits<char>_> { // PlaceHolder Structure
};

typedef struct basic_ostream<char,struct_std::char_traits<char>_> basic_ostream<char,struct_std::char_traits<char>_>, *Pbasic_ostream<char,struct_std::char_traits<char>_>;

struct basic_ostream<char,struct_std::char_traits<char>_> { // PlaceHolder Structure
};

typedef struct basic_ios<char,struct_std::char_traits<char>_> basic_ios<char,struct_std::char_traits<char>_>, *Pbasic_ios<char,struct_std::char_traits<char>_>;

struct basic_ios<char,struct_std::char_traits<char>_> { // PlaceHolder Structure
};

typedef union uif uif, *Puif;

union uif {
};

typedef int (* _onexit_t)(void);

typedef ulonglong size_t;

typedef size_t rsize_t;

typedef int errno_t;

typedef struct IUnknownVtbl IUnknownVtbl, *PIUnknownVtbl;

typedef struct IUnknown IUnknown, *PIUnknown;

struct IUnknownVtbl {
    HRESULT (* QueryInterface)(struct IUnknown *, IID *, void * *);
    ULONG (* AddRef)(struct IUnknown *);
    ULONG (* Release)(struct IUnknown *);
};

struct IUnknown {
    struct IUnknownVtbl * lpVtbl;
};

typedef struct IUnknown * LPUNKNOWN;




ulonglong FUN_1800010f0(int param_1,undefined4 *param_2)

{
  longlong lVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  
  uVar5 = 0;
  switch(param_1) {
  case 6:
    if (DAT_18006649c != '\0') {
      *param_2 = 0xe3fed78f;
      param_2[1] = 0x4acfe8db;
      param_2[2] = 0x7fe9c184;
      param_2[3] = 0x27b33661;
      return 1;
    }
    break;
  default:
    uVar5 = 0;
    uVar6 = uVar5;
    do {
      if (*(int *)((longlong)&DAT_180065230 + uVar5) == param_1) {
        lVar1 = uVar6 * 0x18;
        uVar2 = *(undefined4 *)(lVar1 + 0x180065224);
        uVar3 = *(undefined4 *)(lVar1 + 0x180065228);
        uVar4 = *(undefined4 *)(lVar1 + 0x18006522c);
        *param_2 = *(undefined4 *)(&DAT_180065220 + lVar1);
        param_2[1] = uVar2;
        param_2[2] = uVar3;
        param_2[3] = uVar4;
        return CONCAT71((int7)(uVar6 * 3 >> 8),1);
      }
      uVar6 = uVar6 + 1;
      uVar5 = uVar5 + 0x18;
    } while (uVar5 < 0x180);
    break;
  case 0x1c:
  case 0x1d:
  case 0x5b:
    *param_2 = 0x6fddc324;
    param_2[1] = 0x4bfe4e03;
    param_2[2] = 0x773d85b1;
    param_2[3] = 0xfc98d76;
    return 1;
  case 0x28:
    *param_2 = 0x6fddc324;
    param_2[1] = 0x4bfe4e03;
    param_2[2] = 0x773d85b1;
    param_2[3] = 0x11c98d76;
    return 1;
  case 0x37:
    *param_2 = 0x6fddc324;
    param_2[1] = 0x4bfe4e03;
    param_2[2] = 0x773d85b1;
    param_2[3] = 0xbc98d76;
    return 1;
  case 0x5d:
    *param_2 = 0x6fddc324;
    param_2[1] = 0x4bfe4e03;
    param_2[2] = 0x773d85b1;
    param_2[3] = 0xec98d76;
    return 1;
  }
  *param_2 = 0;
  param_2[1] = 0;
  param_2[2] = 0;
  param_2[3] = 0;
  return uVar5 & 0xffffffffffffff00;
}



longlong FUN_180001220(void)

{
  HRESULT HVar1;
  
  if (DAT_1800664a0 == 0) {
    HVar1 = CoCreateInstance((IID *)&DAT_18005d230,(LPUNKNOWN)0x0,1,(IID *)&DAT_18005d328,
                             (LPVOID *)&DAT_1800664a0);
    if (HVar1 < 0) {
      HVar1 = CoCreateInstance((IID *)&DAT_18005d220,(LPUNKNOWN)0x0,1,(IID *)&DAT_18005d338,
                               (LPVOID *)&DAT_1800664a0);
      if (HVar1 < 0) {
        DAT_1800664a0 = 0;
        return 0;
      }
    }
    else {
      DAT_18006649c = 1;
    }
  }
  return DAT_1800664a0;
}



undefined8 FUN_1800012c0(undefined4 param_1)

{
  switch(param_1) {
  case 1:
  case 2:
  case 3:
  case 4:
    return 0x80;
  case 5:
  case 6:
  case 7:
  case 8:
    return 0x60;
  case 9:
  case 10:
  case 0xb:
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x66:
  case 0x6c:
  case 0x6d:
    return 0x40;
  case 0x17:
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
  case 0x20:
  case 0x21:
  case 0x22:
  case 0x23:
  case 0x24:
  case 0x25:
  case 0x26:
  case 0x27:
  case 0x28:
  case 0x29:
  case 0x2a:
  case 0x2b:
  case 0x2c:
  case 0x2d:
  case 0x2e:
  case 0x2f:
  case 0x43:
  case 0x44:
  case 0x45:
  case 0x57:
  case 0x58:
  case 0x59:
  case 0x5a:
  case 0x5b:
  case 0x5c:
  case 0x5d:
  case 100:
  case 0x65:
  case 0x6b:
  case 0x74:
  case 0x75:
    return 0x20;
  case 0x30:
  case 0x31:
  case 0x32:
  case 0x33:
  case 0x34:
  case 0x35:
  case 0x36:
  case 0x37:
  case 0x38:
  case 0x39:
  case 0x3a:
  case 0x3b:
  case 0x55:
  case 0x56:
  case 0x72:
  case 0x73:
    return 0x10;
  case 0x3c:
  case 0x3d:
  case 0x3e:
  case 0x3f:
  case 0x40:
  case 0x41:
  case 0x49:
  case 0x4a:
  case 0x4b:
  case 0x4c:
  case 0x4d:
  case 0x4e:
  case 0x52:
  case 0x53:
  case 0x54:
  case 0x5e:
  case 0x5f:
  case 0x60:
  case 0x61:
  case 0x62:
  case 99:
  case 0x6f:
  case 0x70:
  case 0x71:
    return 8;
  case 0x42:
    return 1;
  case 0x46:
  case 0x47:
  case 0x48:
  case 0x4f:
  case 0x50:
  case 0x51:
    return 4;
  case 0x67:
  case 0x6a:
  case 0x6e:
    return 0xc;
  case 0x68:
  case 0x69:
  case 0x76:
  case 0x77:
  case 0x78:
    return 0x18;
  default:
    return 0;
  }
}



undefined8 FUN_1800013d0(undefined4 param_1)

{
  switch(param_1) {
  case 1:
  case 2:
  case 3:
  case 4:
  case 5:
  case 6:
  case 7:
  case 8:
  case 0xf:
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x27:
  case 0x28:
  case 0x29:
  case 0x2a:
  case 0x2b:
    return 0x20;
  case 9:
  case 10:
  case 0xb:
  case 0xc:
  case 0xd:
  case 0xe:
  case 0x21:
  case 0x22:
  case 0x23:
  case 0x24:
  case 0x25:
  case 0x26:
  case 0x35:
  case 0x36:
  case 0x37:
  case 0x38:
  case 0x39:
  case 0x3a:
  case 0x3b:
  case 0x5e:
  case 0x5f:
  case 0x60:
  case 0x66:
  case 0x69:
  case 0x6d:
  case 0x76:
  case 0x77:
  case 0x78:
    return 0x10;
  case 0x17:
  case 0x18:
  case 0x19:
  case 0x59:
  case 0x65:
  case 0x68:
  case 0x6c:
  case 0x74:
  case 0x75:
    return 10;
  case 0x1a:
    return 0xb;
  case 0x1b:
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
  case 0x20:
  case 0x30:
  case 0x31:
  case 0x32:
  case 0x33:
  case 0x34:
  case 0x3c:
  case 0x3d:
  case 0x3e:
  case 0x3f:
  case 0x40:
  case 0x41:
  case 0x44:
  case 0x45:
  case 0x4f:
  case 0x50:
  case 0x51:
  case 0x52:
  case 0x53:
  case 0x54:
  case 0x57:
  case 0x58:
  case 0x5a:
  case 0x5b:
  case 0x5c:
  case 0x5d:
  case 100:
  case 0x67:
  case 0x6a:
  case 0x6b:
  case 0x6e:
    return 8;
  case 0x2c:
  case 0x2d:
  case 0x2e:
  case 0x2f:
    return 0x18;
  case 0x42:
    return 1;
  case 0x43:
    return 0xe;
  case 0x46:
  case 0x47:
  case 0x48:
  case 0x49:
  case 0x4a:
  case 0x4b:
  case 0x4c:
  case 0x4d:
  case 0x4e:
  case 0x55:
    return 6;
  case 0x56:
    return 5;
  case 0x61:
  case 0x62:
  case 99:
    return 7;
  default:
    return 0;
  case 0x73:
    return 4;
  }
}



void FUN_1800014f0(int param_1,longlong param_2,longlong param_3,ulonglong *param_4,
                  longlong *param_5,uint param_6)

{
  ulonglong uVar1;
  ulonglong *puVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  longlong lVar5;
  ulonglong local_18;
  ulonglong local_10;
  
  if ((0x45 < param_1) && ((param_1 < 0x55 || (param_1 - 0x5eU < 6)))) {
    if ((param_1 - 0x46U < 3) || (lVar5 = 0x10, param_1 - 0x4fU < 3)) {
      lVar5 = 8;
    }
    local_18 = param_2 + 3U >> 2;
    uVar3 = param_3 + 3U >> 2;
    local_10 = 1;
    puVar2 = &local_18;
    if (local_18 < 2) {
      puVar2 = &local_10;
    }
    uVar1 = *puVar2;
    *param_4 = uVar1 * lVar5;
    uVar4 = 1;
    if (1 < uVar3) {
      uVar4 = uVar3;
    }
    *param_5 = uVar4 * uVar1 * lVar5;
    return;
  }
  if ((0x43 < param_1) && ((param_1 < 0x46 || (param_1 - 0x6bU < 3)))) {
    lVar5 = 8;
    if (1 < param_1 - 0x6cU) {
      lVar5 = 4;
    }
    uVar3 = (param_2 + 1U >> 1) * lVar5;
    *param_4 = uVar3;
    *param_5 = uVar3 * param_3;
    return;
  }
  if (param_1 == 0x6e) {
    uVar3 = param_2 + 3U & 0xfffffffffffffffc;
    *param_4 = uVar3;
    *param_5 = uVar3 * param_3 * 2;
    return;
  }
  if ((0x66 < param_1) && ((param_1 < 0x6b || (param_1 - 0x76U < 3)))) {
    if ((param_1 - 0x68U < 2) || (lVar5 = 2, param_1 - 0x76U < 3)) {
      lVar5 = 4;
    }
    uVar3 = (param_2 + 1U >> 1) * lVar5;
    *param_4 = uVar3;
    *param_5 = ((param_3 + 1U >> 1) + param_3) * uVar3;
    return;
  }
  if ((param_6 >> 0x10 & 1) == 0) {
    if ((param_6 >> 0x11 & 1) == 0) {
      if ((param_6 >> 0x12 & 1) == 0) {
        lVar5 = FUN_1800012c0(param_1);
      }
      else {
        lVar5 = 8;
      }
    }
    else {
      lVar5 = 0x10;
    }
  }
  else {
    lVar5 = 0x18;
  }
  lVar5 = lVar5 * param_2;
  if ((param_6 & 1) == 0) {
    if ((param_6 & 2) == 0) {
      uVar3 = lVar5 + 7U >> 3;
    }
    else {
      uVar3 = (lVar5 + 0x7fU >> 7) << 4;
    }
  }
  else {
    uVar3 = (lVar5 + 0x1fU >> 5) << 2;
  }
  *param_4 = uVar3;
  *param_5 = uVar3 * param_3;
  return;
}



void FUN_180001710(ulonglong *param_1,uint param_2,longlong *param_3,longlong *param_4,int param_5)

{
  int iVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  longlong lVar6;
  longlong lVar7;
  ulonglong local_58;
  ulonglong local_50;
  ulonglong local_48 [2];
  
  lVar7 = 0;
  if (param_5 < 4) {
    local_58 = param_1[3];
    lVar6 = 0;
    if (local_58 != 0) {
      uVar3 = param_1[4];
      lVar6 = lVar7;
      do {
        uVar5 = *param_1;
        uVar4 = param_1[1];
        if (uVar3 != 0) {
          iVar1 = *(int *)(param_1 + 6);
          lVar6 = lVar6 + uVar3;
          do {
            FUN_1800014f0(iVar1,uVar5,uVar4,local_48,(longlong *)&local_50,param_2);
            lVar7 = lVar7 + local_50;
            if (1 < uVar4) {
              uVar4 = uVar4 >> 1;
            }
            if (1 < uVar5) {
              uVar5 = uVar5 >> 1;
            }
            uVar3 = uVar3 - 1;
          } while (uVar3 != 0);
          uVar3 = param_1[4];
        }
        local_58 = local_58 - 1;
      } while (local_58 != 0);
    }
  }
  else {
    lVar6 = lVar7;
    if (param_5 == 4) {
      uVar3 = param_1[4];
      uVar5 = *param_1;
      uVar4 = param_1[1];
      uVar2 = param_1[2];
      lVar6 = 0;
      if (uVar3 != 0) {
        iVar1 = *(int *)(param_1 + 6);
        lVar6 = lVar7;
        do {
          FUN_1800014f0(iVar1,uVar5,uVar4,&local_50,(longlong *)&local_58,param_2);
          if (uVar2 != 0) {
            lVar7 = lVar7 + local_58 * uVar2;
            lVar6 = lVar6 + uVar2;
          }
          if (1 < uVar4) {
            uVar4 = uVar4 >> 1;
          }
          if (1 < uVar5) {
            uVar5 = uVar5 >> 1;
          }
          if (1 < uVar2) {
            uVar2 = uVar2 >> 1;
          }
          uVar3 = uVar3 - 1;
        } while (uVar3 != 0);
      }
    }
  }
  *param_3 = lVar6;
  *param_4 = lVar7;
  return;
}



ulonglong FUN_180001890(ulonglong param_1,longlong param_2,ulonglong *param_3,uint param_4,
                       longlong param_5,ulonglong param_6)

{
  uint uVar1;
  undefined4 uVar2;
  ulonglong in_RAX;
  undefined4 *puVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  undefined4 *puVar8;
  ulonglong uVar9;
  ulonglong uVar10;
  undefined4 *puVar11;
  ulonglong uVar12;
  ulonglong local_40;
  ulonglong local_38;
  undefined4 *local_30;
  
  if (param_5 == 0) {
    return in_RAX & 0xffffffffffffff00;
  }
  uVar4 = param_1 + param_2;
  uVar6 = 0;
  uVar1 = *(uint *)((longlong)param_3 + 0x34);
  puVar3 = (undefined4 *)(ulonglong)uVar1;
  if ((int)uVar1 < 2) {
LAB_180001b16:
    uVar4 = (ulonglong)puVar3 & 0xffffffffffffff00;
  }
  else {
    if ((int)uVar1 < 4) {
      if ((param_3[3] == 0) || (puVar3 = (undefined4 *)param_3[4], puVar3 == (undefined4 *)0x0))
      goto LAB_180001b16;
      local_40 = 0;
      if (param_3[3] != 0) {
        do {
          uVar10 = *param_3;
          puVar8 = (undefined4 *)0x0;
          uVar9 = param_3[1];
          if (puVar3 != (undefined4 *)0x0) {
            puVar3 = (undefined4 *)(uVar6 * 0x30);
            puVar11 = (undefined4 *)(param_5 + 0x10 + (longlong)puVar3);
            do {
              if (param_6 <= uVar6) goto LAB_180001b16;
              FUN_1800014f0(*(int *)(param_3 + 6),uVar10,uVar9,&local_38,(longlong *)&local_30,
                            param_4);
              *(ulonglong *)(puVar11 + -4) = uVar10;
              uVar6 = uVar6 + 1;
              *(ulonglong *)(puVar11 + -2) = uVar9;
              *puVar11 = *(undefined4 *)(param_3 + 6);
              *(ulonglong *)(puVar11 + 2) = local_38;
              *(ulonglong *)(puVar11 + 6) = param_1;
              param_1 = param_1 + (longlong)local_30;
              *(undefined4 **)(puVar11 + 4) = local_30;
              puVar11 = puVar11 + 0xc;
              puVar3 = local_30;
              if (uVar4 < param_1) goto LAB_180001b16;
              if (1 < uVar9) {
                uVar9 = uVar9 >> 1;
              }
              if (1 < uVar10) {
                uVar10 = uVar10 >> 1;
              }
              puVar3 = (undefined4 *)param_3[4];
              puVar8 = (undefined4 *)((longlong)puVar8 + 1);
            } while (puVar8 < puVar3);
          }
          local_40 = local_40 + 1;
        } while (local_40 < param_3[3]);
      }
    }
    else {
      if (((uVar1 != 4) || (puVar3 = (undefined4 *)param_3[4], puVar3 == (undefined4 *)0x0)) ||
         (uVar10 = param_3[2], uVar10 == 0)) goto LAB_180001b16;
      uVar9 = *param_3;
      uVar12 = 0;
      uVar7 = param_3[1];
      if (puVar3 != (undefined4 *)0x0) {
        do {
          puVar3 = (undefined4 *)
                   FUN_1800014f0(*(int *)(param_3 + 6),uVar9,uVar7,&local_38,(longlong *)&local_40,
                                 param_4);
          uVar5 = 0;
          if (uVar10 != 0) {
            puVar3 = (undefined4 *)(uVar6 * 0x30 + param_5 + 0x10);
            do {
              if (param_6 <= uVar6) goto LAB_180001b16;
              *(ulonglong *)(puVar3 + -4) = uVar9;
              uVar6 = uVar6 + 1;
              *(ulonglong *)(puVar3 + -2) = uVar7;
              uVar2 = *(undefined4 *)(param_3 + 6);
              *(ulonglong *)(puVar3 + 6) = param_1;
              param_1 = param_1 + local_40;
              *puVar3 = uVar2;
              *(ulonglong *)(puVar3 + 2) = local_38;
              *(ulonglong *)(puVar3 + 4) = local_40;
              puVar3 = puVar3 + 0xc;
              if (uVar4 < param_1) goto LAB_180001b16;
              uVar5 = uVar5 + 1;
            } while (uVar5 < uVar10);
          }
          if (1 < uVar7) {
            uVar7 = uVar7 >> 1;
          }
          if (1 < uVar9) {
            uVar9 = uVar9 >> 1;
          }
          if (1 < uVar10) {
            uVar10 = uVar10 >> 1;
          }
          uVar12 = uVar12 + 1;
        } while (uVar12 < param_3[4]);
      }
    }
    uVar4 = CONCAT71((int7)((ulonglong)puVar3 >> 8),1);
  }
  return uVar4;
}



undefined8 FUN_180001b50(ulonglong *param_1,ulonglong *param_2)

{
  int iVar1;
  int iVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  __uint64 _Var5;
  void *pvVar6;
  undefined8 uVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  ulonglong local_res10 [2];
  ulonglong local_res20;
  
  iVar1 = *(int *)(param_2 + 6);
  if (0x77 < iVar1 - 1U) {
    return 0x80070057;
  }
  if (iVar1 - 0x6fU < 4) {
    return 0x80070032;
  }
  iVar2 = *(int *)((longlong)param_2 + 0x34);
  local_res10[0] = param_2[4];
  uVar8 = local_res10[0];
  if (iVar2 == 2) {
    uVar4 = *param_2;
    if (uVar4 == 0) {
      return 0x80070057;
    }
    if (param_2[1] != 1) {
      return 0x80070057;
    }
    if (param_2[2] != 1) {
      return 0x80070057;
    }
    if (param_2[3] == 0) {
      return 0x80070057;
    }
    if (iVar1 - 100U < 0xf) {
      return 0x80070032;
    }
    if (1 < local_res10[0]) {
      uVar9 = 1;
      uVar3 = 1;
      do {
        if (uVar9 < 2) {
          if (uVar4 < 2) goto code_r0x000180001d8c;
LAB_180001dac:
          uVar4 = uVar4 >> 1;
        }
        else {
          uVar9 = 0;
          if (1 < uVar4) goto LAB_180001dac;
        }
        uVar3 = uVar3 + 1;
      } while( true );
    }
    if (local_res10[0] == 0) {
      uVar9 = 1;
      uVar8 = 1;
      while( true ) {
        while (1 < uVar9) {
          uVar9 = 0;
          if (1 < uVar4) {
            uVar4 = uVar4 >> 1;
          }
          uVar8 = uVar8 + 1;
        }
        if (uVar4 < 2) break;
        uVar4 = uVar4 >> 1;
        uVar8 = uVar8 + 1;
      }
    }
    else {
      uVar8 = 1;
    }
  }
  else {
    if (iVar2 != 3) {
      if (iVar2 != 4) {
        return 0x80070032;
      }
      uVar8 = *param_2;
      if ((((uVar8 != 0) && (uVar4 = param_2[1], uVar4 != 0)) && (uVar9 = param_2[2], uVar9 != 0))
         && (param_2[3] == 1)) {
        if (iVar1 - 100U < 0xf) {
          return 0x80070032;
        }
        if (0x66 < iVar1) {
          if (iVar1 < 0x6b) {
            return 0x80070032;
          }
          if (iVar1 == 0x6e) {
            return 0x80070032;
          }
          if (iVar1 - 0x76U < 3) {
            return 0x80070032;
          }
        }
        uVar3 = FUN_1800021c0(iVar1);
        if ((char)uVar3 != '\0') {
          return 0x80070032;
        }
        uVar4 = FUN_1800071a0(uVar8,uVar4,uVar9,local_res10);
        uVar8 = local_res10[0];
        if ((char)uVar4 != '\0') goto LAB_180001dea;
      }
      return 0x80070057;
    }
    uVar4 = *param_2;
    if (uVar4 == 0) {
      return 0x80070057;
    }
    uVar9 = param_2[1];
    if (uVar9 == 0) {
      return 0x80070057;
    }
    if (param_2[2] != 1) {
      return 0x80070057;
    }
    uVar3 = param_2[3];
    if (uVar3 == 0) {
      return 0x80070057;
    }
    if ((*(uint *)(param_2 + 5) >> 2 & 1) != 0) {
      if (uVar3 != (uVar3 / 6) * 6) {
        return 0x80070057;
      }
      if (iVar1 - 100U < 0xf) {
        return 0x80070032;
      }
    }
    if (1 < local_res10[0]) {
      uVar3 = 1;
      do {
        if (uVar9 < 2) {
          if (uVar4 < 2) goto code_r0x000180001cd1;
LAB_180001cf5:
          uVar4 = uVar4 >> 1;
        }
        else {
          uVar9 = uVar9 >> 1;
          if (1 < uVar4) goto LAB_180001cf5;
        }
        uVar3 = uVar3 + 1;
      } while( true );
    }
    uVar8 = 1;
    if (local_res10[0] == 0) {
      while( true ) {
        while (1 < uVar9) {
          uVar9 = uVar9 >> 1;
          if (1 < uVar4) {
            uVar4 = uVar4 >> 1;
          }
          uVar8 = uVar8 + 1;
        }
        if (uVar4 < 2) break;
        uVar4 = uVar4 >> 1;
        uVar8 = uVar8 + 1;
      }
    }
  }
LAB_180001dea:
  FUN_1800020c0(param_1);
  param_1[2] = *param_2;
  param_1[3] = param_2[1];
  param_1[4] = param_2[2];
  param_1[5] = param_2[3];
  param_1[6] = uVar8;
  *(undefined4 *)(param_1 + 7) = *(undefined4 *)(param_2 + 5);
  *(undefined4 *)((longlong)param_1 + 0x3c) = *(undefined4 *)((longlong)param_2 + 0x2c);
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_2 + 6);
  iVar1 = *(int *)((longlong)param_2 + 0x34);
  *(int *)((longlong)param_1 + 0x44) = iVar1;
  if (iVar1 < 2) {
    local_res20 = 0;
    uVar8 = local_res20;
  }
  else {
    FUN_180001710(param_1 + 2,0,(longlong *)&local_res20,(longlong *)local_res10,iVar1);
    uVar8 = local_res10[0];
  }
  _Var5 = SUB168(ZEXT816(0x30) * ZEXT816(local_res20),0);
  if (SUB168(ZEXT816(0x30) * ZEXT816(local_res20) >> 0x40,0) != 0) {
    _Var5 = 0xffffffffffffffff;
  }
  pvVar6 = (void *)thunk_FUN_18001ac00(_Var5);
  param_1[9] = (ulonglong)pvVar6;
  if (pvVar6 != (void *)0x0) {
    *param_1 = local_res20;
    memset(pvVar6,0,local_res20 * 0x30);
    pvVar6 = _aligned_malloc(uVar8,0x10);
    param_1[10] = (ulonglong)pvVar6;
    if (pvVar6 != (void *)0x0) {
      param_1[1] = uVar8;
      uVar7 = FUN_180001890((ulonglong)pvVar6,uVar8,param_1 + 2,0,param_1[9],local_res20);
      if ((char)uVar7 == '\0') {
        FUN_1800020c0(param_1);
        return 0x80004005;
      }
      return 0;
    }
    FUN_1800020c0(param_1);
  }
  return 0x8007000e;
code_r0x000180001d8c:
  if (uVar3 < local_res10[0]) {
    return 0x80070057;
  }
  goto LAB_180001dea;
code_r0x000180001cd1:
  if (uVar3 < local_res10[0]) {
    return 0x80070057;
  }
  goto LAB_180001dea;
}



undefined8
FUN_180001f40(ulonglong *param_1,undefined8 param_2,ulonglong param_3,ulonglong param_4,
             size_t param_5,ulonglong param_6)

{
  ulonglong uVar1;
  __uint64 _Var2;
  void *pvVar3;
  undefined8 uVar4;
  size_t _Size;
  ulonglong local_18 [2];
  
  local_18[0] = 1;
  if (((param_3 != 0) && (param_4 != 0)) &&
     (uVar1 = FUN_180007130(param_3,param_4,local_18), (char)uVar1 != '\0')) {
    FUN_1800020c0(param_1);
    param_1[3] = param_4;
    uVar1 = 0;
    param_1[6] = local_18[0];
    param_1[7] = 0;
    param_1[2] = param_3;
    param_1[4] = 1;
    param_1[5] = 1;
    *(undefined4 *)(param_1 + 8) = 2;
    *(undefined4 *)((longlong)param_1 + 0x44) = 3;
    _Size = uVar1;
    if (1 < *(int *)((longlong)param_1 + 0x44)) {
      FUN_180001710(param_1 + 2,0,(longlong *)&param_6,(longlong *)&param_5,
                    *(int *)((longlong)param_1 + 0x44));
      uVar1 = param_6;
      _Size = param_5;
    }
    _Var2 = SUB168(ZEXT816(0x30) * ZEXT816(uVar1),0);
    if (SUB168(ZEXT816(0x30) * ZEXT816(uVar1) >> 0x40,0) != 0) {
      _Var2 = 0xffffffffffffffff;
    }
    pvVar3 = (void *)thunk_FUN_18001ac00(_Var2);
    param_1[9] = (ulonglong)pvVar3;
    if (pvVar3 != (void *)0x0) {
      *param_1 = uVar1;
      memset(pvVar3,0,uVar1 * 0x30);
      pvVar3 = _aligned_malloc(_Size,0x10);
      param_1[10] = (ulonglong)pvVar3;
      if (pvVar3 != (void *)0x0) {
        param_1[1] = _Size;
        uVar4 = FUN_180001890((ulonglong)pvVar3,_Size,param_1 + 2,0,param_1[9],uVar1);
        if ((char)uVar4 == '\0') {
          FUN_1800020c0(param_1);
          return 0x80004005;
        }
        return 0;
      }
      FUN_1800020c0(param_1);
    }
    return 0x8007000e;
  }
  return 0x80070057;
}



void FUN_1800020c0(undefined8 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  if ((void *)param_1[9] != (void *)0x0) {
    free((void *)param_1[9]);
    param_1[9] = 0;
  }
  if ((void *)param_1[10] != (void *)0x0) {
    _aligned_free((void *)param_1[10]);
    param_1[10] = 0;
  }
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  return;
}



longlong FUN_180002130(longlong param_1,ulonglong param_2,ulonglong param_3,ulonglong param_4)

{
  int iVar1;
  ulonglong uVar2;
  longlong lVar3;
  
  if (param_2 < *(ulonglong *)(param_1 + 0x30)) {
    iVar1 = *(int *)(param_1 + 0x44);
    lVar3 = 0;
    if (1 < iVar1) {
      if (iVar1 < 4) {
        if ((param_4 == 0) && (param_3 < *(ulonglong *)(param_1 + 0x28))) {
          return (*(ulonglong *)(param_1 + 0x30) * param_3 + param_2) * 0x30 +
                 *(longlong *)(param_1 + 0x48);
        }
      }
      else if ((iVar1 == 4) && (param_3 == 0)) {
        uVar2 = *(ulonglong *)(param_1 + 0x20);
        if (param_2 != 0) {
          do {
            lVar3 = lVar3 + uVar2;
            if (1 < uVar2) {
              uVar2 = uVar2 >> 1;
            }
            param_2 = param_2 - 1;
          } while (param_2 != 0);
        }
        if (param_4 < uVar2) {
          return (lVar3 + param_4) * 0x30 + *(longlong *)(param_1 + 0x48);
        }
      }
    }
  }
  return 0;
}



void FUN_1800021b0(void **param_1)

{
  if (*param_1 != (void *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0001800021b8. Too many branches
                    // WARNING: Treating indirect jump as call
    _aligned_free(*param_1);
    return;
  }
  return;
}



ulonglong FUN_1800021c0(undefined4 param_1)

{
  switch(param_1) {
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x28:
  case 0x2d:
  case 0x2e:
  case 0x2f:
  case 0x37:
  case 0x76:
  case 0x77:
  case 0x78:
    return 1;
  default:
    return 0;
  }
}



int FUN_180002260(longlong param_1,byte param_2,uint *param_3)

{
  int iVar1;
  uint *puVar2;
  uint uVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  bool bVar6;
  
  puVar2 = &DAT_1800653ac;
  uVar4 = 0;
  uVar5 = uVar4;
  do {
    uVar3 = *puVar2;
    if ((*(uint *)(param_1 + 4) & uVar3) != 0) {
      if ((uVar3 & 4) == 0) {
        if ((uVar3 & 0x20) == 0) {
          if ((((*(uint *)(param_1 + 0xc) != puVar2[2]) || (*(uint *)(param_1 + 0x10) != puVar2[3]))
              || (*(uint *)(param_1 + 0x14) != puVar2[4])) ||
             (*(uint *)(param_1 + 0x18) != puVar2[5])) goto LAB_1800022c4;
          bVar6 = *(uint *)(param_1 + 0x1c) == puVar2[6];
        }
        else {
          bVar6 = *(uint *)(param_1 + 0xc) == puVar2[2];
        }
      }
      else {
        bVar6 = *(uint *)(param_1 + 8) == puVar2[1];
      }
      if (bVar6) {
        if (0x2d < uVar4) {
          return 0;
        }
        uVar3 = (&DAT_1800653a4)[uVar4 * 10];
        iVar1 = (&DAT_1800653a0)[uVar4 * 10];
        if (((uVar3 & 1) != 0) && ((param_2 & 2) != 0)) {
          return 0;
        }
        if ((iVar1 == 0x18) && ((param_2 & 4) != 0)) {
          uVar3 = uVar3 ^ 4;
        }
        *param_3 = uVar3;
        return iVar1;
      }
    }
LAB_1800022c4:
    uVar4 = uVar4 + 1;
    uVar5 = uVar5 + 0x28;
    puVar2 = puVar2 + 10;
    if (0x72f < uVar5) {
      return 0;
    }
  } while( true );
}



undefined8
FUN_180002320(int *param_1,ulonglong param_2,byte param_3,ulonglong *param_4,uint *param_5)

{
  int iVar1;
  uint uVar2;
  ulonglong uVar3;
  
  *param_4 = 0;
  param_4[1] = 0;
  param_4[2] = 0;
  param_4[3] = 0;
  param_4[4] = 0;
  param_4[5] = 0;
  param_4[6] = 0;
  if (param_2 < 0x80) {
    return 0x8007000d;
  }
  if (((*param_1 != 0x20534444) || (param_1[1] != 0x7c)) || (param_1[0x13] != 0x20)) {
    return 0x80004005;
  }
  uVar3 = (ulonglong)(uint)param_1[7];
  if (uVar3 == 0) {
    uVar3 = 1;
  }
  param_4[4] = uVar3;
  if (((*(byte *)(param_1 + 0x14) & 4) == 0) || (param_1[0x15] != 0x30315844)) {
    param_4[3] = 1;
    if ((param_1[2] & 0x800000U) == 0) {
      if (((uint)param_1[0x1c] >> 9 & 1) != 0) {
        if ((param_1[0x1c] & 0xfe00U) != 0xfe00) {
          return 0x80070032;
        }
        *(uint *)(param_4 + 5) = *(uint *)(param_4 + 5) | 4;
        param_4[3] = 6;
      }
      *param_4 = (ulonglong)(uint)param_1[4];
      param_4[1] = (ulonglong)(uint)param_1[3];
      param_4[2] = 1;
      *(undefined4 *)((longlong)param_4 + 0x34) = 3;
    }
    else {
      *param_4 = (ulonglong)(uint)param_1[4];
      param_4[1] = (ulonglong)(uint)param_1[3];
      param_4[2] = (ulonglong)(uint)param_1[6];
      *(undefined4 *)((longlong)param_4 + 0x34) = 4;
    }
    iVar1 = FUN_180002260((longlong)(param_1 + 0x13),param_3,param_5);
    *(int *)(param_4 + 6) = iVar1;
    if (iVar1 == 0) {
      return 0x80070032;
    }
    uVar2 = *param_5;
    if ((uVar2 >> 0x11 & 1) != 0) {
      *(uint *)((longlong)param_4 + 0x2c) = *(uint *)((longlong)param_4 + 0x2c) | 2;
    }
    if ((param_3 & 0x20) != 0) {
      iVar1 = *(int *)(param_4 + 6);
      if (iVar1 == 0x31) {
        uVar2 = uVar2 | 0x100001;
LAB_1800025c9:
        *(undefined4 *)(param_4 + 6) = 0x1c;
      }
      else {
        if (iVar1 != 0x38) {
          if (iVar1 != 0x3d) goto LAB_1800025d3;
          uVar2 = uVar2 | 0x40001;
          goto LAB_1800025c9;
        }
        *(undefined4 *)(param_4 + 6) = 0xb;
        uVar2 = uVar2 | 0x80001;
      }
      *param_5 = uVar2;
    }
  }
  else {
    if (param_2 < 0x94) {
      return 0x80004005;
    }
    uVar2 = param_1[0x23];
    param_4[3] = (ulonglong)uVar2;
    *param_5 = *param_5 | 0x10000;
    if ((ulonglong)uVar2 == 0) {
      return 0x8007000d;
    }
    iVar1 = param_1[0x20];
    *(int *)(param_4 + 6) = iVar1;
    if (0x77 < (longlong)iVar1 - 1U) {
      return 0x80070032;
    }
    if (iVar1 - 0x6fU < 4) {
      return 0x80070032;
    }
    uVar2 = param_1[0x22];
    *(uint *)(param_4 + 5) = uVar2 & 0xfffffffb;
    iVar1 = param_1[0x21];
    if (iVar1 == 2) {
      if (((*(byte *)(param_1 + 2) & 2) != 0) && (param_1[3] != 1)) {
        return 0x8007000d;
      }
      *param_4 = (ulonglong)(uint)param_1[4];
      param_4[1] = 1;
      *(undefined4 *)((longlong)param_4 + 0x34) = 2;
      param_4[2] = 1;
      *(int *)((longlong)param_4 + 0x2c) = param_1[0x24];
    }
    else if (iVar1 == 3) {
      if ((*(byte *)(param_1 + 0x22) & 4) != 0) {
        *(uint *)(param_4 + 5) = uVar2 & 0xfffffffb | 4;
        param_4[3] = param_4[3] * 6;
      }
      *param_4 = (ulonglong)(uint)param_1[4];
      param_4[1] = (ulonglong)(uint)param_1[3];
      *(undefined4 *)((longlong)param_4 + 0x34) = 3;
      param_4[2] = 1;
      *(int *)((longlong)param_4 + 0x2c) = param_1[0x24];
    }
    else {
      if (iVar1 != 4) {
        return 0x8007000d;
      }
      if ((param_1[2] & 0x800000U) == 0) {
        return 0x8007000d;
      }
      if (1 < param_4[3]) {
        return 0x80070032;
      }
      *param_4 = (ulonglong)(uint)param_1[4];
      param_4[1] = (ulonglong)(uint)param_1[3];
      param_4[2] = (ulonglong)(uint)param_1[6];
      *(undefined4 *)((longlong)param_4 + 0x34) = 4;
      *(int *)((longlong)param_4 + 0x2c) = param_1[0x24];
    }
  }
LAB_1800025d3:
  if ((param_3 & 8) == 0) goto switchD_1800025f7_caseD_59;
  switch(*(undefined4 *)(param_4 + 6)) {
  case 0x57:
    *param_5 = *param_5 | 4;
    *(undefined4 *)(param_4 + 6) = 0x1c;
    break;
  case 0x58:
    *(undefined4 *)(param_4 + 6) = 0x1c;
    goto LAB_180002639;
  case 0x5a:
    *param_5 = *param_5 | 4;
    *(undefined4 *)(param_4 + 6) = 0x1b;
    break;
  case 0x5b:
    *param_5 = *param_5 | 4;
    *(undefined4 *)(param_4 + 6) = 0x1d;
    break;
  case 0x5c:
    *(undefined4 *)(param_4 + 6) = 0x1b;
    goto LAB_180002639;
  case 0x5d:
    *(undefined4 *)(param_4 + 6) = 0x1d;
LAB_180002639:
    *param_5 = *param_5 | 6;
  }
switchD_1800025f7_caseD_59:
  if (((param_3 & 0x10) != 0) &&
     ((*(int *)(param_4 + 6) - 0x55U < 2 || (*(int *)(param_4 + 6) == 0x73)))) {
    *param_5 = *param_5 | 1;
    *(undefined4 *)(param_4 + 6) = 0x1c;
  }
  return 0;
}



uint FUN_1800026a0(uint param_1)

{
  uint uVar1;
  
  if ((param_1 & 8) != 0) {
    return (param_1 & 0x800 | 0x2000) >> 0xb;
  }
  if ((param_1 & 0x10) != 0) {
    return 1;
  }
  if ((param_1 >> 9 & 1) != 0) {
    return 2;
  }
  if ((param_1 >> 10 & 1) != 0) {
    return 3;
  }
  if ((param_1 >> 8 & 1) != 0) {
    return 6;
  }
  if ((char)param_1 < '\0') {
    return 7;
  }
  if ((param_1 >> 0x12 & 1) != 0) {
    return 8;
  }
  if ((param_1 >> 0x13 & 1) != 0) {
    return 9;
  }
  uVar1 = 0;
  if ((param_1 >> 0x14 & 1) != 0) {
    uVar1 = 10;
  }
  return uVar1;
}



ulonglong FUN_180002730(ulonglong *param_1,ulonglong param_2,int param_3,ushort *param_4,
                       ulonglong param_5,int param_6,longlong param_7,uint param_8)

{
  undefined *puVar1;
  ushort *puVar2;
  undefined uVar3;
  byte bVar4;
  byte bVar5;
  ushort uVar6;
  uint uVar7;
  uint uVar8;
  ulonglong uVar9;
  ulonglong *puVar10;
  uint uVar11;
  ulonglong uVar12;
  ushort *puVar13;
  
  uVar7 = param_6 - 1;
  uVar9 = (ulonglong)uVar7;
  if (uVar7 < 10) {
    uVar9 = (ulonglong)(int)uVar7;
    switch(uVar7) {
    case 0:
      if (((param_3 == 0x1c) && (2 < param_5)) && (3 < param_2)) {
        if (param_5 != 2) {
          puVar13 = param_4 + 1;
          puVar10 = param_1;
          while (uVar9 = (longlong)puVar10 - (longlong)param_1, uVar9 < param_2 - 3) {
            puVar1 = (undefined *)((longlong)puVar13 + -1);
            puVar2 = puVar13 + -1;
            uVar3 = *(undefined *)puVar13;
            puVar13 = (ushort *)((longlong)puVar13 + 3);
            *(uint *)puVar10 = CONCAT21(CONCAT11(*(undefined *)puVar2,*puVar1),uVar3) | 0xff000000;
            puVar10 = (ulonglong *)((longlong)puVar10 + 4);
            puVar1 = (undefined *)((-2 - (longlong)param_4) + (longlong)puVar13);
            if ((undefined *)(param_5 - 2) <= puVar1) {
              return CONCAT71((int7)((ulonglong)puVar1 >> 8),1);
            }
          }
        }
LAB_180003017:
        return CONCAT71((int7)(uVar9 >> 8),1);
      }
      break;
    case 1:
      if (param_3 == 0x1c) {
        if ((param_5 != 0) && (3 < param_2)) {
          if (param_5 != 0) {
            puVar10 = param_1;
            puVar13 = param_4;
            while (uVar9 = (longlong)puVar10 - (longlong)param_1, uVar9 < param_2 - 3) {
              bVar5 = *(byte *)puVar13;
              puVar13 = (ushort *)((longlong)puVar13 + 1);
              uVar7 = (uint)bVar5;
              uVar8 = uVar7 & 3;
              *(uint *)puVar10 =
                   ((((((uVar7 * 4 | uVar8) << 2 | uVar8) << 2 | uVar8) << 5 | uVar7 & 0x1c) << 3 |
                    uVar7 & 0x1c) << 3 | uVar7 & 0x18) << 5 |
                   ((uint)(bVar5 >> 3) | uVar7 & 0xe0) >> 3 | uVar7 & 0xe0 | 0xff000000;
              puVar10 = (ulonglong *)((longlong)puVar10 + 4);
              if (param_5 <= (ulonglong)((longlong)puVar13 - (longlong)param_4)) {
                return CONCAT71((int7)((ulonglong)((longlong)puVar13 - (longlong)param_4) >> 8),1);
              }
            }
          }
          goto LAB_180003017;
        }
      }
      else if (((param_3 == 0x55) && (param_5 != 0)) && (1 < param_2)) {
        if (param_5 != 0) {
          puVar10 = param_1;
          puVar13 = param_4;
          while (uVar9 = (longlong)puVar10 - (longlong)param_1, uVar9 < param_2 - 1) {
            bVar5 = *(byte *)puVar13;
            puVar13 = (ushort *)((longlong)puVar13 + 1);
            *(ushort *)puVar10 =
                 (((((bVar5 & 0xffe0) << 2 | (ushort)(bVar5 & 0x1c)) * 2 | (ushort)(bVar5 & 0xc0))
                   << 2 | (ushort)(bVar5 & 0x1f)) << 2 | (ushort)(bVar5 & 3)) * 2 |
                 (ushort)(bVar5 >> 1 & 1);
            puVar10 = (ulonglong *)((longlong)puVar10 + 2);
            if (param_5 <= (ulonglong)((longlong)puVar13 - (longlong)param_4)) {
              return CONCAT71((int7)((ulonglong)((longlong)puVar13 - (longlong)param_4) >> 8),1);
            }
          }
        }
        goto LAB_180003017;
      }
      break;
    case 2:
      if (((param_3 == 0x1c) && (1 < param_5)) && (3 < param_2)) {
        uVar12 = 0;
        if (param_5 != 1) {
          puVar10 = param_1;
          while (uVar9 = (longlong)puVar10 - (longlong)param_1, uVar9 < param_2 - 3) {
            uVar6 = *param_4;
            param_4 = param_4 + 1;
            uVar7 = (uint)uVar6;
            uVar8 = uVar7 & 3;
            if ((param_8 & 1) == 0) {
              uVar11 = (uVar7 & 0xff00) << 0x10;
            }
            else {
              uVar11 = 0xff000000;
            }
            uVar12 = uVar12 + 2;
            *(uint *)puVar10 =
                 uVar11 | (((uVar8 * 4 | uVar8) << 2 | uVar8) << 2 | uVar8) << 0x10 |
                 (((uVar7 & 0x1c) * 8 | uVar7 & 0x1c) << 3 | uVar7 & 0x18) << 5 |
                 (uVar6 >> 3 & 0x18 | uVar7 & 0xe0) >> 3 | uVar7 & 0xe0;
            puVar10 = (ulonglong *)((longlong)puVar10 + 4);
            if (param_5 - 1 <= uVar12) {
              return 1;
            }
          }
        }
        goto LAB_180003017;
      }
      break;
    case 3:
      if (((param_3 == 0x1c) && (param_7 != 0)) && ((param_5 != 0 && (3 < param_2)))) {
        if (param_5 != 0) {
          puVar10 = param_1;
          puVar13 = param_4;
          while (uVar9 = (longlong)puVar10 - (longlong)param_1, uVar9 < param_2 - 3) {
            bVar5 = *(byte *)puVar13;
            puVar13 = (ushort *)((longlong)puVar13 + 1);
            *(undefined4 *)puVar10 = *(undefined4 *)(param_7 + (ulonglong)bVar5 * 4);
            puVar10 = (ulonglong *)((longlong)puVar10 + 4);
            if (param_5 <= (ulonglong)((longlong)puVar13 - (longlong)param_4)) {
              return CONCAT71((int7)((ulonglong)((longlong)puVar13 - (longlong)param_4) >> 8),1);
            }
          }
        }
        goto LAB_180003017;
      }
      break;
    case 4:
      if ((((param_3 == 0x1c) && (param_7 != 0)) && (1 < param_5)) && (3 < param_2)) {
        uVar12 = 0;
        if (param_5 != 1) {
          puVar10 = param_1;
          while (uVar9 = (longlong)puVar10 - (longlong)param_1, uVar9 < param_2 - 3) {
            uVar6 = *param_4;
            param_4 = param_4 + 1;
            if ((param_8 & 1) == 0) {
              uVar7 = (uVar6 & 0xff00) << 0x10;
            }
            else {
              uVar7 = 0xff000000;
            }
            uVar7 = uVar7 | *(uint *)(param_7 + (ulonglong)(byte)uVar6 * 4);
            uVar12 = uVar12 + 2;
            *(uint *)puVar10 = uVar7;
            puVar10 = (ulonglong *)((longlong)puVar10 + 4);
            if (param_5 - 1 <= uVar12) {
              return CONCAT71((uint7)(uint3)(uVar7 >> 8),1);
            }
          }
        }
        goto LAB_180003017;
      }
      break;
    case 5:
      if (param_3 == 0x1c) {
        if ((param_5 != 0) && (3 < param_2)) {
          uVar12 = 0;
          if (param_5 != 0) {
            puVar10 = param_1;
            while (uVar9 = (longlong)puVar10 - (longlong)param_1, uVar9 < param_2 - 3) {
              bVar5 = *(byte *)param_4;
              param_4 = (ushort *)((longlong)param_4 + 1);
              uVar7 = (uint)bVar5;
              uVar8 = (uVar7 & 0xf) << 4 | uVar7 & 0xf;
              if ((param_8 & 1) == 0) {
                uVar7 = (uVar7 & 0xf0) << 0x14 | (uVar7 & 0xf0) << 0x18;
              }
              else {
                uVar7 = 0xff000000;
              }
              uVar12 = uVar12 + 1;
              uVar7 = (uVar8 << 8 | uVar8) << 8 | uVar7;
              *(uint *)puVar10 = uVar7 | uVar8;
              puVar10 = (ulonglong *)((longlong)puVar10 + 4);
              if (param_5 <= uVar12) {
                return CONCAT71((uint7)(uint3)(uVar7 >> 8),1);
              }
            }
          }
          goto LAB_180003017;
        }
      }
      else if (((param_3 == 0x73) && (param_5 != 0)) && (1 < param_2)) {
        uVar12 = 0;
        if (param_5 != 0) {
          puVar10 = param_1;
          while (uVar9 = (longlong)puVar10 - (longlong)param_1, uVar9 < param_2 - 1) {
            bVar5 = *(byte *)param_4;
            param_4 = (ushort *)((longlong)param_4 + 1);
            bVar4 = bVar5 & 0xf;
            if ((param_8 & 1) == 0) {
              uVar6 = (bVar5 & 0xfff0) << 8;
            }
            else {
              uVar6 = 0xf000;
            }
            uVar12 = uVar12 + 1;
            uVar6 = ((ushort)bVar4 << 4 | (ushort)bVar4) << 4 | uVar6;
            *(ushort *)puVar10 = uVar6 | bVar4;
            puVar10 = (ulonglong *)((longlong)puVar10 + 2);
            if (param_5 <= uVar12) {
              return CONCAT71((uint7)(byte)(uVar6 >> 8),1);
            }
          }
        }
        goto LAB_180003017;
      }
      break;
    case 6:
      if (((param_3 == 0x1c) && (1 < param_5)) && (3 < param_2)) {
        uVar12 = 0;
        if (param_5 != 1) {
          puVar10 = param_1;
          do {
            uVar9 = (longlong)puVar10 - (longlong)param_1;
            if (param_2 - 3 <= uVar9) break;
            uVar6 = *param_4;
            param_4 = param_4 + 1;
            uVar7 = (uint)uVar6;
            if ((param_8 & 1) == 0) {
              uVar8 = (uVar7 & 0xf000) << 0x10 | (uVar7 & 0xf000) << 0xc;
            }
            else {
              uVar8 = 0xff000000;
            }
            uVar12 = uVar12 + 2;
            uVar7 = uVar8 | ((uVar7 & 0xf) << 4 | uVar7 & 0xf) << 0x10 |
                    ((uVar7 & 0xf0) << 4 | uVar7 & 0xf0) << 4 |
                    (uVar6 >> 4 & 0xf0 | uVar6 & 0xf00) >> 4;
            uVar9 = (ulonglong)uVar7;
            *(uint *)puVar10 = uVar7;
            puVar10 = (ulonglong *)((longlong)puVar10 + 4);
          } while (uVar12 < param_5 - 1);
        }
        return CONCAT71((int7)(uVar9 >> 8),1);
      }
      break;
    case 7:
      if (((param_3 == 0x1c) && (param_5 != 0)) && (3 < param_2)) {
        if (param_5 != 0) {
          puVar10 = param_1;
          puVar13 = param_4;
          while (uVar9 = (longlong)puVar10 - (longlong)param_1, uVar9 < param_2 - 3) {
            bVar5 = *(byte *)puVar13;
            puVar13 = (ushort *)((longlong)puVar13 + 1);
            *(uint *)puVar10 = ((bVar5 | 0xffffff00) << 8 | (uint)bVar5) << 8 | (uint)bVar5;
            puVar10 = (ulonglong *)((longlong)puVar10 + 4);
            if (param_5 <= (ulonglong)((longlong)puVar13 - (longlong)param_4)) {
              return CONCAT71((int7)((ulonglong)((longlong)puVar13 - (longlong)param_4) >> 8),1);
            }
          }
        }
        goto LAB_180003017;
      }
      break;
    case 8:
      if (((param_3 == 0xb) && (1 < param_5)) && (7 < param_2)) {
        if (param_5 != 1) {
          puVar10 = param_1;
          puVar13 = param_4;
          while (uVar9 = (longlong)puVar10 - (longlong)param_1, uVar9 < param_2 - 7) {
            uVar6 = *puVar13;
            puVar13 = puVar13 + 1;
            *puVar10 = (((ulonglong)uVar6 | 0xffffffffffff0000) << 0x10 | (ulonglong)uVar6) << 0x10
                       | (ulonglong)uVar6;
            puVar10 = puVar10 + 1;
            if (param_5 - 1 <= (ulonglong)((longlong)puVar13 - (longlong)param_4)) {
              return CONCAT71((int7)((ulonglong)((longlong)puVar13 - (longlong)param_4) >> 8),1);
            }
          }
        }
        goto LAB_180003017;
      }
      break;
    case 9:
      if (((param_3 == 0x1c) && (1 < param_5)) && (3 < param_2)) {
        uVar12 = 0;
        if (param_5 != 1) {
          puVar10 = param_1;
          do {
            uVar9 = (longlong)puVar10 - (longlong)param_1;
            if (param_2 - 3 <= uVar9) break;
            uVar6 = *param_4;
            param_4 = param_4 + 1;
            bVar5 = (byte)uVar6;
            uVar9 = 0;
            if ((param_8 & 1) == 0) {
              uVar7 = (uVar6 & 0xff00) << 0x10;
            }
            else {
              uVar7 = 0xff000000;
            }
            uVar12 = uVar12 + 2;
            *(uint *)puVar10 = uVar7 | (uint)bVar5 << 0x10 | (uint)bVar5 << 8 | (uint)bVar5;
            puVar10 = (ulonglong *)((longlong)puVar10 + 4);
          } while (uVar12 < param_5 - 1);
        }
        goto LAB_180003017;
      }
    }
  }
  return uVar9 & 0xffffffffffffff00;
}



undefined4
FUN_180003070(ulonglong param_1,longlong param_2,ulonglong *param_3,uint param_4,uint param_5,
             longlong param_6,ulonglong *param_7)

{
  longlong lVar1;
  int iVar2;
  char cVar3;
  undefined4 uVar4;
  uint uVar5;
  __uint64 _Var6;
  void *_Memory;
  undefined8 uVar7;
  ulonglong uVar8;
  uint uVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  uint *puVar12;
  ulonglong *puVar13;
  uint uVar14;
  ulonglong *puVar15;
  ulonglong *puVar16;
  uint uVar17;
  ulonglong uVar18;
  ulonglong uVar19;
  ulonglong *puVar20;
  ulonglong local_60;
  ulonglong local_58;
  ulonglong local_50;
  ulonglong local_48;
  longlong local_40;
  ulonglong local_38;
  
  uVar9 = param_5 & 1;
  if (uVar9 != 0) {
    if ((param_5 & 0x10) == 0) {
      if ((param_5 & 0x180ce0) == 0) {
        if ((param_5 & 0x40308) != 0) {
          param_4 = param_4 | 0x40000;
        }
      }
      else {
        param_4 = param_4 | 0x20000;
      }
    }
    else {
      param_4 = param_4 | 0x10000;
    }
  }
  if (((*(int *)((longlong)param_3 + 0x34) < 2) ||
      (FUN_180001710(param_3,param_4,(longlong *)&local_48,&local_40,
                     *(int *)((longlong)param_3 + 0x34)), uVar18 = local_48, local_48 == 0)) ||
     (local_48 != *param_7)) {
    return 0x80004005;
  }
  _Var6 = SUB168(ZEXT816(0x30) * ZEXT816(local_48),0);
  if (SUB168(ZEXT816(0x30) * ZEXT816(local_48) >> 0x40,0) != 0) {
    _Var6 = 0xffffffffffffffff;
  }
  _Memory = (void *)thunk_FUN_18001ac00(_Var6);
  if (_Memory == (void *)0x0) {
    uVar4 = 0x8007000e;
    goto LAB_180003368;
  }
  uVar7 = FUN_180001890(param_1,param_2,param_3,param_4,(longlong)_Memory,uVar18);
  if ((((char)uVar7 != '\0') && (local_48 == *param_7)) &&
     (uVar18 = param_7[9], local_38 = uVar18, uVar18 != 0)) {
    uVar14 = param_5 >> 1 & 1;
    uVar17 = param_5 & 4;
    if (uVar17 != 0) {
      uVar14 = uVar14 | 2;
    }
    iVar2 = *(int *)((longlong)param_3 + 0x34);
    if (1 < iVar2) {
      if (iVar2 < 4) {
        uVar10 = 0;
        local_58 = 0;
        local_60 = 0;
        uVar11 = local_48;
        if (param_3[3] != 0) {
          do {
            local_50 = 0;
            if (param_3[4] != 0) {
              puVar20 = (ulonglong *)(uVar10 * 0x30 + 0x18 + uVar18);
              local_40 = (longlong)_Memory - uVar18;
              lVar1 = local_40 + 8;
              do {
                uVar18 = 0;
                if ((uVar11 <= uVar10) ||
                   (uVar11 = puVar20[-2],
                   uVar11 != *(ulonglong *)(local_40 + -0x10 + (longlong)puVar20)))
                goto LAB_180003361;
                puVar12 = *(uint **)(local_40 + 0x10 + (longlong)puVar20);
                uVar10 = *puVar20;
                uVar19 = *(ulonglong *)(local_40 + (longlong)puVar20);
                if ((puVar12 == (uint *)0x0) ||
                   (puVar13 = (ulonglong *)puVar20[2], puVar13 == (ulonglong *)0x0))
                goto LAB_180003784;
                iVar2 = *(int *)(param_3 + 6);
                if ((iVar2 < 0x46) || ((0x54 < iVar2 && (5 < iVar2 - 0x5eU)))) {
                  if ((iVar2 < 0x67) || (((0x6a < iVar2 && (iVar2 != 0x6e)) && (2 < iVar2 - 0x76U)))
                     ) {
                    if (uVar11 != 0) {
                      do {
                        uVar11 = (ulonglong)uVar14;
                        if (uVar9 == 0) {
                          if (uVar17 == 0) {
                            FUN_180007b80((uint *)puVar13,uVar10,puVar12,uVar19,
                                          *(int *)(param_3 + 6),(byte)uVar14);
                          }
                          else {
                            FUN_180008010((uint *)puVar13,uVar10,puVar12,uVar19,
                                          *(int *)(param_3 + 6),uVar14);
                          }
                        }
                        else {
                          if ((param_5 & 0xe0) == 0) {
                            puVar16 = param_3;
                            uVar5 = FUN_1800026a0(param_5);
                            uVar11 = FUN_180002730(puVar13,uVar10,*(int *)(puVar16 + 6),
                                                   (ushort *)puVar12,uVar19,uVar5,param_6,
                                                   (uint)uVar11);
                            cVar3 = (char)uVar11;
                          }
                          else {
                            uVar7 = FUN_1800083a0((uint *)puVar13,uVar10,uVar11,(ushort *)puVar12,
                                                  uVar19,0x56 - (uint)((param_5 & 0x20) != 0),uVar14
                                                 );
                            cVar3 = (char)uVar7;
                          }
                          if (cVar3 == '\0') goto LAB_180003361;
                        }
                        puVar12 = (uint *)((longlong)puVar12 + uVar19);
                        puVar13 = (ulonglong *)((longlong)puVar13 + uVar10);
                        uVar18 = uVar18 + 1;
                      } while (uVar18 < puVar20[-2]);
                    }
                  }
                  else {
                    if ((iVar2 < 0x46) || ((0x54 < iVar2 && (5 < iVar2 - 0x5eU)))) {
                      if (iVar2 == 0x6e) {
                        uVar11 = uVar11 * 2;
                      }
                      else if ((0x66 < iVar2) && ((iVar2 < 0x6b || (iVar2 - 0x76U < 3)))) {
                        uVar11 = (uVar11 + 1 >> 1) + uVar11;
                      }
                    }
                    else {
                      uVar18 = uVar11 + 3 >> 2;
                      uVar11 = 1;
                      if (1 < uVar18) {
                        uVar11 = uVar18;
                      }
                    }
                    if (uVar11 == 0) {
                      uVar4 = 0x8000ffff;
                      goto LAB_180003368;
                    }
                    uVar18 = uVar10;
                    if (uVar19 < uVar10) {
                      uVar18 = uVar19;
                    }
                    for (; uVar11 != 0; uVar11 = uVar11 - 1) {
                      FUN_180003f40(puVar13,uVar10,puVar12,uVar18);
                      puVar12 = (uint *)((longlong)puVar12 + uVar19);
                      puVar13 = (ulonglong *)((longlong)puVar13 + uVar10);
                    }
                  }
                }
                else {
                  puVar16 = (ulonglong *)(lVar1 + (longlong)puVar20);
                  puVar15 = puVar20 + 1;
                  if (*puVar16 < puVar20[1]) {
                    puVar15 = puVar16;
                  }
                  FUN_180003f40(puVar13,puVar20[1],puVar12,*puVar15);
                }
                puVar20 = puVar20 + 6;
                local_50 = local_50 + 1;
                uVar10 = local_58 + 1;
                uVar11 = local_48;
                uVar18 = local_38;
                local_58 = uVar10;
              } while (local_50 < param_3[4]);
            }
            local_60 = local_60 + 1;
          } while (local_60 < param_3[3]);
          uVar4 = 0;
          goto LAB_180003368;
        }
      }
      else {
        if (iVar2 != 4) goto LAB_180003361;
        uVar11 = param_3[2];
        uVar19 = 0;
        local_50 = 0;
        uVar10 = local_48;
        local_58 = uVar11;
        if (param_3[4] != 0) {
          do {
            local_60 = 0;
            if (uVar11 != 0) {
              puVar20 = (ulonglong *)(uVar19 * 0x30 + 0x18 + uVar18);
              local_40 = (longlong)_Memory - uVar18;
              lVar1 = local_40 + 8;
              do {
                uVar18 = 0;
                if ((uVar10 <= uVar19) ||
                   (puVar20[-2] != *(ulonglong *)(local_40 + -0x10 + (longlong)puVar20)))
                goto LAB_180003361;
                puVar12 = *(uint **)(local_40 + 0x10 + (longlong)puVar20);
                uVar11 = *puVar20;
                uVar10 = *(ulonglong *)(local_40 + (longlong)puVar20);
                if ((puVar12 == (uint *)0x0) ||
                   (puVar13 = (ulonglong *)puVar20[2], puVar13 == (ulonglong *)0x0))
                goto LAB_180003784;
                iVar2 = *(int *)(param_3 + 6);
                if ((iVar2 < 0x46) || ((0x54 < iVar2 && (5 < iVar2 - 0x5eU)))) {
                  if ((0x66 < iVar2) && (((iVar2 < 0x6b || (iVar2 == 0x6e)) || (iVar2 - 0x76U < 3)))
                     ) {
                    uVar4 = 0x80070032;
                    goto LAB_180003368;
                  }
                  if (puVar20[-2] != 0) {
                    do {
                      uVar8 = (ulonglong)uVar14;
                      if (uVar9 == 0) {
                        if (uVar17 == 0) {
                          FUN_180007b80((uint *)puVar13,uVar11,puVar12,uVar10,*(int *)(param_3 + 6),
                                        (byte)uVar14);
                        }
                        else {
                          FUN_180008010((uint *)puVar13,uVar11,puVar12,uVar10,*(int *)(param_3 + 6),
                                        uVar14);
                        }
                      }
                      else {
                        if ((param_5 & 0xe0) == 0) {
                          puVar16 = param_3;
                          uVar5 = FUN_1800026a0(param_5);
                          uVar8 = FUN_180002730(puVar13,uVar11,*(int *)(puVar16 + 6),
                                                (ushort *)puVar12,uVar10,uVar5,param_6,(uint)uVar8);
                          cVar3 = (char)uVar8;
                        }
                        else {
                          uVar7 = FUN_1800083a0((uint *)puVar13,uVar11,uVar8,(ushort *)puVar12,
                                                uVar10,0x56 - (uint)((param_5 & 0x20) != 0),uVar14);
                          cVar3 = (char)uVar7;
                        }
                        if (cVar3 == '\0') goto LAB_180003361;
                      }
                      puVar12 = (uint *)((longlong)puVar12 + uVar10);
                      puVar13 = (ulonglong *)((longlong)puVar13 + uVar11);
                      uVar18 = uVar18 + 1;
                    } while (uVar18 < puVar20[-2]);
                  }
                }
                else {
                  puVar16 = (ulonglong *)(lVar1 + (longlong)puVar20);
                  puVar15 = puVar20 + 1;
                  if (*puVar16 < puVar20[1]) {
                    puVar15 = puVar16;
                  }
                  FUN_180003f40(puVar13,puVar20[1],puVar12,*puVar15);
                }
                uVar19 = uVar19 + 1;
                local_60 = local_60 + 1;
                puVar20 = puVar20 + 6;
                uVar11 = local_58;
                uVar10 = local_48;
                uVar18 = local_38;
              } while (local_60 < local_58);
            }
            if (1 < uVar11) {
              uVar11 = uVar11 >> 1;
              local_58 = uVar11;
            }
            local_50 = local_50 + 1;
          } while (local_50 < param_3[4]);
        }
      }
      uVar4 = 0;
      goto LAB_180003368;
    }
  }
LAB_180003361:
  uVar4 = 0x80004005;
LAB_180003368:
  if (_Memory != (void *)0x0) {
    free(_Memory);
  }
  return uVar4;
LAB_180003784:
  uVar4 = 0x80004003;
  goto LAB_180003368;
}



undefined8 FUN_1800037c0(uint param_1,ulonglong *param_2)

{
  int iVar1;
  ulonglong uVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  ulonglong *puVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  
  if (param_2[10] == 0) {
    return 0x80004005;
  }
  if (param_2[9] != 0) {
    iVar1 = *(int *)(param_2 + 8);
    if ((0x66 < iVar1) && (((iVar1 < 0x6b || (iVar1 == 0x6e)) || (iVar1 - 0x76U < 3)))) {
      return 0x80070032;
    }
    uVar4 = param_1 >> 1 & 1;
    uVar3 = uVar4 | 2;
    if ((param_1 & 4) == 0) {
      uVar3 = uVar4;
    }
    uVar8 = 0;
    if (*param_2 != 0) {
      puVar6 = (ulonglong *)(param_2[9] + 8);
      do {
        puVar5 = (uint *)puVar6[4];
        if (puVar5 == (uint *)0x0) {
          return 0x80004003;
        }
        uVar2 = puVar6[2];
        uVar7 = 0;
        if (*puVar6 != 0) {
          do {
            if ((param_1 & 4) == 0) {
              FUN_180007b80(puVar5,uVar2,puVar5,uVar2,*(int *)(param_2 + 8),(byte)uVar3);
            }
            else {
              FUN_180008010(puVar5,uVar2,puVar5,uVar2,*(int *)(param_2 + 8),uVar3);
            }
            puVar5 = (uint *)((longlong)puVar5 + uVar2);
            uVar7 = uVar7 + 1;
          } while (uVar7 < *puVar6);
        }
        uVar8 = uVar8 + 1;
        puVar6 = puVar6 + 6;
      } while (uVar8 < *param_2);
    }
    return 0;
  }
  return 0x80004005;
}



ulonglong FUN_180003910(int *param_1,ulonglong param_2,uint param_3,undefined4 *param_4,
                       ulonglong *param_5)

{
  uint uVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  longlong lVar4;
  uint local_res8 [2];
  undefined4 local_68;
  undefined4 uStack_64;
  undefined4 uStack_60;
  undefined4 uStack_5c;
  undefined4 local_58;
  undefined4 uStack_54;
  undefined4 uStack_50;
  undefined4 uStack_4c;
  undefined4 local_48;
  undefined4 uStack_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  undefined8 local_38;
  
  if ((param_1 != (int *)0x0) && (param_2 != 0)) {
    FUN_1800020c0(param_5);
    lVar4 = 0;
    local_res8[0] = 0;
    uVar2 = FUN_180002320(param_1,param_2,(byte)param_3,(ulonglong *)&local_68,local_res8);
    uVar1 = local_res8[0];
    if (-1 < (int)uVar2) {
      uVar3 = 0x94;
      if ((local_res8[0] >> 0x10 & 1) == 0) {
        uVar3 = 0x80;
      }
      if ((local_res8[0] & 8) != 0) {
        lVar4 = uVar3 + (longlong)param_1;
        uVar3 = uVar3 + 0x400;
        if (param_2 < uVar3) {
          return 0x80004005;
        }
      }
      uVar2 = FUN_180001b50(param_5,(ulonglong *)&local_68);
      if (-1 < (int)uVar2) {
        if (param_2 - uVar3 == 0) {
          FUN_1800020c0(param_5);
          uVar2 = 0x80004005;
        }
        else {
          uVar1 = FUN_180003070(uVar3 + (longlong)param_1,param_2 - uVar3,(ulonglong *)&local_68,
                                param_3 & 1,uVar1,lVar4,param_5);
          if ((int)uVar1 < 0) {
            FUN_1800020c0(param_5);
            uVar2 = (ulonglong)uVar1;
          }
          else {
            if (param_4 != (undefined4 *)0x0) {
              *param_4 = local_68;
              param_4[1] = uStack_64;
              param_4[2] = uStack_60;
              param_4[3] = uStack_5c;
              param_4[4] = local_58;
              param_4[5] = uStack_54;
              param_4[6] = uStack_50;
              param_4[7] = uStack_4c;
              param_4[8] = local_48;
              param_4[9] = uStack_44;
              param_4[10] = uStack_40;
              param_4[0xb] = uStack_3c;
              *(undefined8 *)(param_4 + 0xc) = local_38;
            }
            uVar2 = 0;
          }
        }
      }
    }
    return uVar2;
  }
  return 0x80070057;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_180003aa0(LPCWSTR param_1,uint param_2,undefined4 *param_3,ulonglong *param_4)

{
  ulonglong uVar1;
  BOOL BVar2;
  HANDLE hFile;
  undefined8 uVar3;
  LPVOID lpBuffer;
  void *lpBuffer_00;
  int iVar4;
  uint nNumberOfBytesToRead;
  undefined auStackY_198 [32];
  uint local_158 [2];
  ulonglong local_150;
  uint local_148;
  undefined4 *local_140;
  undefined4 local_138;
  undefined4 uStack_134;
  undefined4 uStack_130;
  undefined4 uStack_12c;
  undefined4 local_128;
  undefined4 uStack_124;
  undefined4 uStack_120;
  undefined4 uStack_11c;
  undefined4 local_118;
  undefined4 uStack_114;
  undefined4 uStack_110;
  undefined4 uStack_10c;
  undefined8 local_108;
  undefined local_100 [8];
  undefined8 local_f8;
  int local_e8 [40];
  ulonglong local_48;
  
  local_48 = DAT_180065150 ^ (ulonglong)auStackY_198;
  local_148 = param_2;
  local_140 = param_3;
  if (param_1 == (LPCWSTR)0x0) goto LAB_180003f19;
  *param_4 = 0;
  param_4[1] = 0;
  if ((void *)param_4[9] != (void *)0x0) {
    free((void *)param_4[9]);
    param_4[9] = 0;
  }
  if ((void *)param_4[10] != (void *)0x0) {
    _aligned_free((void *)param_4[10]);
    param_4[10] = 0;
  }
  param_4[2] = 0;
  param_4[3] = 0;
  param_4[4] = 0;
  param_4[5] = 0;
  param_4[6] = 0;
  param_4[7] = 0;
  param_4[8] = 0;
  hFile = CreateFileW(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x8000000,(HANDLE)0x0);
  if (hFile == (HANDLE)0xffffffffffffffff) {
    hFile = (HANDLE)0x0;
  }
  if ((hFile == (HANDLE)0x0) ||
     (BVar2 = GetFileInformationByHandleEx(hFile,FileStandardInfo,local_100,0x18), BVar2 == 0)) {
LAB_180003c67:
    GetLastError();
  }
  else if (((int)((ulonglong)local_f8 >> 0x20) < 1) && (0x7f < (uint)local_f8)) {
    iVar4 = 0x94;
    local_158[0] = 0;
    BVar2 = ReadFile(hFile,local_e8,0x94,local_158,(LPOVERLAPPED)0x0);
    if (BVar2 == 0) goto LAB_180003c67;
    local_150 = local_150 & 0xffffffff00000000;
    uVar3 = FUN_180002320(local_e8,(ulonglong)local_158[0],(byte)param_2,(ulonglong *)&local_138,
                          (uint *)&local_150);
    uVar1 = local_150;
    if (-1 < (int)uVar3) {
      if (((uint)local_150 >> 0x10 & 1) == 0) {
        local_150 = 0x80;
        BVar2 = SetFilePointerEx(hFile,(LARGE_INTEGER)0x80,(PLARGE_INTEGER)0x0,0);
        if (BVar2 == 0) goto LAB_180003c67;
        iVar4 = 0x80;
      }
      lpBuffer = (LPVOID)0x0;
      if ((uVar1 & 8) == 0) {
LAB_180003d1e:
        nNumberOfBytesToRead = (uint)local_f8 - iVar4;
        if ((nNumberOfBytesToRead != 0) &&
           (uVar3 = FUN_180001b50(param_4,(ulonglong *)&local_138), -1 < (int)uVar3)) {
          if ((((uint)local_150 | local_148) & 1) == 0) {
            if (param_4[1] < (ulonglong)nNumberOfBytesToRead) {
              FUN_1800020c0(param_4);
            }
            else {
              BVar2 = ReadFile(hFile,(LPVOID)param_4[10],(DWORD)param_4[1],local_158,
                               (LPOVERLAPPED)0x0);
              if (BVar2 == 0) {
                FUN_1800020c0(param_4);
                goto LAB_180003ce2;
              }
              if (((uVar1 & 6) == 0) ||
                 (uVar3 = FUN_1800037c0((uint)local_150,param_4), -1 < (int)uVar3)) {
LAB_180003eab:
                if (local_140 != (undefined4 *)0x0) {
                  *local_140 = local_138;
                  local_140[1] = uStack_134;
                  local_140[2] = uStack_130;
                  local_140[3] = uStack_12c;
                  local_140[4] = local_128;
                  local_140[5] = uStack_124;
                  local_140[6] = uStack_120;
                  local_140[7] = uStack_11c;
                  local_140[8] = local_118;
                  local_140[9] = uStack_114;
                  local_140[10] = uStack_110;
                  local_140[0xb] = uStack_10c;
                  *(undefined8 *)(local_140 + 0xc) = local_108;
                }
              }
              else {
                FUN_1800020c0(param_4);
              }
            }
          }
          else {
            lpBuffer_00 = (void *)thunk_FUN_18001ac00((ulonglong)nNumberOfBytesToRead);
            if (lpBuffer_00 == (void *)0x0) {
              FUN_1800020c0(param_4);
            }
            else {
              BVar2 = ReadFile(hFile,lpBuffer_00,nNumberOfBytesToRead,local_158,(LPOVERLAPPED)0x0);
              if (BVar2 == 0) {
                FUN_1800020c0(param_4);
                GetLastError();
              }
              else if (local_158[0] == nNumberOfBytesToRead) {
                if ((nNumberOfBytesToRead != 0) &&
                   (iVar4 = FUN_180003070((ulonglong)lpBuffer_00,(ulonglong)nNumberOfBytesToRead,
                                          (ulonglong *)&local_138,local_148 & 1,(uint)local_150,
                                          (longlong)lpBuffer,param_4), -1 < iVar4)) {
                  free(lpBuffer_00);
                  goto LAB_180003eab;
                }
                FUN_1800020c0(param_4);
              }
              else {
                FUN_1800020c0(param_4);
              }
            }
            if (lpBuffer_00 != (void *)0x0) {
              free(lpBuffer_00);
            }
          }
        }
      }
      else {
        lpBuffer = (LPVOID)thunk_FUN_18001ac00(0x400);
        if (lpBuffer != (LPVOID)0x0) {
          BVar2 = ReadFile(hFile,lpBuffer,0x400,local_158,(LPOVERLAPPED)0x0);
          if (BVar2 == 0) {
LAB_180003ce2:
            GetLastError();
          }
          else if (local_158[0] == 0x400) {
            iVar4 = iVar4 + 0x400;
            goto LAB_180003d1e;
          }
        }
      }
      if (lpBuffer != (void *)0x0) {
        free(lpBuffer);
      }
    }
  }
  if (hFile != (HANDLE)0x0) {
    CloseHandle(hFile);
  }
LAB_180003f19:
  __security_check_cookie(local_48 ^ (ulonglong)auStackY_198);
  return;
}



undefined8 FUN_180003f40(void *param_1,ulonglong param_2,void *param_3,ulonglong param_4)

{
  int *piVar1;
  
  if (param_4 == 0) {
    return 0;
  }
  if (param_1 != (void *)0x0) {
    if ((param_3 != (void *)0x0) && (param_4 <= param_2)) {
      memcpy(param_1,param_3,param_4);
      return 0;
    }
    memset(param_1,0,param_2);
    if (param_3 != (void *)0x0) {
      if (param_4 <= param_2) {
        return 0x16;
      }
      piVar1 = _errno();
      *piVar1 = 0x22;
      _invalid_parameter_noinfo();
      return 0x22;
    }
  }
  piVar1 = _errno();
  *piVar1 = 0x16;
  _invalid_parameter_noinfo();
  return 0x16;
}



void FUN_180003ff0(ulonglong param_1,ulonglong param_2,char param_3,longlong param_4)

{
  ulonglong uVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  ulonglong *puVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  
  fVar7 = (float)param_1;
  if ((longlong)param_1 < 0) {
    fVar7 = fVar7 + 1.844674e+19;
  }
  fVar5 = (float)param_2;
  if ((longlong)param_2 < 0) {
    fVar5 = fVar5 + 1.844674e+19;
  }
  uVar2 = 0;
  if (param_2 != 0) {
    puVar4 = (ulonglong *)(param_4 + 0x10);
    do {
      fVar6 = (float)uVar2;
      if ((longlong)uVar2 < 0) {
        fVar6 = fVar6 + 1.844674e+19;
      }
      fVar6 = (fVar6 + 0.5) * (fVar7 / fVar5) + 0.5;
      uVar1 = (ulonglong)fVar6;
      uVar3 = uVar1 - 1;
      if ((longlong)uVar3 < 0) {
        if (param_3 == '\0') {
          uVar3 = 0;
        }
        else {
          uVar3 = param_1 - 1;
        }
      }
      if (param_1 <= uVar1) {
        if (param_3 == '\0') {
          uVar1 = param_1 - 1;
        }
        else {
          uVar1 = 0;
        }
      }
      puVar4[-2] = uVar3;
      *puVar4 = uVar1;
      uVar2 = uVar2 + 1;
      fVar6 = ((float)uVar1 + 1.0) - fVar6;
      *(float *)(puVar4 + -1) = fVar6;
      *(float *)(puVar4 + 1) = 1.0 - fVar6;
      puVar4 = puVar4 + 4;
    } while (uVar2 < param_2);
  }
  return;
}



void FUN_1800040e0(longlong param_1,ulonglong param_2,char param_3,char param_4,longlong param_5)

{
  ulonglong uVar1;
  ulonglong uVar2;
  ulonglong *puVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  bool bVar9;
  bool bVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  
  fVar13 = (float)param_1;
  if (param_1 < 0) {
    fVar13 = fVar13 + 1.844674e+19;
  }
  fVar11 = (float)param_2;
  if ((longlong)param_2 < 0) {
    fVar11 = fVar11 + 1.844674e+19;
  }
  uVar8 = 0;
  if (param_2 != 0) {
    uVar1 = param_1 - 1;
    puVar3 = (ulonglong *)(param_5 + 0x10);
    uVar7 = uVar8;
    do {
      fVar12 = (float)uVar7;
      if ((longlong)uVar7 < 0) {
        fVar12 = fVar12 + 1.844674e+19;
      }
      fVar12 = (fVar12 + 0.5) * (fVar13 / fVar11) - 0.5;
      uVar2 = (ulonglong)fVar12;
      if (param_3 == '\0') {
        if (param_4 != '\0') {
          if ((longlong)uVar2 < 0) {
            uVar2 = -uVar2 - 1;
          }
          else {
            bVar10 = SBORROW8(uVar1,uVar2);
            bVar9 = (longlong)(uVar1 - uVar2) < 0;
            if ((longlong)uVar2 <= (longlong)uVar1) goto LAB_1800041bf;
            uVar2 = (uVar1 * 2 - uVar2) + 1;
          }
        }
LAB_1800041bc:
        bVar10 = SBORROW8(uVar1,uVar2);
        bVar9 = (longlong)(uVar1 - uVar2) < 0;
      }
      else {
        if ((longlong)uVar2 < 0) {
          uVar2 = uVar2 + 1 + uVar1;
          goto LAB_1800041bc;
        }
        bVar10 = SBORROW8(uVar1,uVar2);
        bVar9 = (longlong)(uVar1 - uVar2) < 0;
        if ((longlong)uVar1 < (longlong)uVar2) {
          uVar2 = uVar2 + (-1 - uVar1);
          goto LAB_1800041bc;
        }
      }
LAB_1800041bf:
      if (bVar10 != bVar9) {
        uVar2 = uVar1;
      }
      if ((longlong)uVar2 < 0) {
        uVar2 = uVar8;
      }
      uVar6 = uVar2 - 1;
      if (param_3 == '\0') {
        if (param_4 != '\0') {
          if ((longlong)uVar6 < 0) {
            uVar6 = -uVar6 - 1;
          }
          else {
            bVar10 = SBORROW8(uVar1,uVar6);
            bVar9 = (longlong)(uVar1 - uVar6) < 0;
            if ((longlong)uVar6 <= (longlong)uVar1) goto LAB_180004219;
            uVar6 = (uVar1 * 2 - uVar6) + 1;
          }
        }
LAB_180004216:
        bVar10 = SBORROW8(uVar1,uVar6);
        bVar9 = (longlong)(uVar1 - uVar6) < 0;
      }
      else {
        if ((longlong)uVar6 < 0) {
          uVar6 = uVar2 + uVar1;
          goto LAB_180004216;
        }
        bVar10 = SBORROW8(uVar1,uVar6);
        bVar9 = (longlong)(uVar1 - uVar6) < 0;
        if ((longlong)uVar1 < (longlong)uVar6) {
          uVar6 = uVar6 + (-1 - uVar1);
          goto LAB_180004216;
        }
      }
LAB_180004219:
      if (bVar10 != bVar9) {
        uVar6 = uVar1;
      }
      uVar5 = uVar2 + 1;
      if ((longlong)uVar6 < 0) {
        uVar6 = uVar8;
      }
      if (param_3 == '\0') {
        if (param_4 != '\0') {
          if ((longlong)uVar5 < 0) {
            uVar5 = -uVar5 - 1;
          }
          else {
            bVar10 = SBORROW8(uVar1,uVar5);
            bVar9 = (longlong)(uVar1 - uVar5) < 0;
            if ((longlong)uVar5 <= (longlong)uVar1) goto LAB_180004273;
            uVar5 = (uVar1 * 2 - uVar5) + 1;
          }
        }
LAB_180004270:
        bVar10 = SBORROW8(uVar1,uVar5);
        bVar9 = (longlong)(uVar1 - uVar5) < 0;
      }
      else {
        if ((longlong)uVar5 < 0) {
          uVar5 = uVar2 + 2 + uVar1;
          goto LAB_180004270;
        }
        bVar10 = SBORROW8(uVar1,uVar5);
        bVar9 = (longlong)(uVar1 - uVar5) < 0;
        if ((longlong)uVar1 < (longlong)uVar5) {
          uVar5 = uVar5 + (-1 - uVar1);
          goto LAB_180004270;
        }
      }
LAB_180004273:
      if (bVar10 != bVar9) {
        uVar5 = uVar1;
      }
      uVar4 = uVar2 + 2;
      if ((longlong)uVar5 < 0) {
        uVar5 = uVar8;
      }
      if (param_3 == '\0') {
        if (param_4 != '\0') {
          if ((longlong)uVar4 < 0) {
            uVar4 = -uVar4 - 1;
          }
          else {
            bVar10 = SBORROW8(uVar1,uVar4);
            bVar9 = (longlong)(uVar1 - uVar4) < 0;
            if ((longlong)uVar4 <= (longlong)uVar1) goto LAB_1800042cd;
            uVar4 = (uVar1 * 2 - uVar4) + 1;
          }
        }
LAB_1800042ca:
        bVar10 = SBORROW8(uVar1,uVar4);
        bVar9 = (longlong)(uVar1 - uVar4) < 0;
      }
      else {
        if ((longlong)uVar4 < 0) {
          uVar4 = uVar2 + 3 + uVar1;
          goto LAB_1800042ca;
        }
        bVar10 = SBORROW8(uVar1,uVar4);
        bVar9 = (longlong)(uVar1 - uVar4) < 0;
        if ((longlong)uVar1 < (longlong)uVar4) {
          uVar4 = uVar4 + (-1 - uVar1);
          goto LAB_1800042ca;
        }
      }
LAB_1800042cd:
      if (bVar10 != bVar9) {
        uVar4 = uVar1;
      }
      puVar3[-2] = uVar6;
      puVar3[-1] = uVar2;
      *puVar3 = uVar5;
      if ((longlong)uVar4 < 0) {
        uVar4 = uVar8;
      }
      uVar7 = uVar7 + 1;
      puVar3[1] = uVar4;
      *(float *)(puVar3 + 2) = fVar12 - (float)uVar2;
      puVar3 = puVar3 + 5;
    } while (uVar7 < param_2);
  }
  return;
}



undefined8 FUN_180004340(ulonglong param_1,longlong param_2,char param_3,ulonglong **param_4)

{
  longlong *plVar1;
  ulonglong *_Memory;
  uint uVar2;
  ulonglong *_Memory_00;
  longlong lVar3;
  int iVar4;
  longlong lVar5;
  ulonglong uVar6;
  longlong lVar7;
  ulonglong uVar8;
  longlong lVar9;
  longlong lVar10;
  ulonglong uVar11;
  ulonglong uVar12;
  ulonglong uVar13;
  undefined auVar14 [16];
  float fVar15;
  float fVar16;
  float fVar17;
  float fVar18;
  float fVar19;
  float fVar20;
  float fVar21;
  float fVar22;
  float fVar23;
  float fVar24;
  float fVar25;
  float local_res18;
  
  fVar25 = (float)param_1;
  if ((longlong)param_1 < 0) {
    fVar25 = fVar25 + 1.844674e+19;
  }
  auVar14 = ZEXT416((uint)(float)param_2) & (undefined  [16])0xffffffffffffffff;
  local_res18 = SUB164(auVar14,0);
  if (param_2 < 0) {
    local_res18 = local_res18 + 1.844674e+19;
    auVar14 = CONCAT124(SUB1612(auVar14 >> 0x20,0),local_res18);
  }
  uVar6 = 0x30;
  fVar24 = SUB164(auVar14,0) / fVar25;
  if (param_3 == '\0') {
    fVar23 = 0.0;
  }
  else {
    fVar23 = 1.0;
  }
  uVar8 = 0;
  if (7 < param_1) {
    lVar10 = 2;
    do {
      fVar15 = (float)uVar8;
      if ((longlong)uVar8 < 0) {
        fVar15 = fVar15 + 1.844674e+19;
      }
      fVar15 = (fVar15 - 0.5) * fVar24;
      fVar15 = ((fVar15 + fVar24) - fVar15) + fVar23 + 1.0;
      if (9.223372e+18 <= fVar15) {
        fVar15 = fVar15 - 9.223372e+18;
      }
      fVar16 = (float)(lVar10 + -1);
      if (lVar10 + -1 < 0) {
        fVar16 = fVar16 + 1.844674e+19;
      }
      fVar16 = (fVar16 - 0.5) * fVar24;
      fVar16 = ((fVar16 + fVar24) - fVar16) + fVar23 + 1.0;
      if (9.223372e+18 <= fVar16) {
        fVar16 = fVar16 - 9.223372e+18;
      }
      fVar17 = (float)lVar10;
      if (lVar10 < 0) {
        fVar17 = fVar17 + 1.844674e+19;
      }
      fVar17 = (fVar17 - 0.5) * fVar24;
      fVar17 = ((fVar17 + fVar24) - fVar17) + fVar23 + 1.0;
      if (9.223372e+18 <= fVar17) {
        fVar17 = fVar17 - 9.223372e+18;
      }
      fVar18 = (float)(lVar10 + 1);
      if (lVar10 + 1 < 0) {
        fVar18 = fVar18 + 1.844674e+19;
      }
      fVar18 = (fVar18 - 0.5) * fVar24;
      fVar18 = ((fVar18 + fVar24) - fVar18) + fVar23 + 1.0;
      if (9.223372e+18 <= fVar18) {
        fVar18 = fVar18 - 9.223372e+18;
      }
      fVar19 = (float)(lVar10 + 2);
      if (lVar10 + 2 < 0) {
        fVar19 = fVar19 + 1.844674e+19;
      }
      fVar19 = (fVar19 - 0.5) * fVar24;
      fVar19 = ((fVar19 + fVar24) - fVar19) + fVar23 + 1.0;
      if (9.223372e+18 <= fVar19) {
        fVar19 = fVar19 - 9.223372e+18;
      }
      fVar20 = (float)(lVar10 + 3);
      if (lVar10 + 3 < 0) {
        fVar20 = fVar20 + 1.844674e+19;
      }
      fVar20 = (fVar20 - 0.5) * fVar24;
      fVar20 = ((fVar20 + fVar24) - fVar20) + fVar23 + 1.0;
      if (9.223372e+18 <= fVar20) {
        fVar20 = fVar20 - 9.223372e+18;
      }
      fVar21 = (float)(lVar10 + 4);
      if (lVar10 + 4 < 0) {
        fVar21 = fVar21 + 1.844674e+19;
      }
      fVar21 = (fVar21 - 0.5) * fVar24;
      fVar21 = ((fVar21 + fVar24) - fVar21) + fVar23 + 1.0;
      if (9.223372e+18 <= fVar21) {
        fVar21 = fVar21 - 9.223372e+18;
      }
      fVar22 = (float)(lVar10 + 5);
      if (lVar10 + 5 < 0) {
        fVar22 = fVar22 + 1.844674e+19;
      }
      fVar22 = (fVar22 - 0.5) * fVar24;
      fVar22 = ((fVar22 + fVar24) - fVar22) + fVar23 + 1.0;
      if (9.223372e+18 <= fVar22) {
        fVar22 = fVar22 - 9.223372e+18;
      }
      uVar8 = uVar8 + 8;
      lVar10 = lVar10 + 8;
      uVar6 = ((longlong)fVar22 + 8) * 0x20 +
              (longlong)fVar21 * 0x20 +
              (longlong)fVar20 * 0x20 +
              (longlong)fVar19 * 0x20 +
              (longlong)fVar18 * 0x20 +
              (longlong)fVar17 * 0x20 + (longlong)fVar16 * 0x20 + (longlong)fVar15 * 0x20 + uVar6;
    } while (uVar8 < param_1 - 7);
  }
  for (; uVar8 < param_1; uVar8 = uVar8 + 1) {
    fVar15 = (float)uVar8;
    if ((longlong)uVar8 < 0) {
      fVar15 = fVar15 + 1.844674e+19;
    }
    fVar15 = (fVar15 - 0.5) * fVar24;
    fVar15 = ((fVar15 + fVar24) - fVar15) + fVar23 + 1.0;
    if (9.223372e+18 <= fVar15) {
      fVar15 = fVar15 - 9.223372e+18;
    }
    uVar6 = uVar6 + 0x20 + (longlong)fVar15 * 0x20;
  }
  _Memory_00 = *param_4;
  if (_Memory_00 != (ulonglong *)0x0) {
    if (_Memory_00[1] < uVar6) {
      *param_4 = (ulonglong *)0x0;
      if (_Memory_00 == (ulonglong *)0x0) goto LAB_18000477d;
      free(_Memory_00);
      _Memory_00 = (ulonglong *)0x0;
    }
    if (*param_4 != (ulonglong *)0x0) goto LAB_1800047ba;
  }
LAB_18000477d:
  _Memory_00 = (ulonglong *)thunk_FUN_18001ac00(uVar6);
  if (_Memory_00 == (ulonglong *)0x0) {
    return 0x8007000e;
  }
  _Memory = *param_4;
  *param_4 = _Memory_00;
  if (_Memory != (ulonglong *)0x0) {
    free(_Memory);
  }
  (*param_4)[1] = uVar6;
LAB_1800047ba:
  lVar10 = 0;
  uVar13 = 0;
  uVar11 = 0x10;
  uVar8 = uVar11;
  if (param_1 != 0) {
    do {
      uVar11 = uVar8 + 0x10;
      if (uVar6 < uVar11) {
        return 0x80004005;
      }
      lVar7 = 0;
      fVar23 = 0.0;
      uVar12 = 0;
      do {
        lVar5 = uVar12 + uVar13;
        fVar15 = (float)lVar5;
        if (lVar5 < 0) {
          fVar15 = fVar15 + 1.844674e+19;
        }
        fVar15 = fVar15 - 0.5;
        fVar18 = fVar15 * fVar24;
        fVar17 = fVar18 + fVar24;
        fVar16 = fVar17;
        if (param_3 == '\0') {
          if (fVar18 <= 0.0) {
            fVar18 = 0.0;
          }
          fVar16 = local_res18;
          if (fVar17 <= local_res18) {
            fVar16 = fVar17;
          }
        }
        iVar4 = (int)fVar18;
        fVar17 = fVar18;
        if ((iVar4 != -0x80000000) && ((float)iVar4 != fVar18)) {
          uVar2 = movmskps((int)lVar5,ZEXT816(CONCAT44(fVar18,fVar18)));
          fVar17 = (float)(iVar4 - (uVar2 & 1));
        }
        lVar5 = (longlong)fVar17;
        fVar17 = (float)lVar5;
        if (fVar17 < fVar16) {
          lVar9 = lVar5 - param_2;
          do {
            if (lVar5 < 0) {
              lVar3 = lVar9 + param_2 * 2;
            }
            else {
              lVar3 = lVar5;
              if (param_2 <= lVar5) {
                lVar3 = lVar9;
              }
            }
            if (lVar3 != lVar10) {
              if (1e-05 < fVar23) {
                plVar1 = (longlong *)(uVar11 + (longlong)_Memory_00);
                lVar7 = lVar7 + 1;
                uVar11 = uVar11 + 0x10;
                if (uVar6 < uVar11) {
                  return 0x80004005;
                }
                *(float *)(plVar1 + 1) = fVar23;
                *plVar1 = lVar10;
              }
              fVar23 = 0.0;
              lVar10 = lVar3;
            }
            fVar19 = fVar17;
            if (fVar17 <= fVar18) {
              fVar19 = fVar18;
            }
            fVar20 = fVar17 + 1.0;
            if (fVar16 <= fVar17 + 1.0) {
              fVar20 = fVar16;
            }
            if (param_3 == '\0') {
              if (0.0 <= fVar15) {
                if (fVar15 + 1.0 < fVar25) goto LAB_180004927;
                fVar21 = 0.0;
              }
              else {
                fVar21 = 1.0;
              }
            }
            else {
LAB_180004927:
              fVar21 = (fVar20 + fVar19) * (0.5 / fVar24) - fVar15;
            }
            if (uVar12 != 0) {
              fVar21 = 1.0 - fVar21;
            }
            lVar5 = lVar5 + 1;
            lVar9 = lVar9 + 1;
            fVar17 = (float)lVar5;
            fVar23 = fVar23 + (fVar20 - fVar19) * fVar21;
          } while (fVar17 < fVar16);
        }
        uVar12 = uVar12 + 1;
      } while (uVar12 < 2);
      if (1e-05 < fVar23) {
        plVar1 = (longlong *)(uVar11 + (longlong)_Memory_00);
        lVar7 = lVar7 + 1;
        uVar11 = uVar11 + 0x10;
        if (uVar6 < uVar11) {
          return 0x80004005;
        }
        *(float *)(plVar1 + 1) = fVar23;
        *plVar1 = lVar10;
      }
      *(longlong *)(uVar8 + (longlong)_Memory_00) = lVar7;
      uVar13 = uVar13 + 1;
      ((longlong *)(uVar8 + (longlong)_Memory_00))[1] = uVar11 - uVar8;
      uVar8 = uVar11;
    } while (uVar13 < param_1);
  }
  **param_4 = uVar11;
  return 0;
}



void FUN_180004a30(undefined4 *param_1,uint param_2,longlong *param_3,ulonglong *param_4)

{
  int iVar1;
  longlong *plVar2;
  undefined8 uVar3;
  longlong *plVar4;
  longlong lVar5;
  undefined auStackY_d8 [32];
  longlong *local_98;
  longlong *local_90;
  int local_88 [2];
  longlong *local_80;
  longlong *local_78;
  longlong *local_70;
  undefined8 local_68;
  longlong local_60;
  longlong local_58;
  ulonglong local_50;
  
  local_68 = 0xfffffffffffffffe;
  local_50 = DAT_180065150 ^ (ulonglong)auStackY_d8;
  if (((*(longlong *)(param_1 + 10) == 0) || (param_4[5] == 0)) ||
     (plVar2 = (longlong *)FUN_180001220(), plVar2 == (longlong *)0x0)) goto LAB_180004d4b;
  local_70 = (longlong *)0x0;
  iVar1 = (**(code **)(*plVar2 + 0x30))(plVar2,param_3,&local_70);
  if (-1 < iVar1) {
    local_78 = (longlong *)0x0;
    iVar1 = (**(code **)*local_70)(local_70,&DAT_18005d540,&local_78);
    if (-1 < iVar1) {
      local_88[0] = 0;
      iVar1 = (**(code **)(*local_78 + 0x80))(local_78,local_88);
      if (-1 < iVar1) {
        local_80 = (longlong *)0x0;
        iVar1 = (**(code **)(*plVar2 + 0xa0))(plVar2,*param_1,param_1[2],param_3);
        if (-1 < iVar1) {
          if (((param_2 >> 8 & 1) == 0) || (local_88[0] == 0)) {
            local_98 = (longlong *)0x0;
            iVar1 = (**(code **)(*plVar2 + 0x58))(plVar2,&local_98);
            if (-1 < iVar1) {
              lVar5 = *local_98;
              plVar4 = local_98;
              FUN_180006a70(param_2);
              iVar1 = (**(code **)(lVar5 + 0x40))
                                (plVar4,local_80,*(undefined4 *)param_4,*(undefined4 *)(param_4 + 1)
                                );
              if ((-1 < iVar1) &&
                 (iVar1 = (**(code **)(*local_98 + 0x20))(local_98,&local_60), -1 < iVar1)) {
                if ((local_60 == *param_3) && (local_58 == param_3[1])) {
                  iVar1 = (**(code **)(*local_98 + 0x38))
                                    (local_98,0,*(undefined4 *)(param_4 + 3),
                                     *(undefined4 *)(param_4 + 4));
                  if (-1 < iVar1) {
LAB_180004cc7:
                    plVar2 = local_98;
                    if (local_98 != (longlong *)0x0) {
                      local_98 = (longlong *)0x0;
                      (**(code **)(*plVar2 + 0x10))();
                    }
                    goto LAB_180004d07;
                  }
                }
                else {
                  local_90 = (longlong *)0x0;
                  iVar1 = (**(code **)(*plVar2 + 0x50))(plVar2,&local_90);
                  if (-1 < iVar1) {
                    if ((param_2 & 0xf0000) == 0x10000) {
                      uVar3 = 1;
                    }
                    else {
                      uVar3 = 8;
                      if ((param_2 & 0xf0000) != 0x20000) {
                        uVar3 = 0;
                      }
                    }
                    iVar1 = (**(code **)(*local_90 + 0x40))(local_90,local_98,param_3,uVar3);
                    if ((-1 < iVar1) &&
                       (iVar1 = (**(code **)(*local_90 + 0x38))
                                          (local_90,0,*(undefined4 *)(param_4 + 3),
                                           *(undefined4 *)(param_4 + 4)), plVar2 = local_90,
                       -1 < iVar1)) {
                      if (local_90 != (longlong *)0x0) {
                        local_90 = (longlong *)0x0;
                        (**(code **)(*plVar2 + 0x10))();
                      }
                      goto LAB_180004cc7;
                    }
                  }
                  plVar2 = local_90;
                  if (local_90 != (longlong *)0x0) {
                    local_90 = (longlong *)0x0;
                    (**(code **)(*plVar2 + 0x10))();
                  }
                }
              }
            }
            plVar2 = local_98;
            if (local_98 != (longlong *)0x0) {
              local_98 = (longlong *)0x0;
              (**(code **)(*plVar2 + 0x10))();
            }
          }
          else {
            FUN_180007380(plVar2,local_80,*param_4,(longlong *)param_4[1],param_2,(longlong)param_4)
            ;
          }
        }
LAB_180004d07:
        plVar2 = local_80;
        if (local_80 != (longlong *)0x0) {
          local_80 = (longlong *)0x0;
          (**(code **)(*plVar2 + 0x10))();
        }
      }
    }
    plVar2 = local_78;
    if (local_78 != (longlong *)0x0) {
      local_78 = (longlong *)0x0;
      (**(code **)(*plVar2 + 0x10))();
    }
  }
  plVar2 = local_70;
  if (local_70 != (longlong *)0x0) {
    local_70 = (longlong *)0x0;
    (**(code **)(*plVar2 + 0x10))();
  }
LAB_180004d4b:
  __security_check_cookie(local_50 ^ (ulonglong)auStackY_d8);
  return;
}



undefined4 * FUN_180004d70(ulonglong *param_1,uint param_2,ulonglong *param_3)

{
  uint uVar1;
  undefined8 uVar2;
  ulonglong *puVar3;
  undefined4 *puVar4;
  undefined4 *_Memory;
  undefined4 *_Memory_00;
  size_t in_stack_fffffffffffffef8;
  ulonglong in_stack_ffffffffffffff00;
  ulonglong local_e8;
  undefined8 local_e0;
  longlong local_c8;
  longlong local_c0;
  longlong local_b8;
  int local_a4;
  undefined4 *local_a0;
  undefined4 *local_98;
  undefined8 local_88;
  ulonglong local_78;
  undefined8 local_70;
  longlong local_58;
  longlong local_50;
  longlong local_48;
  int local_34;
  ulonglong *local_30;
  void *local_28;
  
  local_88 = 0xfffffffffffffffe;
  if ((param_1[5] == 0) || (param_3[5] == 0)) {
    return (undefined4 *)0x80004003;
  }
  puVar4 = (undefined4 *)0x0;
  local_e8 = 0;
  local_e0 = 0;
  local_a0 = (undefined4 *)0x0;
  local_98 = (undefined4 *)0x0;
  puVar3 = &local_e8;
  uVar2 = FUN_18000da50(param_1,puVar3);
  _Memory = local_a0;
  uVar1 = (uint)uVar2;
  if (-1 < (int)uVar1) {
    if ((((local_b8 != 0) && (1 < local_a4)) &&
        ((local_a4 < 4 || (local_c0 = local_c8, local_a4 == 4)))) &&
       ((local_c0 != 0 && (local_a0 != (undefined4 *)0x0)))) {
      local_78 = 0;
      local_70 = 0;
      local_30 = (ulonglong *)0x0;
      local_28 = (void *)0x0;
      uVar2 = FUN_180001f40(&local_78,puVar3,*param_3,param_3[1],in_stack_fffffffffffffef8,
                            in_stack_ffffffffffffff00);
      puVar3 = local_30;
      uVar1 = (uint)uVar2;
      _Memory_00 = local_98;
      if ((int)uVar1 < 0) {
LAB_180004ec3:
        puVar4 = (undefined4 *)(ulonglong)uVar1;
      }
      else {
        if ((((local_48 == 0) || (local_34 < 2)) ||
            ((3 < local_34 && (local_50 = local_58, local_34 != 4)))) ||
           ((local_50 == 0 || (local_30 == (ulonglong *)0x0)))) {
          uVar1 = 0x80004003;
          goto LAB_180004ec3;
        }
        uVar1 = FUN_180004a30(_Memory,param_2,(longlong *)&DAT_18005d1c0,local_30);
        _Memory_00 = local_98;
        if ((int)uVar1 < 0) goto LAB_180004ec3;
        free(_Memory);
        _Memory_00 = local_98;
        if (local_98 != (undefined4 *)0x0) {
          _aligned_free(local_98);
          _Memory_00 = puVar4;
        }
        uVar2 = FUN_18000db80((longlong *)puVar3,(longlong *)param_3);
        uVar1 = (uint)uVar2;
        _Memory = puVar4;
        if ((int)uVar1 < 0) goto LAB_180004ec3;
      }
      if (puVar3 != (ulonglong *)0x0) {
        free(puVar3);
      }
      if (local_28 != (void *)0x0) {
        _aligned_free(local_28);
      }
      goto LAB_180004eee;
    }
    uVar1 = 0x80004003;
  }
  puVar4 = (undefined4 *)(ulonglong)uVar1;
  _Memory_00 = local_98;
LAB_180004eee:
  if (_Memory != (undefined4 *)0x0) {
    free(_Memory);
  }
  if (_Memory_00 != (undefined4 *)0x0) {
    _aligned_free(_Memory_00);
  }
  return puVar4;
}



undefined8 FUN_180004f30(undefined4 param_1,uint param_2)

{
  uint uVar1;
  ulonglong in_RAX;
  ulonglong uVar2;
  
  uVar2 = (ulonglong)param_2;
  if ((param_2 >> 0x1c & 1) == 0) {
    if ((param_2 >> 0x1d & 1) != 0) {
LAB_180004f46:
      return CONCAT71((int7)(in_RAX >> 8),1);
    }
    in_RAX = FUN_1800069f0(param_1);
    if (((char)in_RAX == '\0') && ((uVar2 & 0x3000000) == 0)) {
      uVar1 = (uint)uVar2 & 0xf00000;
      in_RAX = (ulonglong)uVar1;
      if (uVar1 == 0x200000) {
        uVar2 = uVar2 & 7;
      }
      else {
        if (uVar1 != 0x300000) {
          if (uVar1 == 0x500000) {
            return 0x500000;
          }
          goto LAB_180004f46;
        }
        uVar2 = uVar2 & 0x77;
      }
      if (uVar2 == 0) {
        in_RAX = FUN_1800013d0(param_1);
        if (in_RAX < 9) goto LAB_180004f46;
      }
    }
  }
  return in_RAX & 0xffffffffffffff00;
}



ulonglong FUN_180004fb0(longlong *param_1,ulonglong *param_2)

{
  undefined (*pauVar1) [16];
  ulonglong uVar2;
  ulonglong uVar3;
  longlong lVar4;
  longlong lVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  longlong lVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined (*_Memory) [16];
  undefined8 uVar12;
  ulonglong uVar13;
  undefined (*pauVar14) [16];
  ulonglong uVar15;
  ulonglong uVar16;
  ulonglong uVar17;
  ulonglong uVar18;
  undefined8 *puVar19;
  ulonglong local_res10;
  float in_stack_ffffffffffffffa0;
  
  _Memory = (undefined (*) [16])_aligned_malloc((*param_1 + *param_2) * 0x10,0x10);
  if (_Memory == (undefined (*) [16])0x0) {
    uVar16 = 0x8007000e;
  }
  else {
    uVar2 = param_2[1];
    uVar16 = 0;
    uVar3 = *param_2;
    puVar19 = (undefined8 *)param_2[5];
    lVar4 = *param_1;
    lVar5 = param_1[5];
    uVar6 = param_1[3];
    uVar7 = *param_2;
    lVar8 = param_1[1];
    local_res10 = 0xffffffffffffffff;
    uVar15 = uVar16;
    uVar18 = uVar16;
    if (uVar2 != 0) {
      do {
        if ((0xffff < (uVar15 ^ local_res10)) &&
           (uVar12 = FUN_180008680(_Memory[uVar3],*param_1,
                                   (undefined (*) [12])((uVar15 >> 0x10) * uVar6 + lVar5),uVar6,
                                   *(undefined4 *)(param_1 + 2)), local_res10 = uVar15,
           (char)uVar12 == '\0')) {
LAB_180005138:
          uVar16 = 0x80004005;
          break;
        }
        pauVar14 = _Memory;
        uVar13 = uVar16;
        uVar17 = uVar16;
        if (*param_2 != 0) {
          do {
            uVar17 = uVar17 + 1;
            pauVar1 = _Memory[uVar3][uVar13 >> 0x10];
            uVar9 = *(undefined4 *)(*pauVar1 + 4);
            uVar10 = *(undefined4 *)(*pauVar1 + 8);
            uVar11 = *(undefined4 *)(*pauVar1 + 0xc);
            *(undefined4 *)*pauVar14 = *(undefined4 *)*pauVar1;
            *(undefined4 *)(*pauVar14 + 4) = uVar9;
            *(undefined4 *)(*pauVar14 + 8) = uVar10;
            *(undefined4 *)(*pauVar14 + 0xc) = uVar11;
            pauVar14 = pauVar14[1];
            uVar13 = uVar13 + (ulonglong)(lVar4 << 0x10) / uVar7;
          } while (uVar17 < *param_2);
        }
        uVar13 = FUN_18000af80(puVar19,(uint *)param_2[3],*(int *)(param_2 + 2),_Memory,*param_2,
                               in_stack_ffffffffffffffa0);
        if ((char)uVar13 == '\0') goto LAB_180005138;
        puVar19 = (undefined8 *)((longlong)puVar19 + param_2[3]);
        uVar18 = uVar18 + 1;
        uVar15 = uVar15 + (ulonglong)(lVar8 << 0x10) / uVar2;
      } while (uVar18 < param_2[1]);
    }
  }
  if (_Memory != (undefined (*) [16])0x0) {
    _aligned_free(_Memory);
  }
  return uVar16;
}



ulonglong FUN_180005180(longlong *param_1,float param_2,ulonglong *param_3)

{
  undefined (*pauVar1) [16];
  undefined (*pauVar2) [16];
  undefined (*pauVar3) [16];
  undefined (*pauVar4) [16];
  ulonglong uVar5;
  char cVar6;
  undefined (*_Memory) [16];
  undefined8 uVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  undefined (*pauVar10) [16];
  ulonglong uVar11;
  undefined (*pauVar12) [12];
  undefined (*pauVar13) [16];
  undefined (*pauVar14) [16];
  undefined8 *local_res8;
  ulonglong local_res18;
  
  if ((*param_3 * 2 != *param_1) || (param_3[1] * 2 != param_1[1])) {
    return 0x80004005;
  }
  _Memory = (undefined (*) [16])_aligned_malloc((*param_3 + *param_1 * 2) * 0x10,0x10);
  if (_Memory == (undefined (*) [16])0x0) {
    uVar11 = 0x8007000e;
  }
  else {
    uVar11 = 0;
    local_res8 = (undefined8 *)param_3[5];
    pauVar12 = (undefined (*) [12])param_1[5];
    uVar5 = param_1[3];
    pauVar13 = _Memory[*param_3];
    pauVar14 = pauVar13[*param_1];
    local_res18 = 0;
    if (param_3[1] != 0) {
      do {
        uVar7 = FUN_18000dd90(pauVar13,*param_1,pauVar12,uVar5,*(undefined4 *)(param_1 + 2),
                              (uint)param_2);
        if ((char)uVar7 == '\0') {
LAB_180005329:
          uVar11 = 0x80004005;
          break;
        }
        pauVar12 = (undefined (*) [12])(*pauVar12 + uVar5);
        if (pauVar13 != pauVar14) {
          uVar7 = FUN_18000dd90(pauVar14,*param_1,pauVar12,uVar5,*(undefined4 *)(param_1 + 2),
                                (uint)param_2);
          if ((char)uVar7 == '\0') goto LAB_180005329;
          pauVar12 = (undefined (*) [12])(*pauVar12 + uVar5);
        }
        uVar8 = uVar11;
        pauVar10 = _Memory;
        if (*param_3 != 0) {
          do {
            uVar9 = uVar8 + 1;
            pauVar1 = pauVar14[uVar8 * 2];
            pauVar2 = pauVar13[uVar8 * 2];
            pauVar3 = pauVar13[uVar8 * 2 + 1];
            pauVar4 = pauVar14[uVar8 * 2 + 1];
            *pauVar10 = CONCAT412((*(float *)(*pauVar1 + 0xc) + *(float *)(*pauVar2 + 0xc) +
                                   *(float *)(*pauVar3 + 0xc) + *(float *)(*pauVar4 + 0xc)) * 0.25,
                                  CONCAT48((*(float *)(*pauVar1 + 8) + *(float *)(*pauVar2 + 8) +
                                            *(float *)(*pauVar3 + 8) + *(float *)(*pauVar4 + 8)) *
                                           0.25,CONCAT44((*(float *)(*pauVar1 + 4) +
                                                          *(float *)(*pauVar2 + 4) +
                                                          *(float *)(*pauVar3 + 4) +
                                                         *(float *)(*pauVar4 + 4)) * 0.25,
                                                         (*(float *)*pauVar1 + *(float *)*pauVar2 +
                                                          *(float *)*pauVar3 + *(float *)*pauVar4) *
                                                         0.25)));
            uVar8 = uVar9;
            pauVar10 = pauVar10[1];
          } while (uVar9 < *param_3);
        }
        cVar6 = FUN_18000dc40(local_res8,(uint *)param_3[3],*(int *)(param_3 + 2),_Memory,*param_3,
                              param_2);
        if (cVar6 == '\0') goto LAB_180005329;
        local_res8 = (undefined8 *)((longlong)local_res8 + param_3[3]);
        local_res18 = local_res18 + 1;
      } while (local_res18 < param_3[1]);
    }
  }
  if (_Memory != (undefined (*) [16])0x0) {
    _aligned_free(_Memory);
  }
  return uVar11;
}



ulonglong FUN_180005380(ulonglong *param_1,float param_2,ulonglong *param_3)

{
  longlong *plVar1;
  undefined (*pauVar2) [16];
  undefined (*pauVar3) [16];
  undefined (*pauVar4) [16];
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  ulonglong uVar9;
  ulonglong uVar10;
  longlong lVar11;
  undefined auVar12 [16];
  char cVar13;
  undefined (*_Memory) [16];
  __uint64 _Var14;
  void *_Memory_00;
  undefined8 uVar15;
  longlong *plVar16;
  longlong lVar17;
  longlong lVar18;
  ulonglong uVar19;
  undefined (*pauVar20) [16];
  undefined (*pauVar21) [16];
  undefined (*pauVar22) [16];
  undefined (*pauVar23) [16];
  longlong *plVar24;
  ulonglong uVar25;
  void *pvVar26;
  undefined8 *local_res18;
  longlong local_res20;
  ulonglong local_68;
  
  _Memory = (undefined (*) [16])_aligned_malloc((*param_3 + *param_1 * 2) * 0x10,0x10);
  if (_Memory == (undefined (*) [16])0x0) {
    return 0x8007000e;
  }
  auVar12 = ZEXT816(0x20) * ZEXT816(*param_3 + param_3[1]);
  _Var14 = SUB168(auVar12,0);
  if (SUB168(auVar12 >> 0x40,0) != 0) {
    _Var14 = 0xffffffffffffffff;
  }
  _Memory_00 = (void *)thunk_FUN_18001ac00(_Var14);
  if (_Memory_00 == (void *)0x0) {
    uVar25 = 0x8007000e;
  }
  else {
    pvVar26 = (void *)(*param_3 * 0x20 + (longlong)_Memory_00);
    FUN_180003ff0(*param_1,*param_3,SUB41(param_2,0) & 1,(longlong)_Memory_00);
    FUN_180003ff0(param_1[1],param_3[1],(byte)((uint)param_2 >> 1) & 1,(longlong)pvVar26);
    uVar25 = 0;
    local_res18 = (undefined8 *)param_3[5];
    lVar17 = -1;
    uVar9 = param_1[5];
    uVar10 = param_1[3];
    local_res20 = -1;
    local_68 = 0;
    if (param_3[1] != 0) {
      plVar24 = (longlong *)((longlong)pvVar26 + 0x10);
      pauVar20 = _Memory[*param_3];
      pauVar22 = _Memory[*param_3][*param_1];
      do {
        lVar11 = plVar24[-2];
        lVar18 = lVar17;
        pauVar21 = pauVar20;
        pauVar23 = pauVar22;
        if ((((lVar11 != local_res20) &&
             (lVar18 = -1, pauVar21 = pauVar22, pauVar23 = pauVar20, local_res20 = lVar17,
             lVar11 != lVar17)) &&
            (uVar15 = FUN_18000dd90(pauVar20,*param_1,(undefined (*) [12])(lVar11 * uVar10 + uVar9),
                                    uVar10,*(undefined4 *)(param_1 + 2),(uint)param_2),
            lVar18 = lVar17, pauVar21 = pauVar20, pauVar23 = pauVar22, local_res20 = lVar11,
            (char)uVar15 == '\0')) ||
           ((lVar11 = *plVar24, lVar17 = lVar18, lVar11 != lVar18 &&
            (uVar15 = FUN_18000dd90(pauVar23,*param_1,(undefined (*) [12])(lVar11 * uVar10 + uVar9),
                                    uVar10,*(undefined4 *)(param_1 + 2),(uint)param_2),
            lVar17 = lVar11, (char)uVar15 == '\0')))) {
LAB_180005675:
          uVar25 = 0x80004005;
          break;
        }
        if (*param_3 != 0) {
          plVar16 = (longlong *)((longlong)_Memory_00 + 0x10);
          uVar19 = uVar25;
          pauVar20 = _Memory;
          do {
            lVar11 = *plVar16;
            uVar19 = uVar19 + 1;
            plVar1 = plVar16 + -2;
            fVar5 = *(float *)(plVar16 + 1);
            fVar6 = *(float *)(plVar16 + -1);
            plVar16 = plVar16 + 4;
            pauVar3 = pauVar23[lVar11];
            pauVar4 = pauVar23[*plVar1];
            pauVar22 = pauVar21[*plVar1];
            fVar7 = *(float *)(plVar24 + 1);
            pauVar2 = pauVar21[lVar11];
            fVar8 = *(float *)(plVar24 + -1);
            *pauVar20 = CONCAT412((*(float *)(*pauVar4 + 0xc) * fVar6 +
                                  *(float *)(*pauVar3 + 0xc) * fVar5) * fVar7 +
                                  (*(float *)(*pauVar22 + 0xc) * fVar6 +
                                  *(float *)(*pauVar2 + 0xc) * fVar5) * fVar8,
                                  CONCAT48((*(float *)(*pauVar4 + 8) * fVar6 +
                                           *(float *)(*pauVar3 + 8) * fVar5) * fVar7 +
                                           (*(float *)(*pauVar22 + 8) * fVar6 +
                                           *(float *)(*pauVar2 + 8) * fVar5) * fVar8,
                                           CONCAT44((*(float *)(*pauVar4 + 4) * fVar6 +
                                                    *(float *)(*pauVar3 + 4) * fVar5) * fVar7 +
                                                    (*(float *)(*pauVar22 + 4) * fVar6 +
                                                    *(float *)(*pauVar2 + 4) * fVar5) * fVar8,
                                                    (*(float *)*pauVar4 * fVar6 +
                                                    *(float *)*pauVar3 * fVar5) * fVar7 +
                                                    (*(float *)*pauVar22 * fVar6 +
                                                    *(float *)*pauVar2 * fVar5) * fVar8)));
            pauVar20 = pauVar20[1];
          } while (uVar19 < *param_3);
        }
        cVar13 = FUN_18000dc40(local_res18,(uint *)param_3[3],*(int *)(param_3 + 2),_Memory,*param_3
                               ,param_2);
        if (cVar13 == '\0') goto LAB_180005675;
        plVar24 = plVar24 + 4;
        local_res18 = (undefined8 *)((longlong)local_res18 + param_3[3]);
        local_68 = local_68 + 1;
        pauVar20 = pauVar21;
        pauVar22 = pauVar23;
      } while (local_68 < param_3[1]);
    }
  }
  if (_Memory_00 != (void *)0x0) {
    free(_Memory_00);
  }
  _aligned_free(_Memory);
  return uVar25;
}



// WARNING: Could not reconcile some variable overlaps

undefined8 FUN_1800056b0(longlong *param_1,float param_2,ulonglong *param_3)

{
  void *pvVar1;
  undefined (*pauVar2) [16];
  undefined (*pauVar3) [16];
  longlong lVar4;
  longlong lVar5;
  ulonglong uVar6;
  undefined auVar7 [16];
  char cVar8;
  undefined (*_Memory) [16];
  __uint64 _Var9;
  void *_Memory_00;
  undefined8 uVar10;
  longlong lVar11;
  longlong lVar12;
  longlong lVar13;
  longlong lVar14;
  longlong lVar15;
  longlong *plVar16;
  longlong *plVar17;
  undefined (*pauVar18) [16];
  undefined (*pauVar19) [16];
  undefined (*pauVar20) [16];
  undefined (*pauVar21) [16];
  undefined (*pauVar22) [16];
  undefined (*pauVar23) [16];
  float fVar24;
  float fVar25;
  float fVar26;
  float fVar27;
  float fVar28;
  float fVar29;
  float fVar30;
  float fVar31;
  float fVar32;
  float fVar33;
  float fVar34;
  float fVar35;
  float fVar36;
  float fVar37;
  float fVar38;
  float fVar39;
  float fVar40;
  float fVar41;
  float fVar42;
  float fVar43;
  float fVar44;
  float fVar45;
  float fVar46;
  float fVar47;
  float fVar48;
  float fVar49;
  float fVar50;
  float fVar51;
  float fVar52;
  float fVar53;
  float fVar54;
  float fVar55;
  float fVar56;
  float fVar57;
  float fVar58;
  float fVar59;
  float fVar60;
  float fVar61;
  float fVar62;
  float fVar63;
  float fVar64;
  float fVar65;
  float fVar66;
  float fVar67;
  float fVar68;
  float fVar69;
  float fVar70;
  float fVar71;
  float fVar72;
  float fVar73;
  float fVar74;
  float fVar75;
  float fVar76;
  float fVar77;
  float fVar78;
  float fVar79;
  float fVar80;
  undefined (*local_res20) [16];
  undefined8 local_1b0;
  longlong local_1a8;
  undefined local_198 [16];
  longlong local_188;
  undefined8 *local_170;
  ulonglong local_168;
  
  _Memory = (undefined (*) [16])_aligned_malloc((*param_3 + *param_1 * 4) * 0x10,0x10);
  if (_Memory == (undefined (*) [16])0x0) {
    return 0x8007000e;
  }
  auVar7 = ZEXT816(0x28) * ZEXT816(*param_3 + param_3[1]);
  _Var9 = SUB168(auVar7,0);
  if (SUB168(auVar7 >> 0x40,0) != 0) {
    _Var9 = 0xffffffffffffffff;
  }
  _Memory_00 = (void *)thunk_FUN_18001ac00(_Var9);
  if (_Memory_00 == (void *)0x0) {
    local_1b0 = 0x8007000e;
  }
  else {
    pvVar1 = (void *)((longlong)_Memory_00 + *param_3 * 0x28);
    FUN_1800040e0(*param_1,*param_3,SUB41(param_2,0) & 1,(byte)((uint)param_2 >> 4) & 1,
                  (longlong)_Memory_00);
    FUN_1800040e0(param_1[1],param_3[1],(byte)((uint)param_2 >> 1) & 1,
                  (byte)((uint)param_2 >> 5) & 1,(longlong)pvVar1);
    lVar4 = *param_1;
    lVar5 = param_1[5];
    uVar6 = param_1[3];
    local_170 = (undefined8 *)param_3[5];
    pauVar22 = _Memory[*param_3];
    local_188 = -1;
    local_1a8 = -1;
    lVar11 = -1;
    lVar13 = -1;
    local_res20 = pauVar22[lVar4 * 3];
    local_1b0 = 0;
    local_168 = 0;
    pauVar19 = pauVar22[lVar4];
    pauVar21 = pauVar22[lVar4 * 2];
    if (param_3[1] != 0) {
      plVar17 = (longlong *)((longlong)pvVar1 + 8);
      do {
        lVar15 = local_1a8;
        lVar4 = plVar17[-1];
        lVar12 = lVar11;
        lVar14 = lVar13;
        pauVar18 = pauVar19;
        pauVar20 = pauVar21;
        pauVar23 = pauVar22;
        if (lVar4 != local_188) {
          if (lVar4 == local_1a8) {
            local_1a8 = -1;
            pauVar18 = pauVar22;
            pauVar23 = pauVar19;
            local_188 = lVar15;
          }
          else if (lVar4 == lVar11) {
LAB_180005938:
            lVar12 = -1;
            pauVar20 = pauVar22;
            pauVar23 = pauVar21;
            local_188 = lVar11;
          }
          else if (lVar4 == lVar13) {
            if (lVar4 == lVar11) goto LAB_180005938;
            if (lVar4 == lVar13) {
              lVar14 = -1;
              pauVar23 = local_res20;
              local_res20 = pauVar22;
              local_188 = lVar13;
            }
          }
          else {
            uVar10 = FUN_18000dd90(pauVar22,*param_1,(undefined (*) [12])(lVar4 * uVar6 + lVar5),
                                   uVar6,*(undefined4 *)(param_1 + 2),(uint)param_2);
            local_188 = lVar4;
            if ((char)uVar10 == '\0') {
              local_1b0 = 0x80004005;
              break;
            }
          }
        }
        lVar4 = *plVar17;
        lVar11 = lVar12;
        lVar15 = lVar14;
        pauVar19 = pauVar18;
        if (lVar4 != local_1a8) {
          if (lVar4 == lVar12) {
            lVar11 = -1;
            pauVar19 = pauVar20;
            pauVar20 = pauVar18;
            local_1a8 = lVar12;
            goto LAB_1800059e4;
          }
          if (lVar4 == lVar14) {
            lVar15 = -1;
            pauVar19 = local_res20;
            local_res20 = pauVar18;
            local_1a8 = lVar14;
            goto LAB_1800059e4;
          }
          uVar10 = FUN_18000dd90(pauVar18,*param_1,(undefined (*) [12])(lVar4 * uVar6 + lVar5),uVar6
                                 ,*(undefined4 *)(param_1 + 2),(uint)param_2);
          local_1a8 = lVar4;
          if ((char)uVar10 != '\0') goto LAB_1800059e4;
LAB_180005f13:
          local_1b0 = 0x80004005;
          break;
        }
LAB_1800059e4:
        lVar4 = plVar17[1];
        lVar13 = lVar15;
        pauVar21 = pauVar20;
        pauVar22 = local_res20;
        if (((lVar4 != lVar11) &&
            (lVar11 = lVar15, lVar13 = -1, pauVar21 = local_res20, pauVar22 = pauVar20,
            lVar4 != lVar15)) &&
           (uVar10 = FUN_18000dd90(pauVar20,*param_1,(undefined (*) [12])(lVar4 * uVar6 + lVar5),
                                   uVar6,*(undefined4 *)(param_1 + 2),(uint)param_2), lVar11 = lVar4
           , lVar13 = lVar15, pauVar21 = pauVar20, pauVar22 = local_res20, (char)uVar10 == '\0'))
        goto LAB_180005f13;
        local_res20 = pauVar22;
        lVar4 = plVar17[2];
        if ((lVar4 != lVar13) &&
           (uVar10 = FUN_18000dd90(local_res20,*param_1,(undefined (*) [12])(lVar4 * uVar6 + lVar5),
                                   uVar6,*(undefined4 *)(param_1 + 2),(uint)param_2), lVar13 = lVar4
           , (char)uVar10 == '\0')) {
          local_1b0 = 0x80004005;
          break;
        }
        local_198 = local_198 & (undefined  [16])0xffffffffffffffff;
        if (*param_3 != 0) {
          plVar16 = (longlong *)((longlong)_Memory_00 + 0x10);
          pauVar22 = _Memory;
          do {
            lVar4 = plVar16[-1];
            lVar15 = *plVar16;
            lVar12 = plVar16[-2];
            lVar14 = plVar16[1];
            fVar65 = *(float *)(plVar16 + 2);
            pauVar18 = pauVar19[lVar4];
            fVar41 = *(float *)*pauVar18;
            fVar42 = *(float *)(*pauVar18 + 4);
            fVar44 = *(float *)(*pauVar18 + 8);
            fVar45 = *(float *)(*pauVar18 + 0xc);
            pauVar18 = local_res20[lVar4];
            fVar49 = *(float *)*pauVar18;
            fVar52 = *(float *)(*pauVar18 + 4);
            fVar55 = *(float *)(*pauVar18 + 8);
            fVar56 = *(float *)(*pauVar18 + 0xc);
            pauVar18 = pauVar21[lVar4];
            fVar53 = *(float *)*pauVar18;
            fVar54 = *(float *)(*pauVar18 + 4);
            fVar67 = *(float *)(*pauVar18 + 8);
            fVar68 = *(float *)(*pauVar18 + 0xc);
            pauVar18 = pauVar19[lVar15];
            pauVar20 = pauVar23[lVar4];
            fVar46 = *(float *)*pauVar20;
            fVar48 = *(float *)(*pauVar20 + 4);
            fVar51 = *(float *)(*pauVar20 + 8);
            fVar66 = *(float *)(*pauVar20 + 0xc);
            fVar24 = *(float *)*pauVar18 - fVar41;
            fVar28 = *(float *)(*pauVar18 + 4) - fVar42;
            fVar32 = *(float *)(*pauVar18 + 8) - fVar44;
            fVar36 = *(float *)(*pauVar18 + 0xc) - fVar45;
            pauVar18 = pauVar19[lVar12];
            pauVar20 = pauVar19[lVar14];
            fVar57 = *(float *)*pauVar18 - fVar41;
            fVar58 = *(float *)(*pauVar18 + 4) - fVar42;
            fVar59 = *(float *)(*pauVar18 + 8) - fVar44;
            fVar60 = *(float *)(*pauVar18 + 0xc) - fVar45;
            pauVar18 = pauVar23[lVar15];
            pauVar2 = pauVar23[lVar12];
            fVar69 = *(float *)*pauVar18 - fVar46;
            fVar70 = *(float *)(*pauVar18 + 4) - fVar48;
            fVar71 = *(float *)(*pauVar18 + 8) - fVar51;
            fVar72 = *(float *)(*pauVar18 + 0xc) - fVar66;
            pauVar18 = pauVar23[lVar14];
            fVar73 = *(float *)*pauVar2 - fVar46;
            fVar74 = *(float *)(*pauVar2 + 4) - fVar48;
            fVar75 = *(float *)(*pauVar2 + 8) - fVar51;
            fVar76 = *(float *)(*pauVar2 + 0xc) - fVar66;
            pauVar2 = pauVar21[lVar12];
            pauVar3 = pauVar21[lVar14];
            fVar77 = *(float *)*pauVar2 - fVar53;
            fVar78 = *(float *)(*pauVar2 + 4) - fVar54;
            fVar79 = *(float *)(*pauVar2 + 8) - fVar67;
            fVar80 = *(float *)(*pauVar2 + 0xc) - fVar68;
            fVar61 = (*(float *)*pauVar20 - fVar41) * 0.1666667;
            fVar62 = (*(float *)(*pauVar20 + 4) - fVar42) * 0.1666667;
            fVar63 = (*(float *)(*pauVar20 + 8) - fVar44) * 0.1666667;
            fVar64 = (*(float *)(*pauVar20 + 0xc) - fVar45) * 0.1666667;
            pauVar20 = pauVar21[lVar15];
            fVar25 = *(float *)*pauVar20 - fVar53;
            fVar29 = *(float *)(*pauVar20 + 4) - fVar54;
            fVar33 = *(float *)(*pauVar20 + 8) - fVar67;
            fVar37 = *(float *)(*pauVar20 + 0xc) - fVar68;
            pauVar20 = local_res20[lVar12];
            fVar26 = *(float *)*pauVar20 - fVar49;
            fVar30 = *(float *)(*pauVar20 + 4) - fVar52;
            fVar34 = *(float *)(*pauVar20 + 8) - fVar55;
            fVar38 = *(float *)(*pauVar20 + 0xc) - fVar56;
            fVar40 = fVar24 * 0.5;
            fVar43 = fVar28 * 0.5;
            fVar47 = fVar32 * 0.5;
            fVar50 = fVar36 * 0.5;
            pauVar20 = local_res20[lVar15];
            fVar27 = *(float *)*pauVar20 - fVar49;
            fVar31 = *(float *)(*pauVar20 + 4) - fVar52;
            fVar35 = *(float *)(*pauVar20 + 8) - fVar55;
            fVar39 = *(float *)(*pauVar20 + 0xc) - fVar56;
            pauVar20 = local_res20[lVar14];
            fVar40 = ((fVar24 - fVar57 * 0.3333333) - fVar61) * fVar65 + fVar41 +
                     (fVar57 * 0.5 + fVar40) * fVar65 * fVar65 +
                     ((fVar61 - fVar57 * 0.1666667) - fVar40) * fVar65 * fVar65 * fVar65;
            fVar43 = ((fVar28 - fVar58 * 0.3333333) - fVar62) * fVar65 + fVar42 +
                     (fVar58 * 0.5 + fVar43) * fVar65 * fVar65 +
                     ((fVar62 - fVar58 * 0.1666667) - fVar43) * fVar65 * fVar65 * fVar65;
            fVar47 = ((fVar32 - fVar59 * 0.3333333) - fVar63) * fVar65 + fVar44 +
                     (fVar59 * 0.5 + fVar47) * fVar65 * fVar65 +
                     ((fVar63 - fVar59 * 0.1666667) - fVar47) * fVar65 * fVar65 * fVar65;
            fVar50 = ((fVar36 - fVar60 * 0.3333333) - fVar64) * fVar65 + fVar45 +
                     (fVar60 * 0.5 + fVar50) * fVar65 * fVar65 +
                     ((fVar64 - fVar60 * 0.1666667) - fVar50) * fVar65 * fVar65 * fVar65;
            fVar57 = (*(float *)*pauVar18 - fVar46) * 0.1666667;
            fVar58 = (*(float *)(*pauVar18 + 4) - fVar48) * 0.1666667;
            fVar59 = (*(float *)(*pauVar18 + 8) - fVar51) * 0.1666667;
            fVar60 = (*(float *)(*pauVar18 + 0xc) - fVar66) * 0.1666667;
            fVar41 = fVar69 * 0.5;
            fVar44 = fVar70 * 0.5;
            fVar24 = fVar71 * 0.5;
            fVar32 = fVar72 * 0.5;
            local_198 = CONCAT412(fVar50,CONCAT48(fVar47,CONCAT44(fVar43,fVar40)));
            fVar61 = (*(float *)*pauVar3 - fVar53) * 0.1666667;
            fVar62 = (*(float *)(*pauVar3 + 4) - fVar54) * 0.1666667;
            fVar63 = (*(float *)(*pauVar3 + 8) - fVar67) * 0.1666667;
            fVar64 = (*(float *)(*pauVar3 + 0xc) - fVar68) * 0.1666667;
            fVar42 = fVar25 * 0.5;
            fVar45 = fVar29 * 0.5;
            fVar28 = fVar33 * 0.5;
            fVar36 = fVar37 * 0.5;
            fVar57 = (((fVar69 - fVar73 * 0.3333333) - fVar57) * fVar65 + fVar46 +
                      (fVar73 * 0.5 + fVar41) * fVar65 * fVar65 +
                     ((fVar57 - fVar73 * 0.1666667) - fVar41) * fVar65 * fVar65 * fVar65) - fVar40;
            fVar58 = (((fVar70 - fVar74 * 0.3333333) - fVar58) * fVar65 + fVar48 +
                      (fVar74 * 0.5 + fVar44) * fVar65 * fVar65 +
                     ((fVar58 - fVar74 * 0.1666667) - fVar44) * fVar65 * fVar65 * fVar65) - fVar43;
            fVar59 = (((fVar71 - fVar75 * 0.3333333) - fVar59) * fVar65 + fVar51 +
                      (fVar75 * 0.5 + fVar24) * fVar65 * fVar65 +
                     ((fVar59 - fVar75 * 0.1666667) - fVar24) * fVar65 * fVar65 * fVar65) - fVar47;
            fVar32 = (((fVar72 - fVar76 * 0.3333333) - fVar60) * fVar65 + fVar66 +
                      (fVar76 * 0.5 + fVar32) * fVar65 * fVar65 +
                     ((fVar60 - fVar76 * 0.1666667) - fVar32) * fVar65 * fVar65 * fVar65) - fVar50;
            fVar44 = fVar27 * 0.5;
            fVar46 = fVar31 * 0.5;
            fVar48 = fVar35 * 0.5;
            fVar51 = fVar39 * 0.5;
            fVar66 = (((fVar25 - fVar77 * 0.3333333) - fVar61) * fVar65 + fVar53 +
                      (fVar77 * 0.5 + fVar42) * fVar65 * fVar65 +
                     ((fVar61 - fVar77 * 0.1666667) - fVar42) * fVar65 * fVar65 * fVar65) - fVar40;
            fVar24 = (((fVar29 - fVar78 * 0.3333333) - fVar62) * fVar65 + fVar54 +
                      (fVar78 * 0.5 + fVar45) * fVar65 * fVar65 +
                     ((fVar62 - fVar78 * 0.1666667) - fVar45) * fVar65 * fVar65 * fVar65) - fVar43;
            fVar67 = (((fVar33 - fVar79 * 0.3333333) - fVar63) * fVar65 + fVar67 +
                      (fVar79 * 0.5 + fVar28) * fVar65 * fVar65 +
                     ((fVar63 - fVar79 * 0.1666667) - fVar28) * fVar65 * fVar65 * fVar65) - fVar47;
            fVar68 = (((fVar37 - fVar80 * 0.3333333) - fVar64) * fVar65 + fVar68 +
                      (fVar80 * 0.5 + fVar36) * fVar65 * fVar65 +
                     ((fVar64 - fVar80 * 0.1666667) - fVar36) * fVar65 * fVar65 * fVar65) - fVar50;
            fVar53 = (*(float *)*pauVar20 - fVar49) * 0.1666667;
            fVar54 = (*(float *)(*pauVar20 + 4) - fVar52) * 0.1666667;
            fVar55 = (*(float *)(*pauVar20 + 8) - fVar55) * 0.1666667;
            fVar56 = (*(float *)(*pauVar20 + 0xc) - fVar56) * 0.1666667;
            fVar41 = *(float *)(plVar17 + 3);
            fVar42 = fVar66 * 0.5;
            fVar45 = fVar24 * 0.5;
            fVar49 = fVar67 * 0.5;
            fVar52 = fVar68 * 0.5;
            pauVar18 = local_res20[lVar4];
            fVar44 = ((((fVar27 - fVar26 * 0.3333333) - fVar53) * fVar65 + *(float *)*pauVar18 +
                       (fVar26 * 0.5 + fVar44) * fVar65 * fVar65 +
                      ((fVar53 - fVar26 * 0.1666667) - fVar44) * fVar65 * fVar65 * fVar65) - fVar40)
                     * 0.1666667;
            fVar53 = ((((fVar31 - fVar30 * 0.3333333) - fVar54) * fVar65 + *(float *)(*pauVar18 + 4)
                       + (fVar30 * 0.5 + fVar46) * fVar65 * fVar65 +
                      ((fVar54 - fVar30 * 0.1666667) - fVar46) * fVar65 * fVar65 * fVar65) - fVar43)
                     * 0.1666667;
            fVar55 = ((((fVar35 - fVar34 * 0.3333333) - fVar55) * fVar65 + *(float *)(*pauVar18 + 8)
                       + (fVar34 * 0.5 + fVar48) * fVar65 * fVar65 +
                      ((fVar55 - fVar34 * 0.1666667) - fVar48) * fVar65 * fVar65 * fVar65) - fVar47)
                     * 0.1666667;
            fVar65 = ((((fVar39 - fVar38 * 0.3333333) - fVar56) * fVar65 +
                       *(float *)(*pauVar18 + 0xc) + (fVar38 * 0.5 + fVar51) * fVar65 * fVar65 +
                      ((fVar56 - fVar38 * 0.1666667) - fVar51) * fVar65 * fVar65 * fVar65) - fVar50)
                     * 0.1666667;
            local_198._0_8_ = local_198._0_8_ + 1;
            plVar16 = plVar16 + 5;
            *pauVar22 = CONCAT412(((fVar68 - fVar32 * 0.3333333) - fVar65) * fVar41 + fVar50 +
                                  (fVar32 * 0.5 + fVar52) * fVar41 * fVar41 +
                                  ((fVar65 - fVar32 * 0.1666667) - fVar52) *
                                  fVar41 * fVar41 * fVar41,
                                  CONCAT48(((fVar67 - fVar59 * 0.3333333) - fVar55) * fVar41 +
                                           fVar47 + (fVar59 * 0.5 + fVar49) * fVar41 * fVar41 +
                                           ((fVar55 - fVar59 * 0.1666667) - fVar49) *
                                           fVar41 * fVar41 * fVar41,
                                           CONCAT44(((fVar24 - fVar58 * 0.3333333) - fVar53) *
                                                    fVar41 + fVar43 +
                                                    (fVar58 * 0.5 + fVar45) * fVar41 * fVar41 +
                                                    ((fVar53 - fVar58 * 0.1666667) - fVar45) *
                                                    fVar41 * fVar41 * fVar41,
                                                    ((fVar66 - fVar57 * 0.3333333) - fVar44) *
                                                    fVar41 + fVar40 +
                                                    (fVar57 * 0.5 + fVar42) * fVar41 * fVar41 +
                                                    ((fVar44 - fVar57 * 0.1666667) - fVar42) *
                                                    fVar41 * fVar41 * fVar41)));
            pauVar22 = pauVar22[1];
          } while (local_198._0_8_ < *param_3);
        }
        cVar8 = FUN_18000dc40(local_170,(uint *)param_3[3],*(int *)(param_3 + 2),_Memory,*param_3,
                              param_2);
        if (cVar8 == '\0') goto LAB_180005f13;
        plVar17 = plVar17 + 5;
        local_170 = (undefined8 *)((longlong)local_170 + param_3[3]);
        local_168 = local_168 + 1;
        pauVar22 = pauVar23;
      } while (local_168 < param_3[1]);
    }
  }
  if (_Memory_00 != (void *)0x0) {
    free(_Memory_00);
  }
  _aligned_free(_Memory);
  return local_1b0;
}



ulonglong FUN_180005fc0(ulonglong *param_1,float param_2,ulonglong *param_3)

{
  undefined (*pauVar1) [12];
  float *pfVar2;
  float fVar3;
  void *pvVar4;
  undefined (*_Memory) [12];
  undefined (*_Memory_00) [12];
  char cVar5;
  undefined (*_Memory_01) [16];
  ulonglong uVar6;
  __uint64 _Var7;
  ulonglong *puVar8;
  void *pvVar9;
  undefined8 uVar10;
  undefined (*pauVar11) [16];
  ulonglong *puVar12;
  ulonglong uVar13;
  undefined (*pauVar14) [16];
  ulonglong uVar15;
  ulonglong *puVar16;
  ulonglong *puVar17;
  ulonglong *puVar18;
  ulonglong *puVar19;
  float fVar20;
  ulonglong *local_res20;
  undefined (*local_88) [12];
  ulonglong *local_80;
  ulonglong local_78;
  undefined (*local_70) [12];
  ulonglong local_68;
  ulonglong *local_60;
  undefined8 local_58;
  undefined (*local_50) [16];
  
  local_58 = 0xfffffffffffffffe;
  _Memory_01 = (undefined (*) [16])_aligned_malloc(*param_1 << 4,0x10);
  local_50 = _Memory_01;
  if (_Memory_01 == (undefined (*) [16])0x0) {
    uVar13 = 0x8007000e;
    goto LAB_1800064ce;
  }
  uVar13 = param_3[1];
  uVar6 = SUB168(ZEXT816(0x18) * ZEXT816(uVar13),0);
  if (SUB168(ZEXT816(0x18) * ZEXT816(uVar13) >> 0x40,0) != 0) {
    uVar6 = 0xffffffffffffffff;
  }
  _Var7 = uVar6 + 8;
  if (0xfffffffffffffff7 < uVar6) {
    _Var7 = 0xffffffffffffffff;
  }
  puVar8 = (ulonglong *)thunk_FUN_18001ac00(_Var7);
  puVar18 = (ulonglong *)0x0;
  if (puVar8 != (ulonglong *)0x0) {
    *puVar8 = uVar13;
    puVar18 = puVar8 + 1;
    _eh_vector_constructor_iterator_
              (puVar18,0x18,uVar13,(_func_void_void_ptr *)&LAB_180004320,
               (_func_void_void_ptr *)&LAB_1800064f0);
  }
  if (puVar18 == (ulonglong *)0x0) {
    uVar13 = 0x8007000e;
    goto LAB_1800064ce;
  }
  local_res20 = (ulonglong *)0x0;
  local_88 = (undefined (*) [12])0x0;
  uVar6 = FUN_180004340(*param_1,*param_3,SUB41(param_2,0) & 1,(ulonglong **)&local_88);
  _Memory = local_88;
  uVar13 = uVar6 & 0xffffffff;
  if (-1 < (int)uVar6) {
    local_88 = (undefined (*) [12])0x0;
    uVar6 = FUN_180004340(param_1[1],param_3[1],(byte)((uint)param_2 >> 1) & 1,
                          (ulonglong **)&local_88);
    _Memory_00 = local_88;
    uVar13 = uVar6 & 0xffffffff;
    if (-1 < (int)uVar6) {
      puVar19 = (ulonglong *)((longlong)*_Memory + *(longlong *)*_Memory);
      local_60 = (ulonglong *)((longlong)*local_88 + *(longlong *)*local_88);
      puVar8 = (ulonglong *)(local_88[1] + 4);
      for (puVar16 = puVar8; puVar16 < local_60;
          puVar16 = (ulonglong *)((longlong)puVar16 + puVar16[1])) {
        uVar13 = 0;
        puVar17 = puVar16;
        if (*puVar16 != 0) {
          do {
            puVar18[puVar17[2] * 3] = puVar18[puVar17[2] * 3] + 1;
            uVar13 = uVar13 + 1;
            puVar17 = puVar17 + 2;
          } while (uVar13 < *puVar16);
        }
      }
      local_88 = (undefined (*) [12])param_1[5];
      local_78 = param_1[3];
      local_70 = (undefined (*) [12])((longlong)*local_88 + param_1[1] * local_78);
      local_68 = param_3[5];
      local_80 = puVar19;
      if (puVar8 < local_60) {
        do {
          uVar13 = 0;
          puVar16 = puVar8;
          if (*puVar8 != 0) {
            do {
              uVar6 = puVar16[2];
              if (puVar18[uVar6 * 3 + 2] == 0) {
                if (local_res20 == (ulonglong *)0x0) {
                  pvVar9 = _aligned_malloc(*param_3 << 4,0x10);
                  pvVar4 = (void *)puVar18[uVar6 * 3 + 2];
                  puVar18[uVar6 * 3 + 2] = (ulonglong)pvVar9;
                  if (pvVar4 != (void *)0x0) {
                    _aligned_free(pvVar4);
                  }
                  if (puVar18[uVar6 * 3 + 2] == 0) {
                    uVar13 = 0x8007000e;
                    goto LAB_180006474;
                  }
                }
                else {
                  uVar15 = local_res20[2];
                  local_res20[2] = 0;
                  pvVar4 = (void *)puVar18[uVar6 * 3 + 2];
                  puVar18[uVar6 * 3 + 2] = uVar15;
                  if (pvVar4 != (void *)0x0) {
                    _aligned_free(pvVar4);
                  }
                  local_res20 = (ulonglong *)local_res20[1];
                }
                memset((void *)puVar18[uVar6 * 3 + 2],0,*param_3 << 4);
              }
              uVar13 = uVar13 + 1;
              puVar19 = local_80;
              puVar16 = puVar16 + 2;
            } while (uVar13 < *puVar8);
          }
          pauVar1 = (undefined (*) [12])(*local_88 + local_78);
          if ((local_70 < pauVar1) ||
             (uVar10 = FUN_18000dd90(_Memory_01,*param_1,local_88,local_78,
                                     *(undefined4 *)(param_1 + 2),(uint)param_2),
             (char)uVar10 == '\0')) {
LAB_18000646b:
            uVar13 = 0x80004005;
            goto LAB_180006474;
          }
          pauVar14 = _Memory_01;
          for (puVar16 = (ulonglong *)(_Memory[1] + 4); local_88 = pauVar1, puVar16 < puVar19;
              puVar16 = (ulonglong *)((longlong)puVar16 + puVar16[1])) {
            uVar13 = 0;
            if (*puVar8 != 0) {
              puVar17 = puVar8 + 3;
              do {
                fVar3 = *(float *)puVar17;
                uVar6 = puVar18[puVar17[-1] * 3 + 2];
                if (uVar6 == 0) goto LAB_180006464;
                uVar15 = 0;
                if (*puVar16 != 0) {
                  puVar12 = puVar16 + 3;
                  do {
                    fVar20 = fVar3 * *(float *)puVar12;
                    pfVar2 = (float *)(uVar6 + puVar12[-1] * 0x10);
                    *(undefined (*) [16])(uVar6 + puVar12[-1] * 0x10) =
                         CONCAT412(fVar20 * *(float *)(*pauVar14 + 0xc) + pfVar2[3],
                                   CONCAT48(fVar20 * *(float *)(*pauVar14 + 8) + pfVar2[2],
                                            CONCAT44(fVar20 * *(float *)(*pauVar14 + 4) + pfVar2[1],
                                                     fVar20 * *(float *)*pauVar14 + *pfVar2)));
                    uVar15 = uVar15 + 1;
                    puVar12 = puVar12 + 2;
                  } while (uVar15 < *puVar16);
                }
                uVar13 = uVar13 + 1;
                puVar17 = puVar17 + 2;
              } while (uVar13 < *puVar8);
            }
            pauVar14 = pauVar14[1];
          }
          uVar13 = 0;
          puVar16 = puVar8;
          if (*puVar8 != 0) {
            do {
              uVar6 = puVar16[2];
              puVar19 = puVar18 + uVar6 * 3;
              *puVar19 = *puVar19 - 1;
              if (*puVar19 == 0) {
                pauVar14 = (undefined (*) [16])puVar19[2];
                if (pauVar14 == (undefined (*) [16])0x0) goto LAB_180006464;
                if ((*(int *)(param_3 + 2) - 0x18U < 2) &&
                   (uVar15 = 0, pauVar11 = pauVar14, *param_3 != 0)) {
                  do {
                    *pauVar11 = CONCAT412(*(float *)(*pauVar11 + 0xc) + 0.1,
                                          CONCAT48(*(float *)(*pauVar11 + 8) + 0.0,
                                                   CONCAT44(*(float *)(*pauVar11 + 4) + 0.0,
                                                            *(float *)*pauVar11 + 0.0)));
                    uVar15 = uVar15 + 1;
                    pauVar11 = pauVar11[1];
                  } while (uVar15 < *param_3);
                }
                cVar5 = FUN_18000dc40((undefined8 *)
                                      (uVar6 * (longlong)(uint *)param_3[3] + local_68),
                                      (uint *)param_3[3],*(int *)(param_3 + 2),pauVar14,*param_3,
                                      param_2);
                if (cVar5 == '\0') goto LAB_18000646b;
                puVar19[1] = (ulonglong)local_res20;
                local_res20 = puVar19;
              }
              uVar13 = uVar13 + 1;
              puVar19 = local_80;
              puVar16 = puVar16 + 2;
            } while (uVar13 < *puVar8);
          }
          puVar8 = (ulonglong *)((longlong)puVar8 + puVar8[1]);
        } while (puVar8 < local_60);
      }
      uVar13 = 0;
    }
    goto LAB_180006474;
  }
  goto LAB_180006486;
LAB_180006464:
  uVar13 = 0x80004003;
LAB_180006474:
  if (_Memory_00 != (undefined (*) [12])0x0) {
    free(_Memory_00);
  }
LAB_180006486:
  if (_Memory != (undefined (*) [12])0x0) {
    free(_Memory);
  }
  _eh_vector_destructor_iterator_(puVar18,0x18,puVar18[-1],(_func_void_void_ptr *)&LAB_1800064f0);
  free(puVar18 + -1);
LAB_1800064ce:
  if (_Memory_01 != (undefined (*) [16])0x0) {
    _aligned_free(_Memory_01);
  }
  return uVar13;
}



ulonglong FUN_180006510(ulonglong *param_1,float param_2,ulonglong *param_3)

{
  uint uVar1;
  ulonglong uVar2;
  
  if ((param_1[5] == 0) || (param_3[5] == 0)) {
    return 0x80004003;
  }
  uVar1 = (uint)param_2 & 0xf00000;
  if (uVar1 == 0) {
    if ((*param_3 * 2 == *param_1) && (param_3[1] * 2 == param_1[1])) {
LAB_180006572:
      uVar2 = FUN_180005180((longlong *)param_1,param_2,param_3);
      return uVar2;
    }
  }
  else {
    if (uVar1 == 0x100000) {
      uVar2 = FUN_180004fb0((longlong *)param_1,param_3);
      return uVar2;
    }
    if (uVar1 != 0x200000) {
      if (uVar1 == 0x300000) {
        uVar2 = FUN_1800056b0((longlong *)param_1,param_2,param_3);
        return uVar2;
      }
      if (uVar1 != 0x400000) {
        if (uVar1 != 0x500000) {
          return 0x80070032;
        }
        uVar2 = FUN_180005fc0(param_1,param_2,param_3);
        return uVar2;
      }
      goto LAB_180006572;
    }
  }
  uVar2 = FUN_180005380(param_1,param_2,param_3);
  return uVar2;
}



void FUN_180006590(longlong param_1,ulonglong param_2,longlong param_3,ulonglong param_4,
                  ulonglong param_5,float param_6,ulonglong *param_7)

{
  char cVar1;
  int iVar2;
  undefined8 uVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  undefined4 *puVar6;
  longlong lVar7;
  ulonglong *puVar8;
  ulonglong uVar9;
  ulonglong *puVar10;
  undefined auStack_b8 [32];
  char local_98;
  longlong local_90;
  ulonglong local_88;
  ulonglong uStack_80;
  undefined4 local_78;
  undefined4 uStack_74;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  undefined8 local_68;
  undefined4 uStack_60;
  undefined4 uStack_5c;
  undefined8 local_58;
  undefined local_50 [12];
  undefined4 local_44;
  ulonglong local_40;
  
  local_40 = DAT_180065150 ^ (ulonglong)auStack_b8;
  local_90 = param_1;
  if ((((param_1 != 0) && (param_2 != 0)) && (param_4 != 0)) &&
     (((param_5 != 0 && (param_4 < 0x100000000)) && (param_5 < 0x100000000)))) {
    local_78 = *(undefined4 *)(param_3 + 0x10);
    uStack_74 = *(undefined4 *)(param_3 + 0x14);
    uStack_70 = *(undefined4 *)(param_3 + 0x18);
    uStack_6c = *(undefined4 *)(param_3 + 0x1c);
    uStack_60 = *(undefined4 *)(param_3 + 0x28);
    uStack_5c = *(undefined4 *)(param_3 + 0x2c);
    uStack_80 = param_5;
    local_58 = *(undefined8 *)(param_3 + 0x30);
    local_68 = 1;
    local_88 = param_4;
    uVar3 = FUN_180001b50(param_7,&local_88);
    if (-1 < (int)uVar3) {
      iVar2 = *(int *)(param_3 + 0x30);
      uVar3 = FUN_180004f30(iVar2,(uint)param_6);
      local_98 = (char)uVar3;
      local_50._0_4_ = 0;
      local_50._4_8_ = 0;
      local_44 = 0;
      if (local_98 == '\0') {
        cVar1 = '\0';
      }
      else {
        uVar4 = FUN_1800010f0(iVar2,(undefined4 *)local_50);
        cVar1 = (char)uVar4;
      }
      iVar2 = *(int *)(param_3 + 0x34);
      if (1 < iVar2) {
        if (iVar2 < 4) {
          uVar4 = *(ulonglong *)(param_3 + 0x18);
          uVar9 = 0;
          if (uVar4 != 0) {
            do {
              if ((*(longlong *)(param_3 + 0x20) == 0) ||
                 (iVar2 = *(int *)(param_3 + 0x34), iVar2 < 2)) {
LAB_1800068a9:
                uVar4 = 0xffffffffffffffff;
              }
              else if (iVar2 < 4) {
                if (uVar4 <= uVar9) goto LAB_1800068a9;
                uVar4 = *(longlong *)(param_3 + 0x20) * uVar9;
              }
              else {
                if ((iVar2 != 4) || (uVar9 != 0)) goto LAB_1800068a9;
                uVar4 = (ulonglong)(*(longlong *)(param_3 + 0x10) != 0) - 1;
              }
              if (param_2 <= uVar4) goto LAB_1800069a8;
              puVar8 = (ulonglong *)(uVar4 * 0x30 + local_90);
              if (param_7[6] == 0) {
LAB_1800068ea:
                puVar10 = (ulonglong *)0x0;
              }
              else {
                iVar2 = *(int *)((longlong)param_7 + 0x44);
                lVar7 = 0;
                if (iVar2 < 2) goto LAB_1800068ea;
                if (iVar2 < 4) {
                  if (param_7[5] <= uVar9) goto LAB_1800068ea;
                  lVar7 = param_7[6] * uVar9;
                }
                else if (((iVar2 != 4) || (uVar9 != 0)) || (param_7[4] == 0)) goto LAB_1800068ea;
                puVar10 = (ulonglong *)(lVar7 * 0x30 + param_7[9]);
              }
              if ((puVar8 == (ulonglong *)0x0) || (puVar10 == (ulonglong *)0x0)) goto LAB_180006996;
              if ((*(int *)(puVar8 + 2) != *(int *)(param_3 + 0x30)) ||
                 ((0xffffffff < *puVar8 || (0xffffffff < puVar8[1])))) goto LAB_1800069a8;
              if (local_98 == '\0') {
                uVar4 = FUN_180006510(puVar8,param_6,puVar10);
                iVar2 = (int)uVar4;
              }
              else if (cVar1 == '\0') {
                puVar6 = FUN_180004d70(puVar8,(uint)param_6,puVar10);
                iVar2 = (int)puVar6;
              }
              else {
                iVar2 = FUN_180004a30((undefined4 *)puVar8,(uint)param_6,(longlong *)local_50,
                                      puVar10);
              }
              if (iVar2 < 0) goto LAB_180006987;
              uVar4 = *(ulonglong *)(param_3 + 0x18);
              uVar9 = uVar9 + 1;
            } while (uVar9 < uVar4);
          }
          goto LAB_180006847;
        }
        if (iVar2 == 4) {
          uVar4 = *(ulonglong *)(param_3 + 0x10);
          uVar9 = 0;
          if (uVar4 != 0) {
            do {
              if ((*(longlong *)(param_3 + 0x20) == 0) ||
                 (iVar2 = *(int *)(param_3 + 0x34), iVar2 < 2)) {
LAB_180006738:
                uVar5 = 0xffffffffffffffff;
              }
              else if (iVar2 < 4) {
                if (uVar9 != 0) goto LAB_180006738;
                uVar5 = (ulonglong)(*(longlong *)(param_3 + 0x18) != 0) - 1;
              }
              else {
                if (iVar2 != 4) goto LAB_180006738;
                uVar5 = uVar9;
                if (uVar4 <= uVar9) {
                  uVar5 = 0xffffffffffffffff;
                }
              }
              if (param_2 <= uVar5) goto LAB_1800069a8;
              puVar8 = (ulonglong *)(uVar5 * 0x30 + local_90);
              if ((param_7[6] == 0) || (iVar2 = *(int *)((longlong)param_7 + 0x44), iVar2 < 2)) {
LAB_18000679c:
                puVar10 = (ulonglong *)0x0;
              }
              else if (iVar2 < 4) {
                if ((uVar9 != 0) || (param_7[5] == 0)) goto LAB_18000679c;
                puVar10 = (ulonglong *)param_7[9];
              }
              else {
                if ((iVar2 != 4) || (param_7[4] <= uVar9)) goto LAB_18000679c;
                puVar10 = (ulonglong *)(uVar9 * 0x30 + param_7[9]);
              }
              if ((puVar8 == (ulonglong *)0x0) || (puVar10 == (ulonglong *)0x0)) goto LAB_180006996;
              if (((*(int *)(puVar8 + 2) != *(int *)(param_3 + 0x30)) || (0xffffffff < *puVar8)) ||
                 (0xffffffff < puVar8[1])) goto LAB_1800069a8;
              if (local_98 == '\0') {
                uVar4 = FUN_180006510(puVar8,param_6,puVar10);
                iVar2 = (int)uVar4;
              }
              else if (cVar1 == '\0') {
                puVar6 = FUN_180004d70(puVar8,(uint)param_6,puVar10);
                iVar2 = (int)puVar6;
              }
              else {
                iVar2 = FUN_180004a30((undefined4 *)puVar8,(uint)param_6,(longlong *)local_50,
                                      puVar10);
              }
              if (iVar2 < 0) goto LAB_180006987;
              uVar4 = *(ulonglong *)(param_3 + 0x10);
              uVar9 = uVar9 + 1;
            } while (uVar9 < uVar4);
          }
          goto LAB_180006847;
        }
      }
LAB_1800069a8:
      FUN_1800020c0(param_7);
    }
  }
LAB_180006847:
  __security_check_cookie(local_40 ^ (ulonglong)auStack_b8);
  return;
LAB_180006996:
  FUN_1800020c0(param_7);
  goto LAB_180006847;
LAB_180006987:
  FUN_1800020c0(param_7);
  goto LAB_180006847;
}



void FUN_1800069d0(longlong **param_1)

{
  longlong *plVar1;
  
  plVar1 = *param_1;
  if (plVar1 != (longlong *)0x0) {
    *param_1 = (longlong *)0x0;
                    // WARNING: Could not recover jumptable at 0x0001800069e5. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x10))();
    return;
  }
  return;
}



ulonglong FUN_1800069f0(undefined4 param_1)

{
  switch(param_1) {
  case 0x1d:
  case 0x48:
  case 0x4b:
  case 0x4e:
  case 0x5b:
  case 0x5d:
  case 99:
    return 1;
  default:
    return 0;
  }
}



char FUN_180006a70(uint param_1)

{
  uint uVar1;
  
  uVar1 = param_1 & 0xf00000;
  if (uVar1 == 0x100000) {
    return '\0';
  }
  if (uVar1 != 0x200000) {
    return (uVar1 != 0x300000) + '\x02';
  }
  return '\x01';
}



undefined8 FUN_180006aa0(undefined4 param_1)

{
  switch(param_1) {
  case 0x46:
  case 0x47:
  case 0x49:
  case 0x4a:
  case 0x4c:
  case 0x4d:
  case 0x61:
  case 0x62:
    return 0x1c;
  case 0x48:
  case 0x4b:
  case 0x4e:
  case 99:
    return 0x1d;
  case 0x4f:
  case 0x50:
    return 0x3d;
  case 0x51:
    return 0x3f;
  case 0x52:
  case 0x53:
    return 0x31;
  case 0x54:
    return 0x33;
  default:
    return 0;
  case 0x5e:
  case 0x5f:
  case 0x60:
    return 2;
  }
}



void FUN_180006b40(longlong *param_1,longlong param_2)

{
  int iVar1;
  uint *puVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  longlong lVar6;
  undefined8 *puVar7;
  ulonglong uVar8;
  undefined8 *puVar9;
  longlong lVar10;
  code *pcVar11;
  longlong lVar12;
  longlong lVar13;
  undefined auStackY_1b8 [32];
  float in_stack_fffffffffffffe70;
  undefined4 local_188;
  ulonglong local_168;
  undefined local_148 [64];
  undefined local_108 [64];
  undefined local_c8 [64];
  undefined local_88 [64];
  ulonglong local_48;
  
  local_48 = DAT_180065150 ^ (ulonglong)auStackY_1b8;
  lVar10 = param_1[5];
  if ((lVar10 == 0) || (puVar7 = *(undefined8 **)(param_2 + 0x28), puVar7 == (undefined8 *)0x0))
  goto LAB_180006e8b;
  iVar1 = *(int *)(param_2 + 0x10);
  uVar3 = FUN_1800012c0(iVar1);
  if ((uVar3 == 0) || (uVar3 < 8)) goto LAB_180006e8b;
  local_188 = *(undefined4 *)(param_1 + 2);
  switch(local_188) {
  case 0x46:
    local_188 = 0x47;
    break;
  case 0x49:
    local_188 = 0x4a;
    break;
  case 0x4c:
    local_188 = 0x4d;
    break;
  case 0x4f:
    local_188 = 0x50;
    break;
  case 0x52:
    local_188 = 0x53;
    break;
  case 0x5e:
    local_188 = 0x5f;
    break;
  case 0x61:
    local_188 = 0x62;
  }
  switch(local_188) {
  case 0x47:
  case 0x48:
    pcVar11 = (code *)&LAB_18000ee00;
    lVar13 = 8;
    goto LAB_180006ccc;
  default:
    goto LAB_180006e8b;
  case 0x4a:
  case 0x4b:
    pcVar11 = FUN_18000ee10;
    break;
  case 0x4d:
  case 0x4e:
    pcVar11 = (code *)&DAT_18000eed0;
    break;
  case 0x50:
    pcVar11 = FUN_18000f4c0;
    lVar13 = 8;
    goto LAB_180006ccc;
  case 0x51:
    pcVar11 = FUN_18000f510;
    lVar13 = 8;
    goto LAB_180006ccc;
  case 0x53:
    pcVar11 = (code *)&LAB_18000f570;
    break;
  case 0x54:
    pcVar11 = FUN_18000f5f0;
    break;
  case 0x5f:
    pcVar11 = (code *)&DAT_180010f20;
    break;
  case 0x60:
    pcVar11 = (code *)&DAT_180010f30;
    break;
  case 0x62:
  case 99:
    pcVar11 = FUN_180010f40;
  }
  lVar13 = 0x10;
LAB_180006ccc:
  uVar5 = param_1[1];
  puVar2 = *(uint **)(param_2 + 0x18);
  local_168 = 0;
  if (uVar5 != 0) {
    do {
      uVar8 = 4;
      if (uVar5 - local_168 < 4) {
        uVar8 = uVar5 - local_168;
      }
      lVar12 = 0;
      if (param_1[3] != 0) {
        lVar6 = lVar10;
        puVar9 = puVar7;
        do {
          (*pcVar11)(local_148,lVar6);
          FUN_18000def0((undefined (*) [16])local_148,iVar1,local_188);
          uVar5 = 4;
          if ((ulonglong)(*param_1 - lVar12) < 4) {
            uVar5 = *param_1 - lVar12;
          }
          uVar4 = FUN_18000af80(puVar9,puVar2,iVar1,(undefined (*) [16])local_148,uVar5,
                                in_stack_fffffffffffffe70);
          if (((char)uVar4 == '\0') ||
             ((1 < uVar8 &&
              ((uVar4 = FUN_18000af80((undefined8 *)((longlong)puVar9 + (longlong)puVar2),puVar2,
                                      iVar1,(undefined (*) [16])local_108,uVar5,
                                      in_stack_fffffffffffffe70), (char)uVar4 == '\0' ||
               ((2 < uVar8 &&
                ((uVar4 = FUN_18000af80((undefined8 *)((longlong)puVar9 + (longlong)puVar2 * 2),
                                        puVar2,iVar1,(undefined (*) [16])local_c8,uVar5,
                                        in_stack_fffffffffffffe70), (char)uVar4 == '\0' ||
                 ((3 < uVar8 &&
                  (uVar5 = FUN_18000af80((undefined8 *)((longlong)puVar9 + (longlong)puVar2 * 3),
                                         puVar2,iVar1,(undefined (*) [16])local_88,uVar5,
                                         in_stack_fffffffffffffe70), (char)uVar5 == '\0'))))))))))))
          goto LAB_180006e8b;
          lVar6 = lVar6 + lVar13;
          lVar12 = lVar12 + 4;
          puVar9 = (undefined8 *)((longlong)puVar9 + (uVar3 + 7 >> 3) * 4);
        } while ((ulonglong)(lVar6 - lVar10) < (ulonglong)param_1[3]);
      }
      local_168 = local_168 + 4;
      lVar10 = lVar10 + param_1[3];
      uVar5 = param_1[1];
      puVar7 = (undefined8 *)((longlong)puVar7 + (longlong)puVar2 * 4);
    } while (local_168 < uVar5);
  }
LAB_180006e8b:
  __security_check_cookie(local_48 ^ (ulonglong)auStackY_1b8);
  return;
}



ulonglong FUN_180006f50(longlong param_1,ulonglong param_2,undefined4 *param_3,uint param_4,
                       ulonglong *param_5)

{
  int iVar1;
  uint uVar2;
  undefined8 uVar3;
  ulonglong uVar4;
  longlong *plVar5;
  longlong *plVar6;
  longlong lVar7;
  ulonglong uVar8;
  undefined4 local_58;
  undefined4 uStack_54;
  undefined4 uStack_50;
  undefined4 uStack_4c;
  undefined4 local_48;
  undefined4 uStack_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  undefined4 local_38;
  undefined4 uStack_34;
  undefined4 uStack_30;
  undefined4 uStack_2c;
  ulonglong local_28;
  
  if (((((param_1 == 0) || (param_2 == 0)) || (iVar1 = param_3[0xc], iVar1 < 0x46)) ||
      ((0x54 < iVar1 && (5 < iVar1 - 0x5eU)))) ||
     ((0x45 < (int)param_4 && (((int)param_4 < 0x55 || (param_4 - 0x5e < 6)))))) {
    return 0x80070057;
  }
  if (param_4 == 0) {
    uVar3 = FUN_180006aa0(*(undefined4 *)(param_1 + 0x10));
    param_4 = (uint)uVar3;
    if (param_4 == 0) {
      return 0x80004005;
    }
  }
  else if (0x77 < param_4 - 1) {
    return 0x80070057;
  }
  FUN_1800020c0(param_5);
  local_58 = *param_3;
  uStack_54 = param_3[1];
  uStack_50 = param_3[2];
  uStack_4c = param_3[3];
  local_48 = param_3[4];
  uStack_44 = param_3[5];
  uStack_40 = param_3[6];
  uStack_3c = param_3[7];
  local_38 = param_3[8];
  uStack_34 = param_3[9];
  uStack_30 = param_3[10];
  uStack_2c = param_3[0xb];
  local_28 = *(ulonglong *)(param_3 + 0xc) & 0xffffffff00000000 | (ulonglong)param_4;
  uVar4 = FUN_180001b50(param_5,(ulonglong *)&local_58);
  if (-1 < (int)uVar4) {
    if (param_2 == *param_5) {
      uVar4 = param_5[9];
      if (uVar4 == 0) {
        FUN_1800020c0(param_5);
        uVar4 = 0x80004003;
      }
      else {
        uVar8 = 0;
        if (param_2 != 0) {
          plVar6 = (longlong *)(uVar4 + 8);
          lVar7 = param_1 - uVar4;
          do {
            iVar1 = *(int *)((longlong)plVar6 + lVar7 + 8);
            if ((iVar1 < 0x46) || ((0x54 < iVar1 && (5 < iVar1 - 0x5eU)))) {
LAB_1800070ff:
              FUN_1800020c0(param_5);
              return 0x80004005;
            }
            plVar5 = (longlong *)(lVar7 + -8 + (longlong)plVar6);
            if ((*plVar5 != plVar6[-1]) || (*(longlong *)((longlong)plVar6 + lVar7) != *plVar6))
            goto LAB_1800070ff;
            uVar2 = FUN_180006b40(plVar5,(longlong)(plVar6 + -1));
            if ((int)uVar2 < 0) {
              FUN_1800020c0(param_5);
              return (ulonglong)uVar2;
            }
            uVar8 = uVar8 + 1;
            plVar6 = plVar6 + 6;
          } while (uVar8 < param_2);
        }
        uVar4 = 0;
      }
    }
    else {
      FUN_1800020c0(param_5);
      uVar4 = 0x80004005;
    }
  }
  return uVar4;
}



ulonglong FUN_180007130(ulonglong param_1,ulonglong param_2,ulonglong *param_3)

{
  ulonglong uVar1;
  ulonglong uVar2;
  
  uVar1 = *param_3;
  uVar2 = 1;
  if (1 < uVar1) {
    do {
      if (param_2 < 2) {
        if (param_1 < 2) goto code_r0x00018000714c;
LAB_18000715d:
        param_1 = param_1 >> 1;
      }
      else {
        param_2 = param_2 >> 1;
        if (1 < param_1) goto LAB_18000715d;
      }
      uVar2 = uVar2 + 1;
    } while( true );
  }
  if (uVar1 == 0) {
    do {
      if (param_2 < 2) {
        if (param_1 < 2) break;
LAB_18000718b:
        param_1 = param_1 >> 1;
      }
      else {
        param_2 = param_2 >> 1;
        if (1 < param_1) goto LAB_18000718b;
      }
      uVar2 = uVar2 + 1;
    } while( true );
  }
  *param_3 = uVar2;
LAB_18000717f:
  return CONCAT71((int7)(uVar2 >> 8),1);
code_r0x00018000714c:
  if (uVar2 < uVar1) {
    return uVar2 & 0xffffffffffffff00;
  }
  goto LAB_18000717f;
}



ulonglong FUN_1800071a0(ulonglong param_1,ulonglong param_2,ulonglong param_3,ulonglong *param_4)

{
  ulonglong uVar1;
  ulonglong uVar2;
  
  uVar1 = *param_4;
  uVar2 = 1;
  if (uVar1 < 2) {
    if (uVar1 == 0) {
      do {
        if (param_2 < 2) {
          if (param_1 < 2) {
            if (1 < param_3) goto LAB_18000720b;
            break;
          }
LAB_180007211:
          param_1 = param_1 >> 1;
        }
        else {
          param_2 = param_2 >> 1;
LAB_18000720b:
          if (1 < param_1) goto LAB_180007211;
        }
        if (1 < param_3) {
          param_3 = param_3 >> 1;
        }
        uVar2 = uVar2 + 1;
      } while( true );
    }
    *param_4 = uVar2;
LAB_180007205:
    return CONCAT71((int7)(uVar2 >> 8),1);
  }
LAB_1800071b0:
  if (param_2 < 2) {
    if (param_1 < 2) {
      if (1 < param_3) goto LAB_1800071cd;
      if (uVar2 < uVar1) {
        return uVar2 & 0xffffffffffffff00;
      }
      goto LAB_180007205;
    }
LAB_1800071d3:
    param_1 = param_1 >> 1;
  }
  else {
    param_2 = param_2 >> 1;
LAB_1800071cd:
    if (1 < param_1) goto LAB_1800071d3;
  }
  if (1 < param_3) {
    param_3 = param_3 >> 1;
  }
  uVar2 = uVar2 + 1;
  goto LAB_1800071b0;
}



void FUN_180007230(longlong *param_1,longlong *param_2,uint param_3,longlong *param_4,
                  longlong **param_5)

{
  longlong *plVar1;
  int iVar2;
  undefined8 uVar3;
  undefined auStack_a8 [32];
  undefined8 local_88;
  undefined8 local_80;
  undefined4 local_78;
  longlong *local_68;
  undefined8 local_60;
  longlong local_58;
  longlong local_50;
  ulonglong local_48;
  
  local_60 = 0xfffffffffffffffe;
  local_48 = DAT_180065150 ^ (ulonglong)auStack_a8;
  if ((param_2 != (longlong *)0x0) && (param_5 != (longlong **)0x0)) {
    *param_5 = (longlong *)0x0;
    iVar2 = (**(code **)(*param_2 + 0x20))(param_2,&local_58);
    if (-1 < iVar2) {
      if ((local_58 == *param_4) && (local_50 == param_4[1])) {
        (**(code **)(*param_2 + 8))(param_2);
        *param_5 = param_2;
      }
      else {
        local_68 = (longlong *)0x0;
        iVar2 = (**(code **)(*param_1 + 0x50))(param_1,&local_68);
        if (-1 < iVar2) {
          if ((param_3 & 0xf0000) == 0x10000) {
            uVar3 = 1;
          }
          else {
            uVar3 = 8;
            if ((param_3 & 0xf0000) != 0x20000) {
              uVar3 = 0;
            }
          }
          local_78 = 0;
          local_80 = 0;
          local_88 = 0;
          iVar2 = (**(code **)(*local_68 + 0x40))(local_68,param_2,param_4,uVar3);
          if (-1 < iVar2) {
            (**(code **)(*param_1 + 0x90))(param_1,local_68,1,param_5);
          }
        }
        plVar1 = local_68;
        if (local_68 != (longlong *)0x0) {
          local_68 = (longlong *)0x0;
          (**(code **)(*plVar1 + 0x10))();
        }
      }
    }
  }
  __security_check_cookie(local_48 ^ (ulonglong)auStack_a8);
  return;
}



// WARNING: Type propagation algorithm not settling
// WARNING: Could not reconcile some variable overlaps

void FUN_180007380(longlong *param_1,longlong *param_2,ulonglong param_3,longlong *param_4,
                  uint param_5,longlong param_6)

{
  ulonglong uVar1;
  ulonglong uVar2;
  longlong *plVar3;
  int iVar4;
  longlong *plVar5;
  longlong lVar6;
  ulonglong uVar7;
  longlong lVar8;
  longlong lVar9;
  ulonglong uVar10;
  longlong *plVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  undefined auStackY_138 [32];
  longlong *local_108;
  longlong *local_100;
  longlong *local_f8;
  longlong *local_f0;
  longlong *local_e8;
  uint local_e0;
  uint local_dc;
  uint local_d8;
  uint local_d4;
  longlong *local_d0;
  longlong *local_c8;
  longlong *local_c0;
  ulonglong local_b8;
  longlong local_b0;
  longlong local_a8;
  longlong *local_a0;
  ulonglong local_98;
  longlong local_90;
  undefined8 local_88;
  undefined local_80 [16];
  undefined local_70 [16];
  undefined8 local_60;
  undefined4 uStack_58;
  undefined4 uStack_54;
  ulonglong local_50;
  
  local_88 = 0xfffffffffffffffe;
  local_50 = DAT_180065150 ^ (ulonglong)auStackY_138;
  local_90 = param_6;
  local_f8 = param_4;
  local_a0 = param_1;
  local_98 = param_3;
  if (((param_1 == (longlong *)0x0) || (param_2 == (longlong *)0x0)) || (param_6 == 0))
  goto LAB_1800079bf;
  local_60._0_4_ = 0x6fddc324;
  local_60._4_4_ = 0x4bfe4e03;
  uStack_58 = 0x773d85b1;
  uStack_54 = 0xc98d76;
  iVar4 = (**(code **)(*param_2 + 0x20))(param_2,&local_60);
  lVar9 = 0;
  local_b8 = 0;
  uVar10 = 0;
  local_80._0_12_ = CONCAT48(0x773d85b1,0x4bfe4e036fddc324);
  local_80 = CONCAT412(0xc98d76,local_80._0_12_);
  local_70 = CONCAT412(0xc98d76,CONCAT48(0x773d85b1,0x4bfe4e036fddc324));
  if (-1 < iVar4) {
    local_c8 = (longlong *)0x0;
    iVar4 = (**(code **)(*param_1 + 0x30))(param_1,&local_60,&local_c8);
    local_f0 = (longlong *)0x0;
    if (-1 < iVar4) {
      iVar4 = (**(code **)*local_c8)(local_c8,&DAT_18005d580,&local_f0);
    }
    local_e0 = 0;
    if ((-1 < iVar4) && (iVar4 = (**(code **)(*local_f0 + 0x68))(local_f0,&local_e0), -1 < iVar4)) {
      if (local_e0 < 0x21) {
        lVar9 = 3;
        local_b8 = 3;
        local_80._0_12_ = CONCAT48(0x773d85b1,0x4bfe4e036fddc324);
        local_80 = CONCAT412(0xcc98d76,local_80._0_12_);
        uVar10 = 4;
        uVar12 = 0xfc98d76;
      }
      else {
        uVar10 = 0x10;
        lVar9 = 0xc;
        local_b8 = 0xc;
        if (DAT_18006649c == '\0') {
          lVar9 = 0x10;
          uVar12 = 0x6fddc324;
          uVar13 = 0x4bfe4e03;
          uVar14 = 0x773d85b1;
          uVar15 = 0x1bc98d76;
        }
        else {
          uVar12 = 0xe3fed78f;
          uVar13 = 0x4acfe8db;
          uVar14 = 0x7fe9c184;
          uVar15 = 0x27b33661;
        }
        local_80 = CONCAT412(uVar15,CONCAT48(uVar14,CONCAT44(uVar13,uVar12)));
        uVar12 = 0x19c98d76;
      }
      local_70 = CONCAT412(uVar12,CONCAT48(0x773d85b1,0x4bfe4e036fddc324));
    }
    plVar11 = local_f0;
    if (local_f0 != (longlong *)0x0) {
      local_f0 = (longlong *)0x0;
      (**(code **)(*plVar11 + 0x10))();
    }
    plVar11 = local_c8;
    if (local_c8 != (longlong *)0x0) {
      local_c8 = (longlong *)0x0;
      (**(code **)(*plVar11 + 0x10))();
    }
  }
  local_c0 = (longlong *)0x0;
  if (-1 < iVar4) {
    local_100 = (longlong *)0x0;
    iVar4 = (**(code **)(*param_1 + 0x58))(param_1,&local_100);
    if (-1 < iVar4) {
      local_108 = (longlong *)0x0;
      iVar4 = FUN_180007230(param_1,param_2,param_5,(longlong *)local_80,&local_108);
      if (-1 < iVar4) {
        iVar4 = (**(code **)(*local_100 + 0x40))
                          (local_100,local_108,param_3 & 0xffffffff,(ulonglong)local_f8 & 0xffffffff
                          );
      }
      plVar11 = local_108;
      if (local_108 != (longlong *)0x0) {
        local_108 = (longlong *)0x0;
        (**(code **)(*plVar11 + 0x10))();
      }
      if (-1 < iVar4) {
        local_108 = (longlong *)0x0;
        iVar4 = (**(code **)(*param_1 + 0x90))(param_1,local_100,1,&local_108);
        if (-1 < iVar4) {
          iVar4 = FUN_180007230(param_1,local_108,param_5,(longlong *)local_80,&local_c0);
        }
        plVar11 = local_108;
        if (local_108 != (longlong *)0x0) {
          local_108 = (longlong *)0x0;
          (**(code **)(*plVar11 + 0x10))();
        }
      }
    }
    plVar11 = local_100;
    if (local_100 != (longlong *)0x0) {
      local_100 = (longlong *)0x0;
      (**(code **)(*plVar11 + 0x10))();
    }
  }
  local_e8 = (longlong *)0x0;
  if (-1 < iVar4) {
    local_100 = (longlong *)0x0;
    iVar4 = (**(code **)(*param_1 + 0x58))(param_1,&local_100);
    if (-1 < iVar4) {
      local_108 = (longlong *)0x0;
      iVar4 = FUN_180007230(param_1,param_2,param_5,(longlong *)local_70,&local_108);
      if (-1 < iVar4) {
        iVar4 = (**(code **)(*local_100 + 0x40))
                          (local_100,local_108,param_3 & 0xffffffff,(ulonglong)local_f8 & 0xffffffff
                          );
      }
      plVar11 = local_108;
      if (local_108 != (longlong *)0x0) {
        local_108 = (longlong *)0x0;
        (**(code **)(*plVar11 + 0x10))();
      }
      if (-1 < iVar4) {
        local_108 = (longlong *)0x0;
        iVar4 = (**(code **)(*param_1 + 0x90))(param_1,local_100,1,&local_108);
        if (-1 < iVar4) {
          iVar4 = FUN_180007230(param_1,local_108,param_5,(longlong *)local_70,&local_e8);
        }
        plVar11 = local_108;
        if (local_108 != (longlong *)0x0) {
          local_108 = (longlong *)0x0;
          (**(code **)(*plVar11 + 0x10))();
        }
      }
    }
    plVar5 = local_100;
    plVar11 = (longlong *)0x0;
    if (local_100 != (longlong *)0x0) {
      local_100 = (longlong *)0x0;
      (**(code **)(*plVar5 + 0x10))();
    }
    if (-1 < iVar4) {
      local_108 = (longlong *)0x0;
      local_d0 = (longlong *)0x0;
      iVar4 = (**(code **)(*local_c0 + 0x40))(local_c0,0,1,&local_108);
      if ((-1 < iVar4) &&
         (iVar4 = (**(code **)(*local_e8 + 0x40))(local_e8,0,2,&local_d0), -1 < iVar4)) {
        local_a8 = 0;
        local_d4 = 0;
        local_dc = 0;
        iVar4 = (**(code **)(*local_d0 + 0x28))(local_d0,&local_d4,&local_a8);
        if (-1 < iVar4) {
          if (local_a8 == 0) {
            iVar4 = -0x7fffbffd;
          }
          else {
            iVar4 = (**(code **)(*local_d0 + 0x20))(local_d0,&local_dc);
          }
        }
        local_b0 = 0;
        local_100 = (longlong *)((ulonglong)local_100 & 0xffffffff00000000);
        local_d8 = 0;
        plVar5 = local_f8;
        plVar3 = local_a0;
        if ((-1 < iVar4) &&
           (iVar4 = (**(code **)(*local_108 + 0x28))(local_108,&local_100,&local_b0),
           plVar5 = local_f8, plVar3 = local_a0, -1 < iVar4)) {
          if (local_b0 == 0) {
            iVar4 = -0x7fffbffd;
            goto LAB_1800078f2;
          }
          iVar4 = (**(code **)(*local_108 + 0x20))(local_108,&local_d8);
          plVar5 = local_f8;
          plVar3 = local_a0;
        }
        for (; (param_1 = plVar3, local_a0 = param_1, -1 < iVar4 &&
               (uVar7 = 0, uVar1 = uVar7, uVar2 = uVar7, plVar11 < plVar5));
            plVar11 = (longlong *)((longlong)plVar11 + 1)) {
          for (; (-1 < iVar4 && (plVar5 = local_f8, uVar7 < local_98)); uVar7 = uVar7 + 1) {
            lVar8 = (ulonglong)local_dc * (longlong)plVar11 + uVar1;
            lVar6 = (ulonglong)local_d8 * (longlong)plVar11 + uVar2;
            if (((ulonglong)local_d4 < lVar8 + local_b8) ||
               (((ulonglong)local_100 & 0xffffffff) < (ulonglong)(lVar6 + lVar9))) {
              iVar4 = -0x7ff8ffa9;
            }
            else {
              FUN_180003f40((void *)(local_a8 + lVar8),uVar10,(void *)(local_b0 + lVar6),local_b8);
            }
            plVar5 = local_f8;
            uVar1 = uVar1 + uVar10;
            uVar2 = uVar2 + lVar9;
          }
          plVar3 = local_a0;
        }
      }
LAB_1800078f2:
      plVar11 = local_d0;
      if (local_d0 != (longlong *)0x0) {
        local_d0 = (longlong *)0x0;
        (**(code **)(*plVar11 + 0x10))();
      }
      plVar11 = local_108;
      if (local_108 != (longlong *)0x0) {
        local_108 = (longlong *)0x0;
        (**(code **)(*plVar11 + 0x10))();
      }
      if (-1 < iVar4) {
        local_f8 = (longlong *)0x0;
        iVar4 = FUN_180007230(param_1,local_e8,param_5,&local_60,&local_f8);
        if (-1 < iVar4) {
          (**(code **)(*local_f8 + 0x38))
                    (local_f8,0,*(undefined4 *)(local_90 + 0x18),*(undefined4 *)(local_90 + 0x20));
        }
        plVar11 = local_f8;
        if (local_f8 != (longlong *)0x0) {
          local_f8 = (longlong *)0x0;
          (**(code **)(*plVar11 + 0x10))();
        }
      }
    }
  }
  plVar11 = local_e8;
  if (local_e8 != (longlong *)0x0) {
    local_e8 = (longlong *)0x0;
    (**(code **)(*plVar11 + 0x10))();
  }
  plVar11 = local_c0;
  if (local_c0 != (longlong *)0x0) {
    local_c0 = (longlong *)0x0;
    (**(code **)(*plVar11 + 0x10))();
  }
LAB_1800079bf:
  __security_check_cookie(local_50 ^ (ulonglong)auStackY_138);
  return;
}



uint FUN_1800079e0(uint param_1)

{
  uint uVar1;
  
  if ((int)param_1 < 0) {
    return 0;
  }
  if (0x41ff73ff < param_1) {
    return 0x3ff;
  }
  if (param_1 < 0x3e800000) {
    uVar1 = (param_1 & 0x7fffff | 0x800000) >> (0x7dU - (char)(param_1 >> 0x17) & 0x1f);
  }
  else {
    uVar1 = param_1 + 0xc2000000;
  }
  return (uVar1 >> 0x10 & 1) + 0x7fff + uVar1 >> 0x10 & 0x3ff;
}



uint FUN_180007a40(uint param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  
  uVar3 = param_1 & 0x7f;
  if ((param_1 & 0x380) != 0) {
    return ((param_1 >> 7 & 7) + 0x7c) * 0x800000 | uVar3 << 0x10;
  }
  if (uVar3 != 0) {
    iVar1 = 1;
    do {
      iVar2 = iVar1;
      uVar3 = uVar3 * 2;
      iVar1 = iVar2 + -1;
    } while (-1 < (char)uVar3);
    return (iVar2 + 0x7b) * 0x800000 | (uVar3 & 0x7f) << 0x10;
  }
  return 0;
}



uint FUN_180007ab0(uint param_1)

{
  uint uVar1;
  
  if ((int)param_1 < 0) {
    return 0;
  }
  if (0x43feffff < param_1) {
    return 0x3ff;
  }
  if (param_1 < 0x3c800000) {
    uVar1 = (param_1 & 0x7fffff | 0x800000) >> (0x79U - (char)(param_1 >> 0x17) & 0x1f);
  }
  else {
    uVar1 = param_1 + 0xc4000000;
  }
  return (uVar1 >> 0x11 & 1) + 0xffff + uVar1 >> 0x11 & 0x3ff;
}



uint FUN_180007b10(uint param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  
  uVar3 = param_1 & 0x3f;
  if ((param_1 & 0x3c0) != 0) {
    return ((param_1 >> 6 & 0xf) + 0x78) * 0x800000 | uVar3 << 0x11;
  }
  if (uVar3 != 0) {
    iVar1 = 1;
    do {
      iVar2 = iVar1;
      uVar3 = uVar3 * 2;
      iVar1 = iVar2 + -1;
    } while ((uVar3 & 0x40) == 0);
    return (iVar2 + 0x77) * 0x800000 | (uVar3 & 0x3f) << 0x11;
  }
  return 0;
}



void FUN_180007b80(uint *param_1,ulonglong param_2,uint *param_3,ulonglong param_4,int param_5,
                  byte param_6)

{
  uint uVar1;
  longlong lVar2;
  undefined2 uVar3;
  ulonglong uVar4;
  
  if ((param_6 & 1) == 0) {
switchD_180007bcc_caseD_5:
    if (param_1 != param_3) {
      uVar4 = param_2;
      if (param_4 < param_2) {
        uVar4 = param_4;
      }
      FUN_180003f40(param_1,param_2,param_3,uVar4);
      return;
    }
  }
  else {
    switch(param_5) {
    case 1:
    case 2:
    case 3:
    case 4:
      if ((0xf < param_4) && (0xf < param_2)) {
        if (param_5 == 2) {
          uVar1 = 0x3f800000;
        }
        else {
          uVar1 = 0xffffffff;
          if (param_5 == 4) {
            uVar1 = 0x7fffffff;
          }
        }
        if (param_1 == param_3) {
          if (param_2 != 0xf) {
            lVar2 = (param_2 - 0x10 >> 4) + 1;
            do {
              param_1[3] = uVar1;
              param_1 = param_1 + 4;
              lVar2 = lVar2 + -1;
            } while (lVar2 != 0);
            return;
          }
        }
        else {
          if (param_4 < param_2) {
            param_2 = param_4;
          }
          if (param_2 != 0xf) {
            lVar2 = (param_2 - 0x10 >> 4) + 1;
            do {
              *param_1 = *param_3;
              param_1[1] = param_3[1];
              param_1[2] = param_3[2];
              param_1[3] = uVar1;
              lVar2 = lVar2 + -1;
              param_1 = param_1 + 4;
              param_3 = param_3 + 4;
            } while (lVar2 != 0);
            return;
          }
        }
      }
      break;
    default:
      goto switchD_180007bcc_caseD_5;
    case 9:
    case 10:
    case 0xb:
    case 0xc:
    case 0xd:
    case 0xe:
    case 0x66:
      if ((7 < param_4) && (7 < param_2)) {
        if (param_5 == 10) {
          uVar3 = 0x3c00;
        }
        else {
          uVar3 = 0x7fff;
          if (1 < param_5 - 0xdU) {
            uVar3 = 0xffff;
          }
        }
        if (param_1 == param_3) {
          if (param_2 != 7) {
            lVar2 = (param_2 - 8 >> 3) + 1;
            do {
              *(undefined2 *)((longlong)param_1 + 6) = uVar3;
              param_1 = param_1 + 2;
              lVar2 = lVar2 + -1;
            } while (lVar2 != 0);
            return;
          }
        }
        else {
          if (param_4 < param_2) {
            param_2 = param_4;
          }
          if (param_2 != 7) {
            lVar2 = (param_2 - 8 >> 3) + 1;
            do {
              *(undefined2 *)param_1 = *(undefined2 *)param_3;
              *(undefined2 *)((longlong)param_1 + 2) = *(undefined2 *)((longlong)param_3 + 2);
              *(undefined2 *)(param_1 + 1) = *(undefined2 *)(param_3 + 1);
              *(undefined2 *)((longlong)param_1 + 6) = uVar3;
              lVar2 = lVar2 + -1;
              param_1 = param_1 + 2;
              param_3 = param_3 + 2;
            } while (lVar2 != 0);
            return;
          }
        }
      }
      break;
    case 0x17:
    case 0x18:
    case 0x19:
    case 0x59:
    case 0x65:
    case 0x74:
    case 0x75:
      if ((3 < param_4) && (3 < param_2)) {
        if (param_1 == param_3) {
          if (param_2 != 3) {
            lVar2 = (param_2 - 4 >> 2) + 1;
            do {
              *param_1 = *param_1 | 0xc0000000;
              param_1 = param_1 + 1;
              lVar2 = lVar2 + -1;
            } while (lVar2 != 0);
            return;
          }
        }
        else {
          if (param_4 < param_2) {
            param_2 = param_4;
          }
          if (param_2 != 3) {
            uVar4 = 0;
            do {
              *(uint *)(uVar4 + (longlong)param_1) =
                   *(uint *)(uVar4 + (longlong)param_3) | 0xc0000000;
              uVar4 = uVar4 + 4;
            } while (uVar4 < param_2 - 3);
            return;
          }
        }
      }
      break;
    case 0x1b:
    case 0x1c:
    case 0x1d:
    case 0x1e:
    case 0x1f:
    case 0x20:
    case 0x57:
    case 0x5a:
    case 0x5b:
    case 100:
      if ((3 < param_4) && (3 < param_2)) {
        uVar1 = 0x7f000000;
        if (1 < param_5 - 0x1fU) {
          uVar1 = 0xff000000;
        }
        if (param_1 == param_3) {
          if (param_2 != 3) {
            lVar2 = (param_2 - 4 >> 2) + 1;
            do {
              *param_1 = *param_1 & 0xffffff;
              *param_1 = *param_1 | uVar1;
              param_1 = param_1 + 1;
              lVar2 = lVar2 + -1;
            } while (lVar2 != 0);
            return;
          }
        }
        else {
          if (param_4 < param_2) {
            param_2 = param_4;
          }
          if (param_2 != 3) {
            uVar4 = 0;
            do {
              *(uint *)(uVar4 + (longlong)param_1) =
                   *(uint *)(uVar4 + (longlong)param_3) & 0xffffff | uVar1;
              uVar4 = uVar4 + 4;
            } while (uVar4 < param_2 - 3);
            return;
          }
        }
      }
      break;
    case 0x41:
      memset(param_1,0xff,param_2);
      return;
    case 0x56:
      if ((1 < param_4) && (1 < param_2)) {
        if (param_1 == param_3) {
          if (param_2 != 1) {
            lVar2 = (param_2 - 2 >> 1) + 1;
            do {
              *(ushort *)param_1 = *(ushort *)param_1 | 0x8000;
              param_1 = (uint *)((longlong)param_1 + 2);
              lVar2 = lVar2 + -1;
            } while (lVar2 != 0);
            return;
          }
        }
        else {
          if (param_4 < param_2) {
            param_2 = param_4;
          }
          if (param_2 != 1) {
            uVar4 = 0;
            do {
              *(ushort *)(uVar4 + (longlong)param_1) =
                   *(ushort *)(uVar4 + (longlong)param_3) | 0x8000;
              uVar4 = uVar4 + 2;
            } while (uVar4 < param_2 - 1);
            return;
          }
        }
      }
      break;
    case 0x73:
      if ((1 < param_4) && (1 < param_2)) {
        if (param_1 == param_3) {
          if (param_2 != 1) {
            lVar2 = (param_2 - 2 >> 1) + 1;
            do {
              *(ushort *)param_1 = *(ushort *)param_1 | 0xf000;
              param_1 = (uint *)((longlong)param_1 + 2);
              lVar2 = lVar2 + -1;
            } while (lVar2 != 0);
            return;
          }
        }
        else {
          if (param_4 < param_2) {
            param_2 = param_4;
          }
          if (param_2 != 1) {
            uVar4 = 0;
            do {
              *(ushort *)(uVar4 + (longlong)param_1) =
                   *(ushort *)(uVar4 + (longlong)param_3) | 0xf000;
              uVar4 = uVar4 + 2;
            } while (uVar4 < param_2 - 1);
            return;
          }
        }
      }
    }
  }
  return;
}



void FUN_180008010(uint *param_1,ulonglong param_2,uint *param_3,ulonglong param_4,
                  undefined4 param_5,uint param_6)

{
  uint uVar1;
  uint uVar2;
  longlong lVar3;
  ulonglong uVar4;
  
  switch(param_5) {
  case 0x17:
  case 0x18:
  case 0x19:
  case 0x59:
    if (((3 < param_4) && (3 < param_2)) && ((param_6 & 2) != 0)) {
      if (param_1 == param_3) {
        if (param_2 == 3) {
          return;
        }
        lVar3 = (param_2 - 4 >> 2) + 1;
        do {
          uVar1 = *param_1;
          uVar2 = 0xc0000000;
          if ((param_6 & 1) == 0) {
            uVar2 = uVar1 & 0xc0000000;
          }
          *param_1 = uVar2 | uVar1 & 0xffc00 | (uVar1 & 0x3ff) << 0x14 | uVar1 >> 0x14 & 0x3ff;
          lVar3 = lVar3 + -1;
          param_1 = param_1 + 1;
        } while (lVar3 != 0);
        return;
      }
      if (param_4 < param_2) {
        param_2 = param_4;
      }
      if (param_2 == 3) {
        return;
      }
      uVar4 = 0;
      do {
        uVar1 = *(uint *)(uVar4 + (longlong)param_3);
        uVar2 = 0xc0000000;
        if ((param_6 & 1) == 0) {
          uVar2 = uVar1 & 0xc0000000;
        }
        *(uint *)(uVar4 + (longlong)param_1) =
             uVar2 | uVar1 & 0xffc00 | (uVar1 & 0x3ff) << 0x14 | uVar1 >> 0x14 & 0x3ff;
        uVar4 = uVar4 + 4;
      } while (uVar4 < param_2 - 3);
      return;
    }
    break;
  case 0x1b:
  case 0x1c:
  case 0x1d:
  case 0x57:
  case 0x58:
  case 0x5a:
  case 0x5b:
  case 0x5c:
  case 0x5d:
    if ((3 < param_4) && (3 < param_2)) {
      if (param_1 == param_3) {
        if (param_2 == 3) {
          return;
        }
        lVar3 = (param_2 - 4 >> 2) + 1;
        do {
          uVar1 = *param_1;
          uVar2 = 0xff000000;
          if ((param_6 & 1) == 0) {
            uVar2 = uVar1 & 0xff000000;
          }
          *param_1 = uVar2 | uVar1 & 0xff00 | (uVar1 & 0xff) << 0x10 | uVar1 >> 0x10 & 0xff;
          lVar3 = lVar3 + -1;
          param_1 = param_1 + 1;
        } while (lVar3 != 0);
        return;
      }
      if (param_4 < param_2) {
        param_2 = param_4;
      }
      if (param_2 == 3) {
        return;
      }
      uVar4 = 0;
      do {
        uVar1 = *(uint *)(uVar4 + (longlong)param_3);
        uVar2 = 0xff000000;
        if ((param_6 & 1) == 0) {
          uVar2 = uVar1 & 0xff000000;
        }
        *(uint *)(uVar4 + (longlong)param_1) =
             uVar2 | uVar1 & 0xff00 | (uVar1 & 0xff) << 0x10 | uVar1 >> 0x10 & 0xff;
        uVar4 = uVar4 + 4;
      } while (uVar4 < param_2 - 3);
      return;
    }
    break;
  case 0x6b:
    if (((3 < param_4) && (3 < param_2)) && ((param_6 & 2) != 0)) {
      if (param_1 == param_3) {
        if (param_2 == 3) {
          return;
        }
        lVar3 = (param_2 - 4 >> 2) + 1;
        do {
          uVar1 = *param_1;
          *param_1 = (uVar1 >> 8 ^ uVar1 << 8) & 0xff00ff ^ uVar1 << 8;
          lVar3 = lVar3 + -1;
          param_1 = param_1 + 1;
        } while (lVar3 != 0);
        return;
      }
      if (param_4 < param_2) {
        param_2 = param_4;
      }
      if (param_2 == 3) {
        return;
      }
      uVar4 = 0;
      do {
        uVar1 = *(uint *)(uVar4 + (longlong)param_3);
        *(uint *)(uVar4 + (longlong)param_1) = (uVar1 >> 8 ^ uVar1 << 8) & 0xff00ff ^ uVar1 << 8;
        uVar4 = uVar4 + 4;
      } while (uVar4 < param_2 - 3);
      return;
    }
  }
  if (param_1 != param_3) {
    uVar4 = param_2;
    if (param_4 < param_2) {
      uVar4 = param_4;
    }
    FUN_180003f40(param_1,param_2,param_3,uVar4);
  }
  return;
}



undefined8
FUN_1800083a0(uint *param_1,ulonglong param_2,undefined8 param_3,ushort *param_4,ulonglong param_5,
             int param_6,uint param_7)

{
  ulonglong uVar1;
  ushort uVar2;
  uint uVar3;
  uint uVar4;
  ulonglong in_RAX;
  ulonglong uVar5;
  ushort *puVar6;
  uint *puVar7;
  
  if (param_6 == 0x55) {
    if ((param_5 < 2) || (param_2 < 4)) {
      return param_5 & 0xffffffffffffff00;
    }
    uVar1 = param_5 - 1;
    if (param_5 != 1) {
      puVar6 = param_4;
      puVar7 = param_1;
      do {
        param_5 = (longlong)puVar7 - (longlong)param_1;
        if (param_2 - 3 <= param_5) break;
        uVar2 = *puVar6;
        puVar6 = puVar6 + 1;
        uVar4 = (uint)uVar2;
        param_5 = (longlong)puVar6 - (longlong)param_4;
        *puVar7 = ((uVar4 & 0x1c | (uint)uVar2 << 5) << 9 | uVar4 & 0x7e0) << 5 |
                  (((uint)(uVar2 >> 5) | uVar4 & 0xf800) >> 3 | uVar4 & 0x600) >> 5 | 0xff000000;
        puVar7 = puVar7 + 1;
      } while (param_5 < uVar1);
    }
    return CONCAT71((int7)(param_5 >> 8),1);
  }
  if (param_6 == 0x56) {
    in_RAX = param_5;
    if ((param_5 < 2) || (param_2 < 4)) goto LAB_1800085b8;
    uVar1 = param_5 - 1;
    uVar5 = 0;
    if (param_5 != 1) {
      puVar7 = param_1;
      do {
        param_5 = (longlong)puVar7 - (longlong)param_1;
        if (param_2 - 3 <= param_5) break;
        uVar2 = *param_4;
        param_4 = param_4 + 1;
        uVar4 = (uint)uVar2;
        if ((param_7 & 1) == 0) {
          uVar3 = 0;
          if ((short)uVar2 < 0) {
            uVar3 = 0xff000000;
          }
        }
        else {
          uVar3 = 0xff000000;
        }
        uVar5 = uVar5 + 2;
        uVar4 = uVar3 | ((uVar4 & 0x1f) << 5 | uVar4 & 0x1c) << 0xe |
                ((uVar4 & 0x3e0) << 5 | uVar4 & 0x380) * 2 |
                (uVar2 >> 5 & 0x380 | uVar2 & 0x7c00) >> 7;
        param_5 = (ulonglong)uVar4;
        *puVar7 = uVar4;
        puVar7 = puVar7 + 1;
      } while (uVar5 < uVar1);
    }
  }
  else {
    if (((param_6 != 0x73) || (in_RAX = param_5, param_5 < 2)) || (param_2 < 4)) {
LAB_1800085b8:
      return in_RAX & 0xffffffffffffff00;
    }
    uVar5 = 0;
    uVar1 = param_5 - 1;
    if (param_5 != 1) {
      puVar7 = param_1;
      while (param_5 = (longlong)puVar7 - (longlong)param_1, param_5 < param_2 - 3) {
        uVar2 = *param_4;
        param_4 = param_4 + 1;
        uVar4 = (uint)uVar2;
        if ((param_7 & 1) == 0) {
          uVar3 = (uVar4 & 0xf000) << 0x10 | (uVar4 & 0xf000) << 0xc;
        }
        else {
          uVar3 = 0xff000000;
        }
        uVar5 = uVar5 + 2;
        uVar4 = uVar3 | ((uVar4 & 0xf) << 4 | uVar4 & 0xf) << 0x10 |
                ((uVar4 & 0xf0) << 4 | uVar4 & 0xf0) << 4;
        *puVar7 = uVar4 | (uVar2 >> 4 & 0xf0 | uVar2 & 0xf00) >> 4;
        puVar7 = puVar7 + 1;
        if (uVar1 <= uVar5) {
          return CONCAT71((uint7)(uint3)(uVar4 >> 8),1);
        }
      }
    }
  }
  return CONCAT71((int7)(param_5 >> 8),1);
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Restarted to delay deadcode elimination for space: stack

ulonglong FUN_180008680(undefined (*param_1) [16],longlong param_2,undefined (*param_3) [12],
                       ulonglong param_4,int param_5)

{
  byte *pbVar1;
  byte *pbVar2;
  byte *pbVar3;
  ushort *puVar4;
  ushort *puVar5;
  ushort *puVar6;
  undefined (*pauVar7) [16];
  uint uVar8;
  char cVar9;
  byte bVar10;
  ushort uVar11;
  int iVar12;
  uint uVar13;
  ulonglong uVar14;
  undefined auVar15 [12];
  undefined *puVar16;
  uint uVar17;
  ulonglong in_RAX;
  undefined8 uVar18;
  undefined4 extraout_var;
  uint *puVar19;
  int *piVar20;
  undefined (*pauVar21) [12];
  uint *puVar22;
  uint uVar23;
  int iVar24;
  int iVar25;
  ulonglong *puVar26;
  undefined (**ppauVar27) [12];
  int iVar28;
  ulonglong uVar29;
  longlong lVar30;
  undefined (**ppauVar31) [12];
  ushort *puVar32;
  int iVar33;
  ulonglong uVar34;
  undefined (*pauVar35) [12];
  longlong lVar36;
  byte *pbVar37;
  longlong lVar38;
  longlong lVar39;
  longlong lVar40;
  uint extraout_XMM0_Da;
  uint extraout_XMM0_Da_00;
  uint extraout_XMM0_Da_01;
  uint extraout_XMM0_Da_02;
  uint extraout_XMM0_Da_03;
  uint extraout_XMM0_Da_04;
  uint extraout_XMM0_Da_05;
  uint extraout_XMM0_Da_06;
  undefined4 extraout_XMM0_Da_07;
  uint extraout_XMM0_Da_08;
  uint extraout_XMM0_Da_09;
  undefined4 extraout_XMM0_Da_10;
  float fVar41;
  undefined8 extraout_XMM0_Qa;
  undefined8 extraout_XMM0_Qa_00;
  ulonglong extraout_XMM0_Qa_01;
  undefined4 extraout_XMM0_Dc;
  float fVar43;
  undefined auVar42 [16];
  float fVar44;
  undefined (*local_res8) [12];
  undefined8 local_98;
  ulonglong uStack_90;
  undefined (*local_88) [12];
  undefined (*local_80) [12];
  undefined (*local_78) [12];
  undefined (*local_70) [12];
  ulonglong local_68;
  undefined (*local_60) [12];
  undefined (*local_58) [12];
  ulonglong local_50;
  uint local_48 [2];
  int local_40 [6];
  
  if (param_1 == (undefined (*) [16])0x0) {
    return in_RAX & 0xffffffffffffff00;
  }
  uVar29 = param_2 * 0x10;
  pauVar7 = param_1[param_2];
  pauVar21 = (undefined (*) [12])0x0;
  switch(param_5 + -2) {
  case 0:
    if (uVar29 < param_4) {
      param_4 = uVar29;
    }
    uVar18 = FUN_180003f40(param_1,uVar29,param_3,param_4);
    return CONCAT71((int7)((ulonglong)uVar18 >> 8),1);
  case 1:
    if (0xf < param_4) {
      if (param_4 != 0xf) {
        lVar36 = (longlong)param_3 - (longlong)param_1;
        while (param_1 < pauVar7) {
          puVar22 = (uint *)(lVar36 + (longlong)param_1);
          uVar17 = *puVar22;
          uVar23 = puVar22[1];
          uVar8 = puVar22[2];
          uVar13 = puVar22[3];
          *(float *)*param_1 =
               (float)((int)uVar17 >> 0x1f & 0x4f000000) + (float)(uVar17 & 0x80000000 ^ uVar17);
          *(float *)(*param_1 + 4) =
               (float)((int)uVar23 >> 0x1f & 0x4f000000) + (float)(uVar23 & 0x80000000 ^ uVar23);
          *(float *)(*param_1 + 8) =
               (float)((int)uVar8 >> 0x1f & 0x4f000000) + (float)(uVar8 & 0x80000000 ^ uVar8);
          *(float *)(*param_1 + 0xc) =
               (float)((int)uVar13 >> 0x1f & 0x4f000000) + (float)(uVar13 & 0x80000000 ^ uVar13);
          param_1 = param_1[1];
          pauVar21 = (undefined (*) [12])((lVar36 - (longlong)param_3) + (longlong)param_1);
          if ((undefined (*) [12])(param_4 - 0xf) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
LAB_18000ada1:
      return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
    }
    break;
  case 2:
    if (0xf < param_4) {
      if (param_4 != 0xf) {
        lVar36 = (longlong)param_3 - (longlong)param_1;
        while (param_1 < pauVar7) {
          piVar20 = (int *)(lVar36 + (longlong)param_1);
          iVar24 = piVar20[1];
          iVar28 = piVar20[2];
          iVar33 = piVar20[3];
          *(float *)*param_1 = (float)*piVar20;
          *(float *)(*param_1 + 4) = (float)iVar24;
          *(float *)(*param_1 + 8) = (float)iVar28;
          *(float *)(*param_1 + 0xc) = (float)iVar33;
          param_1 = param_1[1];
          pauVar21 = (undefined (*) [12])((lVar36 - (longlong)param_3) + (longlong)param_1);
          if ((undefined (*) [12])(param_4 - 0xf) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 4:
    if (0xb < param_4) {
      uVar29 = 0;
      if (param_4 != 0xb) {
        while (pauVar21 = param_3, param_1 < pauVar7) {
          uVar29 = uVar29 + 0xc;
          auVar15 = *pauVar21;
          *(undefined4 *)*param_1 = *(undefined4 *)*pauVar21;
          *(int *)(*param_1 + 4) =
               SUB164(ZEXT1216(auVar15 & (undefined  [12])0xffffffffffffffff) >> 0x20,0);
          *(undefined4 *)(*param_1 + 8) = 0;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          param_1 = param_1[1];
          param_3 = pauVar21[1];
          if (param_4 - 0xb <= uVar29) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 5:
    if (0xb < param_4) {
      uVar29 = 0;
      if (param_4 != 0xb) {
        puVar22 = (uint *)(*param_3 + 8);
        while( true ) {
          uVar17 = puVar22[-2];
          uVar23 = puVar22[-1];
          uVar8 = *puVar22;
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 0xc;
          *param_1 = ZEXT1216(CONCAT48((float)((int)uVar8 >> 0x1f & 0x4f000000) +
                                       (float)(uVar8 & 0x80000000 ^ uVar8),
                                       CONCAT44((float)((int)uVar23 >> 0x1f & 0x4f000000) +
                                                (float)(uVar23 & 0x80000000 ^ uVar23),
                                                (float)((int)uVar17 >> 0x1f & 0x4f000000) +
                                                (float)(uVar17 & 0x80000000 ^ uVar17))) &
                              (undefined  [12])0xffffffffffffffff) |
                     CONCAT412(0xffffffff,ZEXT812(0)) & (undefined  [16])0xffffffffffffffff;
          param_1 = param_1[1];
          puVar22 = puVar22 + 3;
          if (param_4 - 0xb <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 6:
    if (0xb < param_4) {
      uVar29 = 0;
      if (param_4 != 0xb) {
        piVar20 = (int *)(*param_3 + 8);
        while( true ) {
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 0xc;
          *param_1 = ZEXT1216(CONCAT48((float)*piVar20,
                                       CONCAT44((float)piVar20[-1],(float)piVar20[-2])) &
                              (undefined  [12])0xffffffffffffffff) |
                     CONCAT412(0xffffffff,ZEXT812(0)) & (undefined  [16])0xffffffffffffffff;
          param_1 = param_1[1];
          piVar20 = piVar20 + 3;
          if (param_4 - 0xb <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 8:
    if (7 < param_4) {
      if (param_4 != 7) {
        puVar32 = (ushort *)(*param_3 + 4);
        lVar36 = -4 - (longlong)param_3;
        while (param_1 < pauVar7) {
          FUN_18000ec90(puVar32[-2]);
          local_98 = (undefined (*) [12])
                     ((ulonglong)local_98 & 0xffffffff00000000 | (ulonglong)extraout_XMM0_Da);
          FUN_18000ec90(puVar32[-1]);
          local_98 = (undefined (*) [12])
                     ((ulonglong)local_98 & 0xffffffff | (ulonglong)extraout_XMM0_Da_00 << 0x20);
          FUN_18000ec90(*puVar32);
          uStack_90 = uStack_90 & 0xffffffff00000000 | (ulonglong)extraout_XMM0_Da_01;
          FUN_18000ec90(puVar32[1]);
          puVar32 = puVar32 + 4;
          uVar29 = uStack_90 & 0xffffffff;
          uStack_90 = uVar29 | (ulonglong)extraout_XMM0_Da_02 << 0x20;
          uStack_90._0_4_ = (undefined4)uVar29;
          *(undefined4 *)*param_1 = (undefined4)local_98;
          *(undefined4 *)(*param_1 + 4) = local_98._4_4_;
          *(undefined4 *)(*param_1 + 8) = (undefined4)uStack_90;
          *(uint *)(*param_1 + 0xc) = extraout_XMM0_Da_02;
          param_1 = param_1[1];
          pauVar21 = (undefined (*) [12])(lVar36 + (longlong)puVar32);
          if ((undefined (*) [12])(param_4 - 7) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 9:
    if (7 < param_4) {
      if (param_4 != 7) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          puVar16 = *pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 8);
          auVar42 = shufpd(ZEXT816(*(ulonglong *)puVar16),ZEXT816(*(ulonglong *)puVar16),0);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *param_1 = CONCAT412(((float)(SUB164(auVar42 >> 0x60,0) & 0xffff0000 ^ 0x80000000) +
                               2.147484e+09) * 2.328342e-10,
                               CONCAT48(((float)(SUB164(auVar42 >> 0x20,0) & 0xffff) + 0.0) *
                                        1.525902e-05,
                                        CONCAT44(((float)(SUB164(auVar42 >> 0x40,0) & 0xffff0000 ^
                                                         0x80000000) + 2.147484e+09) * 2.328342e-10,
                                                 ((float)(SUB164(auVar42,0) & 0xffff) + 0.0) *
                                                 1.525902e-05)));
          param_1 = param_1[1];
          if ((undefined (*) [12])(param_4 - 7) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 10:
    if (7 < param_4) {
      if (param_4 != 7) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          puVar16 = *pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 8);
          auVar42 = shufpd(ZEXT816(*(ulonglong *)puVar16),ZEXT816(*(ulonglong *)puVar16),0);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *param_1 = CONCAT412((float)(SUB164(auVar42 >> 0x60,0) & 0xffff0000 ^ 0x80000000) *
                               1.525879e-05 + 32768.0,
                               CONCAT48((float)(SUB164(auVar42 >> 0x20,0) & 0xffff) * 1.0 + 0.0,
                                        CONCAT44((float)(SUB164(auVar42 >> 0x40,0) & 0xffff0000 ^
                                                        0x80000000) * 1.525879e-05 + 32768.0,
                                                 (float)(SUB164(auVar42,0) & 0xffff) * 1.0 + 0.0)));
          param_1 = param_1[1];
          if ((undefined (*) [12])(param_4 - 7) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0xb:
    if (7 < param_4) {
      if (param_4 != 7) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          puVar16 = *pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 8);
          auVar42 = shufpd(ZEXT816(*(ulonglong *)puVar16),ZEXT816(*(ulonglong *)puVar16),0);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          auVar42 = maxps(CONCAT412(((float)(SUB164(auVar42 >> 0x60,0) & 0xffff0000) + 0.0) *
                                    4.656755e-10,
                                    CONCAT48(((float)(SUB164(auVar42 >> 0x20,0) & 0xffff ^ 0x8000) +
                                             -32768.0) * 3.051851e-05,
                                             CONCAT44(((float)(SUB164(auVar42 >> 0x40,0) &
                                                              0xffff0000) + 0.0) * 4.656755e-10,
                                                      ((float)(SUB164(auVar42,0) & 0xffff ^ 0x8000)
                                                      + -32768.0) * 3.051851e-05))),_DAT_18005d430);
          *param_1 = auVar42;
          param_1 = param_1[1];
          if ((undefined (*) [12])(param_4 - 7) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0xc:
    if (7 < param_4) {
      if (param_4 != 7) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          puVar16 = *pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 8);
          auVar42 = shufpd(ZEXT816(*(ulonglong *)puVar16),ZEXT816(*(ulonglong *)puVar16),0);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *param_1 = CONCAT412(((float)(SUB164(auVar42 >> 0x60,0) & 0xffff0000) + 0.0) *
                               1.525879e-05,
                               CONCAT48(((float)(SUB164(auVar42 >> 0x20,0) & 0xffff ^ 0x8000) +
                                        -32768.0) * 1.0,
                                        CONCAT44(((float)(SUB164(auVar42 >> 0x40,0) & 0xffff0000) +
                                                 0.0) * 1.525879e-05,
                                                 ((float)(SUB164(auVar42,0) & 0xffff ^ 0x8000) +
                                                 -32768.0) * 1.0)));
          param_1 = param_1[1];
          if ((undefined (*) [12])(param_4 - 7) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0xe:
    if (7 < param_4) {
      uVar29 = 0;
      if (param_4 != 7) {
        while (pauVar21 = param_3, param_1 < pauVar7) {
          uVar29 = uVar29 + 8;
          *param_1 = ZEXT816(*(ulonglong *)*pauVar21) |
                     CONCAT412(0xffffffff,ZEXT812(0)) & (undefined  [16])0xffffffffffffffff;
          param_1 = param_1[1];
          param_3 = (undefined (*) [12])(*pauVar21 + 8);
          if (param_4 - 7 <= uVar29) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0xf:
    if (7 < param_4) {
      uVar29 = 0;
      if (param_4 != 7) {
        while( true ) {
          uVar17 = *(uint *)*param_3;
          uVar23 = *(uint *)(*param_3 + 4);
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 8;
          *param_1 = ZEXT816(CONCAT44((float)((int)uVar23 >> 0x1f & 0x4f000000) +
                                      (float)(uVar23 & 0x80000000 ^ uVar23),
                                      (float)((int)uVar17 >> 0x1f & 0x4f000000) +
                                      (float)(uVar17 & 0x80000000 ^ uVar17))) |
                     CONCAT412(0xffffffff,ZEXT812(0)) & (undefined  [16])0xffffffffffffffff;
          param_1 = param_1[1];
          param_3 = (undefined (*) [12])(*param_3 + 8);
          if (param_4 - 7 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x10:
    if (7 < param_4) {
      uVar29 = 0;
      if (param_4 != 7) {
        while( true ) {
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 8;
          *param_1 = ZEXT816(CONCAT44((float)*(int *)(*param_3 + 4),(float)*(int *)*param_3)) |
                     CONCAT412(0xffffffff,ZEXT812(0)) & (undefined  [16])0xffffffffffffffff;
          param_1 = param_1[1];
          param_3 = (undefined (*) [12])(*param_3 + 8);
          if (param_4 - 7 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x12:
    if (7 < param_4) {
      if (param_4 != 7) {
        uVar29 = 0;
        while (pauVar21 = (undefined (*) [12])0x0, param_1 < pauVar7) {
          lVar36 = uVar29 + 4;
          uVar17 = *(uint *)(*param_3 + uVar29);
          uVar29 = uVar29 + 8;
          *(ulonglong *)*param_1 = CONCAT44((float)(uint)(byte)(*param_3)[lVar36],uVar17);
          *(longlong *)(*param_1 + 8) =
               SUB168(CONCAT412(0x3f800000,ZEXT412(uVar17) & (undefined  [12])0xffffffff) >> 0x40,0)
          ;
          param_1 = param_1[1];
          if (param_4 - 7 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x13:
    if (7 < param_4) {
      if (param_4 != 7) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          puVar16 = *pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 8);
          *param_1 = CONCAT412(0x3f800000,
                               ZEXT412(*(uint *)puVar16) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0));
          param_1 = param_1[1];
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          if ((undefined (*) [12])(param_4 - 7) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x14:
    if (7 < param_4) {
      if (param_4 != 7) {
        uVar29 = 0;
        while (pauVar21 = (undefined (*) [12])0x0, param_1 < pauVar7) {
          lVar36 = uVar29 + 4;
          uVar29 = uVar29 + 8;
          *(ulonglong *)*param_1 = (ulonglong)(uint)(float)(uint)(byte)(*param_3)[lVar36] << 0x20;
          *(undefined8 *)(*param_1 + 8) = 0x3f80000000000000;
          param_1 = param_1[1];
          if (param_4 - 7 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x16:
    if (3 < param_4) {
      if (param_4 != 3) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          uVar17 = *(uint *)*pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 4);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *(float *)*param_1 = ((float)(uVar17 & 0x3ff) + 0.0) * 0.0009775171;
          *(float *)(*param_1 + 4) = ((float)(uVar17 & 0xffc00) + 0.0) * 9.546065e-07;
          *(float *)(*param_1 + 8) = ((float)(uVar17 & 0x3ff00000) + 0.0) * 9.32233e-10;
          *(float *)(*param_1 + 0xc) =
               ((float)(uVar17 & 0xc0000000 ^ 0x80000000) + 2.147484e+09) * 3.104409e-10;
          param_1 = param_1[1];
          if ((undefined (*) [12])(param_4 - 3) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x17:
    if (3 < param_4) {
      if (param_4 != 3) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          uVar17 = *(uint *)*pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 4);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *(float *)*param_1 = ((float)(uVar17 & 0x3ff) + 0.0) * 1.0;
          *(float *)(*param_1 + 4) = ((float)(uVar17 & 0xffc00) + 0.0) * 0.0009765625;
          *(float *)(*param_1 + 8) = ((float)(uVar17 & 0x3ff00000) + 0.0) * 9.536743e-07;
          *(float *)(*param_1 + 0xc) =
               ((float)(uVar17 & 0xc0000000 ^ 0x80000000) + 2.147484e+09) * 9.313226e-10;
          param_1 = param_1[1];
          if ((undefined (*) [12])(param_4 - 3) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x18:
    if (3 < param_4) {
      uVar29 = 0;
      uVar34 = param_4 - 3;
      if (uVar34 != 0) {
        while( true ) {
          pauVar21 = (undefined (*) [12])FUN_18000eb40((uint *)param_3);
          param_3 = (undefined (*) [12])(*param_3 + 4);
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 4;
          *(int *)*param_1 = (int)extraout_XMM0_Qa;
          *(int *)(*param_1 + 4) = (int)((ulonglong)extraout_XMM0_Qa >> 0x20);
          *(undefined4 *)(*param_1 + 8) = extraout_XMM0_Dc;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          param_1 = param_1[1];
          if (uVar34 <= uVar29) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x1a:
  case 0x1b:
    if (3 < param_4) {
      if (param_4 != 3) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          uVar17 = *(uint *)*pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 4);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *(float *)*param_1 = ((float)(uVar17 & 0xff) + 0.0) * 0.003921569;
          *(float *)(*param_1 + 4) = ((float)(uVar17 & 0xff00) + 0.0) * 1.531863e-05;
          *(float *)(*param_1 + 8) = ((float)(uVar17 & 0xff0000) + 0.0) * 5.983839e-08;
          *(float *)(*param_1 + 0xc) =
               ((float)(uVar17 & 0xff000000 ^ 0x80000000) + 2.147484e+09) * 2.337437e-10;
          param_1 = param_1[1];
          if ((undefined (*) [12])(param_4 - 3) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x1c:
    if (3 < param_4) {
      if (param_4 != 3) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          uVar17 = *(uint *)*pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 4);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *(float *)*param_1 = ((float)(uVar17 & 0xff) + 0.0) * 1.0;
          *(float *)(*param_1 + 4) = ((float)(uVar17 & 0xff00) + 0.0) * 0.00390625;
          *(float *)(*param_1 + 8) = ((float)(uVar17 & 0xff0000) + 0.0) * 1.525879e-05;
          *(float *)(*param_1 + 0xc) =
               ((float)(uVar17 & 0xff000000 ^ 0x80000000) + 2.147484e+09) * 5.960464e-08;
          param_1 = param_1[1];
          if ((undefined (*) [12])(param_4 - 3) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x1d:
    if (3 < param_4) {
      if (param_4 != 3) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          uVar17 = *(uint *)*pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 4);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          auVar42 = maxps(CONCAT412(((float)(uVar17 & 0xff000000) + 0.0) * 4.693279e-10,
                                    CONCAT48(((float)(uVar17 & 0xff0000 ^ 0x800000) + -8388608.0) *
                                             1.201479e-07,
                                             CONCAT44(((float)(uVar17 & 0xff00 ^ 0x8000) + -32768.0)
                                                      * 3.075787e-05,
                                                      ((float)(uVar17 & 0xff ^ 0x80) + -128.0) *
                                                      0.007874016))),_DAT_18005d430);
          *param_1 = auVar42;
          param_1 = param_1[1];
          if ((undefined (*) [12])(param_4 - 3) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x1e:
    if (3 < param_4) {
      if (param_4 != 3) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          uVar17 = *(uint *)*pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 4);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *(float *)*param_1 = ((float)(uVar17 & 0xff ^ 0x80) + -128.0) * 1.0;
          *(float *)(*param_1 + 4) = ((float)(uVar17 & 0xff00 ^ 0x8000) + -32768.0) * 0.00390625;
          *(float *)(*param_1 + 8) =
               ((float)(uVar17 & 0xff0000 ^ 0x800000) + -8388608.0) * 1.525879e-05;
          *(float *)(*param_1 + 0xc) = ((float)(uVar17 & 0xff000000) + 0.0) * 5.960464e-08;
          param_1 = param_1[1];
          if ((undefined (*) [12])(param_4 - 3) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x20:
    if (3 < param_4) {
      uVar29 = 0;
      uVar34 = param_4 - 3;
      if (uVar34 != 0) {
        uStack_90 = 0;
        while( true ) {
          FUN_18000ec90(*(ushort *)*param_3);
          local_98 = (undefined (*) [12])
                     ((ulonglong)local_98 & 0xffffffff00000000 | (ulonglong)extraout_XMM0_Da_03);
          uVar17 = FUN_18000ec90(*(ushort *)(*param_3 + 2));
          pauVar21 = (undefined (*) [12])CONCAT44(extraout_var,uVar17);
          uVar14 = (ulonglong)local_98 & 0xffffffff;
          local_98 = (undefined (*) [12])(uVar14 | (ulonglong)extraout_XMM0_Da_04 << 0x20);
          param_3 = (undefined (*) [12])(*param_3 + 4);
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 4;
          local_98._0_4_ = (undefined4)uVar14;
          *(undefined4 *)*param_1 = (undefined4)local_98;
          *(uint *)(*param_1 + 4) = extraout_XMM0_Da_04;
          *(undefined4 *)(*param_1 + 8) = 0;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          param_1 = param_1[1];
          if (uVar34 <= uVar29) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x21:
    if (3 < param_4) {
      uVar29 = 0;
      if (param_4 != 3) {
        while( true ) {
          uVar17 = *(uint *)*param_3;
          param_3 = (undefined (*) [12])(*param_3 + 4);
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 4;
          *(float *)*param_1 = ((float)(uVar17 & 0xffff) + 0.0) * 1.525902e-05;
          *(float *)(*param_1 + 4) =
               ((float)(uVar17 & 0xffff0000 ^ 0x80000000) + 2.147484e+09) * 2.328342e-10;
          *(undefined4 *)(*param_1 + 8) = 0;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          param_1 = param_1[1];
          if (param_4 - 3 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x22:
    if (3 < param_4) {
      uVar29 = 0;
      if (param_4 != 3) {
        while( true ) {
          uVar17 = *(uint *)*param_3;
          param_3 = (undefined (*) [12])(*param_3 + 4);
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 4;
          *(float *)*param_1 = (float)(uVar17 & 0xffff) * 1.0 + 0.0;
          *(float *)(*param_1 + 4) =
               (float)(uVar17 & 0xffff0000 ^ 0x80000000) * 1.525879e-05 + 32768.0;
          *(undefined4 *)(*param_1 + 8) = 0;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          param_1 = param_1[1];
          if (param_4 - 3 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x23:
    if (3 < param_4) {
      uVar29 = 0;
      if (param_4 != 3) {
        while( true ) {
          puVar16 = *param_3;
          param_3 = (undefined (*) [12])(*param_3 + 4);
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 4;
          auVar42 = maxps(ZEXT816(CONCAT44(((float)(*(uint *)puVar16 & 0xffff0000) + 0.0) *
                                           4.656755e-10,
                                           ((float)(*(uint *)puVar16 & 0xffff ^ 0x8000) + -32768.0)
                                           * 3.051851e-05)),_DAT_18005d430);
          *(int *)*param_1 = SUB164(auVar42,0);
          *(int *)(*param_1 + 4) = SUB164(auVar42 >> 0x20,0);
          *(undefined4 *)(*param_1 + 8) = 0;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          param_1 = param_1[1];
          if (param_4 - 3 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x24:
    if (3 < param_4) {
      uVar29 = 0;
      if (param_4 != 3) {
        while( true ) {
          uVar17 = *(uint *)*param_3;
          param_3 = (undefined (*) [12])(*param_3 + 4);
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 4;
          *(float *)*param_1 = ((float)(uVar17 & 0xffff ^ 0x8000) + -32768.0) * 1.0;
          *(float *)(*param_1 + 4) = ((float)(uVar17 & 0xffff0000) + 0.0) * 1.525879e-05;
          *(undefined4 *)(*param_1 + 8) = 0;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          param_1 = param_1[1];
          if (param_4 - 3 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x26:
  case 0x27:
    if (3 < param_4) {
      uVar29 = 0;
      if (param_4 != 3) {
        while (pauVar21 = param_3, param_1 < pauVar7) {
          uVar29 = uVar29 + 4;
          *param_1 = ZEXT416(*(uint *)*pauVar21) |
                     CONCAT412(0xffffffff,ZEXT812(0)) & (undefined  [16])0xffffffffffffffff;
          param_1 = param_1[1];
          param_3 = (undefined (*) [12])(*pauVar21 + 4);
          if (param_4 - 3 <= uVar29) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x28:
    if (3 < param_4) {
      uVar29 = 0;
      if (param_4 != 3) {
        while( true ) {
          pauVar21 = param_3;
          uVar17 = *(uint *)*pauVar21;
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 4;
          *(float *)*param_1 =
               ((float)((int)uVar17 >> 0x1f & 0x4f000000) + (float)(uVar17 & 0x80000000 ^ uVar17)) *
               1.0;
          *(undefined4 *)(*param_1 + 4) = 0;
          *(undefined4 *)(*param_1 + 8) = 0;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          param_1 = param_1[1];
          param_3 = (undefined (*) [12])(*pauVar21 + 4);
          if (param_4 - 3 <= uVar29) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x29:
    if (3 < param_4) {
      uVar29 = 0;
      if (param_4 != 3) {
        while( true ) {
          pauVar21 = param_3;
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 4;
          *(float *)*param_1 = (float)*(int *)*pauVar21 * 1.0;
          *(undefined4 *)(*param_1 + 4) = 0;
          *(undefined4 *)(*param_1 + 8) = 0;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          param_1 = param_1[1];
          param_3 = (undefined (*) [12])(*pauVar21 + 4);
          if (param_4 - 3 <= uVar29) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x2b:
    if (3 < param_4) {
      uVar29 = 0;
      if (param_4 != 3) {
        while( true ) {
          auVar42 = ZEXT416((uint)(float)(ulonglong)(*(uint *)*param_3 & 0xffffff)) &
                    (undefined  [16])0xffffffffffffffff;
          pauVar21 = (undefined (*) [12])0x0;
          if (pauVar7 <= param_1) break;
          uVar34 = SUB168(CONCAT124(SUB1612(auVar42 >> 0x20,0),SUB164(auVar42,0) * 5.960465e-08),0);
          uVar29 = uVar29 + 4;
          *(ulonglong *)*param_1 =
               uVar34 | (ulonglong)(uint)(float)(uint)(byte)(*param_3)[3] << 0x20;
          *(longlong *)(*param_1 + 8) =
               SUB168(CONCAT412(0x3f800000,ZEXT812(uVar34) & (undefined  [12])0xffffffff) >> 0x40,0)
          ;
          param_1 = param_1[1];
          param_3 = (undefined (*) [12])(*param_3 + 4);
          if (param_4 - 3 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x2c:
    if (3 < param_4) {
      uVar29 = 0;
      if (param_4 != 3) {
        while( true ) {
          puVar16 = *param_3;
          param_3 = (undefined (*) [12])(*param_3 + 4);
          uVar17 = *(uint *)puVar16 & 0xffffff;
          pauVar21 = (undefined (*) [12])(ulonglong)uVar17;
          auVar42 = ZEXT416((uint)(float)(longlong)pauVar21) & (undefined  [16])0xffffffffffffffff;
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 4;
          *param_1 = CONCAT412(0x3f800000,
                               SUB1612(CONCAT88(SUB168(auVar42 >> 0x40,0),
                                                SUB168(CONCAT124(SUB1612(auVar42 >> 0x20,0),
                                                                 SUB164(auVar42,0) * 5.960465e-08),0
                                                      )),0) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0));
          param_1 = param_1[1];
          if (param_4 - 3 <= uVar29) {
            return CONCAT71((uint7)(uint3)(uVar17 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x2d:
    if (3 < param_4) {
      uVar29 = 0;
      if (param_4 != 3) {
        pbVar37 = *param_3 + 3;
        while( true ) {
          bVar10 = *pbVar37;
          pauVar21 = (undefined (*) [12])0x0;
          pbVar37 = pbVar37 + 4;
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 4;
          *(ulonglong *)*param_1 = (ulonglong)(uint)(float)(uint)bVar10 << 0x20;
          *(undefined8 *)(*param_1 + 8) = 0x3f80000000000000;
          param_1 = param_1[1];
          if (param_4 - 3 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x2f:
    if (1 < param_4) {
      uVar29 = 0;
      if (param_4 != 1) {
        while( true ) {
          bVar10 = (*param_3)[1];
          pauVar21 = (undefined (*) [12])0x0;
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 2;
          *(float *)*param_1 = (float)(uint)(byte)(*param_3)[0] * 0.003921569;
          *(float *)(*param_1 + 4) = (float)(uint)bVar10 * 0.003921569;
          *(undefined4 *)(*param_1 + 8) = 0;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          param_1 = param_1[1];
          param_3 = (undefined (*) [12])(*param_3 + 2);
          if (param_4 - 1 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x30:
    if (1 < param_4) {
      uVar29 = 0;
      if (param_4 != 1) {
        while( true ) {
          bVar10 = (*param_3)[1];
          pauVar21 = (undefined (*) [12])0x0;
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 2;
          *(float *)*param_1 = (float)(uint)(byte)(*param_3)[0];
          *(float *)(*param_1 + 4) = (float)(uint)bVar10;
          *(undefined4 *)(*param_1 + 8) = 0;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          param_1 = param_1[1];
          param_3 = (undefined (*) [12])(*param_3 + 2);
          if (param_4 - 1 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x31:
    if (1 < param_4) {
      uVar29 = 0;
      uVar34 = param_4 - 1;
      if (uVar34 != 0) {
        while( true ) {
          pauVar21 = (undefined (*) [12])FUN_18000eac0((longlong)param_3);
          param_3 = (undefined (*) [12])(*param_3 + 2);
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 2;
          *(int *)*param_1 = (int)extraout_XMM0_Qa_00;
          *(int *)(*param_1 + 4) = (int)((ulonglong)extraout_XMM0_Qa_00 >> 0x20);
          *(undefined4 *)(*param_1 + 8) = 0;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          param_1 = param_1[1];
          if (uVar34 <= uVar29) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x32:
    if (1 < param_4) {
      uVar29 = 0;
      if (param_4 != 1) {
        while( true ) {
          cVar9 = (*param_3)[1];
          pauVar21 = (undefined (*) [12])(ulonglong)(uint)(int)cVar9;
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 2;
          *(float *)*param_1 = (float)(int)(char)(*param_3)[0];
          *(float *)(*param_1 + 4) = (float)(int)cVar9;
          *(undefined4 *)(*param_1 + 8) = 0;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          param_1 = param_1[1];
          param_3 = (undefined (*) [12])(*param_3 + 2);
          if (param_4 - 1 <= uVar29) {
            return CONCAT71((uint7)(uint3)(cVar9 >> 7),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x34:
    if (1 < param_4) {
      pauVar35 = (undefined (*) [12])(param_4 - 1);
      if (pauVar35 != (undefined (*) [12])0x0) {
        lVar36 = -(longlong)param_3;
        while (param_1 < pauVar7) {
          FUN_18000ec90(*(ushort *)*param_3);
          param_3 = (undefined (*) [12])(*param_3 + 2);
          *param_1 = CONCAT412(0x3f800000,
                               ZEXT812(extraout_XMM0_Qa_01) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0));
          pauVar21 = (undefined (*) [12])(*param_3 + lVar36);
          param_1 = param_1[1];
          if (pauVar35 <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x35:
  case 0x36:
    if (1 < param_4) {
      if (param_4 != 1) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          puVar16 = *pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 2);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *param_1 = CONCAT412(0x3f800000,
                               ZEXT412((uint)((float)(uint)*(ushort *)puVar16 * 1.525902e-05)) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0));
          param_1 = param_1[1];
          if ((undefined (*) [12])(param_4 - 1) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x37:
    if (1 < param_4) {
      if (param_4 != 1) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          puVar16 = *pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 2);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *param_1 = CONCAT412(0x3f800000,
                               ZEXT412((uint)(float)(uint)*(ushort *)puVar16) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0));
          param_1 = param_1[1];
          if ((undefined (*) [12])(param_4 - 1) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x38:
    if (1 < param_4) {
      if (param_4 != 1) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          puVar16 = *pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 2);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *param_1 = CONCAT412(0x3f800000,
                               ZEXT412((uint)((float)(int)*(short *)puVar16 * 3.051851e-05)) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0));
          param_1 = param_1[1];
          if ((undefined (*) [12])(param_4 - 1) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x39:
    if (1 < param_4) {
      if (param_4 != 1) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          puVar16 = *pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 2);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *param_1 = CONCAT412(0x3f800000,
                               ZEXT412((uint)(float)(int)*(short *)puVar16) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0));
          param_1 = param_1[1];
          if ((undefined (*) [12])(param_4 - 1) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x3b:
    if (param_4 != 0) {
      if (param_4 != 0) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          puVar16 = *pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 1);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *param_1 = CONCAT412(0x3f800000,
                               ZEXT412((uint)((float)(uint)(byte)*puVar16 * 0.003921569)) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0));
          param_1 = param_1[1];
          if (param_4 <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x3c:
    if (param_4 != 0) {
      if (param_4 != 0) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          puVar16 = *pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 1);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *param_1 = CONCAT412(0x3f800000,
                               ZEXT412((uint)(float)(uint)(byte)*puVar16) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0));
          param_1 = param_1[1];
          if (param_4 <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x3d:
    if (param_4 != 0) {
      if (param_4 != 0) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          puVar16 = *pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 1);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *param_1 = CONCAT412(0x3f800000,
                               ZEXT412((uint)((float)(int)(char)*puVar16 * 0.007874016)) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0));
          param_1 = param_1[1];
          if (param_4 <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x3e:
    if (param_4 != 0) {
      if (param_4 != 0) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          puVar16 = *pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 1);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *param_1 = CONCAT412(0x3f800000,
                               ZEXT412((uint)(float)(int)(char)*puVar16) &
                               SUB1612((undefined  [16])0xffffffffffffffff,0));
          param_1 = param_1[1];
          if (param_4 <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x3f:
    if (param_4 != 0) {
      if (param_4 != 0) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          puVar16 = *pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 1);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *param_1 = ZEXT416((uint)((float)(uint)(byte)*puVar16 * 0.003921569)) <<
                     (undefined  [16])0x60;
          param_1 = param_1[1];
          if (param_4 <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x40:
    if (param_4 != 0) {
      if (param_4 != 0) {
        do {
          lVar36 = 8;
          do {
            if (pauVar7 <= param_1) break;
            if (((byte)(*param_3)[0] >> ((char)lVar36 - 1U & 0x1f) & 1) == 0) {
              uVar29 = 0;
            }
            else {
              uVar29 = 0x3f800000;
            }
            *param_1 = CONCAT412(0x3f800000,
                                 ZEXT812(uVar29) & SUB1612((undefined  [16])0xffffffffffffffff,0));
            param_1 = param_1[1];
            lVar36 = lVar36 + -1;
          } while (lVar36 != 0);
          param_3 = (undefined (*) [12])(*param_3 + 1);
          param_4 = param_4 - 1;
          if (param_4 == 0) {
            return 1;
          }
        } while( true );
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x41:
    if (3 < param_4) {
      uVar29 = 0;
      if (param_4 != 3) {
        while( true ) {
          uVar17 = *(uint *)*param_3;
          param_3 = (undefined (*) [12])(*param_3 + 4);
          fVar41 = (float)((uVar17 >> 4 & 0xf800000) + 0x33800000);
          uVar23 = uVar17 >> 0x12 & 0x1ff;
          pauVar21 = (undefined (*) [12])(ulonglong)uVar23;
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 4;
          *(float *)*param_1 = (float)(ulonglong)(uVar17 & 0x1ff) * fVar41;
          *(float *)(*param_1 + 4) = (float)(ulonglong)(uVar17 >> 9 & 0x1ff) * fVar41;
          *(float *)(*param_1 + 8) = (float)(longlong)pauVar21 * fVar41;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          param_1 = param_1[1];
          if (param_4 - 3 <= uVar29) {
            return CONCAT71((uint7)(uint3)(uVar23 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x42:
    if (3 < param_4) {
      uVar29 = 0;
      if (param_4 != 3) {
        while( true ) {
          uVar17 = *(uint *)*param_3;
          param_3 = (undefined (*) [12])(*param_3 + 4);
          fVar41 = ((float)(uVar17 & 0xff) + 0.0) * 0.003921569;
          fVar43 = ((float)(uVar17 & 0xff0000) + 0.0) * 5.983839e-08;
          if (pauVar7 <= param_1) break;
          *(float *)*param_1 = fVar41;
          *(float *)(*param_1 + 4) = ((float)(uVar17 & 0xff00) + 0.0) * 1.531863e-05;
          *(float *)(*param_1 + 8) = fVar43;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          if (pauVar7 <= param_1[1]) break;
          uVar29 = uVar29 + 4;
          *(float *)param_1[1] = fVar41;
          *(float *)(param_1[1] + 4) =
               ((float)(uVar17 & 0xff000000 ^ 0x80000000) + 2.147484e+09) * 2.337437e-10;
          *(float *)(param_1[1] + 8) = fVar43;
          *(undefined4 *)(param_1[1] + 0xc) = 0x3f800000;
          param_1 = param_1[2];
          if (param_4 - 3 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x43:
    if (3 < param_4) {
      uVar29 = 0;
      if (param_4 != 3) {
        while( true ) {
          uVar17 = *(uint *)*param_3;
          param_3 = (undefined (*) [12])(*param_3 + 4);
          fVar41 = ((float)(uVar17 & 0xff00) + 0.0) * 1.531863e-05;
          fVar43 = ((float)(uVar17 & 0xff000000 ^ 0x80000000) + 2.147484e+09) * 2.337437e-10;
          if (pauVar7 <= param_1) break;
          *(float *)*param_1 = fVar41;
          *(float *)(*param_1 + 4) = ((float)(uVar17 & 0xff) + 0.0) * 0.003921569;
          *(float *)(*param_1 + 8) = fVar43;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          if (pauVar7 <= param_1[1]) break;
          uVar29 = uVar29 + 4;
          *(float *)param_1[1] = fVar41;
          *(float *)(param_1[1] + 4) = ((float)(uVar17 & 0xff0000) + 0.0) * 5.983839e-08;
          *(float *)(param_1[1] + 8) = fVar43;
          *(undefined4 *)(param_1[1] + 0xc) = 0x3f800000;
          param_1 = param_1[2];
          if (param_4 - 3 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x53:
    if (1 < param_4) {
      uVar29 = 0;
      if (param_4 != 1) {
        while( true ) {
          uVar17 = *(uint *)*param_3;
          param_3 = (undefined (*) [12])(*param_3 + 2);
          fVar41 = (float)(uVar17 & 0x1f) * 1.0 * _DAT_180065200;
          fVar43 = (float)(uVar17 & 0x7e0) * 0.03125 * fRam0000000180065204;
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 2;
          *(float *)*param_1 = (float)(uVar17 & 0xf800) * 0.0004882813 * fRam0000000180065208;
          *(float *)(*param_1 + 4) = fVar43;
          *(float *)(*param_1 + 8) = fVar41;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          param_1 = param_1[1];
          if (param_4 - 1 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x54:
    if (1 < param_4) {
      uVar29 = 0;
      if (param_4 != 1) {
        while( true ) {
          uVar17 = *(uint *)*param_3;
          param_3 = (undefined (*) [12])(*param_3 + 2);
          fVar41 = (float)(uVar17 & 0x1f) * 1.0 * _DAT_1800651f0;
          fVar43 = (float)(uVar17 & 0x3e0) * 0.03125 * fRam00000001800651f4;
          fVar44 = (float)(uVar17 & 0x8000) * 3.051758e-05 * fRam00000001800651fc;
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 2;
          *(float *)*param_1 = (float)(uVar17 & 0x7c00) * 0.0009765625 * fRam00000001800651f8;
          *(float *)(*param_1 + 4) = fVar43;
          *(float *)(*param_1 + 8) = fVar41;
          *(float *)(*param_1 + 0xc) = fVar44;
          param_1 = param_1[1];
          if (param_4 - 1 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x55:
  case 0x59:
    if (3 < param_4) {
      uVar29 = 0;
      if (param_4 != 3) {
        while( true ) {
          uVar17 = *(uint *)*param_3;
          param_3 = (undefined (*) [12])(*param_3 + 4);
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 4;
          *(float *)*param_1 = ((float)(uVar17 & 0xff0000) + 0.0) * 5.983839e-08;
          *(float *)(*param_1 + 4) = ((float)(uVar17 & 0xff00) + 0.0) * 1.531863e-05;
          *(float *)(*param_1 + 8) = ((float)(uVar17 & 0xff) + 0.0) * 0.003921569;
          *(float *)(*param_1 + 0xc) =
               ((float)(uVar17 & 0xff000000 ^ 0x80000000) + 2.147484e+09) * 2.337437e-10;
          param_1 = param_1[1];
          if (param_4 - 3 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x56:
  case 0x5b:
    if (3 < param_4) {
      uVar29 = 0;
      if (param_4 != 3) {
        while( true ) {
          uVar17 = *(uint *)*param_3;
          param_3 = (undefined (*) [12])(*param_3 + 4);
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 4;
          *(float *)*param_1 = ((float)(uVar17 & 0xff0000) + 0.0) * 5.983839e-08;
          *(float *)(*param_1 + 4) = ((float)(uVar17 & 0xff00) + 0.0) * 1.531863e-05;
          *(float *)(*param_1 + 8) = ((float)(uVar17 & 0xff) + 0.0) * 0.003921569;
          *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
          param_1 = param_1[1];
          if (param_4 - 3 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x57:
    if (3 < param_4) {
      if (param_4 != 3) {
        pauVar35 = param_3;
        while (param_1 < pauVar7) {
          uVar17 = *(uint *)*pauVar35;
          pauVar35 = (undefined (*) [12])(*pauVar35 + 4);
          pauVar21 = (undefined (*) [12])((longlong)pauVar35 - (longlong)param_3);
          *(float *)*param_1 = (float)((uVar17 & 0x3ff) - 0x180) * 0.001960784;
          *(float *)(*param_1 + 4) = (float)((uVar17 >> 10 & 0x3ff) - 0x180) * 0.001960784;
          *(float *)(*param_1 + 8) = (float)((uVar17 >> 0x14 & 0x3ff) - 0x180) * 0.001960784;
          *(float *)(*param_1 + 0xc) = (float)(ulonglong)(uVar17 >> 0x1e) * 0.3333333;
          param_1 = param_1[1];
          if ((undefined (*) [12])(param_4 - 3) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x62:
    if (3 < param_4) {
      uVar29 = 0;
      if (param_4 != 3) {
        pbVar37 = *param_3 + 2;
        while( true ) {
          bVar10 = *pbVar37;
          pbVar1 = pbVar37 + -2;
          pbVar2 = pbVar37 + -1;
          pbVar3 = pbVar37 + 1;
          pbVar37 = pbVar37 + 4;
          iVar24 = (bVar10 - 0x10) * 0x12a;
          uVar17 = (*pbVar2 - 0x80) * 0x204;
          pauVar21 = (undefined (*) [12])(ulonglong)uVar17;
          local_70._0_4_ = (int)((*pbVar1 - 0x80) * 0x199 + 0x80 + iVar24) >> 8;
          local_88._0_4_ =
               (int)(iVar24 + 0x80 + (*pbVar2 - 0x80) * -100 + (*pbVar1 - 0x80) * -0xd0) >> 8;
          uVar17 = (int)(iVar24 + 0x80 + uVar17) >> 8;
          local_78 = (undefined (*) [12])
                     ((ulonglong)local_78 & 0xffffffff00000000 | (ulonglong)uVar17);
          if (pauVar7 <= param_1) break;
          local_80._0_4_ = 0;
          local_68._0_4_ = 0;
          ppauVar27 = &local_res8;
          if (-1 < (int)uVar17) {
            ppauVar27 = &local_78;
          }
          puVar22 = (uint *)&local_80;
          if (-1 < (int)(uint)local_88) {
            puVar22 = (uint *)&local_88;
          }
          iVar24 = *(int *)ppauVar27;
          piVar20 = (int *)&local_68;
          if (-1 < (int)(uint)local_70) {
            piVar20 = (int *)&local_70;
          }
          if (0xff < iVar24) {
            iVar24 = 0xff;
          }
          uVar17 = *puVar22;
          if (0xff < (int)*puVar22) {
            uVar17 = 0xff;
          }
          iVar28 = *piVar20;
          if (0xff < *piVar20) {
            iVar28 = 0xff;
          }
          uVar29 = uVar29 + 4;
          *param_1 = CONCAT412((float)(ulonglong)*pbVar3 * 0.003921569,
                               CONCAT48((float)iVar24 * 0.003921569,
                                        CONCAT44((float)uVar17 * 0.003921569,
                                                 (float)iVar28 * 0.003921569)));
          param_1 = param_1[1];
          if (param_4 - 3 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 99:
    if (3 < param_4) {
      local_60 = (undefined (*) [12])(param_4 - 3);
      pauVar35 = (undefined (*) [12])0x0;
      pauVar21 = local_60;
      if (local_60 != (undefined (*) [12])0x0) {
        while( true ) {
          uVar17 = *(uint *)*param_3;
          param_3 = (undefined (*) [12])(*param_3 + 4);
          lVar30 = (longlong)(int)((uVar17 & 0x3ff) - 0x200);
          lVar36 = (longlong)(int)((uVar17 >> 0x14 & 0x3ff) - 0x200);
          lVar39 = (longlong)(int)((uVar17 >> 10 & 0x3ff) - 0x40) * 0x12af5;
          local_68._0_4_ = (uint)((ulonglong)(lVar36 * 0x199c9 + 0x8000 + lVar39) >> 0x10);
          pauVar21 = (undefined (*) [12])(lVar30 * 0x205ee);
          local_80._0_4_ =
               (uint)((ulonglong)(lVar36 * -0xd0b1 + lVar30 * -0x6493 + 0x8000 + lVar39) >> 0x10);
          local_70._0_4_ = (uint)((ulonglong)(lVar39 + 0x8000 + (longlong)pauVar21) >> 0x10);
          if (pauVar7 <= param_1) break;
          local_78 = (undefined (*) [12])((ulonglong)local_78 & 0xffffffff00000000);
          local_88._0_4_ = 0;
          ppauVar27 = &local_res8;
          if (-1 < (int)(uint)local_70) {
            ppauVar27 = &local_70;
          }
          ppauVar31 = &local_78;
          if (-1 < (int)(uint)local_80) {
            ppauVar31 = &local_80;
          }
          puVar22 = (uint *)&local_88;
          if (-1 < (int)(uint)local_68) {
            puVar22 = (uint *)&local_68;
          }
          iVar24 = *(int *)ppauVar27;
          if (0x3ff < *(int *)ppauVar27) {
            iVar24 = 0x3ff;
          }
          uVar23 = *(uint *)ppauVar31;
          if (0x3ff < (int)*(uint *)ppauVar31) {
            uVar23 = 0x3ff;
          }
          uVar8 = *puVar22;
          if (0x3ff < (int)*puVar22) {
            uVar8 = 0x3ff;
          }
          pauVar35 = (undefined (*) [12])(*pauVar35 + 4);
          *param_1 = CONCAT412((float)(ulonglong)(uVar17 >> 0x1e) * 0.3333333,
                               CONCAT48((float)iVar24 * 0.0009775171,
                                        CONCAT44((float)uVar23 * 0.0009775171,
                                                 (float)uVar8 * 0.0009775171)));
          param_1 = param_1[1];
          if (local_60 <= pauVar35) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 100:
    if (7 < param_4) {
      uVar29 = 0;
      if (param_4 != 7) {
        puVar32 = (ushort *)(*param_3 + 4);
        while( true ) {
          puVar4 = puVar32 + -1;
          uVar11 = *puVar32;
          puVar5 = puVar32 + -2;
          puVar6 = puVar32 + 1;
          puVar32 = puVar32 + 4;
          lVar39 = ((ulonglong)*puVar4 - 0x1000) * 0x12b3f;
          lVar36 = ((ulonglong)*puVar5 - 0x8000) * 0x2066e + 0x8000 + lVar39;
          local_58._0_4_ = (uint)(((ulonglong)uVar11 - 0x8000) * 0x19a2e + 0x8000 + lVar39 >> 0x10);
          local_88._0_4_ =
               (uint)(lVar39 + 0x8000 +
                      ((ulonglong)uVar11 - 0x8000) * -0xd0e5 +
                      ((ulonglong)*puVar5 - 0x8000) * -0x64ac >> 0x10);
          uVar17 = (uint)((ulonglong)lVar36 >> 0x10);
          local_78 = (undefined (*) [12])
                     ((ulonglong)local_78 & 0xffffffff00000000 | (ulonglong)uVar17);
          pauVar21 = (undefined (*) [12])(lVar36 >> 0x10);
          if (pauVar7 <= param_1) break;
          local_60 = (undefined (*) [12])
                     ((ulonglong)local_60 & 0xffffffff00000000 | (ulonglong)*puVar6);
          local_70._0_4_ = 0;
          local_80._0_4_ = 0;
          local_68._0_4_ = 0;
          local_60._0_4_ = (uint)*puVar6;
          ppauVar27 = &local_70;
          if (-1 < (int)uVar17) {
            ppauVar27 = &local_78;
          }
          puVar22 = (uint *)&local_80;
          if (-1 < (int)(uint)local_88) {
            puVar22 = (uint *)&local_88;
          }
          puVar19 = (uint *)&local_68;
          if (-1 < (int)(uint)local_58) {
            puVar19 = (uint *)&local_58;
          }
          if (0xffff < (uint)local_60) {
            local_60._0_4_ = 0xffff;
          }
          iVar24 = *(int *)ppauVar27;
          if (0xffff < *(int *)ppauVar27) {
            iVar24 = 0xffff;
          }
          uVar17 = *puVar22;
          if (0xffff < (int)*puVar22) {
            uVar17 = 0xffff;
          }
          uVar23 = *puVar19;
          if (0xffff < (int)*puVar19) {
            uVar23 = 0xffff;
          }
          uVar29 = uVar29 + 8;
          *param_1 = CONCAT412((float)(uint)local_60 * 1.525902e-05,
                               CONCAT48((float)iVar24 * 1.525902e-05,
                                        CONCAT44((float)uVar17 * 1.525902e-05,
                                                 (float)uVar23 * 1.525902e-05)));
          param_1 = param_1[1];
          if (param_4 - 7 <= uVar29) {
            return CONCAT71((int7)((ulonglong)puVar19 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x69:
    if (3 < param_4) {
      local_98 = (undefined (*) [12])(param_4 - 3);
      local_78 = (undefined (*) [12])0x0;
      pauVar21 = local_98;
      if (local_98 != (undefined (*) [12])0x0) {
        pbVar37 = *param_3 + 2;
        while( true ) {
          iVar33 = pbVar37[-1] - 0x80;
          iVar28 = (pbVar37[-2] - 0x10) * 0x12a;
          iVar24 = pbVar37[1] - 0x80;
          local_88._0_4_ = iVar28 + iVar33 * -100 + iVar24 * -0xd0 + 0x80 >> 8;
          local_68._0_4_ = iVar33 * 0x204 + 0x80 + iVar28 >> 8;
          local_80._0_4_ = iVar24 * 0x199 + 0x80 + iVar28 >> 8;
          pauVar21 = (undefined (*) [12])(ulonglong)(uint)local_88;
          if (pauVar7 <= param_1) break;
          local_58._0_4_ = 0;
          local_60 = (undefined (*) [12])((ulonglong)local_60 & 0xffffffff00000000);
          local_70._0_4_ = 0;
          piVar20 = (int *)&local_58;
          if (-1 < (int)(uint)local_68) {
            piVar20 = (int *)&local_68;
          }
          ppauVar27 = &local_60;
          if (-1 < (int)(uint)local_88) {
            ppauVar27 = &local_88;
          }
          iVar28 = *piVar20;
          piVar20 = (int *)&local_70;
          if (-1 < (int)(uint)local_80) {
            piVar20 = (int *)&local_80;
          }
          if (0xff < iVar28) {
            iVar28 = 0xff;
          }
          uVar17 = *(uint *)ppauVar27;
          if (0xff < (int)*(uint *)ppauVar27) {
            uVar17 = 0xff;
          }
          iVar12 = *piVar20;
          if (0xff < *piVar20) {
            iVar12 = 0xff;
          }
          iVar25 = (*pbVar37 - 0x10) * 0x12a;
          local_88._0_4_ = iVar25 + iVar33 * -100 + iVar24 * -0xd0 + 0x80 >> 8;
          local_80._0_4_ = iVar25 + 0x80 + iVar24 * 0x199 >> 8;
          local_68._0_4_ = iVar25 + 0x80 + iVar33 * 0x204 >> 8;
          *param_1 = CONCAT412(0x3f800000,
                               CONCAT48((float)iVar28 * 0.003921569,
                                        CONCAT44((float)uVar17 * 0.003921569,
                                                 (float)iVar12 * 0.003921569)));
          pauVar21 = (undefined (*) [12])(ulonglong)(uint)local_88;
          if (pauVar7 <= param_1[1]) break;
          local_50 = local_50 & 0xffffffff00000000;
          local_48[0] = 0;
          local_40[0] = 0;
          puVar26 = &local_50;
          if (-1 < (int)(uint)local_68) {
            puVar26 = &local_68;
          }
          puVar22 = local_48;
          if (-1 < (int)(uint)local_88) {
            puVar22 = (uint *)&local_88;
          }
          piVar20 = local_40;
          if (-1 < (int)(uint)local_80) {
            piVar20 = (int *)&local_80;
          }
          uVar17 = *puVar22;
          uVar23 = *(uint *)puVar26;
          if (0xff < (int)*(uint *)puVar26) {
            uVar23 = 0xff;
          }
          if (0xff < (int)uVar17) {
            uVar17 = 0xff;
          }
          iVar24 = *piVar20;
          if (0xff < *piVar20) {
            iVar24 = 0xff;
          }
          local_78 = (undefined (*) [12])(*local_78 + 4);
          param_1[1] = CONCAT412(0x3f800000,
                                 CONCAT48((float)uVar23 * 0.003921569,
                                          CONCAT44((float)uVar17 * 0.003921569,
                                                   (float)iVar24 * 0.003921569)));
          param_1 = param_1[2];
          pbVar37 = pbVar37 + 4;
          if (local_98 <= local_78) {
            return CONCAT71((int7)((ulonglong)local_78 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x6a:
    if (7 < param_4) {
      local_78 = (undefined (*) [12])(param_4 - 7);
      pauVar35 = (undefined (*) [12])0x0;
      pauVar21 = local_78;
      if (local_78 != (undefined (*) [12])0x0) {
        puVar32 = (ushort *)(*param_3 + 4);
        while( true ) {
          puVar4 = puVar32 + -2;
          puVar5 = puVar32 + 1;
          puVar6 = puVar32 + -1;
          uVar11 = *puVar32;
          puVar32 = puVar32 + 4;
          lVar39 = ((ulonglong)(*puVar4 >> 6) - 0x40) * 0x12af5;
          lVar30 = (ulonglong)(*puVar6 >> 6) - 0x200;
          lVar36 = (ulonglong)(*puVar5 >> 6) - 0x200;
          lVar38 = lVar36 * 0x199c9;
          local_50 = lVar30 * 0x205ee;
          lVar30 = lVar36 * -0xd0b1 + lVar30 * -0x6493;
          lVar36 = lVar39 + 0x8000 + lVar30;
          local_88._0_4_ = (uint)((ulonglong)(lVar38 + 0x8000 + lVar39) >> 0x10);
          local_80._0_4_ = (uint)((ulonglong)lVar36 >> 0x10);
          pauVar21 = (undefined (*) [12])(lVar36 >> 0x10);
          if (pauVar7 <= param_1) break;
          local_98 = (undefined (*) [12])((ulonglong)local_98 & 0xffffffff00000000);
          local_40[0] = 0;
          local_48[0] = 0;
          ppauVar27 = (undefined (**) [12])&local_98;
          if (-1 < (int)(lVar39 + 0x8000 + local_50 >> 0x10)) {
            ppauVar27 = &local_res8;
          }
          piVar20 = local_40;
          if (-1 < (int)(uint)local_80) {
            piVar20 = (int *)&local_80;
          }
          iVar24 = *(int *)ppauVar27;
          puVar22 = local_48;
          if (-1 < (int)(uint)local_88) {
            puVar22 = (uint *)&local_88;
          }
          if (0x3ff < iVar24) {
            iVar24 = 0x3ff;
          }
          iVar28 = *piVar20;
          if (0x3ff < *piVar20) {
            iVar28 = 0x3ff;
          }
          uVar17 = *puVar22;
          if (0x3ff < (int)*puVar22) {
            uVar17 = 0x3ff;
          }
          pauVar21 = (undefined (*) [12])(((ulonglong)(uVar11 >> 6) - 0x40) * 0x12af5);
          local_88._0_4_ = (uint)((ulonglong)(lVar38 + 0x8000 + (longlong)pauVar21) >> 0x10);
          local_80._0_4_ = (uint)((ulonglong)(lVar30 + 0x8000 + (longlong)pauVar21) >> 0x10);
          *param_1 = CONCAT412(0x3f800000,
                               CONCAT48((float)iVar24 * 0.0009775171,
                                        CONCAT44((float)iVar28 * 0.0009775171,
                                                 (float)uVar17 * 0.0009775171)));
          if (pauVar7 <= param_1[1]) break;
          local_58._0_4_ = 0;
          local_60 = (undefined (*) [12])((ulonglong)local_60 & 0xffffffff00000000);
          local_70._0_4_ = 0;
          ppauVar27 = &local_58;
          if (-1 < (int)(local_50 + 0x8000 + (longlong)pauVar21 >> 0x10)) {
            ppauVar27 = &local_res8;
          }
          ppauVar31 = &local_60;
          if (-1 < (int)(uint)local_80) {
            ppauVar31 = &local_80;
          }
          puVar22 = (uint *)&local_70;
          if (-1 < (int)(uint)local_88) {
            puVar22 = (uint *)&local_88;
          }
          iVar24 = *(int *)ppauVar31;
          iVar28 = *(int *)ppauVar27;
          if (0x3ff < *(int *)ppauVar27) {
            iVar28 = 0x3ff;
          }
          if (0x3ff < iVar24) {
            iVar24 = 0x3ff;
          }
          uVar17 = *puVar22;
          if (0x3ff < (int)*puVar22) {
            uVar17 = 0x3ff;
          }
          pauVar35 = (undefined (*) [12])(*pauVar35 + 8);
          param_1[1] = CONCAT412(0x3f800000,
                                 CONCAT48((float)iVar28 * 0.0009775171,
                                          CONCAT44((float)iVar24 * 0.0009775171,
                                                   (float)uVar17 * 0.0009775171)));
          param_1 = param_1[2];
          if (local_78 <= pauVar35) {
            return CONCAT71((int7)((ulonglong)puVar22 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x6b:
    if (7 < param_4) {
      local_78 = (undefined (*) [12])(param_4 - 7);
      pauVar35 = (undefined (*) [12])0x0;
      pauVar21 = local_78;
      if (local_78 != (undefined (*) [12])0x0) {
        puVar32 = (ushort *)(*param_3 + 4);
        while( true ) {
          local_50 = (ulonglong)*puVar32;
          lVar30 = ((ulonglong)puVar32[-2] - 0x1000) * 0x12b3f;
          lVar38 = ((ulonglong)puVar32[-1] - 0x8000) * 0x2066e;
          lVar40 = ((ulonglong)puVar32[1] - 0x8000) * 0x19a2e;
          lVar39 = ((ulonglong)puVar32[1] - 0x8000) * -0xd0e5 +
                   ((ulonglong)puVar32[-1] - 0x8000) * -0x64ac;
          lVar36 = lVar39 + 0x8000 + lVar30;
          local_80._0_4_ = (uint)((ulonglong)lVar36 >> 0x10);
          local_88._0_4_ = (uint)((ulonglong)(lVar40 + 0x8000 + lVar30) >> 0x10);
          pauVar21 = (undefined (*) [12])(lVar36 >> 0x10);
          if (pauVar7 <= param_1) break;
          local_98 = (undefined (*) [12])((ulonglong)local_98 & 0xffffffff00000000);
          local_40[0] = 0;
          local_48[0] = 0;
          ppauVar27 = (undefined (**) [12])&local_98;
          if (-1 < (int)((ulonglong)(lVar38 + 0x8000 + lVar30) >> 0x10)) {
            ppauVar27 = &local_res8;
          }
          piVar20 = local_40;
          if (-1 < (int)(uint)local_80) {
            piVar20 = (int *)&local_80;
          }
          iVar24 = *(int *)ppauVar27;
          puVar22 = local_48;
          if (-1 < (int)(uint)local_88) {
            puVar22 = (uint *)&local_88;
          }
          if (0xffff < iVar24) {
            iVar24 = 0xffff;
          }
          iVar28 = *piVar20;
          if (0xffff < *piVar20) {
            iVar28 = 0xffff;
          }
          uVar17 = *puVar22;
          if (0xffff < (int)*puVar22) {
            uVar17 = 0xffff;
          }
          lVar36 = ((ulonglong)*puVar32 - 0x1000) * 0x12b3f;
          lVar39 = lVar36 + 0x8000 + lVar39;
          local_88._0_4_ = (uint)((ulonglong)(lVar36 + 0x8000 + lVar40) >> 0x10);
          local_80._0_4_ = (uint)((ulonglong)lVar39 >> 0x10);
          *param_1 = CONCAT412(0x3f800000,
                               CONCAT48((float)iVar24 * 1.525902e-05,
                                        CONCAT44((float)iVar28 * 1.525902e-05,
                                                 (float)uVar17 * 1.525902e-05)));
          pauVar21 = (undefined (*) [12])(lVar39 >> 0x10);
          if (pauVar7 <= param_1[1]) break;
          local_58._0_4_ = 0;
          local_60 = (undefined (*) [12])((ulonglong)local_60 & 0xffffffff00000000);
          local_70._0_4_ = 0;
          ppauVar27 = &local_58;
          if (-1 < (int)((ulonglong)(lVar36 + 0x8000 + lVar38) >> 0x10)) {
            ppauVar27 = &local_res8;
          }
          ppauVar31 = &local_60;
          if (-1 < (int)(uint)local_80) {
            ppauVar31 = &local_80;
          }
          puVar22 = (uint *)&local_70;
          if (-1 < (int)(uint)local_88) {
            puVar22 = (uint *)&local_88;
          }
          iVar24 = *(int *)ppauVar31;
          iVar28 = *(int *)ppauVar27;
          if (0xffff < *(int *)ppauVar27) {
            iVar28 = 0xffff;
          }
          if (0xffff < iVar24) {
            iVar24 = 0xffff;
          }
          uVar17 = *puVar22;
          if (0xffff < (int)*puVar22) {
            uVar17 = 0xffff;
          }
          pauVar35 = (undefined (*) [12])(*pauVar35 + 8);
          param_1[1] = CONCAT412(0x3f800000,
                                 CONCAT48((float)iVar28 * 1.525902e-05,
                                          CONCAT44((float)iVar24 * 1.525902e-05,
                                                   (float)uVar17 * 1.525902e-05)));
          param_1 = param_1[2];
          puVar32 = puVar32 + 4;
          if (local_78 <= pauVar35) {
            return CONCAT71((int7)((ulonglong)puVar22 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x71:
    if (1 < param_4) {
      uVar29 = 0;
      if (param_4 != 1) {
        while( true ) {
          uVar17 = *(uint *)*param_3;
          param_3 = (undefined (*) [12])(*param_3 + 2);
          fVar41 = (float)(uVar17 & 0xf) * 1.0 * _DAT_1800651e0;
          fVar43 = (float)(uVar17 & 0xf0) * 0.0625 * fRam00000001800651e4;
          fVar44 = (float)(uVar17 & 0xf000) * 0.0002441406 * fRam00000001800651ec;
          if (pauVar7 <= param_1) break;
          uVar29 = uVar29 + 2;
          *(float *)*param_1 = (float)(uVar17 & 0xf00) * 0.00390625 * fRam00000001800651e8;
          *(float *)(*param_1 + 4) = fVar43;
          *(float *)(*param_1 + 8) = fVar41;
          *(float *)(*param_1 + 0xc) = fVar44;
          param_1 = param_1[1];
          if (param_4 - 1 <= uVar29) {
            return 1;
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x72:
    if (3 < param_4) {
      if (param_4 != 3) {
        auVar42 = ZEXT1216(ZEXT812(0x3eaaaaab));
        lVar36 = -(longlong)param_3;
        while (param_1 < pauVar7) {
          uVar29 = (ulonglong)*(uint *)*param_3;
          FUN_180007a40(*(uint *)*param_3 & 0x3ff);
          local_98 = (undefined (*) [12])
                     ((ulonglong)local_98 & 0xffffffff00000000 | (ulonglong)extraout_XMM0_Da_05);
          FUN_180007a40((uint)((uVar29 & 0xffffffff) >> 10) & 0x3ff);
          uVar17 = (uint)uVar29;
          local_98 = (undefined (*) [12])
                     ((ulonglong)local_98 & 0xffffffff | (ulonglong)extraout_XMM0_Da_06 << 0x20);
          FUN_180007a40((uint)((uVar29 & 0xffffffff) >> 0x14) & 0x3ff);
          param_3 = (undefined (*) [12])(*param_3 + 4);
          pauVar21 = (undefined (*) [12])(*param_3 + lVar36);
          fVar41 = (float)(ulonglong)(uVar17 >> 0x1e) * SUB164(auVar42,0);
          uStack_90 = CONCAT44(fVar41,extraout_XMM0_Da_07);
          *(undefined4 *)*param_1 = (undefined4)local_98;
          *(undefined4 *)(*param_1 + 4) = local_98._4_4_;
          *(undefined4 *)(*param_1 + 8) = extraout_XMM0_Da_07;
          *(float *)(*param_1 + 0xc) = fVar41;
          param_1 = param_1[1];
          if ((undefined (*) [12])(param_4 - 3) <= pauVar21) {
            return CONCAT71((int7)((ulonglong)pauVar21 >> 8),1);
          }
        }
      }
      goto LAB_18000ada1;
    }
    break;
  case 0x73:
    if (3 < param_4) {
      if (param_4 != 3) {
        auVar42 = ZEXT1216(ZEXT812(0x3eaaaaab));
        lVar36 = -(longlong)param_3;
        do {
          if (pauVar7 <= param_1) break;
          uVar29 = (ulonglong)*(uint *)*param_3;
          FUN_180007b10(*(uint *)*param_3 & 0x3ff);
          local_98 = (undefined (*) [12])
                     ((ulonglong)local_98 & 0xffffffff00000000 | (ulonglong)extraout_XMM0_Da_08);
          FUN_180007b10((uint)((uVar29 & 0xffffffff) >> 10) & 0x3ff);
          uVar17 = (uint)uVar29;
          local_98 = (undefined (*) [12])
                     ((ulonglong)local_98 & 0xffffffff | (ulonglong)extraout_XMM0_Da_09 << 0x20);
          FUN_180007b10((uint)((uVar29 & 0xffffffff) >> 0x14) & 0x3ff);
          param_3 = (undefined (*) [12])(*param_3 + 4);
          pauVar21 = (undefined (*) [12])(*param_3 + lVar36);
          fVar41 = (float)(ulonglong)(uVar17 >> 0x1e) * SUB164(auVar42,0);
          uStack_90 = CONCAT44(fVar41,extraout_XMM0_Da_10);
          *(undefined4 *)*param_1 = (undefined4)local_98;
          *(undefined4 *)(*param_1 + 4) = local_98._4_4_;
          *(undefined4 *)(*param_1 + 8) = extraout_XMM0_Da_10;
          *(float *)(*param_1 + 0xc) = fVar41;
          param_1 = param_1[1];
        } while (pauVar21 < (undefined (*) [12])(param_4 - 3));
      }
      goto LAB_18000ada1;
    }
  }
                    // WARNING: Read-only address (ram,0x00018005d430) is written
  return 0;
}



// WARNING: Heritage AFTER dead removal. Example location: s0xffffffffffffff68 : 0x00018000d0b5
// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Restarted to delay deadcode elimination for space: stack

ulonglong FUN_18000af80(undefined8 *param_1,uint *param_2,int param_3,undefined (*param_4) [16],
                       longlong param_5,float param_6)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined *puVar5;
  undefined *puVar6;
  undefined *puVar7;
  undefined2 uVar8;
  short sVar9;
  uint uVar10;
  uint uVar11;
  ulonglong in_RAX;
  float *pfVar12;
  undefined4 extraout_var;
  undefined8 *puVar13;
  uint *puVar14;
  uint *puVar15;
  uint **ppuVar16;
  undefined uVar17;
  ushort uVar18;
  undefined2 *puVar19;
  ushort uVar20;
  ulonglong uVar21;
  undefined8 *puVar22;
  undefined (*pauVar23) [16];
  undefined (*pauVar24) [16];
  ulonglong uVar25;
  ulonglong uVar26;
  uint uVar27;
  uint uVar28;
  ulonglong uVar29;
  ulonglong uVar30;
  uint *puVar31;
  ulonglong uVar32;
  longlong lVar33;
  undefined *puVar34;
  short *psVar35;
  ushort uVar36;
  int iVar37;
  uint uVar38;
  uint uVar39;
  uint extraout_XMM0_Db;
  uint extraout_XMM0_Db_00;
  uint extraout_XMM0_Db_01;
  undefined in_XMM0 [16];
  float fVar40;
  float fVar41;
  float fVar42;
  float fVar43;
  undefined auVar44 [16];
  uint uVar45;
  float in_xmmTmp2_Dd;
  undefined8 local_res20;
  uint local_98;
  undefined4 local_90;
  undefined8 local_88;
  uint local_80 [2];
  undefined8 local_78;
  uint *local_70;
  uint *local_68 [2];
  undefined local_58 [4];
  undefined auStack_54 [12];
  undefined local_48 [8];
  undefined8 uStack_40;
  
  if (param_4 == (undefined (*) [16])0x0) {
    return in_RAX & 0xffffffffffffff00;
  }
  pauVar23 = param_4[param_5];
  puVar15 = (uint *)0x0;
  switch(param_3 + -2) {
  case 0:
    if ((uint *)0xf < param_2) {
      if (param_2 != (uint *)0xf) {
        lVar33 = (longlong)param_1 - (longlong)param_4;
        while (param_4 < pauVar23) {
          uVar2 = *(undefined4 *)(*param_4 + 4);
          uVar3 = *(undefined4 *)(*param_4 + 8);
          uVar4 = *(undefined4 *)(*param_4 + 0xc);
          puVar1 = (undefined4 *)(lVar33 + (longlong)param_4);
          *puVar1 = *(undefined4 *)*param_4;
          puVar1[1] = uVar2;
          puVar1[2] = uVar3;
          puVar1[3] = uVar4;
          param_4 = param_4[1];
          puVar15 = (uint *)((lVar33 - (longlong)param_1) + (longlong)param_4);
          if ((uint *)((longlong)param_2 + -0xf) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
LAB_18000d895:
      return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
    }
    break;
  case 1:
    if ((uint *)0xf < param_2) {
      if (param_2 != (uint *)0xf) {
        lVar33 = (longlong)param_1 - (longlong)param_4;
        while (param_4 < pauVar23) {
          auVar44 = maxps(*param_4,_DAT_18005d4d0);
          fVar40 = SUB164(auVar44,0);
          fVar42 = SUB164(auVar44 >> 0x20,0);
          fVar41 = SUB164(auVar44 >> 0x60,0);
          puVar15 = (uint *)(lVar33 + (longlong)param_4);
          *puVar15 = -(uint)(2.147484e+09 <= fVar40) & 0x80000000 ^
                     (int)(fVar40 - (float)(-(uint)(2.147484e+09 <= fVar40) & 0x4f000000)) |
                     -(uint)(4.294967e+09 < fVar40);
          puVar15[1] = -(uint)(2.147484e+09 <= fVar42) & 0x80000000 ^
                       (int)(fVar42 - (float)(-(uint)(2.147484e+09 <= fVar42) & 0x4f000000)) |
                       -(uint)(4.294967e+09 < fVar42);
          puVar15[2] = -(uint)(2.147484e+09 <= fVar41) & 0x80000000 ^
                       (int)(SUB164(auVar44 >> 0x40,0) -
                            (float)(-(uint)(2.147484e+09 <= fVar41) & 0x4f000000)) |
                       -(uint)(4.294967e+09 < fVar41);
          puVar15[3] = -(uint)(2.147484e+09 <= in_xmmTmp2_Dd) & 0x80000000 ^
                       (int)(fVar41 - (float)(-(uint)(2.147484e+09 <= in_xmmTmp2_Dd) & 0x4f000000))
                       | -(uint)(4.294967e+09 < in_xmmTmp2_Dd);
          param_4 = param_4[1];
          puVar15 = (uint *)((lVar33 - (longlong)param_1) + (longlong)param_4);
          if ((uint *)((longlong)param_2 + -0xf) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 2:
    if ((uint *)0xf < param_2) {
      if (param_2 != (uint *)0xf) {
        lVar33 = (longlong)param_1 - (longlong)param_4;
        while (param_4 < pauVar23) {
          fVar40 = *(float *)(*param_4 + 4);
          fVar42 = *(float *)(*param_4 + 8);
          fVar41 = *(float *)(*param_4 + 0xc);
          uVar11 = -(uint)(2.147484e+09 < *(float *)*param_4);
          uVar28 = -(uint)(2.147484e+09 < *(float *)(*param_4 + 4));
          uVar10 = -(uint)(2.147484e+09 < *(float *)(*param_4 + 8));
          uVar45 = -(uint)(2.147484e+09 < *(float *)(*param_4 + 0xc));
          puVar15 = (uint *)(lVar33 + (longlong)param_4);
          *puVar15 = uVar11 & 0x7fffffff | ~uVar11 & (int)*(float *)*param_4;
          puVar15[1] = uVar28 & 0x7fffffff | ~uVar28 & (int)fVar40;
          puVar15[2] = uVar10 & 0x7fffffff | ~uVar10 & (int)fVar42;
          puVar15[3] = uVar45 & 0x7fffffff | ~uVar45 & (int)fVar41;
          param_4 = param_4[1];
          puVar15 = (uint *)((lVar33 - (longlong)param_1) + (longlong)param_4);
          if ((uint *)((longlong)param_2 + -0xf) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 4:
    if ((uint *)0xb < param_2) {
      if (param_2 != (uint *)0xb) {
        puVar22 = param_1 + 1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          uVar2 = *(undefined4 *)(*param_4 + 4);
          uVar3 = *(undefined4 *)(*param_4 + 8);
          param_4 = param_4[1];
          *(undefined4 *)(puVar22 + -1) = *(undefined4 *)puVar34;
          *(undefined4 *)((longlong)puVar22 + -4) = uVar2;
          *(undefined4 *)puVar22 = uVar3;
          puVar22 = (undefined8 *)((longlong)puVar22 + 0xc);
          puVar15 = (uint *)((-8 - (longlong)param_1) + (longlong)puVar22);
          if ((uint *)((longlong)param_2 - 0xbU) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 5:
    if ((uint *)0xb < param_2) {
      if (param_2 != (uint *)0xb) {
        puVar22 = param_1 + 1;
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d4d0);
          fVar40 = SUB164(auVar44,0);
          fVar42 = SUB164(auVar44 >> 0x20,0);
          fVar41 = SUB164(auVar44 >> 0x60,0);
          auVar44 = CONCAT412(-(uint)(2.147484e+09 <= in_xmmTmp2_Dd) & 0x80000000 ^
                              (int)(fVar41 - (float)(-(uint)(2.147484e+09 <= in_xmmTmp2_Dd) &
                                                    0x4f000000)),
                              CONCAT48(-(uint)(2.147484e+09 <= fVar41) & 0x80000000 ^
                                       (int)(SUB164(auVar44 >> 0x40,0) -
                                            (float)(-(uint)(2.147484e+09 <= fVar41) & 0x4f000000)),
                                       CONCAT44(-(uint)(2.147484e+09 <= fVar42) & 0x80000000 ^
                                                (int)(fVar42 - (float)(-(uint)(2.147484e+09 <=
                                                                              fVar42) & 0x4f000000))
                                                ,-(uint)(2.147484e+09 <= fVar40) & 0x80000000 ^
                                                 (int)(fVar40 - (float)(-(uint)(2.147484e+09 <=
                                                                               fVar40) & 0x4f000000)
                                                      )))) |
                    CONCAT412(-(uint)(4.294967e+09 < in_xmmTmp2_Dd),
                              CONCAT48(-(uint)(4.294967e+09 < fVar41),
                                       CONCAT44(-(uint)(4.294967e+09 < fVar42),
                                                -(uint)(4.294967e+09 < fVar40))));
          *(int *)(puVar22 + -1) = SUB164(auVar44,0);
          *(int *)((longlong)puVar22 + -4) = SUB164(auVar44 >> 0x20,0);
          *(int *)puVar22 = SUB164(auVar44 >> 0x40,0);
          puVar22 = (undefined8 *)((longlong)puVar22 + 0xc);
          puVar15 = (uint *)((longlong)puVar22 + (-8 - (longlong)param_1));
          if ((uint *)((longlong)param_2 - 0xbU) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 6:
    if ((uint *)0xb < param_2) {
      if (param_2 != (uint *)0xb) {
        puVar22 = param_1 + 1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          fVar40 = *(float *)(*param_4 + 4);
          fVar42 = *(float *)(*param_4 + 8);
          uVar11 = -(uint)(2.147484e+09 < *(float *)*param_4);
          uVar28 = -(uint)(2.147484e+09 < *(float *)(*param_4 + 4));
          uVar10 = -(uint)(2.147484e+09 < *(float *)(*param_4 + 8));
          param_4 = param_4[1];
          *(uint *)(puVar22 + -1) = uVar11 & 0x7fffffff | ~uVar11 & (int)*(float *)puVar34;
          *(uint *)((longlong)puVar22 + -4) = uVar28 & 0x7fffffff | ~uVar28 & (int)fVar40;
          *(uint *)puVar22 = uVar10 & 0x7fffffff | ~uVar10 & (int)fVar42;
          puVar22 = (undefined8 *)((longlong)puVar22 + 0xc);
          puVar15 = (uint *)((longlong)puVar22 + (-8 - (longlong)param_1));
          if ((uint *)((longlong)param_2 - 0xbU) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 8:
    if ((uint *)0x7 < param_2) {
      puVar31 = (uint *)((longlong)param_2 + -7);
      if (puVar31 != (uint *)0x0) {
        puVar19 = (undefined2 *)((longlong)param_1 + 4);
        while (param_4 < pauVar23) {
          uVar11 = *(uint *)(*param_4 + 8);
          uVar28 = *(uint *)(*param_4 + 0xc);
          uVar10 = FUN_18000ea20(*(uint *)*param_4);
          puVar19[-2] = (short)uVar10;
          uVar10 = FUN_18000ea20(extraout_XMM0_Db);
          puVar19[-1] = (short)uVar10;
          uVar11 = FUN_18000ea20(uVar11);
          *puVar19 = (short)uVar11;
          uVar11 = FUN_18000ea20(uVar28);
          puVar19[1] = (short)uVar11;
          param_4 = param_4[1];
          puVar19 = puVar19 + 4;
          puVar15 = (uint *)((-4 - (longlong)param_1) + (longlong)puVar19);
          if (puVar31 <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 9:
    if ((uint *)0x7 < param_2) {
      if (param_2 != (uint *)0x7) {
        puVar19 = (undefined2 *)((longlong)param_1 + 4);
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          puVar19[-2] = (short)(int)(SUB164(auVar44,0) * 65535.0);
          puVar19[-1] = (short)(int)(SUB164(auVar44 >> 0x20,0) * 65535.0);
          *puVar19 = (short)(int)(SUB164(auVar44 >> 0x40,0) * 65535.0);
          puVar19[1] = (short)(int)(SUB164(auVar44 >> 0x60,0) * 65535.0);
          puVar19 = puVar19 + 4;
          puVar15 = (uint *)((longlong)puVar19 + (-4 - (longlong)param_1));
          if ((uint *)((longlong)param_2 + -7) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 10:
    if ((uint *)0x7 < param_2) {
      if (param_2 != (uint *)0x7) {
        puVar19 = (undefined2 *)((longlong)param_1 + 4);
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005f930);
          puVar19[-2] = (short)(int)SUB164(auVar44,0);
          puVar19[-1] = (short)(int)SUB164(auVar44 >> 0x20,0);
          *puVar19 = (short)(int)SUB164(auVar44 >> 0x40,0);
          puVar19[1] = (short)(int)SUB164(auVar44 >> 0x60,0);
          puVar19 = puVar19 + 4;
          puVar15 = (uint *)((longlong)puVar19 + (-4 - (longlong)param_1));
          if ((uint *)((longlong)param_2 + -7) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0xb:
    if ((uint *)0x7 < param_2) {
      if (param_2 != (uint *)0x7) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d430);
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          auVar44 = CONCAT412((int)(SUB164(auVar44 >> 0x60,0) * 32767.0),
                              CONCAT48((int)(SUB164(auVar44 >> 0x40,0) * 32767.0),
                                       CONCAT44((int)(SUB164(auVar44 >> 0x20,0) * 32767.0),
                                                (int)(SUB164(auVar44,0) * 32767.0))));
          auVar44 = packssdw(auVar44,auVar44);
          *puVar22 = SUB168(auVar44,0);
          puVar22 = puVar22 + 1;
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -7) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0xc:
    if ((uint *)0x7 < param_2) {
      if (param_2 != (uint *)0x7) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005f920);
          auVar44 = minps(auVar44,_DAT_18005f850);
          auVar44 = CONCAT412((int)SUB164(auVar44 >> 0x60,0),
                              CONCAT48((int)SUB164(auVar44 >> 0x40,0),
                                       CONCAT44((int)SUB164(auVar44 >> 0x20,0),
                                                (int)SUB164(auVar44,0))));
          auVar44 = packssdw(auVar44,auVar44);
          *puVar22 = SUB168(auVar44,0);
          puVar22 = puVar22 + 1;
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -7) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0xe:
    if ((uint *)0x7 < param_2) {
      if (param_2 != (uint *)0x7) {
        uVar21 = 0;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          uVar2 = *(undefined4 *)(*param_4 + 4);
          param_4 = param_4[1];
          *(undefined4 *)(uVar21 + (longlong)param_1) = *(undefined4 *)puVar34;
          *(undefined4 *)(uVar21 + 4 + (longlong)param_1) = uVar2;
          uVar21 = uVar21 + 8;
          if ((longlong)param_2 - 7U <= uVar21) {
            return 1;
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0xf:
    if ((uint *)0x7 < param_2) {
      if (param_2 != (uint *)0x7) {
        uVar21 = 0;
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d4d0);
          fVar40 = SUB164(auVar44,0);
          fVar42 = SUB164(auVar44 >> 0x20,0);
          *(uint *)(uVar21 + (longlong)param_1) =
               -(uint)(2.147484e+09 <= fVar40) & 0x80000000 ^
               (int)(fVar40 - (float)(-(uint)(2.147484e+09 <= fVar40) & 0x4f000000)) |
               -(uint)(4.294967e+09 < fVar40);
          *(uint *)(uVar21 + 4 + (longlong)param_1) =
               -(uint)(2.147484e+09 <= fVar42) & 0x80000000 ^
               (int)(fVar42 - (float)(-(uint)(2.147484e+09 <= fVar42) & 0x4f000000)) |
               -(uint)(4.294967e+09 < fVar42);
          uVar21 = uVar21 + 8;
          if ((longlong)param_2 - 7U <= uVar21) {
            return 1;
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x10:
    if ((uint *)0x7 < param_2) {
      if (param_2 != (uint *)0x7) {
        uVar21 = 0;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          fVar40 = *(float *)(*param_4 + 4);
          uVar11 = -(uint)(2.147484e+09 < *(float *)*param_4);
          uVar28 = -(uint)(2.147484e+09 < *(float *)(*param_4 + 4));
          param_4 = param_4[1];
          *(uint *)(uVar21 + (longlong)param_1) =
               uVar11 & 0x7fffffff | ~uVar11 & (int)*(float *)puVar34;
          *(uint *)(uVar21 + 4 + (longlong)param_1) = uVar28 & 0x7fffffff | ~uVar28 & (int)fVar40;
          uVar21 = uVar21 + 8;
          if ((longlong)param_2 - 7U <= uVar21) {
            return 1;
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x12:
    if ((uint *)0x7 < param_2) {
      if (param_2 != (uint *)0x7) {
        puVar19 = (undefined2 *)((longlong)param_1 + 6);
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          fVar40 = *(float *)(*param_4 + 4);
          _local_58 = *param_4;
          param_4 = param_4[1];
          param_6 = 0.0;
          *(undefined4 *)(puVar19 + -3) = *(undefined4 *)puVar34;
          pfVar12 = (float *)(local_58 + 4);
          if (fVar40 <= 0.0) {
            pfVar12 = &param_6;
          }
          fVar40 = *pfVar12;
          if (255.0 <= *pfVar12) {
            fVar40 = 255.0;
          }
          *puVar19 = 0;
          *(undefined *)((longlong)puVar19 + -1) = 0;
          *(char *)(puVar19 + -1) = (char)(longlong)fVar40;
          puVar19 = puVar19 + 4;
          puVar15 = (uint *)((-6 - (longlong)param_1) + (longlong)puVar19);
          if ((uint *)((longlong)param_2 - 7U) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x16:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          *(uint *)puVar22 =
               ((int)(SUB164(auVar44 >> 0x60,0) * 1.610613e+09) & 0x60000000U |
               (int)(SUB164(auVar44 >> 0x20,0) * 523776.0) & 0x7fe00U) * 2 |
               (int)(SUB164(auVar44 >> 0x40,0) * 1.072693e+09) & 0x3ff00000U |
               (int)(SUB164(auVar44,0) * 1023.0) & 0x3ffU;
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -3) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x17:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005f900);
          *(uint *)puVar22 =
               ((int)(SUB164(auVar44 >> 0x60,0) * 5.368709e+08) & 0x60000000U |
               (int)(SUB164(auVar44 >> 0x20,0) * 512.0) & 0x7fe00U) * 2 |
               (int)(SUB164(auVar44 >> 0x40,0) * 1048576.0) & 0x3ff00000U |
               (int)(SUB164(auVar44,0) * 1.0) & 0x3ffU;
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -3) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x18:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          FUN_18000e840((uint *)puVar22,*(undefined8 *)*param_4);
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          param_4 = param_4[1];
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 - 3U) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x1a:
  case 0x1b:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          *(uint *)puVar22 =
               ((int)(SUB164(auVar44 >> 0x60,0) * 2.139095e+09) & 0x7f800000U |
               (int)(SUB164(auVar44 >> 0x20,0) * 32640.0) & 0x7f80U) * 2 |
               (int)(SUB164(auVar44 >> 0x40,0) * 1.671168e+07) & 0xff0000U |
               (int)(SUB164(auVar44,0) * 255.0) & 0xffU;
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -3) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x1c:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005f830);
          *(uint *)puVar22 =
               ((int)(SUB164(auVar44 >> 0x60,0) * 8388608.0) & 0x7f800000U |
               (int)(SUB164(auVar44 >> 0x20,0) * 128.0) & 0x7f80U) * 2 |
               (int)(SUB164(auVar44 >> 0x40,0) * 65536.0) & 0xff0000U |
               (int)(SUB164(auVar44,0) * 1.0) & 0xffU;
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -3) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x1d:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d430);
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          *(uint *)puVar22 =
               (int)(SUB164(auVar44 >> 0x60,0) * 2.130706e+09) & 0xff000000U |
               (int)(SUB164(auVar44 >> 0x20,0) * 32512.0) & 0xff00U |
               (int)(SUB164(auVar44 >> 0x40,0) * 8323072.0) & 0xff0000U |
               (int)(SUB164(auVar44,0) * 127.0) & 0xffU;
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -3) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x1e:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005f810);
          auVar44 = minps(auVar44,_DAT_18005f820);
          *(uint *)puVar22 =
               (int)(SUB164(auVar44 >> 0x60,0) * 1.677722e+07) & 0xff000000U |
               (int)(SUB164(auVar44 >> 0x20,0) * 256.0) & 0xff00U |
               (int)(SUB164(auVar44 >> 0x40,0) * 65536.0) & 0xff0000U |
               (int)(SUB164(auVar44,0) * 1.0) & 0xffU;
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -3) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x20:
    if ((uint *)0x3 < param_2) {
      uVar21 = (longlong)param_2 - 3;
      if (uVar21 != 0) {
        uVar25 = 0;
        while (param_4 < pauVar23) {
          uVar11 = *(uint *)(*param_4 + 4);
          uVar28 = FUN_18000ea20(*(uint *)*param_4);
          *(short *)(uVar25 + (longlong)param_1) = (short)uVar28;
          uVar11 = FUN_18000ea20(uVar11);
          puVar15 = (uint *)CONCAT44(extraout_var,uVar11);
          *(short *)((longlong)param_1 + uVar25 + 2) = (short)uVar11;
          param_4 = param_4[1];
          uVar25 = uVar25 + 4;
          if (uVar21 <= uVar25) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x21:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        uVar21 = 0;
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          iVar37 = (int)(SUB164(auVar44 >> 0x20,0) * 65535.0);
          *(short *)(uVar21 + (longlong)param_1) = (short)(int)(SUB164(auVar44,0) * 65535.0);
          uVar36 = (ushort)iVar37;
          puVar15 = (uint *)(ulonglong)uVar36;
          *(ushort *)(uVar21 + 2 + (longlong)param_1) = uVar36;
          uVar21 = uVar21 + 4;
          if ((longlong)param_2 - 3U <= uVar21) {
            return CONCAT71((uint7)(byte)((uint)iVar37 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x22:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        uVar21 = 0;
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005f930);
          iVar37 = (int)SUB164(auVar44 >> 0x20,0);
          *(short *)(uVar21 + (longlong)param_1) = (short)(int)SUB164(auVar44,0);
          uVar36 = (ushort)iVar37;
          puVar15 = (uint *)(ulonglong)uVar36;
          *(ushort *)(uVar21 + 2 + (longlong)param_1) = uVar36;
          uVar21 = uVar21 + 4;
          if ((longlong)param_2 - 3U <= uVar21) {
            return CONCAT71((uint7)(byte)((uint)iVar37 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x23:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d430);
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          auVar44 = CONCAT412((int)(SUB164(auVar44 >> 0x60,0) * 32767.0),
                              CONCAT48((int)(SUB164(auVar44 >> 0x40,0) * 32767.0),
                                       CONCAT44((int)(SUB164(auVar44 >> 0x20,0) * 32767.0),
                                                (int)(SUB164(auVar44,0) * 32767.0))));
          auVar44 = packssdw(auVar44,auVar44);
          *(int *)puVar22 = SUB164(auVar44,0);
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -3) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x24:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005f920);
          auVar44 = minps(auVar44,_DAT_18005f850);
          auVar44 = CONCAT412((int)SUB164(auVar44 >> 0x60,0),
                              CONCAT48((int)SUB164(auVar44 >> 0x40,0),
                                       CONCAT44((int)SUB164(auVar44 >> 0x20,0),
                                                (int)SUB164(auVar44,0))));
          auVar44 = packssdw(auVar44,auVar44);
          *(int *)puVar22 = SUB164(auVar44,0);
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -3) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x26:
  case 0x27:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          param_4 = param_4[1];
          *(undefined4 *)puVar22 = *(undefined4 *)puVar34;
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -3) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x28:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          puVar5 = *param_4;
          puVar6 = *param_4;
          puVar7 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(CONCAT412(*(float *)(puVar7 + 0xc) * 1.0,
                                    CONCAT48(*(float *)(puVar6 + 8) * 1.0,
                                             CONCAT44(*(float *)(puVar5 + 4) * 1.0,
                                                      *(float *)puVar34 * 1.0))),_DAT_18005d4d0);
          fVar40 = SUB164(auVar44,0);
          *(uint *)puVar22 =
               -(uint)(2.147484e+09 <= fVar40) & 0x80000000 ^
               (int)(fVar40 - (float)(-(uint)(2.147484e+09 <= fVar40) & 0x4f000000)) |
               -(uint)(4.294967e+09 < fVar40);
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -3) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x29:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          fVar40 = *(float *)*param_4 * 1.0;
          param_4 = param_4[1];
          uVar11 = -(uint)(2.147484e+09 < fVar40);
          *(uint *)puVar22 = ~uVar11 & (int)fVar40 | uVar11 & 0x7fffffff;
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -3) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x2b:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          auVar44 = maxps(ZEXT1216(ZEXT812(0) >> 0x20) << 0x20,*param_4);
          param_4 = param_4[1];
          auVar44 = minps(auVar44,_DAT_18005f840);
          *(uint *)puVar22 =
               (uint)(longlong)(SUB164(auVar44,0) * 1.677722e+07) & 0xffffff |
               (int)(longlong)SUB164(auVar44 >> 0x20,0) << 0x18;
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 - 3U) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x2f:
    if ((uint *)0x1 < param_2) {
      if (param_2 != (uint *)0x1) {
        uVar21 = 0;
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          fVar40 = SUB164(auVar44,0) * 255.0 + 0.5;
          fVar42 = SUB164(auVar44 >> 0x20,0) * 255.0 + 0.5;
          uVar11 = -(uint)(((uint)fVar40 & 0x7fffffff) < 0x4b000000);
          uVar28 = -(uint)(((uint)fVar42 & 0x7fffffff) < 0x4b000000);
          *(char *)(uVar21 + (longlong)param_1) =
               (char)(longlong)(float)((uint)(float)(int)fVar40 & uVar11 | ~uVar11 & (uint)fVar40);
          puVar15 = (uint *)(longlong)
                            (float)((uint)(float)(int)fVar42 & uVar28 | ~uVar28 & (uint)fVar42);
          *(char *)((longlong)param_1 + uVar21 + 1) = (char)puVar15;
          uVar21 = uVar21 + 2;
          if ((longlong)param_2 - 1U <= uVar21) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x30:
    if ((uint *)0x1 < param_2) {
      if (param_2 != (uint *)0x1) {
        uVar21 = 0;
        while (param_4 < pauVar23) {
          auVar44 = maxps(ZEXT816(0),*param_4);
          param_4 = param_4[1];
          auVar44 = minps(auVar44,_DAT_18005f830);
          fVar41 = SUB164(auVar44,0);
          fVar43 = SUB164(auVar44 >> 0x20,0);
          uVar11 = -(uint)((float)((uint)fVar41 & 0x7fffffff) <= 8388608.0);
          uVar28 = -(uint)((float)((uint)fVar43 & 0x7fffffff) <= 8388608.0);
          fVar40 = (float)((uint)fVar41 & 0x80000000 | 0x4b000000);
          fVar42 = (float)((uint)fVar43 & 0x80000000 | 0x4b000000);
          *(char *)(uVar21 + (longlong)param_1) =
               (char)(longlong)
                     (float)((uint)((fVar40 + fVar41) - fVar40) & uVar11 ^ ~uVar11 & (uint)fVar41);
          puVar15 = (uint *)(longlong)
                            (float)((uint)((fVar42 + fVar43) - fVar42) & uVar28 ^
                                   ~uVar28 & (uint)fVar43);
          *(char *)(uVar21 + 1 + (longlong)param_1) = (char)puVar15;
          uVar21 = uVar21 + 2;
          if ((longlong)param_2 - 1U <= uVar21) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x31:
    if ((uint *)0x1 < param_2) {
      if (param_2 != (uint *)0x1) {
        uVar21 = 0;
        while (param_4 < pauVar23) {
          auVar44 = maxps(_DAT_18005d430,*param_4);
          param_4 = param_4[1];
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          fVar41 = SUB164(auVar44,0) * 127.0;
          fVar43 = SUB164(auVar44 >> 0x20,0) * 127.0;
          uVar11 = -(uint)((float)((uint)fVar41 & 0x7fffffff) <= 8388608.0);
          uVar28 = -(uint)((float)((uint)fVar43 & 0x7fffffff) <= 8388608.0);
          fVar40 = (float)((uint)fVar41 & 0x80000000 | 0x4b000000);
          fVar42 = (float)((uint)fVar43 & 0x80000000 | 0x4b000000);
          *(char *)(uVar21 + (longlong)param_1) =
               (char)(int)(float)((uint)((fVar40 + fVar41) - fVar40) & uVar11 ^
                                 ~uVar11 & (uint)fVar41);
          uVar11 = (uint)(float)((uint)((fVar42 + fVar43) - fVar42) & uVar28 ^
                                ~uVar28 & (uint)fVar43);
          puVar15 = (uint *)(ulonglong)uVar11;
          *(char *)((longlong)param_1 + uVar21 + 1) = (char)uVar11;
          uVar21 = uVar21 + 2;
          if ((longlong)param_2 - 1U <= uVar21) {
            return CONCAT71((uint7)(uint3)(uVar11 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x32:
    if ((uint *)0x1 < param_2) {
      if (param_2 != (uint *)0x1) {
        uVar21 = 0;
        while (param_4 < pauVar23) {
          auVar44 = maxps(_DAT_18005f810,*param_4);
          param_4 = param_4[1];
          auVar44 = minps(auVar44,_DAT_18005f820);
          fVar41 = SUB164(auVar44,0);
          fVar43 = SUB164(auVar44 >> 0x20,0);
          uVar11 = -(uint)((float)((uint)fVar41 & 0x7fffffff) <= 8388608.0);
          uVar28 = -(uint)((float)((uint)fVar43 & 0x7fffffff) <= 8388608.0);
          fVar40 = (float)((uint)fVar41 & 0x80000000 | 0x4b000000);
          fVar42 = (float)((uint)fVar43 & 0x80000000 | 0x4b000000);
          *(char *)(uVar21 + (longlong)param_1) =
               (char)(int)(float)((uint)((fVar40 + fVar41) - fVar40) & uVar11 ^
                                 ~uVar11 & (uint)fVar41);
          uVar11 = (uint)(float)((uint)((fVar42 + fVar43) - fVar42) & uVar28 ^
                                ~uVar28 & (uint)fVar43);
          puVar15 = (uint *)(ulonglong)uVar11;
          *(char *)((longlong)param_1 + uVar21 + 1) = (char)uVar11;
          uVar21 = uVar21 + 2;
          if ((longlong)param_2 - 1U <= uVar21) {
            return CONCAT71((uint7)(uint3)(uVar11 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x34:
    if ((uint *)0x1 < param_2) {
      puVar31 = (uint *)((longlong)param_2 + -1);
      if (puVar31 != (uint *)0x0) {
        lVar33 = -(longlong)param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          param_4 = param_4[1];
          uVar11 = FUN_18000ea20(*(uint *)puVar34);
          *(short *)param_1 = (short)uVar11;
          param_1 = (undefined8 *)((longlong)param_1 + 2);
          puVar15 = (uint *)(lVar33 + (longlong)param_1);
          if (puVar31 <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x35:
  case 0x36:
    if ((uint *)0x1 < param_2) {
      if (param_2 != (uint *)0x1) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          param_4 = param_4[1];
          local_res20 = (uint *)((ulonglong)local_res20 & 0xffffffff00000000 |
                                (ulonglong)(uint)*(float *)puVar34);
          param_6 = 1.0;
          puVar13 = (undefined8 *)&param_6;
          if (*(float *)puVar34 <= 1.0) {
            puVar13 = &local_res20;
          }
          fVar40 = *(float *)puVar13;
          if (fVar40 < 0.0) {
            fVar40 = 0.0;
          }
          *(short *)puVar22 = (short)(longlong)(fVar40 * 65535.0 + 0.5);
          puVar22 = (undefined8 *)((longlong)puVar22 + 2);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -1) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x37:
    if ((uint *)0x1 < param_2) {
      if (param_2 != (uint *)0x1) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          param_4 = param_4[1];
          local_res20 = (uint *)((ulonglong)local_res20 & 0xffffffff00000000 |
                                (ulonglong)(uint)*(float *)puVar34);
          param_6 = 65535.0;
          puVar13 = (undefined8 *)&param_6;
          if (*(float *)puVar34 <= 65535.0) {
            puVar13 = &local_res20;
          }
          fVar40 = *(float *)puVar13;
          if (fVar40 < 0.0) {
            fVar40 = 0.0;
          }
          *(short *)puVar22 = (short)(longlong)fVar40;
          puVar22 = (undefined8 *)((longlong)puVar22 + 2);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -1) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x38:
    if ((uint *)0x1 < param_2) {
      if (param_2 != (uint *)0x1) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          param_4 = param_4[1];
          local_res20 = (uint *)((ulonglong)local_res20 & 0xffffffff00000000 |
                                (ulonglong)(uint)*(float *)puVar34);
          param_6 = 1.0;
          puVar13 = (undefined8 *)&param_6;
          if (*(float *)puVar34 <= 1.0) {
            puVar13 = &local_res20;
          }
          fVar40 = *(float *)puVar13;
          if (*(float *)puVar13 < -1.0) {
            fVar40 = -1.0;
          }
          *(short *)puVar22 = (short)(longlong)(fVar40 * 32767.0);
          puVar22 = (undefined8 *)((longlong)puVar22 + 2);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -1) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x39:
    if ((uint *)0x1 < param_2) {
      if (param_2 != (uint *)0x1) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          param_4 = param_4[1];
          local_res20 = (uint *)((ulonglong)local_res20 & 0xffffffff00000000 |
                                (ulonglong)(uint)*(float *)puVar34);
          param_6 = 32767.0;
          puVar13 = (undefined8 *)&param_6;
          if (*(float *)puVar34 <= 32767.0) {
            puVar13 = &local_res20;
          }
          fVar40 = *(float *)puVar13;
          if (*(float *)puVar13 < -32767.0) {
            fVar40 = -32767.0;
          }
          *(short *)puVar22 = (short)(int)fVar40;
          puVar22 = (undefined8 *)((longlong)puVar22 + 2);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -1) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x3b:
    if (param_2 != (uint *)0x0) {
      if (param_2 != (uint *)0x0) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          param_4 = param_4[1];
          local_res20 = (uint *)((ulonglong)local_res20 & 0xffffffff00000000 |
                                (ulonglong)(uint)*(float *)puVar34);
          param_6 = 1.0;
          puVar13 = (undefined8 *)&param_6;
          if (*(float *)puVar34 <= 1.0) {
            puVar13 = &local_res20;
          }
          fVar40 = *(float *)puVar13;
          if (fVar40 < 0.0) {
            fVar40 = 0.0;
          }
          *(char *)puVar22 = (char)(longlong)(fVar40 * 255.0);
          puVar22 = (undefined8 *)((longlong)puVar22 + 1);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if (param_2 <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x3c:
    if (param_2 != (uint *)0x0) {
      if (param_2 != (uint *)0x0) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          param_4 = param_4[1];
          local_res20 = (uint *)((ulonglong)local_res20 & 0xffffffff00000000 |
                                (ulonglong)(uint)*(float *)puVar34);
          param_6 = 255.0;
          puVar13 = (undefined8 *)&param_6;
          if (*(float *)puVar34 <= 255.0) {
            puVar13 = &local_res20;
          }
          fVar40 = *(float *)puVar13;
          if (fVar40 < 0.0) {
            fVar40 = 0.0;
          }
          *(char *)puVar22 = (char)(longlong)fVar40;
          puVar22 = (undefined8 *)((longlong)puVar22 + 1);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if (param_2 <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x3d:
    if (param_2 != (uint *)0x0) {
      if (param_2 != (uint *)0x0) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          param_4 = param_4[1];
          local_res20 = (uint *)((ulonglong)local_res20 & 0xffffffff00000000 |
                                (ulonglong)(uint)*(float *)puVar34);
          param_6 = 1.0;
          puVar13 = (undefined8 *)&param_6;
          if (*(float *)puVar34 <= 1.0) {
            puVar13 = &local_res20;
          }
          fVar40 = *(float *)puVar13;
          if (*(float *)puVar13 < -1.0) {
            fVar40 = -1.0;
          }
          *(char *)puVar22 = (char)(int)(fVar40 * 127.0);
          puVar22 = (undefined8 *)((longlong)puVar22 + 1);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if (param_2 <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x3e:
    if (param_2 != (uint *)0x0) {
      if (param_2 != (uint *)0x0) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          param_4 = param_4[1];
          local_res20 = (uint *)((ulonglong)local_res20 & 0xffffffff00000000 |
                                (ulonglong)(uint)*(float *)puVar34);
          param_6 = 127.0;
          puVar13 = (undefined8 *)&param_6;
          if (*(float *)puVar34 <= 127.0) {
            puVar13 = &local_res20;
          }
          fVar40 = *(float *)puVar13;
          if (*(float *)puVar13 < -127.0) {
            fVar40 = -127.0;
          }
          *(char *)puVar22 = (char)(int)fVar40;
          puVar22 = (undefined8 *)((longlong)puVar22 + 1);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if (param_2 <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x3f:
    if (param_2 != (uint *)0x0) {
      if (param_2 != (uint *)0x0) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          param_4 = param_4[1];
          local_res20 = (uint *)((ulonglong)local_res20 & 0xffffffff00000000 |
                                (ulonglong)(uint)*(float *)(puVar34 + 0xc));
          param_6 = 1.0;
          puVar13 = (undefined8 *)&param_6;
          if (*(float *)(puVar34 + 0xc) <= 1.0) {
            puVar13 = &local_res20;
          }
          fVar40 = *(float *)puVar13;
          if (fVar40 < 0.0) {
            fVar40 = 0.0;
          }
          *(char *)puVar22 = (char)(longlong)(fVar40 * 255.0);
          puVar22 = (undefined8 *)((longlong)puVar22 + 1);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if (param_2 <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x40:
    if (param_2 != (uint *)0x0) {
      if (param_2 != (uint *)0x0) {
        do {
          uVar11 = 0;
          lVar33 = 8;
          do {
            uVar17 = (undefined)uVar11;
            if (pauVar23 <= param_4) break;
            auVar44 = *param_4;
            param_4 = param_4[1];
            if (0.25 < SUB164(auVar44,0)) {
              uVar28 = (int)lVar33 - 1;
              puVar15 = (uint *)(ulonglong)uVar28;
              uVar11 = uVar11 & 0xff | 1 << (uVar28 & 0x1f);
            }
            uVar17 = (undefined)uVar11;
            lVar33 = lVar33 + -1;
          } while (lVar33 != 0);
          *(undefined *)param_1 = uVar17;
          param_1 = (undefined8 *)((longlong)param_1 + 1);
          param_2 = (uint *)((longlong)param_2 + -1);
          if (param_2 == (uint *)0x0) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        } while( true );
      }
      goto LAB_18000d895;
    }
    break;
  case 0x41:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          FUN_18000e700((uint *)puVar22,*(undefined8 *)*param_4);
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          param_4 = param_4[1];
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 - 3U) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x42:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          pauVar24 = param_4[1];
          if (pauVar24 < pauVar23) {
            uVar2 = *(undefined4 *)(param_4[1] + 4);
            uVar21 = SUB128(CONCAT84(SUB168(in_XMM0 >> 0x40,0),uVar2),0);
            puVar34 = local_58;
            pauVar24 = param_4[2];
            _local_58 = CONCAT412(uVar2,CONCAT48(uVar2,uVar21 << 0x20 | uVar21 & 0xffffffff));
          }
          else {
            puVar34 = local_48;
            _local_48 = ZEXT816(0);
          }
          auVar44 = maxps(ZEXT1216(*(undefined (*) [12])*param_4) |
                          CONCAT412(*(undefined4 *)(puVar34 + 0xc),ZEXT812(0)),_DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          auVar44 = CONCAT412((int)(SUB164(auVar44 >> 0x60,0) * 2.139095e+09),
                              CONCAT48((int)(SUB164(auVar44 >> 0x40,0) * 1.671168e+07),
                                       CONCAT44((int)(SUB164(auVar44 >> 0x20,0) * 32640.0),
                                                (int)(SUB164(auVar44,0) * 255.0)))) & _DAT_18005f890
          ;
          auVar44 = CONCAT412(SUB164(auVar44 >> 0x60,0),
                              CONCAT48(SUB164(auVar44 >> 0x40,0),SUB168(auVar44 >> 0x40,0))) |
                    auVar44;
          iVar37 = SUB164(auVar44 >> 0x20,0);
          in_XMM0 = CONCAT412(iVar37 * 2,CONCAT48(iVar37 * 2,CONCAT44(iVar37 * 2,iVar37 * 2))) |
                    auVar44;
          *(int *)puVar22 = SUB164(in_XMM0,0);
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          param_4 = pauVar24;
          if ((uint *)((longlong)param_2 + -3) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x43:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          pauVar24 = param_4[1];
          if (pauVar24 < pauVar23) {
            uVar2 = *(undefined4 *)(param_4[1] + 4);
            uVar21 = SUB128(CONCAT84(SUB168(in_XMM0 >> 0x40,0),uVar2),0);
            puVar15 = (uint *)local_58;
            pauVar24 = param_4[2];
            _local_58 = CONCAT412(uVar2,CONCAT48(uVar2,uVar21 << 0x20 | uVar21 & 0xffffffff));
          }
          else {
            puVar15 = (uint *)local_48;
            _local_48 = ZEXT816(0);
          }
          auVar44 = maxps(CONCAT412(~uRam00000001800651dc & puVar15[3],
                                    CONCAT48(~uRam00000001800651d8 & puVar15[2],
                                             CONCAT44(~uRam00000001800651d4 & puVar15[1],
                                                      ~_DAT_1800651d0 & *puVar15))) |
                          CONCAT412(*(uint *)(*param_4 + 8) & uRam00000001800651dc,
                                    CONCAT48(*(uint *)(*param_4 + 0xc) & uRam00000001800651d8,
                                             CONCAT44(*(uint *)*param_4 & uRam00000001800651d4,
                                                      *(uint *)(*param_4 + 4) & _DAT_1800651d0))),
                          _DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          auVar44 = CONCAT412((int)(SUB164(auVar44 >> 0x60,0) * 2.139095e+09),
                              CONCAT48((int)(SUB164(auVar44 >> 0x40,0) * 1.671168e+07),
                                       CONCAT44((int)(SUB164(auVar44 >> 0x20,0) * 32640.0),
                                                (int)(SUB164(auVar44,0) * 255.0)))) & _DAT_18005f890
          ;
          auVar44 = CONCAT412(SUB164(auVar44 >> 0x60,0),
                              CONCAT48(SUB164(auVar44 >> 0x40,0),SUB168(auVar44 >> 0x40,0))) |
                    auVar44;
          iVar37 = SUB164(auVar44 >> 0x20,0);
          in_XMM0 = CONCAT412(iVar37 * 2,CONCAT48(iVar37 * 2,CONCAT44(iVar37 * 2,iVar37 * 2))) |
                    auVar44;
          *(int *)puVar22 = SUB164(in_XMM0,0);
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          param_4 = pauVar24;
          if ((uint *)((longlong)param_2 + -3) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x53:
    if ((uint *)0x1 < param_2) {
      if (param_2 != (uint *)0x1) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          puVar5 = *param_4;
          puVar6 = *param_4;
          puVar7 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(CONCAT412(*(float *)(puVar7 + 0xc) * fRam00000001800651cc,
                                    CONCAT48(*(float *)puVar34 * fRam00000001800651c8,
                                             CONCAT44(*(float *)(puVar5 + 4) * fRam00000001800651c4,
                                                      *(float *)(puVar6 + 8) * _DAT_1800651c0))),
                          _DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005f800);
          *(ushort *)puVar22 =
               ((ushort)(int)SUB164(auVar44 >> 0x20,0) & 0x3f |
               (short)(int)SUB164(auVar44 >> 0x40,0) << 6) << 5 |
               (ushort)(int)SUB164(auVar44,0) & 0x1f;
          puVar22 = (undefined8 *)((longlong)puVar22 + 2);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 - 1U) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x54:
    if ((uint *)0x1 < param_2) {
      if (param_2 != (uint *)0x1) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          puVar5 = *param_4;
          puVar6 = *param_4;
          puVar7 = *param_4;
          param_4 = param_4[1];
          fVar40 = *(float *)(puVar7 + 0xc) * fRam00000001800651bc;
          auVar44 = maxps(CONCAT412(fVar40,CONCAT48(*(float *)puVar34 * fRam00000001800651b8,
                                                    CONCAT44(*(float *)(puVar5 + 4) *
                                                             fRam00000001800651b4,
                                                             *(float *)(puVar6 + 8) * _DAT_1800651b0
                                                            ))),_DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005f7f0);
          *(ushort *)puVar22 =
               ((ushort)(0.0 < fVar40) << 10 | (ushort)(int)SUB164(auVar44 >> 0x20,0) & 0x1f) << 5 |
               (ushort)(int)SUB164(auVar44,0) & 0x1f |
               ((ushort)(int)SUB164(auVar44 >> 0x40,0) & 0x1f) << 10;
          puVar22 = (undefined8 *)((longlong)puVar22 + 2);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 - 1U) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x55:
  case 0x59:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          puVar5 = *param_4;
          puVar6 = *param_4;
          puVar7 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(CONCAT412(*(undefined4 *)(puVar7 + 0xc),
                                    CONCAT48(*(undefined4 *)puVar34,
                                             CONCAT44(*(undefined4 *)(puVar5 + 4),
                                                      *(undefined4 *)(puVar6 + 8)))),_DAT_18005d4d0)
          ;
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          *(uint *)puVar22 =
               ((int)(SUB164(auVar44 >> 0x60,0) * 2.139095e+09) & 0x7f800000U |
               (int)(SUB164(auVar44 >> 0x20,0) * 32640.0) & 0x7f80U) * 2 |
               (int)(SUB164(auVar44 >> 0x40,0) * 1.671168e+07) & 0xff0000U |
               (int)(SUB164(auVar44,0) * 255.0) & 0xffU;
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -3) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x56:
  case 0x5b:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          puVar5 = *param_4;
          puVar6 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(ZEXT1216(CONCAT48(*(undefined4 *)puVar34,
                                            CONCAT44(*(undefined4 *)(puVar5 + 4),
                                                     *(undefined4 *)(puVar6 + 8)))) |
                          CONCAT412(0x3f800000,ZEXT812(0)),_DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          *(uint *)puVar22 =
               ((int)(SUB164(auVar44 >> 0x60,0) * 2.139095e+09) & 0x7f800000U |
               (int)(SUB164(auVar44 >> 0x20,0) * 32640.0) & 0x7f80U) * 2 |
               (int)(SUB164(auVar44 >> 0x40,0) * 1.671168e+07) & 0xff0000U |
               (int)(SUB164(auVar44,0) * 255.0) & 0xffU;
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 + -3) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x57:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          puVar5 = *param_4;
          puVar6 = *param_4;
          puVar7 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(_DAT_18005d4d0,
                          CONCAT412(*(float *)(puVar7 + 0xc) * 3.0 + 0.0,
                                    CONCAT48(*(float *)(puVar6 + 8) * 510.0 + 384.0,
                                             CONCAT44(*(float *)(puVar5 + 4) * 510.0 + 384.0,
                                                      *(float *)puVar34 * 510.0 + 384.0))));
          auVar44 = minps(auVar44,_DAT_18005f900);
          *(uint *)puVar22 =
               (((uint)(longlong)SUB164(auVar44 >> 0x40,0) & 0x3ff |
                (int)(longlong)SUB164(auVar44 >> 0x60,0) << 10) << 10 |
               (uint)(longlong)SUB164(auVar44 >> 0x20,0) & 0x3ff) << 10 |
               (uint)(longlong)SUB164(auVar44,0) & 0x3ff;
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 - 3U) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x62:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar34 = (undefined *)((longlong)param_1 + 2);
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d4d0);
          local_res20 = (uint *)CONCAT44(local_res20._4_4_,0xff);
          local_70 = (uint *)((ulonglong)local_70 & 0xffffffff00000000);
          local_90 = 0;
          local_80[0] = 0;
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          uVar28 = (int)(SUB164(auVar44,0) * 255.0) & 0xff;
          uVar11 = ((int)(SUB164(auVar44 >> 0x60,0) * 2.139095e+09) & 0x7f800000U |
                   (int)(SUB164(auVar44 >> 0x20,0) * 32640.0) & 0x7f80U) * 2;
          param_6 = (float)(uVar11 | (int)(SUB164(auVar44 >> 0x40,0) * 1.671168e+07) & 0xff0000U |
                                     uVar28);
          param_6._1_1_ = (byte)(uVar11 >> 8);
          param_6._2_1_ = (byte)((uint)param_6 >> 0x10);
          local_78._0_4_ =
               ((uint)param_6._2_1_ * 0x19 + 0x80 + uVar28 * 0x42 + (uint)param_6._1_1_ * 0x81 >> 8)
               + 0x10;
          local_88._0_4_ =
               ((int)((uint)param_6._2_1_ * 0x70 + uVar28 * -0x26 + (uint)param_6._1_1_ * -0x4a +
                     0x80) >> 8) + 0x80;
          local_98 = ((int)(uVar28 * 0x70 + (uint)param_6._1_1_ * -0x5e +
                            ((uint)param_6._2_1_ + (uint)param_6._2_1_ * 8) * -2 + 0x80) >> 8) +
                     0x80;
          ppuVar16 = &local_70;
          if (-1 < (int)local_98) {
            ppuVar16 = (uint **)&local_98;
          }
          uVar17 = *(undefined *)ppuVar16;
          if (0xff < *(int *)ppuVar16) {
            uVar17 = 0xff;
          }
          puVar34[-2] = uVar17;
          puVar22 = (undefined8 *)&local_90;
          if (-1 < (int)(uint)local_88) {
            puVar22 = &local_88;
          }
          uVar17 = *(undefined *)puVar22;
          if (0xff < *(int *)puVar22) {
            uVar17 = 0xff;
          }
          local_res20 = (uint *)CONCAT44(local_res20._4_4_,0xff);
          puVar34[-1] = uVar17;
          if (0xff < (uint)local_78) {
            local_78._0_1_ = 0xff;
          }
          *puVar34 = (undefined)local_78;
          param_6._3_1_ = (undefined)(uVar11 >> 0x18);
          puVar34[1] = param_6._3_1_;
          puVar34 = puVar34 + 4;
          puVar15 = (uint *)(puVar34 + (-2 - (longlong)param_1));
          if ((uint *)((longlong)param_2 - 3U) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 99:
    if ((uint *)0x3 < param_2) {
      if (param_2 != (uint *)0x3) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d4d0);
          local_res20 = (uint *)((ulonglong)local_res20 & 0xffffffff00000000);
          local_80[0] = 0;
          local_90 = 0;
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          uVar11 = ((int)(SUB164(auVar44 >> 0x60,0) * 1.610613e+09) & 0x60000000U |
                   (int)(SUB164(auVar44 >> 0x20,0) * 523776.0) & 0x7fe00U) * 2;
          param_6 = (float)(uVar11 | (int)(SUB164(auVar44 >> 0x40,0) * 1.072693e+09) & 0x3ff00000U |
                                     (int)(SUB164(auVar44,0) * 1023.0) & 0x3ffU);
          uVar21 = (ulonglong)((uint)param_6 >> 10) & 0x3ff;
          uVar29 = (ulonglong)((uint)param_6 >> 0x14) & 0x3ff;
          uVar25 = (ulonglong)(uint)param_6 & 0x3ff;
          local_88._0_4_ =
               (int)(uVar25 * 0x418c + 0x8000 + uVar29 * 0x1990 + uVar21 * 0x80ae >> 0x10) + 0x40;
          local_78._0_4_ =
               (int)(uVar29 * 0x701c + uVar25 * -0x25d3 + uVar21 * -0x4a49 + 0x8000 >> 0x10) + 0x200
          ;
          local_98 = (int)(uVar25 * 0x701c + uVar29 * -0x123b + uVar21 * -0x5de1 + 0x8000 >> 0x10) +
                     0x200;
          puVar13 = &local_res20;
          if (-1 < (int)(uint)local_78) {
            puVar13 = &local_78;
          }
          uVar28 = *(uint *)puVar13;
          if (0x3ff < (int)uVar28) {
            uVar28 = 0x3ff;
          }
          *(uint *)puVar22 = *(uint *)puVar22 ^ (uVar28 ^ *(uint *)puVar22) & 0x3ff;
          ppuVar16 = (uint **)&local_90;
          if (-1 < (int)local_98) {
            ppuVar16 = (uint **)&local_98;
          }
          uVar28 = *(uint *)ppuVar16;
          if (0x3ff < (int)uVar28) {
            uVar28 = 0x3ff;
          }
          if (0x3ff < (uint)local_88) {
            local_88._0_4_ = 0x3ff;
          }
          *(uint *)puVar22 =
               ((uVar28 & 0x3ff) << 10 | (uint)local_88 & 0x3ff) << 10 | *(uint *)puVar22 & 0x3ff |
               uVar11 & 0xc0000000;
          puVar22 = (undefined8 *)((longlong)puVar22 + 4);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 - 3U) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 100:
    if ((uint *)0x7 < param_2) {
      local_70 = (uint *)((longlong)param_2 - 7);
      puVar15 = local_70;
      if (local_70 != (uint *)0x0) {
        puVar19 = (undefined2 *)((longlong)param_1 + 4);
        while (param_4 < pauVar23) {
          auVar44 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(auVar44,_DAT_18005d4d0);
          param_6 = 9.183409e-41;
          local_res20 = (uint *)((ulonglong)local_res20 & 0xffffffff00000000);
          local_80[0] = 0;
          local_90 = 0;
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          uVar25 = (ulonglong)(uint)(int)(SUB164(auVar44,0) * 65535.0) & 0xffff;
          uVar29 = (ulonglong)(uint)(int)(SUB164(auVar44 >> 0x20,0) * 65535.0) & 0xffff;
          uVar21 = (ulonglong)(ushort)(int)(SUB164(auVar44 >> 0x40,0) * 65535.0);
          puVar19[1] = (short)(int)(SUB164(auVar44 >> 0x60,0) * 65535.0);
          local_88._0_4_ =
               (int)(uVar25 * 0x417b + uVar21 * 0x1989 + uVar29 * 0x808e + 0x8000 >> 0x10) + 0x1000;
          local_78._0_4_ =
               (int)(uVar21 * 0x7000 + uVar25 * -0x25ca + uVar29 * -0x4a36 + 0x8000 >> 0x10) +
               0x8000;
          local_98 = (int)(uVar25 * 0x7000 + uVar21 * -0x1236 + uVar29 * -0x5dca + 0x8000 >> 0x10) +
                     0x8000;
          puVar22 = &local_res20;
          if (-1 < (int)(uint)local_78) {
            puVar22 = &local_78;
          }
          uVar8 = *(undefined2 *)puVar22;
          if (0xffff < *(int *)puVar22) {
            uVar8 = 0xffff;
          }
          param_6 = 9.183409e-41;
          puVar19[-2] = uVar8;
          if (0xffff < (uint)local_88) {
            local_88._0_2_ = 0xffff;
          }
          param_6 = 9.183409e-41;
          puVar19[-1] = (short)local_88;
          ppuVar16 = (uint **)&local_90;
          if (-1 < (int)local_98) {
            ppuVar16 = (uint **)&local_98;
          }
          uVar8 = *(undefined2 *)ppuVar16;
          if (0xffff < *(int *)ppuVar16) {
            uVar8 = 0xffff;
          }
          *puVar19 = uVar8;
          puVar19 = puVar19 + 4;
          puVar15 = (uint *)((-4 - (longlong)param_1) + (longlong)puVar19);
          if (local_70 <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x69:
    if ((uint *)0x3 < param_2) {
      puVar31 = (uint *)((longlong)param_2 - 3);
      _local_58 = CONCAT88(auStack_54._4_8_,puVar31);
      puVar15 = puVar31;
      if (puVar31 != (uint *)0x0) {
        puVar34 = (undefined *)((longlong)param_1 + 2);
        puVar14 = (uint *)(-(longlong)param_1 - 2);
        _local_48 = CONCAT88(uStack_40,puVar14);
        puVar15 = puVar14;
        while (param_4 < pauVar23) {
          pauVar24 = param_4[1];
          auVar44 = maxps(*param_4,_DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          auVar44 = CONCAT412((int)(SUB164(auVar44 >> 0x60,0) * 2.139095e+09),
                              CONCAT48((int)(SUB164(auVar44 >> 0x40,0) * 1.671168e+07),
                                       CONCAT44((int)(SUB164(auVar44 >> 0x20,0) * 32640.0),
                                                (int)(SUB164(auVar44,0) * 255.0)))) & _DAT_18005f890
          ;
          auVar44 = CONCAT412(SUB164(auVar44 >> 0x60,0),
                              CONCAT48(SUB164(auVar44 >> 0x40,0),SUB168(auVar44 >> 0x40,0))) |
                    auVar44;
          uVar38 = SUB164(auVar44 >> 0x20,0) * 2 | SUB164(auVar44,0);
          param_6._1_1_ = (byte)(uVar38 >> 8);
          param_6._2_1_ = (byte)(uVar38 >> 0x10);
          uVar10 = (uint)param_6._1_1_;
          uVar27 = (uint)param_6._2_1_;
          local_78._0_4_ =
               (uVar27 * 0x19 + 0x80 + (uVar38 & 0xff) * 0x42 + uVar10 * 0x81 >> 8) + 0x10;
          uVar45 = (uint)param_6._1_1_;
          uVar28 = (uint)param_6._2_1_;
          uVar11 = (uint)param_6._2_1_;
          if (pauVar24 < pauVar23) {
            auVar44 = *pauVar24;
            pauVar24 = param_4[2];
            auVar44 = maxps(auVar44,_DAT_18005d4d0);
            auVar44 = minps(auVar44,_DAT_18005d4c0);
            auVar44 = CONCAT412((int)(SUB164(auVar44 >> 0x60,0) * 2.139095e+09),
                                CONCAT48((int)(SUB164(auVar44 >> 0x40,0) * 1.671168e+07),
                                         CONCAT44((int)(SUB164(auVar44 >> 0x20,0) * 32640.0),
                                                  (int)(SUB164(auVar44,0) * 255.0)))) &
                      _DAT_18005f890;
            auVar44 = CONCAT412(SUB164(auVar44 >> 0x60,0),
                                CONCAT48(SUB164(auVar44 >> 0x40,0),SUB168(auVar44 >> 0x40,0))) |
                      auVar44;
            uVar39 = SUB164(auVar44 >> 0x20,0) * 2 | SUB164(auVar44,0);
            param_6._2_1_ = (byte)(uVar39 >> 0x10);
            param_6._1_1_ = (byte)(uVar39 >> 8);
            param_6._0_1_ = (byte)uVar39;
          }
          else {
            param_6._2_1_ = 0;
            param_6._1_1_ = 0;
            param_6._0_1_ = 0;
          }
          param_6 = 3.573311e-43;
          local_res20 = (uint *)((ulonglong)local_res20 & 0xffffffff00000000);
          local_80[0] = 0;
          local_90 = 0;
          local_70 = (uint *)((ulonglong)local_70 & 0xffffffff00000000);
          local_98 = ((uint)param_6._1_1_ * 0x81 +
                      (uint)param_6._2_1_ * 0x19 + (uint)param_6._0_1_ * 0x42 + 0x80 >> 8) + 0x10;
          if (0xff < (uint)local_78) {
            local_78._0_1_ = 0xff;
          }
          param_6 = 3.573311e-43;
          puVar34[-2] = (undefined)local_78;
          local_88._0_4_ =
               ((int)(uVar27 * 0x70 + (uVar38 & 0xff) * -0x26 + uVar10 * -0x4a + 0x80) >> 8) + 0x100
               + ((int)((uint)param_6._2_1_ * 0x70 + (uint)param_6._0_1_ * -0x26 +
                        (uint)param_6._1_1_ * -0x4a + 0x80) >> 8) >> 1;
          puVar15 = local_80;
          if (-1 < (int)(uint)local_88) {
            puVar15 = (uint *)&local_88;
          }
          uVar17 = *(undefined *)puVar15;
          if (0xff < (int)*puVar15) {
            uVar17 = 0xff;
          }
          param_6 = 3.573311e-43;
          puVar34[-1] = uVar17;
          if (0xff < local_98) {
            local_98._0_1_ = 0xff;
          }
          param_6 = 3.573311e-43;
          *puVar34 = (undefined)local_98;
          local_68[0]._0_4_ =
               ((int)((uVar38 & 0xff) * 0x70 + uVar45 * -0x5e + (uVar11 + uVar28 * 8) * -2 + 0x80)
               >> 8) + 0x100 +
               ((int)((uint)param_6._0_1_ * 0x70 +
                      ((uint)param_6._2_1_ + (uint)param_6._2_1_ * 8) * -2 +
                      (uint)param_6._1_1_ * -0x5e + 0x80) >> 8) >> 1;
          ppuVar16 = &local_70;
          if (-1 < (int)(uint)local_68[0]) {
            ppuVar16 = local_68;
          }
          uVar17 = *(undefined *)ppuVar16;
          if (0xff < *(int *)ppuVar16) {
            uVar17 = 0xff;
          }
          puVar34[1] = uVar17;
          puVar34 = puVar34 + 4;
          puVar15 = (uint *)((longlong)puVar14 + (longlong)puVar34);
          param_4 = pauVar24;
          if (puVar31 <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x6a:
    if ((uint *)0x7 < param_2) {
      local_70 = (uint *)((longlong)param_2 - 7);
      puVar15 = local_70;
      if (local_70 != (uint *)0x0) {
        psVar35 = (short *)((longlong)param_1 + 4);
        while (param_4 < pauVar23) {
          pauVar24 = param_4[1];
          auVar44 = maxps(*param_4,_DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          auVar44 = CONCAT412((int)(SUB164(auVar44 >> 0x60,0) * 1.610613e+09),
                              CONCAT48((int)(SUB164(auVar44 >> 0x40,0) * 1.072693e+09),
                                       CONCAT44((int)(SUB164(auVar44 >> 0x20,0) * 523776.0),
                                                (int)(SUB164(auVar44,0) * 1023.0)))) &
                    _DAT_18005f8d0;
          auVar44 = CONCAT412(SUB164(auVar44 >> 0x60,0),
                              CONCAT48(SUB164(auVar44 >> 0x40,0),SUB168(auVar44 >> 0x40,0))) |
                    auVar44;
          uVar11 = SUB164(auVar44 >> 0x20,0) * 2 | SUB164(auVar44,0);
          uVar25 = (ulonglong)uVar11 & 0x3ff;
          uVar21 = (ulonglong)(uVar11 >> 10) & 0x3ff;
          uVar29 = (ulonglong)(uVar11 >> 0x14) & 0x3ff;
          uVar11 = (int)(uVar25 * 0x418c + 0x8000 + uVar29 * 0x1990 + uVar21 * 0x80ae >> 0x10) +
                   0x40;
          _local_48 = CONCAT88(uStack_40,(ulonglong)uVar11);
          _local_58 = CONCAT124(auStack_54,uVar11);
          if (pauVar24 < pauVar23) {
            auVar44 = *pauVar24;
            pauVar24 = param_4[2];
            auVar44 = maxps(auVar44,_DAT_18005d4d0);
            auVar44 = minps(auVar44,_DAT_18005d4c0);
            auVar44 = CONCAT412((int)(SUB164(auVar44 >> 0x60,0) * 1.610613e+09),
                                CONCAT48((int)(SUB164(auVar44 >> 0x40,0) * 1.072693e+09),
                                         CONCAT44((int)(SUB164(auVar44 >> 0x20,0) * 523776.0),
                                                  (int)(SUB164(auVar44,0) * 1023.0)))) &
                      _DAT_18005f8d0;
            auVar44 = CONCAT412(SUB164(auVar44 >> 0x60,0),
                                CONCAT48(SUB164(auVar44 >> 0x40,0),SUB168(auVar44 >> 0x40,0))) |
                      auVar44;
            uVar28 = SUB164(auVar44 >> 0x20,0) * 2 | SUB164(auVar44,0);
          }
          else {
            uVar28 = 0;
          }
          uVar30 = (ulonglong)uVar28 & 0x3ff;
          uVar26 = (ulonglong)(uVar28 >> 10) & 0x3ff;
          uVar32 = (ulonglong)(uVar28 >> 0x14) & 0x3ff;
          param_6 = 1.433528e-42;
          local_res20 = (uint *)((ulonglong)local_res20 & 0xffffffff00000000);
          local_68[0]._0_4_ = 0;
          local_80[0] = 0;
          local_90 = 0;
          local_88._0_4_ =
               (int)(uVar30 * 0x418c + uVar32 * 0x1990 + uVar26 * 0x80ae + 0x8000 >> 0x10) + 0x40;
          puVar22 = &local_res20;
          if (-1 < (int)uVar11) {
            puVar22 = (undefined8 *)local_58;
          }
          sVar9 = *(short *)puVar22;
          if (0x3ff < *(int *)puVar22) {
            sVar9 = 0x3ff;
          }
          param_6 = 1.433528e-42;
          psVar35[-2] = sVar9 << 6;
          local_78._0_4_ =
               (int)(uVar32 * 0x701c + uVar26 * -0x4a49 + uVar30 * -0x25d3 + 0x8000 >> 0x10) +
               (int)(uVar29 * 0x701c + uVar21 * -0x4a49 + uVar25 * -0x25d3 + 0x8000 >> 0x10) + 0x400
               >> 1;
          puVar15 = (uint *)local_68;
          if (-1 < (int)(uint)local_78) {
            puVar15 = (uint *)&local_78;
          }
          sVar9 = *(short *)puVar15;
          if (0x3ff < (int)*puVar15) {
            sVar9 = 0x3ff;
          }
          param_6 = 1.433528e-42;
          psVar35[-1] = sVar9 << 6;
          if (0x3ff < (uint)local_88) {
            local_88._0_2_ = 0x3ff;
          }
          param_6 = 1.433528e-42;
          *psVar35 = (short)local_88 << 6;
          local_98 = (int)(uVar30 * 0x701c + uVar32 * -0x123b + uVar26 * -0x5de1 + 0x8000 >> 0x10) +
                     (int)(uVar25 * 0x701c + uVar29 * -0x123b + uVar21 * -0x5de1 + 0x8000 >> 0x10) +
                     0x400 >> 1;
          ppuVar16 = (uint **)&local_90;
          if (-1 < (int)local_98) {
            ppuVar16 = (uint **)&local_98;
          }
          sVar9 = *(short *)ppuVar16;
          if (0x3ff < *(int *)ppuVar16) {
            sVar9 = 0x3ff;
          }
          psVar35[1] = sVar9 << 6;
          psVar35 = psVar35 + 4;
          puVar15 = (uint *)((-4 - (longlong)param_1) + (longlong)psVar35);
          param_4 = pauVar24;
          if (local_70 <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x6b:
    if ((uint *)0x7 < param_2) {
      local_70 = (uint *)((longlong)param_2 - 7);
      puVar15 = local_70;
      if (local_70 != (uint *)0x0) {
        puVar15 = (uint *)((longlong)param_1 + 4);
        local_res20 = puVar15;
        while (param_4 < pauVar23) {
          pauVar24 = param_4[1];
          auVar44 = maxps(*param_4,_DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005d4c0);
          uVar25 = (ulonglong)(uint)(int)(SUB164(auVar44,0) * 65535.0) & 0xffff;
          uVar29 = (ulonglong)(uint)(int)(SUB164(auVar44 >> 0x20,0) * 65535.0) & 0xffff;
          uVar21 = (ulonglong)(ushort)(int)(SUB164(auVar44 >> 0x40,0) * 65535.0);
          uVar11 = (int)(uVar21 * 0x1989 + 0x8000 + uVar29 * 0x808e + uVar25 * 0x417b >> 0x10) +
                   0x1000;
          _local_48 = CONCAT124(stack0xffffffffffffffbc,uVar11);
          if (pauVar24 < pauVar23) {
            auVar44 = *pauVar24;
            pauVar24 = param_4[2];
            auVar44 = maxps(auVar44,_DAT_18005d4d0);
            auVar44 = minps(auVar44,_DAT_18005d4c0);
            uVar36 = (ushort)(int)(SUB164(auVar44,0) * 65535.0);
            uVar18 = (ushort)(int)(SUB164(auVar44 >> 0x20,0) * 65535.0);
            uVar20 = (ushort)(int)(SUB164(auVar44 >> 0x40,0) * 65535.0);
          }
          else {
            uVar36 = 0;
            uVar18 = uVar36;
            uVar20 = uVar36;
          }
          uVar30 = (ulonglong)uVar36;
          uVar32 = (ulonglong)uVar18;
          uVar26 = (ulonglong)uVar20;
          param_6 = 9.183409e-41;
          _local_58 = _local_58 & (undefined  [16])0xffffffff00000000;
          local_88._0_4_ =
               (int)(uVar26 * 0x1989 + uVar32 * 0x808e + uVar30 * 0x417b + 0x8000 >> 0x10) + 0x1000;
          local_68[0]._0_4_ = 0;
          local_80[0] = 0;
          local_90 = 0;
          local_48._0_2_ = (undefined2)uVar11;
          if (0xffff < uVar11) {
            local_48._0_2_ = 0xffff;
          }
          param_6 = 9.183409e-41;
          *(undefined2 *)(local_res20 + -1) = local_48._0_2_;
          local_78._0_4_ =
               (int)(uVar21 * 0x7000 + uVar29 * -0x4a36 + uVar25 * -0x25ca + 0x8000 >> 0x10) +
               0x10000 + (int)(uVar26 * 0x7000 + uVar32 * -0x4a36 + uVar30 * -0x25ca + 0x8000 >>
                              0x10) >> 1;
          puVar15 = (uint *)local_68;
          if (-1 < (int)(uint)local_78) {
            puVar15 = (uint *)&local_78;
          }
          uVar8 = *(undefined2 *)puVar15;
          if (0xffff < (int)*puVar15) {
            uVar8 = 0xffff;
          }
          param_6 = 9.183409e-41;
          *(undefined2 *)((longlong)local_res20 - 2) = uVar8;
          if (0xffff < (uint)local_88) {
            local_88._0_2_ = 0xffff;
          }
          param_6 = 9.183409e-41;
          *(short *)local_res20 = (short)local_88;
          local_98 = (int)(uVar25 * 0x7000 + uVar21 * -0x1236 + uVar29 * -0x5dca + 0x8000 >> 0x10) +
                     0x10000 + (int)(uVar30 * 0x7000 + uVar26 * -0x1236 + uVar32 * -0x5dca + 0x8000
                                    >> 0x10) >> 1;
          ppuVar16 = (uint **)&local_90;
          if (-1 < (int)local_98) {
            ppuVar16 = (uint **)&local_98;
          }
          uVar8 = *(undefined2 *)ppuVar16;
          if (0xffff < *(int *)ppuVar16) {
            uVar8 = 0xffff;
          }
          *(undefined2 *)((longlong)local_res20 + 2) = uVar8;
          local_res20 = local_res20 + 2;
          puVar15 = (uint *)((-4 - (longlong)param_1) + (longlong)local_res20);
          param_4 = pauVar24;
          if (local_70 <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x71:
    if ((uint *)0x1 < param_2) {
      if (param_2 != (uint *)0x1) {
        puVar22 = param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          puVar5 = *param_4;
          puVar6 = *param_4;
          puVar7 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(CONCAT412(*(float *)(puVar7 + 0xc) * fRam00000001800651ac,
                                    CONCAT48(*(float *)puVar34 * fRam00000001800651a8,
                                             CONCAT44(*(float *)(puVar5 + 4) * fRam00000001800651a4,
                                                      *(float *)(puVar6 + 8) * _DAT_1800651a0))),
                          _DAT_18005d4d0);
          auVar44 = minps(auVar44,_DAT_18005f7e0);
          *(ushort *)puVar22 =
               (((ushort)(int)SUB164(auVar44 >> 0x40,0) & 0xf |
                (short)(int)SUB164(auVar44 >> 0x60,0) << 4) << 4 |
               (ushort)(int)SUB164(auVar44 >> 0x20,0) & 0xf) << 4 |
               (ushort)(int)SUB164(auVar44,0) & 0xf;
          puVar22 = (undefined8 *)((longlong)puVar22 + 2);
          puVar15 = (uint *)((longlong)puVar22 - (longlong)param_1);
          if ((uint *)((longlong)param_2 - 1U) <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x72:
    if ((uint *)0x3 < param_2) {
      puVar31 = (uint *)((longlong)param_2 + -3);
      if (puVar31 != (uint *)0x0) {
        lVar33 = -(longlong)param_1;
        while (param_4 < pauVar23) {
          puVar34 = *param_4;
          puVar5 = *param_4;
          puVar6 = *param_4;
          puVar7 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(_DAT_18005d4d0,
                          CONCAT412(*(float *)(puVar7 + 0xc) * 3.0,
                                    CONCAT48(*(float *)(puVar6 + 8) * 1.0,
                                             CONCAT44(*(float *)(puVar5 + 4) * 1.0,
                                                      *(float *)puVar34 * 1.0))));
          auVar44 = minps(auVar44,_DAT_18005f7d0);
          uVar11 = FUN_1800079e0(SUB164(auVar44,0));
          *(uint *)param_1 = *(uint *)param_1 & 0xfffffc00;
          *(uint *)param_1 = *(uint *)param_1 | uVar11 & 0x3ff;
          uVar11 = FUN_1800079e0(extraout_XMM0_Db_00);
          uVar28 = (uVar11 << 10 ^ *(uint *)param_1) & 0xffc00 ^ *(uint *)param_1;
          uVar11 = FUN_1800079e0(SUB164(auVar44 >> 0x40,0));
          *(uint *)param_1 =
               ((int)(longlong)SUB164(auVar44 >> 0x60,0) << 10 | uVar11 & 0x3ff) << 0x14 |
               uVar28 & 0xfffff;
          param_1 = (undefined8 *)((longlong)param_1 + 4);
          puVar15 = (uint *)((longlong)param_1 + lVar33);
          if (puVar31 <= puVar15) {
            return CONCAT71((int7)((ulonglong)puVar15 >> 8),1);
          }
        }
      }
      goto LAB_18000d895;
    }
    break;
  case 0x73:
    if ((uint *)0x3 < param_2) {
      puVar31 = (uint *)((longlong)param_2 + -3);
      if (puVar31 != (uint *)0x0) {
        lVar33 = -(longlong)param_1;
        do {
          if (pauVar23 <= param_4) break;
          puVar34 = *param_4;
          puVar5 = *param_4;
          puVar6 = *param_4;
          puVar7 = *param_4;
          param_4 = param_4[1];
          auVar44 = maxps(_DAT_18005d4d0,
                          CONCAT412(*(float *)(puVar7 + 0xc) * 3.0,
                                    CONCAT48(*(float *)(puVar6 + 8) * 1.0,
                                             CONCAT44(*(float *)(puVar5 + 4) * 1.0,
                                                      *(float *)puVar34 * 1.0))));
          auVar44 = minps(auVar44,_DAT_18005f7b0);
          uVar11 = FUN_180007ab0(SUB164(auVar44,0));
          *(uint *)param_1 = *(uint *)param_1 & 0xfffffc00;
          *(uint *)param_1 = *(uint *)param_1 | uVar11 & 0x3ff;
          uVar11 = FUN_180007ab0(extraout_XMM0_Db_01);
          uVar28 = (uVar11 << 10 ^ *(uint *)param_1) & 0xffc00 ^ *(uint *)param_1;
          uVar11 = FUN_180007ab0(SUB164(auVar44 >> 0x40,0));
          *(uint *)param_1 =
               ((int)(longlong)SUB164(auVar44 >> 0x60,0) << 10 | uVar11 & 0x3ff) << 0x14 |
               uVar28 & 0xfffff;
          param_1 = (undefined8 *)((longlong)param_1 + 4);
          puVar15 = (uint *)((longlong)param_1 + lVar33);
        } while (puVar15 < puVar31);
      }
      goto LAB_18000d895;
    }
  }
                    // WARNING: Read-only address (ram,0x00018005d430) is written
                    // WARNING: Read-only address (ram,0x00018005d4c0) is written
                    // WARNING: Read-only address (ram,0x00018005d4d0) is written
                    // WARNING: Read-only address (ram,0x00018005f7b0) is written
                    // WARNING: Read-only address (ram,0x00018005f7d0) is written
                    // WARNING: Read-only address (ram,0x00018005f7e0) is written
                    // WARNING: Read-only address (ram,0x00018005f7f0) is written
                    // WARNING: Read-only address (ram,0x00018005f800) is written
                    // WARNING: Read-only address (ram,0x00018005f810) is written
                    // WARNING: Read-only address (ram,0x00018005f820) is written
                    // WARNING: Read-only address (ram,0x00018005f830) is written
                    // WARNING: Read-only address (ram,0x00018005f840) is written
                    // WARNING: Read-only address (ram,0x00018005f850) is written
                    // WARNING: Read-only address (ram,0x00018005f890) is written
                    // WARNING: Read-only address (ram,0x00018005f8d0) is written
                    // WARNING: Read-only address (ram,0x00018005f900) is written
                    // WARNING: Read-only address (ram,0x00018005f920) is written
                    // WARNING: Read-only address (ram,0x00018005f930) is written
  return 0;
}



undefined8 FUN_18000da50(ulonglong *param_1,ulonglong *param_2)

{
  int iVar1;
  ulonglong uVar2;
  undefined8 uVar3;
  undefined (*pauVar4) [16];
  ulonglong uVar5;
  undefined (*pauVar6) [12];
  undefined4 in_stack_ffffffffffffffc8;
  undefined4 in_stack_ffffffffffffffcc;
  ulonglong in_stack_ffffffffffffffd0;
  
  uVar3 = FUN_180001f40(param_2,param_2,*param_1,param_1[1],
                        CONCAT44(in_stack_ffffffffffffffcc,in_stack_ffffffffffffffc8),
                        in_stack_ffffffffffffffd0);
  if ((int)uVar3 < 0) {
    return uVar3;
  }
  if ((param_2[6] != 0) && (iVar1 = *(int *)((longlong)param_2 + 0x44), 1 < iVar1)) {
    if (iVar1 < 4) {
      uVar2 = param_2[5];
    }
    else {
      if (iVar1 != 4) goto LAB_18000db5a;
      uVar2 = param_2[4];
    }
    if ((uVar2 != 0) && (uVar2 = param_2[9], uVar2 != 0)) {
      pauVar4 = *(undefined (**) [16])(uVar2 + 0x28);
      if (pauVar4 == (undefined (*) [16])0x0) {
        FUN_1800020c0(param_2);
        return 0x80004003;
      }
      uVar5 = 0;
      pauVar6 = (undefined (*) [12])param_1[5];
      if (param_1[1] != 0) {
        do {
          uVar3 = FUN_180008680(pauVar4,*param_1,pauVar6,param_1[3],*(undefined4 *)(param_1 + 2));
          if ((char)uVar3 == '\0') {
            FUN_1800020c0(param_2);
            return 0x80004005;
          }
          pauVar6 = (undefined (*) [12])(*pauVar6 + param_1[3]);
          uVar5 = uVar5 + 1;
          pauVar4 = (undefined (*) [16])(*pauVar4 + *(longlong *)(uVar2 + 0x18));
        } while (uVar5 < param_1[1]);
      }
      return 0;
    }
  }
LAB_18000db5a:
  FUN_1800020c0(param_2);
  return 0x80004003;
}



undefined8 FUN_18000db80(longlong *param_1,longlong *param_2)

{
  ulonglong uVar1;
  undefined8 uVar2;
  undefined (*pauVar3) [16];
  undefined8 *puVar4;
  ulonglong uVar5;
  float in_stack_fffffffffffffff0;
  
  pauVar3 = (undefined (*) [16])param_1[5];
  if ((pauVar3 == (undefined (*) [16])0x0) ||
     (puVar4 = (undefined8 *)param_2[5], puVar4 == (undefined8 *)0x0)) {
    uVar2 = 0x80004003;
  }
  else if ((*param_1 == *param_2) && (param_1[1] == param_2[1])) {
    uVar5 = 0;
    if (param_1[1] != 0) {
      do {
        uVar1 = FUN_18000af80(puVar4,(uint *)param_2[3],*(int *)(param_2 + 2),pauVar3,*param_1,
                              in_stack_fffffffffffffff0);
        if ((char)uVar1 == '\0') {
          return 0x80004005;
        }
        pauVar3 = (undefined (*) [16])(*pauVar3 + param_1[3]);
        uVar5 = uVar5 + 1;
        puVar4 = (undefined8 *)((longlong)puVar4 + param_2[3]);
      } while (uVar5 < (ulonglong)param_1[1]);
    }
    uVar2 = 0;
  }
  else {
    uVar2 = 0x80004005;
  }
  return uVar2;
}



void FUN_18000dc40(undefined8 *param_1,uint *param_2,int param_3,undefined (*param_4) [16],
                  longlong param_5,float param_6)

{
  float fVar1;
  undefined (*pauVar2) [16];
  longlong lVar3;
  undefined4 extraout_XMM0_Da;
  undefined4 extraout_XMM0_Db;
  undefined4 extraout_XMM0_Dc;
  undefined4 extraout_XMM0_Dd;
  
  switch(param_3) {
  case 2:
  case 6:
  case 10:
  case 0xb:
  case 0x10:
  case 0x18:
  case 0x1a:
  case 0x1c:
  case 0x22:
  case 0x23:
  case 0x29:
  case 0x31:
  case 0x36:
  case 0x38:
  case 0x3d:
  case 0x43:
  case 0x44:
  case 0x45:
  case 0x55:
  case 0x56:
  case 0x57:
  case 0x58:
  case 0x73:
    fVar1 = param_6;
    break;
  default:
    fVar1 = 0.0;
    break;
  case 0x1d:
  case 0x5b:
  case 0x5d:
    fVar1 = (float)((uint)param_6 | 0x3000000);
  }
  if ((((uint)fVar1 >> 0x19 & 1) != 0) && (pauVar2 = param_4, lVar3 = param_5, param_5 != 0)) {
    do {
      FUN_18000e5c0();
      *pauVar2 = CONCAT412(extraout_XMM0_Dd,
                           CONCAT48(extraout_XMM0_Dc,CONCAT44(extraout_XMM0_Db,extraout_XMM0_Da)));
      lVar3 = lVar3 + -1;
      pauVar2 = pauVar2[1];
    } while (lVar3 != 0);
  }
  FUN_18000af80(param_1,param_2,param_3,param_4,param_5,param_6);
  return;
}



undefined8
FUN_18000dd90(undefined (*param_1) [16],longlong param_2,undefined (*param_3) [12],ulonglong param_4
             ,undefined4 param_5,uint param_6)

{
  undefined8 uVar1;
  ulonglong uVar2;
  ulonglong extraout_RAX;
  undefined4 extraout_XMM0_Dc;
  undefined4 extraout_XMM0_Dd;
  
  switch(param_5) {
  case 2:
  case 6:
  case 10:
  case 0xb:
  case 0x10:
  case 0x18:
  case 0x1a:
  case 0x1c:
  case 0x22:
  case 0x23:
  case 0x29:
  case 0x31:
  case 0x36:
  case 0x38:
  case 0x3d:
  case 0x43:
  case 0x44:
  case 0x45:
  case 0x55:
  case 0x56:
  case 0x57:
  case 0x58:
  case 0x73:
    break;
  default:
    param_6 = 0;
    break;
  case 0x1d:
  case 0x5b:
  case 0x5d:
    param_6 = param_6 | 0x3000000;
  }
  uVar2 = FUN_180008680(param_1,param_2,param_3,param_4,param_5);
  if ((char)uVar2 != '\0') {
    if (((param_6 >> 0x18 & 1) != 0) && (param_2 != 0)) {
      do {
        uVar1 = FUN_18000e470(*(undefined8 *)*param_1);
        *param_1 = CONCAT412(extraout_XMM0_Dd,CONCAT48(extraout_XMM0_Dc,uVar1));
        param_1 = param_1[1];
        param_2 = param_2 + -1;
        uVar2 = extraout_RAX;
      } while (param_2 != 0);
    }
    return CONCAT71((int7)(uVar2 >> 8),1);
  }
  return uVar2 & 0xffffffffffffff00;
}



// WARNING: Removing unreachable block (ram,0x00018000e2a0)
// WARNING: Removing unreachable block (ram,0x00018000e2c8)
// WARNING: Removing unreachable block (ram,0x00018000e2cd)
// WARNING: Removing unreachable block (ram,0x00018000e2d0)
// WARNING: Removing unreachable block (ram,0x00018000e2f8)
// WARNING: Removing unreachable block (ram,0x00018000e317)
// WARNING: Removing unreachable block (ram,0x00018000e320)
// WARNING: Removing unreachable block (ram,0x00018000e348)
// WARNING: Removing unreachable block (ram,0x00018000e34a)
// WARNING: Removing unreachable block (ram,0x00018000e350)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_18000def0(undefined (*param_1) [16],undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  void *pvVar5;
  void *pvVar6;
  undefined (*pauVar7) [16];
  uint uVar8;
  uint uVar9;
  longlong lVar10;
  longlong lVar11;
  undefined8 uVar12;
  float fVar14;
  undefined8 extraout_XMM0_Qb;
  undefined auVar13 [16];
  float fVar15;
  undefined extraout_XMM0 [16];
  float fVar16;
  undefined auStackY_88 [32];
  undefined4 local_58 [2];
  undefined8 local_50;
  undefined8 local_48;
  ulonglong local_40;
  
  local_40 = DAT_180065150 ^ (ulonglong)auStackY_88;
  uVar9 = 0;
  local_50 = 0;
  local_48 = 0;
  local_58[0] = param_3;
  pvVar5 = bsearch_s(local_58,&DAT_18005d6e0,0x52,0x18,(_PtFuncCompare *)&LAB_18000ded0,(void *)0x0)
  ;
  local_58[0] = param_2;
  pvVar6 = bsearch_s(local_58,&DAT_18005d6e0,0x52,0x18,(_PtFuncCompare *)&LAB_18000ded0,(void *)0x0)
  ;
  if ((pvVar5 != (void *)0x0) && (pvVar6 != (void *)0x0)) {
    switch(param_3) {
    case 0x1d:
    case 0x48:
    case 0x4b:
    case 0x4e:
    case 0x5b:
    case 0x5d:
    case 99:
      uVar9 = 0x1000000;
    }
    switch(param_2) {
    case 0x1d:
    case 0x48:
    case 0x4b:
    case 0x4e:
    case 0x5b:
    case 0x5d:
    case 99:
      uVar9 = uVar9 | 0x2000000;
      break;
    case 0x41:
    case 0x59:
    }
    if (uVar9 == 0x3000000) {
      uVar9 = 0;
    }
    lVar10 = 0x10;
    if ((((uVar9 >> 0x18 & 1) != 0) && ((*(uint *)((longlong)pvVar5 + 0x10) & 0x20) == 0)) &&
       ((*(uint *)((longlong)pvVar5 + 0x10) & 3) != 0)) {
      lVar11 = 0x10;
      pauVar7 = param_1;
      do {
        uVar12 = FUN_18000e470(*(undefined8 *)*pauVar7);
        *(undefined8 *)*pauVar7 = uVar12;
        *(undefined8 *)(*pauVar7 + 8) = extraout_XMM0_Qb;
        pauVar7 = pauVar7[1];
        lVar11 = lVar11 + -1;
      } while (lVar11 != 0);
    }
    uVar1 = *(uint *)((longlong)pvVar6 + 0x10);
    uVar8 = *(uint *)((longlong)pvVar5 + 0x10);
    if (uVar1 != uVar8) {
      if ((uVar1 & 2) == 0) {
        if ((uVar1 & 8) != 0) {
          if ((uVar8 & 2) == 0) {
            if ((uVar8 & 1) != 0) {
              lVar11 = 0x10;
              pauVar7 = param_1;
              do {
                auVar13 = maxps(_DAT_18005d430,*pauVar7);
                auVar13 = minps(auVar13,_DAT_18005d4c0);
                *pauVar7 = auVar13;
                lVar11 = lVar11 + -1;
                pauVar7 = pauVar7[1];
              } while (lVar11 != 0);
            }
          }
          else {
            lVar11 = 0x10;
            pauVar7 = param_1;
            do {
              fVar16 = *(float *)(*pauVar7 + 4) * fRam0000000180065194;
              fVar14 = *(float *)(*pauVar7 + 8) * fRam0000000180065198;
              fVar15 = *(float *)(*pauVar7 + 0xc) * fRam000000018006519c;
              *(float *)*pauVar7 = *(float *)*pauVar7 * _DAT_180065190 + -1.0;
              *(float *)(*pauVar7 + 4) = fVar16 + -1.0;
              *(float *)(*pauVar7 + 8) = fVar14 + -1.0;
              *(float *)(*pauVar7 + 0xc) = fVar15 + -1.0;
              pauVar7 = pauVar7[1];
              lVar11 = lVar11 + -1;
            } while (lVar11 != 0);
          }
        }
      }
      else if ((uVar8 & 8) == 0) {
        if ((uVar8 & 1) != 0) {
          lVar11 = 0x10;
          pauVar7 = param_1;
          do {
            auVar13 = maxps(*pauVar7,_DAT_18005d4d0);
            auVar13 = minps(auVar13,_DAT_18005d4c0);
            *pauVar7 = auVar13;
            lVar11 = lVar11 + -1;
            pauVar7 = pauVar7[1];
          } while (lVar11 != 0);
        }
      }
      else {
        lVar11 = 0x10;
        pauVar7 = param_1;
        do {
          *pauVar7 = CONCAT412(*(float *)(*pauVar7 + 0xc) * 0.5 + 0.5,
                               CONCAT48(*(float *)(*pauVar7 + 8) * 0.5 + 0.5,
                                        CONCAT44(*(float *)(*pauVar7 + 4) * 0.5 + 0.5,
                                                 *(float *)*pauVar7 * 0.5 + 0.5)));
          pauVar7 = pauVar7[1];
          lVar11 = lVar11 + -1;
        } while (lVar11 != 0);
      }
      uVar1 = *(uint *)((longlong)pvVar6 + 0x10);
      if (((uVar1 & 0xf0000) == 0x80000) && ((*(uint *)((longlong)pvVar5 + 0x10) & 0x80000) == 0)) {
        lVar11 = 0x10;
        pauVar7 = param_1;
        do {
          uVar2 = *(undefined4 *)*pauVar7;
          *(undefined4 *)*pauVar7 = uVar2;
          *(undefined4 *)(*pauVar7 + 4) = uVar2;
          *(undefined4 *)(*pauVar7 + 8) = uVar2;
          *(undefined4 *)(*pauVar7 + 0xc) = uVar2;
          lVar11 = lVar11 + -1;
          pauVar7 = pauVar7[1];
        } while (lVar11 != 0);
      }
      else if (((*(uint *)((longlong)pvVar5 + 0x10) & 0xf0000) == 0x80000) &&
              ((uVar1 & 0x80000) == 0)) {
        lVar11 = 0x10;
        pauVar7 = param_1;
        do {
          uVar2 = *(undefined4 *)(*pauVar7 + 0xc);
          *(undefined4 *)*pauVar7 = uVar2;
          *(undefined4 *)(*pauVar7 + 4) = uVar2;
          *(undefined4 *)(*pauVar7 + 8) = uVar2;
          *(undefined4 *)(*pauVar7 + 0xc) = uVar2;
          lVar11 = lVar11 + -1;
          pauVar7 = pauVar7[1];
        } while (lVar11 != 0);
      }
      else {
        uVar8 = *(uint *)((longlong)pvVar5 + 0x10) & 0x70000;
        if (uVar8 == 0x10000) {
          if ((uVar1 & 0x70000) == 0x70000) {
            lVar11 = 0x10;
            pauVar7 = param_1;
            do {
              uVar2 = *(undefined4 *)*pauVar7;
              uVar3 = *(undefined4 *)(*pauVar7 + 0xc);
              *(undefined4 *)*pauVar7 = uVar2;
              *(undefined4 *)(*pauVar7 + 4) = uVar2;
              *(undefined4 *)(*pauVar7 + 8) = uVar2;
              *(undefined4 *)(*pauVar7 + 0xc) = uVar3;
              lVar11 = lVar11 + -1;
              pauVar7 = pauVar7[1];
            } while (lVar11 != 0);
          }
          else if ((uVar1 & 0x70000) == 0x30000) {
            lVar11 = 0x10;
            pauVar7 = param_1;
            do {
              uVar2 = *(undefined4 *)*pauVar7;
              uVar3 = *(undefined4 *)(*pauVar7 + 8);
              uVar4 = *(undefined4 *)(*pauVar7 + 0xc);
              *(undefined4 *)*pauVar7 = uVar2;
              *(undefined4 *)(*pauVar7 + 4) = uVar2;
              *(undefined4 *)(*pauVar7 + 8) = uVar3;
              *(undefined4 *)(*pauVar7 + 0xc) = uVar4;
              lVar11 = lVar11 + -1;
              pauVar7 = pauVar7[1];
            } while (lVar11 != 0);
          }
        }
        else if ((uVar8 == 0x70000) && ((uVar1 & 0x70000) == 0x10000)) {
          lVar11 = 0x10;
          pauVar7 = param_1;
          do {
            fVar16 = *(float *)*pauVar7 * 0.2125 + *(float *)(*pauVar7 + 4) * 0.7154 + 0.0;
            uVar2 = *(undefined4 *)(*pauVar7 + 0xc);
            *(float *)*pauVar7 = fVar16;
            *(float *)(*pauVar7 + 4) = fVar16;
            *(float *)(*pauVar7 + 8) = fVar16;
            *(undefined4 *)(*pauVar7 + 0xc) = uVar2;
            pauVar7 = pauVar7[1];
            lVar11 = lVar11 + -1;
          } while (lVar11 != 0);
        }
      }
    }
    if (((uVar9 >> 0x19 != 0) && ((*(uint *)((longlong)pvVar6 + 0x10) & 0x20) == 0)) &&
       ((*(uint *)((longlong)pvVar6 + 0x10) & 3) != 0)) {
      do {
        FUN_18000e5c0();
        *param_1 = extraout_XMM0;
        param_1 = param_1[1];
        lVar10 = lVar10 + -1;
      } while (lVar10 != 0);
    }
  }
  __security_check_cookie(local_40 ^ (ulonglong)auStackY_88);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_18000e470(undefined8 param_1)

{
  float fVar1;
  float fVar2;
  undefined4 in_XMM0_Dc;
  undefined4 in_XMM0_Dd;
  float fVar3;
  float fVar5;
  undefined auVar4 [16];
  
  auVar4 = maxps(CONCAT412(in_XMM0_Dd,CONCAT48(in_XMM0_Dc,param_1)),_DAT_18005d4d0);
  auVar4 = minps(auVar4,_DAT_18005d4c0);
  fVar3 = SUB164(auVar4,0);
  fVar5 = SUB164(auVar4 >> 0x20,0);
  fVar1 = powf((fVar3 + 0.055) * 0.9478673,2.4);
  fVar2 = powf((fVar5 + 0.055) * 0.9478673,2.4);
  powf(0.0,0.0);
  powf((SUB164(auVar4 >> 0x60,0) + 0.0) * 1.0,1.0);
  return CONCAT44((uint)fVar2 & -(uint)(0.04045 < fVar5) |
                  ~-(uint)(0.04045 < fVar5) & (uint)(fVar5 * 0.07739938),
                  (uint)fVar1 & -(uint)(0.04045 < fVar3) |
                  ~-(uint)(0.04045 < fVar3) & (uint)(fVar3 * 0.07739938));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_18000e5c0(void)

{
  undefined8 extraout_RAX;
  undefined in_XMM0 [16];
  undefined auVar1 [16];
  
  auVar1 = maxps(in_XMM0,_DAT_18005d4d0);
  auVar1 = minps(auVar1,_DAT_18005d4c0);
  powf(SUB164(auVar1,0),0.4166667);
  powf(SUB164(auVar1 >> 0x20,0),0.4166667);
  powf(SUB164(auVar1 >> 0x40,0),0.0);
  powf(SUB164(auVar1 >> 0x60,0),1.0);
  return extraout_RAX;
}



// WARNING: Removing unreachable block (ram,0x00018000e76b)
// WARNING: Removing unreachable block (ram,0x00018000e771)

void FUN_18000e700(uint *param_1,undefined8 param_2)

{
  float fVar1;
  float fVar2;
  float local_48;
  float fStack_44;
  
  local_48 = (float)param_2;
  if (local_48 < 0.0) {
    local_48 = 0.0;
  }
  else if (65408.0 <= local_48) {
    local_48 = 65408.0;
  }
  fStack_44 = (float)((ulonglong)param_2 >> 0x20);
  if (fStack_44 < 0.0) {
    fStack_44 = 0.0;
  }
  else if (65408.0 <= fStack_44) {
    fStack_44 = 65408.0;
  }
  *param_1 = *param_1 & 0x7ffffff;
  fVar1 = fStack_44;
  if (fStack_44 <= local_48) {
    fVar1 = local_48;
  }
  if (fVar1 <= 0.0) {
    fVar1 = 0.0;
  }
  if (fVar1 <= 1.525879e-05) {
    fVar1 = 1.525879e-05;
  }
  *param_1 = *param_1 | ((int)fVar1 + -0x377fc000 >> 0x17) << 0x1b;
  fVar1 = (float)(-0x7d000000 - ((int)fVar1 + 0x4000));
  fVar2 = (float)roundf(fVar1 * local_48);
  *param_1 = *param_1 & 0xfffffe00;
  *param_1 = *param_1 | (uint)(longlong)fVar2 & 0x1ff;
  fVar2 = (float)roundf(fVar1 * fStack_44);
  *param_1 = *param_1 & 0xfffc01ff;
  *param_1 = *param_1 | ((uint)(longlong)fVar2 & 0x1ff) << 9;
  fVar1 = (float)roundf(fVar1 * 0.0);
  *param_1 = *param_1 & 0xf803ffff;
  *param_1 = *param_1 | ((uint)(longlong)fVar1 & 0x1ff) << 0x12;
  return;
}



void FUN_18000e840(uint *param_1,undefined8 param_2)

{
  uint uVar1;
  uint uVar2;
  longlong lVar3;
  longlong lVar4;
  uint local_38 [4];
  undefined8 local_28;
  uint local_20;
  ulonglong local_18;
  
  local_18 = DAT_180065150 ^ (ulonglong)local_38;
  local_28 = param_2;
  local_20 = 0;
  lVar3 = 0;
  lVar4 = 2;
  do {
    uVar2 = *(uint *)((longlong)&local_28 + lVar3);
    uVar1 = uVar2 & 0x7fffffff;
    if ((uVar2 & 0x7f800000) == 0x7f800000) {
      *(undefined4 *)((longlong)local_38 + lVar3) = 0x7c0;
      if ((uVar2 & 0x7fffff) == 0) {
        if ((uVar2 & 0x80000000) != 0) {
          *(undefined4 *)((longlong)local_38 + lVar3) = 0;
        }
      }
      else {
        *(uint *)((longlong)local_38 + lVar3) =
             (((uVar1 >> 6 | uVar1) >> 5 | uVar1) >> 6 | uVar1) & 0x3f | 0x7c0;
      }
    }
    else if ((uVar2 & 0x80000000) == 0) {
      if (uVar1 < 0x477e0001) {
        if (uVar1 < 0x38800000) {
          uVar1 = (uVar2 & 0x7fffff | 0x800000) >> (0x71U - (char)(uVar1 >> 0x17) & 0x1f);
        }
        else {
          uVar1 = uVar1 + 0xc8000000;
        }
        *(uint *)((longlong)local_38 + lVar3) = uVar1 + 0xffff + (uVar1 >> 0x11 & 1) >> 0x11 & 0x7ff
        ;
      }
      else {
        *(undefined4 *)((longlong)local_38 + lVar3) = 0x7bf;
      }
    }
    else {
      *(undefined4 *)((longlong)local_38 + lVar3) = 0;
    }
    lVar3 = lVar3 + 4;
    lVar4 = lVar4 + -1;
  } while (lVar4 != 0);
  uVar2 = local_20 & 0x7fffffff;
  if ((local_20 & 0x7f800000) == 0x7f800000) {
    uVar1 = 0x3e0;
    if ((local_20 & 0x7fffff) != 0) {
      uVar1 = (((uVar2 >> 5 | uVar2) >> 10 | uVar2) >> 3 | uVar2) & 0x1f | 0x3e0;
      goto LAB_18000e9df;
    }
    if ((local_20 & 0x80000000) == 0) goto LAB_18000e9df;
  }
  else if ((local_20 & 0x80000000) == 0) {
    if (uVar2 < 0x477c0001) {
      if (uVar2 < 0x38800000) {
        uVar2 = (local_20 & 0x7fffff | 0x800000) >> (0x71U - (char)(uVar2 >> 0x17) & 0x1f);
      }
      else {
        uVar2 = uVar2 + 0xc8000000;
      }
      uVar1 = uVar2 + 0x1ffff + (uVar2 >> 0x12 & 1) >> 0x12 & 0x3ff;
    }
    else {
      uVar1 = 0x3df;
    }
    goto LAB_18000e9df;
  }
  uVar1 = 0;
LAB_18000e9df:
  *param_1 = (local_38[1] & 0x7ff | uVar1 << 0xb) << 0xb | local_38[0] & 0x7ff;
  __security_check_cookie(local_18 ^ (ulonglong)local_38);
  return;
}



uint FUN_18000ea20(uint param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = param_1 & 0x7fffffff;
  uVar2 = param_1 >> 0x10 & 0x8000;
  if (0x477fe000 < uVar1) {
    uVar1 = 0x7fff;
    if ((param_1 & 0x7fffff) == 0 || (param_1 & 0x7f800000) != 0x7f800000) {
      uVar1 = 0x7c00;
    }
    return uVar1 | uVar2;
  }
  if (uVar1 < 0x38800000) {
    uVar1 = (param_1 & 0x7fffff | 0x800000) >> (0x71U - (char)(uVar1 >> 0x17) & 0x1f);
  }
  else {
    uVar1 = uVar1 + 0xc8000000;
  }
  return (uVar1 >> 0xd & 1) + 0xfff + uVar1 >> 0xd & 0x7fff | uVar2;
}



void FUN_18000eac0(longlong param_1)

{
  if (*(char *)(param_1 + 1) == -0x80) {
    return;
  }
  return;
}



void FUN_18000eb40(uint *param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint local_28;
  uint uStack_24;
  uint uStack_20;
  ulonglong local_18;
  
  local_18 = DAT_180065150 ^ (ulonglong)&local_28;
  uVar1 = *param_1;
  uVar3 = uVar1 & 0x3f;
  if ((uVar1 & 0x7c0) == 0x7c0) {
    local_28 = (uVar3 | 0x3fc0) << 0x11;
  }
  else {
    if ((uVar1 & 0x7c0) == 0) {
      if (uVar3 == 0) {
        uVar2 = 0xffffff90;
      }
      else {
        uVar2 = 1;
        do {
          uVar2 = uVar2 - 1;
          uVar3 = uVar3 * 2;
        } while ((uVar3 & 0x40) == 0);
        uVar3 = uVar3 & 0x3f;
      }
    }
    else {
      uVar2 = uVar1 >> 6 & 0x1f;
    }
    local_28 = (uVar2 + 0x70) * 0x800000 | uVar3 << 0x11;
  }
  uVar3 = uVar1 >> 0xb & 0x3f;
  if ((uVar1 & 0x3e0000) == 0x3e0000) {
    uStack_24 = (uVar1 & 0x1f800 | 0x1fe0000) << 6;
  }
  else {
    if ((uVar1 & 0x3e0000) == 0) {
      if (uVar3 == 0) {
        uVar2 = 0xffffff90;
      }
      else {
        uVar2 = 1;
        do {
          uVar2 = uVar2 - 1;
          uVar3 = uVar3 * 2;
        } while ((uVar3 & 0x40) == 0);
        uVar3 = uVar3 & 0x3f;
      }
    }
    else {
      uVar2 = uVar1 >> 0x11 & 0x1f;
    }
    uStack_24 = (uVar2 + 0x70) * 0x800000 | uVar3 << 0x11;
  }
  uVar3 = uVar1 >> 0x16 & 0x1f;
  uVar2 = uVar1 >> 0x1b;
  if (uVar2 == 0x1f) {
    uStack_20 = uVar1 >> 5 & 0x3e0000 | 0x7f800000;
  }
  else {
    if (uVar1 < 0x8000000) {
      if (uVar3 == 0) {
        uVar2 = 0xffffff90;
      }
      else {
        uVar2 = 1;
        do {
          uVar2 = uVar2 - 1;
          uVar3 = uVar3 * 2;
        } while ((uVar3 & 0x20) == 0);
        uVar3 = uVar3 & 0x1f;
      }
    }
    uStack_20 = (uVar2 + 0x70) * 0x800000 | uVar3 << 0x12;
  }
  __security_check_cookie(local_18 ^ (ulonglong)&local_28);
  return;
}



uint FUN_18000ec90(ushort param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = param_1 & 0x3ff;
  if ((param_1 & 0x7c00) == 0x7c00) {
    uVar1 = 0x8f;
  }
  else if ((param_1 & 0x7c00) == 0) {
    if ((param_1 & 0x3ff) == 0) {
      uVar1 = 0xffffff90;
    }
    else {
      uVar1 = 1;
      do {
        uVar1 = uVar1 - 1;
        uVar2 = uVar2 * 2;
      } while ((uVar2 >> 10 & 1) == 0);
    }
  }
  else {
    uVar1 = param_1 >> 10 & 0x1f;
  }
  return (uVar1 + 0x70) * 0x800000;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_18000ed10(undefined (*param_1) [16],uint *param_2,char param_3)

{
  uint uVar1;
  uint uVar2;
  longlong lVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  undefined4 uVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  
  uVar2 = *param_2;
  uVar1 = *(uint *)((longlong)param_2 + 2);
  fVar14 = (float)(uVar1 & 0x1f) * 1.0 * _DAT_180065210;
  fVar15 = (float)(uVar1 & 0x7e0) * 0.03125 * fRam0000000180065214;
  fVar16 = (float)(uVar1 & 0xf800) * 0.0004882813 * fRam0000000180065218;
  fVar11 = (float)(uVar2 & 0x1f) * 1.0 * _DAT_180065210;
  fVar12 = (float)(uVar2 & 0x7e0) * 0.03125 * fRam0000000180065214;
  fVar13 = (float)(uVar2 & 0xf800) * 0.0004882813 * fRam0000000180065218;
  if ((param_3 == '\0') ||
     (*(ushort *)((longlong)param_2 + 2) <= *(ushort *)param_2 &&
      *(ushort *)param_2 != *(ushort *)((longlong)param_2 + 2))) {
    fVar4 = (fVar16 - fVar13) * 0.3333333;
    fVar5 = (fVar15 - fVar12) * 0.3333333;
    fVar6 = (fVar14 - fVar11) * 0.3333333;
    fVar7 = (fVar16 - fVar13) * 0.6666667 + fVar13;
    fVar8 = (fVar15 - fVar12) * 0.6666667 + fVar12;
    fVar9 = (fVar14 - fVar11) * 0.6666667 + fVar11;
    uVar10 = 0x3f800000;
  }
  else {
    fVar7 = 0.0;
    fVar8 = 0.0;
    fVar9 = 0.0;
    uVar10 = 0;
    fVar4 = (fVar16 - fVar13) * 0.5;
    fVar5 = (fVar15 - fVar12) * 0.5;
    fVar6 = (fVar14 - fVar11) * 0.5;
  }
  uVar2 = param_2[1];
  lVar3 = 0x10;
  do {
    uVar1 = uVar2 & 3;
    if (uVar1 == 0) {
      *(float *)*param_1 = fVar13;
      *(float *)(*param_1 + 4) = fVar12;
      *(float *)(*param_1 + 8) = fVar11;
      *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
    }
    else if (uVar1 == 1) {
      *(float *)*param_1 = fVar16;
      *(float *)(*param_1 + 4) = fVar15;
      *(float *)(*param_1 + 8) = fVar14;
      *(undefined4 *)(*param_1 + 0xc) = 0x3f800000;
    }
    else if (uVar1 == 2) {
      *param_1 = CONCAT412(0x3f800000,
                           CONCAT48(fVar6 + fVar11,CONCAT44(fVar5 + fVar12,fVar4 + fVar13)));
    }
    else {
      *param_1 = CONCAT412(uVar10,CONCAT48(fVar9,CONCAT44(fVar8,fVar7)));
    }
    param_1 = param_1[1];
    uVar2 = uVar2 >> 2;
    lVar3 = lVar3 + -1;
  } while (lVar3 != 0);
  return;
}



void FUN_18000ee10(undefined (*param_1) [16],uint *param_2)

{
  longlong lVar1;
  undefined (*pauVar2) [16];
  longlong lVar3;
  uint uVar4;
  
  FUN_18000ed10(param_1,param_2 + 2,'\0');
  lVar3 = 8;
  lVar1 = 8;
  pauVar2 = param_1;
  uVar4 = *param_2;
  do {
    *pauVar2 = CONCAT412((float)(ulonglong)(uVar4 & 0xf) * 0.06666667,
                         ZEXT812(*(ulonglong *)*pauVar2));
    lVar1 = lVar1 + -1;
    pauVar2 = pauVar2[1];
    uVar4 = uVar4 >> 4;
  } while (lVar1 != 0);
  pauVar2 = param_1[8];
  uVar4 = param_2[1];
  do {
    *pauVar2 = CONCAT412((float)(ulonglong)(uVar4 & 0xf) * 0.06666667,
                         ZEXT812(*(ulonglong *)*pauVar2));
    lVar3 = lVar3 + -1;
    pauVar2 = pauVar2[1];
    uVar4 = uVar4 >> 4;
  } while (lVar3 != 0);
  return;
}



float FUN_18000f280(byte *param_1,longlong param_2)

{
  longlong lVar1;
  undefined auVar2 [16];
  float fVar3;
  undefined auVar4 [16];
  float fVar5;
  
  if (param_2 == 0) {
    return (float)(uint)*param_1 * 0.003921569;
  }
  if (param_2 == 1) {
    return (float)(uint)param_1[1] * 0.003921569;
  }
  fVar3 = (float)(uint)*param_1 * 0.003921569;
  fVar5 = (float)(uint)param_1[1] * 0.003921569;
  if (param_1[1] < *param_1) {
    lVar1 = param_2 + -1;
    auVar2 = ZEXT416((uint)(float)(7 - lVar1)) & (undefined  [16])0xffffffffffffffff;
    if (7 - lVar1 < 0) {
      auVar2 = CONCAT124(SUB1612(auVar2 >> 0x20,0),SUB164(auVar2,0) + 1.844674e+19);
    }
    auVar4 = ZEXT416((uint)(float)lVar1) & (undefined  [16])0xffffffffffffffff;
    if (lVar1 < 0) {
      auVar4 = CONCAT124(SUB1612(auVar4 >> 0x20,0),SUB164(auVar4,0) + 1.844674e+19);
    }
    return (SUB164(auVar2,0) * fVar3 + SUB164(auVar4,0) * fVar5) * 0.1428571;
  }
  if (param_2 == 6) {
    return 0.0;
  }
  if (param_2 == 7) {
    return 1.0;
  }
  lVar1 = param_2 + -1;
  auVar2 = ZEXT416((uint)(float)(5 - lVar1)) & (undefined  [16])0xffffffffffffffff;
  if (5 - lVar1 < 0) {
    auVar2 = CONCAT124(SUB1612(auVar2 >> 0x20,0),SUB164(auVar2,0) + 1.844674e+19);
  }
  auVar4 = ZEXT416((uint)(float)lVar1) & (undefined  [16])0xffffffffffffffff;
  if (lVar1 < 0) {
    auVar4 = CONCAT124(SUB1612(auVar4 >> 0x20,0),SUB164(auVar4,0) + 1.844674e+19);
  }
  return (SUB164(auVar2,0) * fVar3 + SUB164(auVar4,0) * fVar5) * 0.2;
}



float FUN_18000f390(char *param_1,longlong param_2)

{
  char cVar1;
  char cVar2;
  char cVar3;
  char cVar4;
  longlong lVar5;
  undefined auVar6 [16];
  undefined auVar7 [16];
  
  cVar1 = *param_1;
  cVar2 = param_1[1];
  cVar3 = cVar1;
  if (cVar1 == -0x80) {
    cVar3 = -0x7f;
  }
  cVar4 = cVar2;
  if (cVar2 == -0x80) {
    cVar4 = -0x7f;
  }
  if (param_2 == 0) {
    return (float)(int)cVar3 * 0.007874016;
  }
  if (param_2 == 1) {
    return (float)(int)cVar4 * 0.007874016;
  }
  if (cVar2 < cVar1) {
    lVar5 = param_2 + -1;
    auVar6 = ZEXT416((uint)(float)(7 - lVar5)) & (undefined  [16])0xffffffffffffffff;
    if (7 - lVar5 < 0) {
      auVar6 = CONCAT124(SUB1612(auVar6 >> 0x20,0),SUB164(auVar6,0) + 1.844674e+19);
    }
    auVar7 = ZEXT416((uint)(float)lVar5) & (undefined  [16])0xffffffffffffffff;
    if (lVar5 < 0) {
      auVar7 = CONCAT124(SUB1612(auVar7 >> 0x20,0),SUB164(auVar7,0) + 1.844674e+19);
    }
    return (SUB164(auVar6,0) * (float)(int)cVar3 * 0.007874016 +
           SUB164(auVar7,0) * (float)(int)cVar4 * 0.007874016) * 0.1428571;
  }
  if (param_2 == 6) {
    return -1.0;
  }
  if (param_2 == 7) {
    return 1.0;
  }
  lVar5 = param_2 + -1;
  auVar6 = ZEXT416((uint)(float)(5 - lVar5)) & (undefined  [16])0xffffffffffffffff;
  if (5 - lVar5 < 0) {
    auVar6 = CONCAT124(SUB1612(auVar6 >> 0x20,0),SUB164(auVar6,0) + 1.844674e+19);
  }
  auVar7 = ZEXT416((uint)(float)lVar5) & (undefined  [16])0xffffffffffffffff;
  if (lVar5 < 0) {
    auVar7 = CONCAT124(SUB1612(auVar7 >> 0x20,0),SUB164(auVar7,0) + 1.844674e+19);
  }
  return (SUB164(auVar6,0) * (float)(int)cVar3 * 0.007874016 +
         SUB164(auVar7,0) * (float)(int)cVar4 * 0.007874016) * 0.2;
}



void FUN_18000f4c0(undefined (*param_1) [16],ulonglong *param_2)

{
  ulonglong uVar1;
  float fVar2;
  
  uVar1 = 0x10;
  do {
    fVar2 = FUN_18000f280((byte *)param_2,(ulonglong)((uint)(*param_2 >> ((byte)uVar1 & 0x3f)) & 7))
    ;
    uVar1 = uVar1 + 3;
    *param_1 = CONCAT412(0x3f800000,ZEXT412((uint)fVar2));
    param_1 = param_1[1];
  } while (uVar1 < 0x40);
  return;
}



void FUN_18000f510(undefined (*param_1) [16],ulonglong *param_2)

{
  ulonglong uVar1;
  float fVar2;
  
  uVar1 = 0x10;
  do {
    fVar2 = FUN_18000f390((char *)param_2,(ulonglong)((uint)(*param_2 >> ((byte)uVar1 & 0x3f)) & 7))
    ;
    uVar1 = uVar1 + 3;
    *param_1 = CONCAT412(0x3f800000,ZEXT412((uint)fVar2));
    param_1 = param_1[1];
  } while (uVar1 < 0x40);
  return;
}



void FUN_18000f5f0(undefined (*param_1) [16],ulonglong *param_2)

{
  ulonglong uVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  
  uVar4 = 0x3f800000;
  uVar1 = 0x10;
  do {
    fVar2 = FUN_18000f390((char *)(param_2 + 1),
                          (ulonglong)((uint)(param_2[1] >> ((byte)uVar1 & 0x3f)) & 7));
    fVar3 = FUN_18000f390((char *)param_2,(ulonglong)((uint)(*param_2 >> ((byte)uVar1 & 0x3f)) & 7))
    ;
    uVar1 = uVar1 + 3;
    *param_1 = CONCAT412(uVar4,ZEXT812(CONCAT44(fVar2,fVar3)));
    param_1 = param_1[1];
  } while (uVar1 < 0x40);
  return;
}



uint * FUN_18000f680(uint *param_1,byte *param_2)

{
  uint uVar1;
  
  if ((*param_1 >> ((byte)(*param_2 - 1) & 0x1f) & 1) == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = -1 << (*param_2 & 0x1f);
  }
  *param_1 = *param_1 | uVar1;
  if ((param_1[1] >> ((byte)(param_2[1] - 1) & 0x1f) & 1) == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = -1 << (param_2[1] & 0x1f);
  }
  param_1[1] = param_1[1] | uVar1;
  uVar1 = param_1[2];
  if ((uVar1 >> ((byte)(param_2[2] - 1) & 0x1f) & 1) != 0) {
    param_1[2] = uVar1 | -1 << (param_2[2] & 0x1f);
    return param_1;
  }
  param_1[2] = uVar1;
  return param_1;
}



void FUN_18000f720(int *param_1,byte *param_2,char param_3)

{
  uint *puVar1;
  uint *puVar2;
  byte bVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  puVar1 = (uint *)(param_1 + 8);
  puVar2 = (uint *)(param_1 + 0xc);
  uVar6 = (1 << (*param_2 & 0x1f)) - 1;
  bVar3 = param_2[2];
  uVar5 = (1 << (param_2[1] & 0x1f)) - 1;
  param_1[4] = param_1[4] + *param_1;
  param_1[5] = param_1[5] + param_1[1];
  param_1[6] = param_1[6] + param_1[2];
  param_1[4] = param_1[4] & uVar6;
  param_1[5] = param_1[5] & uVar5;
  uVar4 = (1 << (bVar3 & 0x1f)) - 1;
  param_1[6] = param_1[6] & uVar4;
  *puVar1 = *puVar1 + *param_1;
  param_1[9] = param_1[9] + param_1[1];
  param_1[10] = param_1[10] + param_1[2];
  *puVar1 = *puVar1 & uVar6;
  param_1[9] = param_1[9] & uVar5;
  param_1[10] = param_1[10] & uVar4;
  *puVar2 = *puVar2 + *param_1;
  param_1[0xd] = param_1[0xd] + param_1[1];
  param_1[0xe] = param_1[0xe] + param_1[2];
  *puVar2 = *puVar2 & uVar6;
  param_1[0xd] = param_1[0xd] & uVar5;
  param_1[0xe] = param_1[0xe] & uVar4;
  if (param_3 != '\0') {
    FUN_18000f680((uint *)(param_1 + 4),param_2);
    FUN_18000f680(puVar1,param_2);
    FUN_18000f680(puVar2,param_2);
  }
  return;
}



int FUN_18000ffa0(int param_1,byte param_2,char param_3)

{
  int iVar1;
  bool bVar2;
  
  iVar1 = 0;
  if (param_3 == '\0') {
    if (param_2 < 0xf) {
      if (param_1 == 0) {
        return 0;
      }
      if (param_1 == (1 << (param_2 & 0x1f)) + -1) {
        return 0xffff;
      }
      param_1 = param_1 * 0x10000 + 0x8000 >> (param_2 & 0x1f);
    }
  }
  else if (param_2 < 0x10) {
    bVar2 = param_1 < 0;
    if (bVar2) {
      param_1 = -param_1;
    }
    if (param_1 != 0) {
      if (param_1 < (1 << (param_2 - 1 & 0x1f)) + -1) {
        iVar1 = param_1 * 0x8000 + 0x4000 >> (param_2 - 1 & 0x1f);
      }
      else {
        iVar1 = 0x7fff;
      }
    }
    if (bVar2) {
      iVar1 = -iVar1;
    }
    return iVar1;
  }
  return param_1;
}



// WARNING: Type propagation algorithm not settling
// WARNING: Could not reconcile some variable overlaps

void FUN_180010030(longlong param_1,float *param_2)

{
  int iVar1;
  uint uVar2;
  undefined *puVar3;
  uint uVar4;
  undefined4 *puVar5;
  byte *pbVar6;
  ulonglong uVar7;
  byte bVar8;
  byte bVar9;
  int iVar10;
  ulonglong uVar11;
  ulonglong uVar12;
  byte *pbVar13;
  longlong lVar14;
  char cVar15;
  byte bVar16;
  uint uVar17;
  ulonglong uVar18;
  uint uVar19;
  byte *pbVar20;
  char *pcVar21;
  uint uVar22;
  byte bVar23;
  ulonglong uVar24;
  longlong lVar25;
  float fVar26;
  float fVar27;
  undefined auStack_d8 [32];
  byte local_b8;
  undefined local_b4 [2];
  byte bStack_b2;
  byte bStack_b1;
  byte local_b0;
  byte local_af;
  undefined4 local_ac;
  ulonglong local_a8;
  uint local_a0;
  uint local_9c;
  uint local_98;
  ulonglong local_90;
  longlong local_88;
  float fStack_80;
  float fStack_7c;
  ulonglong local_78;
  undefined4 local_70;
  float *local_58;
  byte abStack_48 [8];
  byte local_40 [16];
  ulonglong local_30;
  
  local_30 = DAT_180065150 ^ (ulonglong)auStack_d8;
  uVar18 = 0;
  local_58 = param_2;
  do {
    if (0x7f < uVar18) break;
    cVar15 = (char)uVar18;
    uVar11 = uVar18 >> 3;
    uVar18 = uVar18 + 1;
  } while ((*(byte *)(uVar11 + param_1) >> (cVar15 + (char)uVar11 * -8 & 0x1fU) & 1) == 0);
  bVar16 = (char)uVar18 - 1;
  local_88 = param_1;
  if (bVar16 < 8) {
    lVar25 = (ulonglong)bVar16 * 0xf;
    local_a8 = (ulonglong)bVar16 + 1;
    local_b0 = (&DAT_180065c00)[lVar25];
    bVar16 = (&DAT_180065c01)[lVar25];
    uVar18 = (ulonglong)bVar16;
    local_af = (&DAT_180065c05)[lVar25];
    bVar23 = (local_b0 + 1) * '\x02';
    local_b8 = (&DAT_180065c06)[lVar25];
    if (uVar18 == 0) {
      local_a0 = local_a0 & 0xffffff00;
    }
    else {
      uVar11 = local_a8 >> 3;
      lVar14 = local_a8 - (local_a8 & 0xfffffffffffffff8);
      bVar8 = (byte)lVar14;
      if (lVar14 + uVar18 < 9) {
        local_a0 = local_a0 & 0xffffff00 |
                   (uint)(byte)(*(byte *)(uVar11 + param_1) >> (bVar8 & 0x1f) &
                               ('\x01' << (bVar16 & 0x1f)) - 1U);
      }
      else {
        local_a0 = (uint)(byte)((('\x01' << (bVar16 - (8 - bVar8) & 0x1f)) - 1U &
                                *(byte *)(uVar11 + 1 + param_1)) << (8 - bVar8 & 0x1f) |
                               *(byte *)(uVar11 + param_1) >> (bVar8 & 0x1f));
      }
      local_a8 = local_a8 + uVar18;
    }
    uVar18 = 0;
    bVar16 = (&DAT_180065c03)[lVar25];
    uVar11 = (ulonglong)bVar16;
    if (uVar11 == 0) {
      local_9c = local_9c & 0xffffff00 | (uint)bVar16;
    }
    else {
      uVar12 = local_a8 >> 3;
      lVar14 = local_a8 - (local_a8 & 0xfffffffffffffff8);
      bVar8 = (byte)lVar14;
      if (lVar14 + uVar11 < 9) {
        local_9c = local_9c & 0xffffff00 |
                   (uint)(byte)(*(byte *)(uVar12 + param_1) >> (bVar8 & 0x1f) &
                               ('\x01' << (bVar16 & 0x1f)) - 1U);
      }
      else {
        local_9c = (uint)(byte)((('\x01' << (bVar16 - (8 - bVar8) & 0x1f)) - 1U &
                                *(byte *)(uVar12 + 1 + param_1)) << (8 - bVar8 & 0x1f) |
                               *(byte *)(uVar12 + param_1) >> (bVar8 & 0x1f));
      }
      local_a8 = local_a8 + uVar11;
    }
    bVar16 = (&DAT_180065c04)[lVar25];
    uVar11 = (ulonglong)bVar16;
    if (uVar11 == 0) {
      local_98 = local_98 & 0xffffff00 | (uint)bVar16;
    }
    else {
      uVar12 = local_a8 >> 3;
      lVar14 = local_a8 - (local_a8 & 0xfffffffffffffff8);
      bVar8 = (byte)lVar14;
      if (lVar14 + uVar11 < 9) {
        local_98 = local_98 & 0xffffff00 |
                   (uint)(byte)(*(byte *)(uVar12 + param_1) >> (bVar8 & 0x1f) &
                               ('\x01' << (bVar16 & 0x1f)) - 1U);
      }
      else {
        local_98 = (uint)(byte)((('\x01' << (bVar16 - (8 - bVar8) & 0x1f)) - 1U &
                                *(byte *)(uVar12 + 1 + param_1)) << (8 - bVar8 & 0x1f) |
                               *(byte *)(uVar12 + param_1) >> (bVar8 & 0x1f));
      }
      local_a8 = local_a8 + uVar11;
    }
    _local_b4 = *(uint *)((longlong)&DAT_180065c07 + lVar25);
    local_ac = *(undefined4 *)((longlong)&DAT_180065c0b + lVar25);
    local_90 = (ulonglong)bVar23;
    uVar11 = local_a8;
    if (bVar23 != 0) {
      uVar12 = (ulonglong)(_local_b4 & 0xff);
      do {
        if (0x80 < uVar12 + uVar11) {
          lVar25 = 0x10;
          do {
            *param_2 = 0.0;
            param_2[1] = 0.0;
            param_2[2] = 0.0;
            param_2[3] = 1.0;
            param_2 = param_2 + 4;
            lVar25 = lVar25 + -1;
          } while (lVar25 != 0);
          goto LAB_180010410;
        }
        if (uVar12 == 0) {
          bVar16 = 0;
        }
        else {
          uVar7 = uVar11 >> 3;
          lVar14 = uVar11 - (uVar11 & 0xfffffffffffffff8);
          bVar16 = (byte)lVar14;
          bVar23 = (byte)(_local_b4 & 0xff);
          if (lVar14 + uVar12 < 9) {
            bVar16 = *(byte *)(uVar7 + param_1) >> (bVar16 & 0x1f) &
                     ('\x01' << (bVar23 & 0x1f)) - 1U;
          }
          else {
            bVar16 = (('\x01' << (bVar23 - (8 - bVar16) & 0x1f)) - 1U &
                     *(byte *)(uVar7 + 1 + param_1)) << (8 - bVar16 & 0x1f) |
                     *(byte *)(uVar7 + param_1) >> (bVar16 & 0x1f);
          }
          uVar11 = uVar11 + uVar12;
          local_a8 = uVar11;
        }
        *(byte *)(&local_70 + uVar18) = bVar16;
        uVar18 = uVar18 + 1;
      } while (uVar18 < local_90);
    }
    uVar18 = 0;
    if (local_90 != 0) {
      local_b4[1] = (byte)(_local_b4 >> 8);
      uVar12 = (ulonglong)local_b4[1];
      do {
        if (0x80 < uVar12 + uVar11) {
          lVar25 = 0x10;
          do {
            *param_2 = 0.0;
            param_2[1] = 0.0;
            param_2[2] = 0.0;
            param_2[3] = 1.0;
            param_2 = param_2 + 4;
            lVar25 = lVar25 + -1;
          } while (lVar25 != 0);
          goto LAB_180010410;
        }
        if (uVar12 == 0) {
          bVar16 = 0;
        }
        else {
          uVar7 = uVar11 >> 3;
          lVar14 = uVar11 - (uVar11 & 0xfffffffffffffff8);
          bVar16 = (byte)lVar14;
          if (lVar14 + uVar12 < 9) {
            bVar16 = *(byte *)(uVar7 + param_1) >> (bVar16 & 0x1f) &
                     ('\x01' << (local_b4[1] & 0x1f)) - 1U;
          }
          else {
            bVar16 = (('\x01' << (local_b4[1] - (8 - bVar16) & 0x1f)) - 1U &
                     *(byte *)(uVar7 + 1 + param_1)) << (8 - bVar16 & 0x1f) |
                     *(byte *)(uVar7 + param_1) >> (bVar16 & 0x1f);
          }
          uVar11 = uVar11 + uVar12;
          local_a8 = uVar11;
        }
        *(byte *)((longlong)&local_70 + uVar18 * 4 + 1) = bVar16;
        uVar18 = uVar18 + 1;
      } while (uVar18 < local_90);
    }
    uVar18 = 0;
    if (local_90 != 0) {
      bStack_b2 = (byte)(_local_b4 >> 0x10);
      uVar12 = (ulonglong)bStack_b2;
      do {
        if (0x80 < uVar12 + uVar11) {
          lVar25 = 0x10;
          do {
            *param_2 = 0.0;
            param_2[1] = 0.0;
            param_2[2] = 0.0;
            param_2[3] = 1.0;
            param_2 = param_2 + 4;
            lVar25 = lVar25 + -1;
          } while (lVar25 != 0);
          goto LAB_180010410;
        }
        if (uVar12 == 0) {
          bVar16 = 0;
        }
        else {
          uVar7 = uVar11 >> 3;
          lVar14 = uVar11 - (uVar11 & 0xfffffffffffffff8);
          bVar16 = (byte)lVar14;
          if (lVar14 + uVar12 < 9) {
            bVar16 = *(byte *)(uVar7 + param_1) >> (bVar16 & 0x1f) &
                     ('\x01' << (bStack_b2 & 0x1f)) - 1U;
          }
          else {
            bVar16 = (('\x01' << (bStack_b2 - (8 - bVar16) & 0x1f)) - 1U &
                     *(byte *)(uVar7 + 1 + param_1)) << (8 - bVar16 & 0x1f) |
                     *(byte *)(uVar7 + param_1) >> (bVar16 & 0x1f);
          }
          uVar11 = uVar11 + uVar12;
          local_a8 = uVar11;
        }
        *(byte *)((longlong)&local_70 + uVar18 * 4 + 2) = bVar16;
        uVar18 = uVar18 + 1;
      } while (uVar18 < local_90);
    }
    uVar18 = 0;
    if (local_90 != 0) {
      bStack_b1 = (byte)(_local_b4 >> 0x18);
      uVar12 = (ulonglong)bStack_b1;
      do {
        if (0x80 < uVar12 + uVar11) {
          lVar25 = 0x10;
          do {
            *param_2 = 0.0;
            param_2[1] = 0.0;
            param_2[2] = 0.0;
            param_2[3] = 1.0;
            param_2 = param_2 + 4;
            lVar25 = lVar25 + -1;
          } while (lVar25 != 0);
          goto LAB_180010410;
        }
        if (bStack_b1 == 0) {
          bVar16 = 0xff;
        }
        else if (uVar12 == 0) {
          bVar16 = 0;
        }
        else {
          uVar7 = uVar11 >> 3;
          lVar14 = uVar11 - (uVar11 & 0xfffffffffffffff8);
          bVar16 = (byte)lVar14;
          if (lVar14 + uVar12 < 9) {
            bVar16 = *(byte *)(uVar7 + param_1) >> (bVar16 & 0x1f) &
                     ('\x01' << (bStack_b1 & 0x1f)) - 1U;
            uVar11 = uVar11 + uVar12;
            local_a8 = uVar11;
          }
          else {
            bVar16 = (('\x01' << (bStack_b1 - (8 - bVar16) & 0x1f)) - 1U &
                     *(byte *)(uVar7 + 1 + param_1)) << (8 - bVar16 & 0x1f) |
                     *(byte *)(uVar7 + param_1) >> (bVar16 & 0x1f);
            uVar11 = uVar11 + uVar12;
            local_a8 = uVar11;
          }
        }
        *(byte *)((longlong)&local_70 + uVar18 * 4 + 3) = bVar16;
        uVar18 = uVar18 + 1;
      } while (uVar18 < local_90);
    }
    uVar18 = 0;
    bVar16 = (&DAT_180065c02)[lVar25];
    if ((ulonglong)bVar16 != 0) {
      do {
        if (0x7f < uVar11) {
          lVar25 = 0x10;
          do {
            *param_2 = 0.0;
            param_2[1] = 0.0;
            param_2[2] = 0.0;
            param_2[3] = 1.0;
            param_2 = param_2 + 4;
            lVar25 = lVar25 + -1;
          } while (lVar25 != 0);
          goto LAB_180010410;
        }
        cVar15 = (char)uVar11;
        uVar12 = uVar11 >> 3;
        uVar11 = uVar11 + 1;
        abStack_48[uVar18] = *(byte *)(uVar12 + param_1) >> (cVar15 + (char)uVar12 * -8 & 0x1fU) & 1
        ;
        uVar18 = uVar18 + 1;
        local_a8 = uVar11;
      } while (uVar18 < bVar16);
    }
    local_ac._3_1_ = (byte)((uint)local_ac >> 0x18);
    local_ac._2_1_ = (byte)((uint)local_ac >> 0x10);
    local_ac._1_1_ = (byte)((uint)local_ac >> 8);
    bVar23 = (byte)local_ac;
    if ((bVar16 != 0) && (local_90 != 0)) {
      bVar16 = (&DAT_180065c02)[lVar25];
      pbVar20 = (byte *)((longlong)&local_70 + 2);
      uVar18 = 0;
      local_78 = local_90;
      do {
        lVar25 = 4;
        uVar11 = 0;
        do {
          if (uVar11 == 0) {
LAB_1800107e1:
            puVar5 = (undefined4 *)local_b4;
          }
          else if (uVar11 == 1) {
            puVar5 = (undefined4 *)((longlong)local_b4 + 1);
          }
          else if (uVar11 == 2) {
            puVar5 = (undefined4 *)((longlong)local_b4 + 2);
          }
          else {
            if (uVar11 != 3) goto LAB_1800107e1;
            puVar5 = (undefined4 *)((longlong)local_b4 + 3);
          }
          bVar8 = bVar23;
          if ((((uVar11 != 0) && (bVar8 = local_ac._1_1_, uVar11 != 1)) &&
              (bVar8 = local_ac._2_1_, uVar11 != 2)) && (bVar8 = bVar23, uVar11 == 3)) {
            bVar8 = local_ac._3_1_;
          }
          if (*(byte *)puVar5 != bVar8) {
            if (uVar11 == 0) {
LAB_180010844:
              pbVar13 = pbVar20 + -2;
            }
            else if (uVar11 == 1) {
              pbVar13 = pbVar20 + -1;
            }
            else {
              pbVar13 = pbVar20;
              if (uVar11 != 2) {
                if (uVar11 != 3) goto LAB_180010844;
                pbVar13 = pbVar20 + 1;
              }
            }
            if (uVar11 == 0) {
LAB_180010873:
              pbVar6 = pbVar20 + -2;
            }
            else if (uVar11 == 1) {
              pbVar6 = pbVar20 + -1;
            }
            else {
              pbVar6 = pbVar20;
              if (uVar11 != 2) {
                if (uVar11 != 3) goto LAB_180010873;
                pbVar6 = pbVar20 + 1;
              }
            }
            *pbVar6 = *pbVar13 * '\x02' | abStack_48[uVar18 / local_90];
          }
          uVar11 = uVar11 + 1;
          lVar25 = lVar25 + -1;
        } while (lVar25 != 0);
        uVar18 = uVar18 + bVar16;
        pbVar20 = pbVar20 + 4;
        local_78 = local_78 - 1;
        uVar11 = local_a8;
        param_2 = local_58;
      } while (local_78 != 0);
    }
    if (local_90 != 0) {
      pcVar21 = (char *)((longlong)&local_70 + 2);
      uVar18 = local_90;
      do {
        uVar2 = _local_b4;
        bVar16 = pcVar21[-2] << (8 - bVar23 & 0x1f);
        bVar16 = bVar16 >> (bVar23 & 0x1f) | bVar16;
        bVar8 = pcVar21[-1] << (8 - local_ac._1_1_ & 0x1f);
        _local_b4 = _local_b4 & 0xffffff00 | (uint)bVar16;
        bVar9 = *pcVar21 << (8 - local_ac._2_1_ & 0x1f);
        _local_b4 = CONCAT12(bVar9 >> (local_ac._2_1_ & 0x1f) | bVar9,
                             (undefined  [2])
                             CONCAT11(bVar8 >> (local_ac._1_1_ & 0x1f) | bVar8,bVar16));
        _local_b4 = uVar2 & 0xff000000 | (uint)_local_b4;
        if (local_ac._3_1_ == 0) {
          _local_b4 = CONCAT13(0xff,_local_b4);
        }
        else {
          bVar16 = pcVar21[1] << (8 - local_ac._3_1_ & 0x1f);
          _local_b4 = CONCAT13(bVar16 >> (local_ac._3_1_ & 0x1f) | bVar16,_local_b4);
        }
        *(uint *)(pcVar21 + -2) = _local_b4;
        pcVar21 = pcVar21 + 4;
        uVar18 = uVar18 - 1;
        param_2 = local_58;
      } while (uVar18 != 0);
    }
    uVar18 = (ulonglong)local_b0;
    uVar12 = 0;
    do {
      uVar7 = 0;
      do {
        if (uVar12 == (byte)(&DAT_18005e820)
                            [uVar7 + (uVar18 * 0x40 + (ulonglong)(byte)local_a0) * 3]) {
          uVar2 = local_af - 1;
          goto LAB_1800109dd;
        }
        uVar7 = uVar7 + 1;
      } while (uVar7 <= uVar18);
      uVar2 = (uint)local_af;
LAB_1800109dd:
      uVar7 = (longlong)(int)uVar2 + uVar11;
      if (0x80 < uVar7) {
        lVar25 = 0x10;
        do {
          *param_2 = 0.0;
          param_2[1] = 0.0;
          param_2[2] = 0.0;
          param_2[3] = 1.0;
          param_2 = param_2 + 4;
          lVar25 = lVar25 + -1;
        } while (lVar25 != 0);
        goto LAB_180010410;
      }
      if (uVar2 == 0) {
        bVar16 = 0;
        uVar7 = uVar11;
      }
      else {
        uVar24 = uVar11 >> 3;
        lVar25 = uVar11 - (uVar11 & 0xfffffffffffffff8);
        bVar16 = (byte)lVar25;
        if ((ulonglong)(lVar25 + (int)uVar2) < 9) {
          bVar16 = ('\x01' << ((byte)uVar2 & 0x1f)) - 1U &
                   *(byte *)(uVar24 + param_1) >> (bVar16 & 0x1f);
        }
        else {
          bVar16 = (('\x01' << ((byte)uVar2 - (8 - bVar16) & 0x1f)) - 1U &
                   *(byte *)(uVar24 + 1 + param_1)) << (8 - bVar16 & 0x1f) |
                   *(byte *)(uVar24 + param_1) >> (bVar16 & 0x1f);
        }
      }
      uVar24 = 0;
      local_40[uVar12] = bVar16;
      uVar12 = uVar12 + 1;
      uVar11 = uVar7;
    } while (uVar12 < 0x10);
    if (local_b8 != 0) {
      do {
        uVar2 = (uint)local_b8;
        if (uVar24 == 0) {
          uVar2 = uVar2 - 1;
        }
        uVar11 = (longlong)(int)uVar2 + uVar7;
        if (0x80 < uVar11) {
          lVar25 = 0x10;
          do {
            *param_2 = 0.0;
            param_2[1] = 0.0;
            param_2[2] = 0.0;
            param_2[3] = 1.0;
            param_2 = param_2 + 4;
            lVar25 = lVar25 + -1;
          } while (lVar25 != 0);
          goto LAB_180010410;
        }
        if (uVar2 == 0) {
          bVar16 = 0;
          uVar11 = uVar7;
        }
        else {
          uVar12 = uVar7 >> 3;
          lVar25 = uVar7 - (uVar7 & 0xfffffffffffffff8);
          bVar16 = (byte)lVar25;
          if ((ulonglong)(lVar25 + (int)uVar2) < 9) {
            bVar16 = ('\x01' << ((byte)uVar2 & 0x1f)) - 1U &
                     *(byte *)(uVar12 + param_1) >> (bVar16 & 0x1f);
          }
          else {
            bVar16 = (('\x01' << ((byte)uVar2 - (8 - bVar16) & 0x1f)) - 1U &
                     *(byte *)(uVar12 + 1 + param_1)) << (8 - bVar16 & 0x1f) |
                     *(byte *)(uVar12 + param_1) >> (bVar16 & 0x1f);
          }
        }
        *(byte *)((longlong)&local_58 + uVar24) = bVar16;
        uVar24 = uVar24 + 1;
        uVar7 = uVar11;
      } while (uVar24 < 0x10);
    }
    uVar2 = local_9c & 0xff;
    uVar11 = 0;
    do {
      uVar17 = (uint)local_b8;
      pbVar20 = local_40 + uVar11;
      bVar16 = pbVar20[(longlong)
                       (&DAT_18005ea60 +
                       ((uVar18 * 0x40 + (ulonglong)(byte)local_a0) * 0x10 - (longlong)local_40))];
      uVar7 = (ulonglong)((uint)bVar16 * 2 + 1);
      uVar12 = (ulonglong)((uint)bVar16 + (uint)bVar16);
      bVar16 = local_af;
      if (local_b8 == 0) {
        uVar24 = (ulonglong)*pbVar20;
        if (local_af == 2) {
          puVar3 = &DAT_18005f700;
        }
        else if (local_af == 3) {
          puVar3 = &DAT_18005f6e0;
        }
        else {
          if (local_af != 4) {
            uVar22 = 0;
            uVar19 = 0;
            goto LAB_180010dd8;
          }
          puVar3 = &DAT_18005f6a0;
        }
        iVar1 = *(int *)(puVar3 + uVar24 * 4);
        iVar10 = 0x40 - iVar1;
        uVar19 = (uint)*(byte *)(&local_70 + uVar12) * iVar10 +
                 (uint)*(byte *)(&local_70 + uVar7) * iVar1 + 0x20 >> 6;
        uVar22 = (uint)*(byte *)((longlong)&local_70 + uVar7 * 4 + 1) * iVar1 +
                 (uint)*(byte *)((longlong)&local_70 + uVar12 * 4 + 1) * iVar10 + 0x20 >> 6;
        uVar17 = iVar1 * (uint)*(byte *)((longlong)&local_70 + uVar7 * 4 + 2) + 0x20 +
                 (uint)*(byte *)((longlong)&local_70 + uVar12 * 4 + 2) * iVar10 >> 6;
      }
      else if ((char)local_98 == '\0') {
        uVar24 = (ulonglong)*(byte *)((longlong)&local_58 + uVar11);
        bVar16 = local_b8;
        if (local_af == 2) {
          puVar3 = &DAT_18005f700;
        }
        else if (local_af == 3) {
          puVar3 = &DAT_18005f6e0;
        }
        else {
          if (local_af != 4) {
            uVar17 = 0;
            uVar22 = 0;
            uVar19 = 0;
            goto LAB_180010dd8;
          }
          puVar3 = &DAT_18005f6a0;
        }
        iVar1 = *(int *)(puVar3 + (ulonglong)*pbVar20 * 4);
        iVar10 = 0x40 - iVar1;
        uVar19 = (uint)*(byte *)(&local_70 + uVar7) * iVar1 +
                 (uint)*(byte *)(&local_70 + uVar12) * iVar10 + 0x20 >> 6;
        uVar22 = (uint)*(byte *)((longlong)&local_70 + uVar12 * 4 + 1) * iVar10 +
                 (uint)*(byte *)((longlong)&local_70 + uVar7 * 4 + 1) * iVar1 + 0x20 >> 6;
        uVar17 = (uint)*(byte *)((longlong)&local_70 + uVar7 * 4 + 2) * iVar1 + 0x20 +
                 (uint)*(byte *)((longlong)&local_70 + uVar12 * 4 + 2) * iVar10 >> 6 & 0xff;
      }
      else {
        uVar24 = (ulonglong)*pbVar20;
        if (uVar17 == 2) {
          puVar3 = &DAT_18005f700;
        }
        else if (uVar17 == 3) {
          puVar3 = &DAT_18005f6e0;
        }
        else {
          if (uVar17 != 4) {
            uVar17 = 0;
            uVar22 = 0;
            uVar19 = 0;
            goto LAB_180010dd8;
          }
          puVar3 = &DAT_18005f6a0;
        }
        iVar1 = *(int *)(puVar3 + (ulonglong)*(byte *)((longlong)&local_58 + uVar11) * 4);
        iVar10 = 0x40 - iVar1;
        uVar19 = (uint)*(byte *)(&local_70 + uVar12) * iVar10 +
                 (uint)*(byte *)(&local_70 + uVar7) * iVar1 + 0x20 >> 6;
        uVar22 = (uint)*(byte *)((longlong)&local_70 + uVar12 * 4 + 1) * iVar10 +
                 (uint)*(byte *)((longlong)&local_70 + uVar7 * 4 + 1) * iVar1 + 0x20 >> 6;
        uVar17 = (uint)*(byte *)((longlong)&local_70 + uVar7 * 4 + 2) * iVar1 + 0x20 +
                 (uint)*(byte *)((longlong)&local_70 + uVar12 * 4 + 2) * iVar10 >> 6 & 0xff;
      }
LAB_180010dd8:
      if (bVar16 == 2) {
        puVar3 = &DAT_18005f700;
LAB_180010e07:
        uVar4 = *(int *)(puVar3 + uVar24 * 4) * (uint)*(byte *)((longlong)&local_70 + uVar7 * 4 + 3)
                + (uint)*(byte *)((longlong)&local_70 + uVar12 * 4 + 3) *
                  (0x40 - *(int *)(puVar3 + uVar24 * 4)) + 0x20 >> 6;
      }
      else {
        if (bVar16 == 3) {
          puVar3 = &DAT_18005f6e0;
          goto LAB_180010e07;
        }
        if (bVar16 == 4) {
          puVar3 = &DAT_18005f6a0;
          goto LAB_180010e07;
        }
        uVar4 = 0;
      }
      if (uVar2 == 1) {
        bVar16 = (byte)uVar19;
        uVar19 = uVar4 & 0xff;
LAB_180010e58:
        uVar4 = (uint)bVar16;
      }
      else {
        if (uVar2 == 2) {
          bVar16 = (byte)uVar22;
          uVar22 = uVar4 & 0xff;
          goto LAB_180010e58;
        }
        if (uVar2 == 3) {
          bVar16 = (byte)uVar17;
          uVar17 = uVar4 & 0xff;
          goto LAB_180010e58;
        }
      }
      uVar11 = uVar11 + 1;
      fVar26 = (float)(uVar19 & 0xff) * 0.003921569;
      fVar27 = (float)(uVar22 & 0xff) * 0.003921569;
      local_88 = CONCAT44(fVar27,fVar26);
      fStack_80 = (float)(uVar17 & 0xff) * 0.003921569;
      fStack_7c = (float)(uVar4 & 0xff) * 0.003921569;
      *param_2 = fVar26;
      param_2[1] = fVar27;
      param_2[2] = fStack_80;
      param_2[3] = fStack_7c;
      param_2 = param_2 + 4;
    } while (uVar11 < 0x10);
  }
  else {
    memset(param_2,0,0x100);
  }
LAB_180010410:
  __security_check_cookie(local_30 ^ (ulonglong)auStack_d8);
  return;
}



void FUN_180010f40(float *param_1,longlong param_2)

{
  FUN_180010030(param_2,param_1);
  return;
}



void FUN_180010f50(ulonglong **param_1)

{
  ulonglong *puVar1;
  ulonglong *_Memory;
  
  if ((ulonglong *)0xf < param_1[3]) {
    puVar1 = *param_1;
    _Memory = puVar1;
    if (0xfff < (longlong)param_1[3] + 1U) {
      if (((ulonglong)puVar1 & 0x1f) != 0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      _Memory = (ulonglong *)puVar1[-1];
      if (puVar1 <= _Memory) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if ((ulonglong)((longlong)puVar1 - (longlong)_Memory) < 8) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if (0x27 < (ulonglong)((longlong)puVar1 - (longlong)_Memory)) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
    }
    free(_Memory);
  }
  param_1[3] = (ulonglong *)0xf;
  param_1[2] = (ulonglong *)0x0;
  if ((ulonglong *)0xf < param_1[3]) {
    param_1 = (ulonglong **)*param_1;
  }
  *(undefined *)param_1 = 0;
  return;
}



void FUN_180010fe0(ulonglong **param_1,ulonglong *param_2,ulonglong *param_3)

{
  ulonglong *extraout_RAX;
  ulonglong *puVar1;
  ulonglong **ppuVar2;
  ulonglong uVar3;
  ulonglong **_Dst;
  ulonglong *puVar4;
  
  puVar4 = (ulonglong *)((ulonglong)param_2 | 0xf);
  if (puVar4 != (ulonglong *)0xffffffffffffffff) {
    puVar1 = param_1[3];
    uVar3 = (ulonglong)puVar1 >> 1;
    param_2 = puVar4;
    if (((ulonglong)puVar4 / 3 < uVar3) &&
       (param_2 = (ulonglong *)0xfffffffffffffffe, puVar1 <= (ulonglong *)(-uVar3 - 2))) {
      param_2 = (ulonglong *)((longlong)puVar1 + uVar3);
    }
  }
  puVar4 = (ulonglong *)((longlong)param_2 + 1);
  if (puVar4 == (ulonglong *)0x0) {
    _Dst = (ulonglong **)0x0;
  }
  else if (puVar4 < (ulonglong *)0x1000) {
    _Dst = (ulonglong **)operator_new((__uint64)puVar4);
    if (_Dst == (ulonglong **)0x0) {
                    // WARNING: Subroutine does not return
      _invalid_parameter_noinfo_noreturn();
    }
  }
  else {
    puVar1 = param_2 + 5;
    if (puVar1 <= puVar4) {
      std::_Xbad_alloc();
      puVar1 = extraout_RAX;
    }
    puVar4 = (ulonglong *)operator_new((__uint64)puVar1);
    if (puVar4 == (ulonglong *)0x0) {
                    // WARNING: Subroutine does not return
      _invalid_parameter_noinfo_noreturn();
    }
    _Dst = (ulonglong **)((longlong)puVar4 + 0x27U & 0xffffffffffffffe0);
    _Dst[-1] = puVar4;
  }
  if (param_3 != (ulonglong *)0x0) {
    ppuVar2 = param_1;
    if ((ulonglong *)0xf < param_1[3]) {
      ppuVar2 = (ulonglong **)*param_1;
    }
    if (param_3 != (ulonglong *)0x0) {
      memcpy(_Dst,ppuVar2,(size_t)param_3);
    }
  }
  if ((ulonglong *)0xf < param_1[3]) {
    puVar4 = *param_1;
    puVar1 = puVar4;
    if (0xfff < (longlong)param_1[3] + 1U) {
      if (((ulonglong)puVar4 & 0x1f) != 0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      puVar1 = (ulonglong *)puVar4[-1];
      if (puVar4 <= puVar1) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if ((ulonglong)((longlong)puVar4 - (longlong)puVar1) < 8) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if (0x27 < (ulonglong)((longlong)puVar4 - (longlong)puVar1)) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
    }
    free(puVar1);
  }
  param_1[3] = (ulonglong *)0xf;
  param_1[2] = (ulonglong *)0x0;
  ppuVar2 = param_1;
  if ((ulonglong *)0xf < param_1[3]) {
    ppuVar2 = (ulonglong **)*param_1;
  }
  *(undefined *)ppuVar2 = 0;
  *param_1 = (ulonglong *)_Dst;
  param_1[3] = param_2;
  param_1[2] = param_3;
  if ((ulonglong *)0xf < param_1[3]) {
    param_1 = _Dst;
  }
  *(undefined *)((longlong)param_1 + (longlong)param_3) = 0;
  return;
}



void FUN_180011190(void **param_1,void *param_2,void *param_3)

{
  void *pvVar1;
  void **_Dst;
  void **ppvVar2;
  ulonglong uVar3;
  void *pvVar4;
  
  pvVar4 = (void *)((ulonglong)param_2 | 7);
  if (pvVar4 < (void *)0x7fffffffffffffff) {
    pvVar1 = param_1[3];
    uVar3 = (ulonglong)pvVar1 >> 1;
    param_2 = pvVar4;
    if (((ulonglong)pvVar4 / 3 < uVar3) &&
       (param_2 = (void *)(uVar3 + (longlong)pvVar1), (void *)(0x7ffffffffffffffe - uVar3) < pvVar1)
       ) {
      param_2 = (void *)0x7ffffffffffffffe;
    }
  }
  _Dst = (void **)FUN_180011320(param_1,(longlong)param_2 + 1);
  if (param_3 != (void *)0x0) {
    ppvVar2 = param_1;
    if ((void *)0x7 < param_1[3]) {
      ppvVar2 = (void **)*param_1;
    }
    if (param_3 != (void *)0x0) {
      memcpy(_Dst,ppvVar2,(longlong)param_3 * 2);
    }
  }
  if ((void *)0x7 < param_1[3]) {
    FUN_180011890(param_1,*param_1,(longlong)param_1[3] + 1);
  }
  param_1[3] = (void *)0x7;
  param_1[2] = (void *)0x0;
  ppvVar2 = param_1;
  if ((void *)0x7 < param_1[3]) {
    ppvVar2 = (void **)*param_1;
  }
  *(undefined2 *)ppvVar2 = 0;
  *param_1 = _Dst;
  param_1[3] = param_2;
  param_1[2] = param_3;
  if ((void *)0x7 < param_1[3]) {
    param_1 = _Dst;
  }
  *(undefined2 *)((longlong)param_1 + (longlong)param_3 * 2) = 0;
  return;
}



void * FUN_1800112b0(undefined8 param_1,ulonglong param_2)

{
  code *pcVar1;
  void *pvVar2;
  void *pvVar3;
  
  if (param_2 == 0) {
    pvVar2 = (void *)0x0;
  }
  else {
    if (0xfff < param_2) {
      if (param_2 + 0x27 <= param_2) {
        std::_Xbad_alloc();
        pcVar1 = (code *)swi(3);
        pvVar2 = (void *)(*pcVar1)();
        return pvVar2;
      }
      pvVar2 = operator_new(param_2 + 0x27);
      if (pvVar2 == (void *)0x0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      pvVar3 = (void *)((longlong)pvVar2 + 0x27U & 0xffffffffffffffe0);
      *(void **)((longlong)pvVar3 + -8) = pvVar2;
      return pvVar3;
    }
    pvVar2 = operator_new(param_2);
    if (pvVar2 == (void *)0x0) {
                    // WARNING: Subroutine does not return
      _invalid_parameter_noinfo_noreturn();
    }
  }
  return pvVar2;
}



void * FUN_180011320(undefined8 param_1,ulonglong param_2)

{
  code *pcVar1;
  ulonglong uVar2;
  void *pvVar3;
  void *pvVar4;
  
  if (param_2 == 0) {
    pvVar3 = (void *)0x0;
  }
  else {
    if (0x7fffffffffffffff < param_2) {
      std::_Xbad_alloc();
      pcVar1 = (code *)swi(3);
      pvVar3 = (void *)(*pcVar1)();
      return pvVar3;
    }
    uVar2 = param_2 * 2;
    if (0xfff < uVar2) {
      if (uVar2 + 0x27 <= uVar2) {
        std::_Xbad_alloc();
        pcVar1 = (code *)swi(3);
        pvVar3 = (void *)(*pcVar1)();
        return pvVar3;
      }
      pvVar3 = operator_new(uVar2 + 0x27);
      if (pvVar3 == (void *)0x0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      pvVar4 = (void *)((longlong)pvVar3 + 0x27U & 0xffffffffffffffe0);
      *(void **)((longlong)pvVar4 + -8) = pvVar3;
      return pvVar4;
    }
    pvVar3 = operator_new(uVar2);
    if (pvVar3 == (void *)0x0) {
                    // WARNING: Subroutine does not return
      _invalid_parameter_noinfo_noreturn();
    }
  }
  return pvVar3;
}



ulonglong **
FUN_1800113a0(ulonglong **param_1,ulonglong **param_2,ulonglong *param_3,ulonglong *param_4)

{
  code *pcVar1;
  ulonglong **ppuVar2;
  ulonglong *puVar3;
  
  if (param_2[2] < param_3) {
    std::_Xout_of_range("invalid string position");
    pcVar1 = (code *)swi(3);
    ppuVar2 = (ulonglong **)(*pcVar1)();
    return ppuVar2;
  }
  puVar3 = (ulonglong *)((longlong)param_2[2] - (longlong)param_3);
  if (puVar3 < param_4) {
    param_4 = puVar3;
  }
  if (param_1 == param_2) {
    puVar3 = (ulonglong *)((longlong)param_3 + (longlong)param_4);
    if (param_1[2] < puVar3) {
      std::_Xout_of_range("invalid string position");
      pcVar1 = (code *)swi(3);
      ppuVar2 = (ulonglong **)(*pcVar1)();
      return ppuVar2;
    }
    param_1[2] = puVar3;
    ppuVar2 = param_1;
    if ((ulonglong *)0xf < param_1[3]) {
      ppuVar2 = (ulonglong **)*param_1;
    }
    *(undefined *)((longlong)ppuVar2 + (longlong)puVar3) = 0;
    FUN_180011900((longlong **)param_1,(longlong *)0x0,(ulonglong)param_3);
  }
  else {
    if (param_4 == (ulonglong *)0xffffffffffffffff) {
      std::_Xlength_error("string too long");
      pcVar1 = (code *)swi(3);
      ppuVar2 = (ulonglong **)(*pcVar1)();
      return ppuVar2;
    }
    if (param_1[3] < param_4) {
      FUN_180010fe0(param_1,param_4,param_1[2]);
      if (param_4 == (ulonglong *)0x0) {
        return param_1;
      }
    }
    else if (param_4 == (ulonglong *)0x0) {
      param_1[2] = (ulonglong *)0x0;
      if ((ulonglong *)0xf < param_1[3]) {
        *(undefined *)*param_1 = 0;
        return param_1;
      }
      *(undefined *)param_1 = 0;
      return param_1;
    }
    if ((ulonglong *)0xf < param_2[3]) {
      param_2 = (ulonglong **)*param_2;
    }
    ppuVar2 = param_1;
    if ((ulonglong *)0xf < param_1[3]) {
      ppuVar2 = (ulonglong **)*param_1;
    }
    if (param_4 != (ulonglong *)0x0) {
      memcpy(ppuVar2,(void *)((longlong)param_2 + (longlong)param_3),(size_t)param_4);
    }
    param_1[2] = param_4;
    ppuVar2 = param_1;
    if ((ulonglong *)0xf < param_1[3]) {
      ppuVar2 = (ulonglong **)*param_1;
    }
    *(undefined *)((longlong)ppuVar2 + (longlong)param_4) = 0;
  }
  return param_1;
}



ulonglong ** FUN_1800114d0(ulonglong **param_1,ulonglong **param_2,ulonglong *param_3)

{
  ulonglong *puVar1;
  code *pcVar2;
  ulonglong **ppuVar3;
  
  if (param_2 != (ulonglong **)0x0) {
    puVar1 = param_1[3];
    ppuVar3 = param_1;
    if ((ulonglong *)0xf < puVar1) {
      ppuVar3 = (ulonglong **)*param_1;
    }
    if (ppuVar3 <= param_2) {
      ppuVar3 = param_1;
      if ((ulonglong *)0xf < puVar1) {
        ppuVar3 = (ulonglong **)*param_1;
      }
      if (param_2 < (ulonglong **)((longlong)ppuVar3 + (longlong)param_1[2])) {
        ppuVar3 = param_1;
        if ((ulonglong *)0xf < puVar1) {
          ppuVar3 = (ulonglong **)*param_1;
        }
        ppuVar3 = FUN_1800113a0(param_1,param_1,(ulonglong *)((longlong)param_2 - (longlong)ppuVar3)
                                ,param_3);
        return ppuVar3;
      }
    }
  }
  if (param_3 == (ulonglong *)0xffffffffffffffff) {
    std::_Xlength_error("string too long");
    pcVar2 = (code *)swi(3);
    ppuVar3 = (ulonglong **)(*pcVar2)();
    return ppuVar3;
  }
  if (param_1[3] < param_3) {
    FUN_180010fe0(param_1,param_3,param_1[2]);
    if (param_3 == (ulonglong *)0x0) {
      return param_1;
    }
  }
  else if (param_3 == (ulonglong *)0x0) {
    param_1[2] = (ulonglong *)0x0;
    if ((ulonglong *)0xf < param_1[3]) {
      *(undefined *)*param_1 = 0;
      return param_1;
    }
    *(undefined *)param_1 = 0;
    return param_1;
  }
  ppuVar3 = param_1;
  if ((ulonglong *)0xf < param_1[3]) {
    ppuVar3 = (ulonglong **)*param_1;
  }
  if (param_3 != (ulonglong *)0x0) {
    memcpy(ppuVar3,param_2,(size_t)param_3);
  }
  param_1[2] = param_3;
  ppuVar3 = param_1;
  if ((ulonglong *)0xf < param_1[3]) {
    ppuVar3 = (ulonglong **)*param_1;
  }
  *(undefined *)((longlong)ppuVar3 + (longlong)param_3) = 0;
  return param_1;
}



void ** FUN_180011600(void **param_1,void **param_2,void *param_3,void *param_4)

{
  code *pcVar1;
  void **ppvVar2;
  void *pvVar3;
  
  if (param_2[2] < param_3) {
    std::_Xout_of_range("invalid string position");
    pcVar1 = (code *)swi(3);
    ppvVar2 = (void **)(*pcVar1)();
    return ppvVar2;
  }
  pvVar3 = (void *)((longlong)param_2[2] - (longlong)param_3);
  if (pvVar3 < param_4) {
    param_4 = pvVar3;
  }
  if (param_1 == param_2) {
    pvVar3 = (void *)((longlong)param_3 + (longlong)param_4);
    if (param_1[2] < pvVar3) {
      std::_Xout_of_range("invalid string position");
      pcVar1 = (code *)swi(3);
      ppvVar2 = (void **)(*pcVar1)();
      return ppvVar2;
    }
    param_1[2] = pvVar3;
    ppvVar2 = param_1;
    if ((void *)0x7 < param_1[3]) {
      ppvVar2 = (void **)*param_1;
    }
    *(undefined2 *)((longlong)ppvVar2 + (longlong)pvVar3 * 2) = 0;
    FUN_1800119d0(param_1,0,(ulonglong)param_3);
  }
  else {
    if ((void *)0x7ffffffffffffffe < param_4) {
      std::_Xlength_error("string too long");
      pcVar1 = (code *)swi(3);
      ppvVar2 = (void **)(*pcVar1)();
      return ppvVar2;
    }
    if (param_1[3] < param_4) {
      FUN_180011190(param_1,param_4,param_1[2]);
      if (param_4 == (void *)0x0) {
        return param_1;
      }
    }
    else if (param_4 == (void *)0x0) {
      param_1[2] = (void *)0x0;
      ppvVar2 = param_1;
      if ((void *)0x7 < param_1[3]) {
        ppvVar2 = (void **)*param_1;
      }
      *(undefined2 *)ppvVar2 = 0;
      return param_1;
    }
    if ((void *)0x7 < param_2[3]) {
      param_2 = (void **)*param_2;
    }
    ppvVar2 = param_1;
    if ((void *)0x7 < param_1[3]) {
      ppvVar2 = (void **)*param_1;
    }
    if (param_4 != (void *)0x0) {
      memcpy(ppvVar2,(void *)((longlong)param_2 + (longlong)param_3 * 2),(longlong)param_4 * 2);
    }
    param_1[2] = param_4;
    ppvVar2 = param_1;
    if ((void *)0x7 < param_1[3]) {
      ppvVar2 = (void **)*param_1;
    }
    *(undefined2 *)((longlong)ppvVar2 + (longlong)param_4 * 2) = 0;
  }
  return param_1;
}



void ** FUN_180011740(void **param_1,void **param_2,void *param_3)

{
  void *pvVar1;
  code *pcVar2;
  void **ppvVar3;
  
  if (param_2 != (void **)0x0) {
    pvVar1 = param_1[3];
    ppvVar3 = param_1;
    if ((void *)0x7 < pvVar1) {
      ppvVar3 = (void **)*param_1;
    }
    if (ppvVar3 <= param_2) {
      ppvVar3 = param_1;
      if ((void *)0x7 < pvVar1) {
        ppvVar3 = (void **)*param_1;
      }
      if (param_2 < (void **)((longlong)ppvVar3 + (longlong)param_1[2] * 2)) {
        ppvVar3 = param_1;
        if ((void *)0x7 < pvVar1) {
          ppvVar3 = (void **)*param_1;
        }
        ppvVar3 = FUN_180011600(param_1,param_1,(void *)((longlong)param_2 - (longlong)ppvVar3 >> 1)
                                ,param_3);
        return ppvVar3;
      }
    }
  }
  if ((void *)0x7ffffffffffffffe < param_3) {
    std::_Xlength_error("string too long");
    pcVar2 = (code *)swi(3);
    ppvVar3 = (void **)(*pcVar2)();
    return ppvVar3;
  }
  if (param_1[3] < param_3) {
    FUN_180011190(param_1,param_3,param_1[2]);
    if (param_3 == (void *)0x0) {
      return param_1;
    }
  }
  else if (param_3 == (void *)0x0) {
    param_1[2] = (void *)0x0;
    if ((void *)0x7 < param_1[3]) {
      *(undefined2 *)*param_1 = 0;
      return param_1;
    }
    *(undefined2 *)param_1 = 0;
    return param_1;
  }
  ppvVar3 = param_1;
  if ((void *)0x7 < param_1[3]) {
    ppvVar3 = (void **)*param_1;
  }
  if (param_3 != (void *)0x0) {
    memcpy(ppvVar3,param_2,(longlong)param_3 * 2);
  }
  param_1[2] = param_3;
  ppvVar3 = param_1;
  if ((void *)0x7 < param_1[3]) {
    ppvVar3 = (void **)*param_1;
  }
  *(undefined2 *)((longlong)ppvVar3 + (longlong)param_3 * 2) = 0;
  return param_1;
}



void FUN_180011890(undefined8 param_1,void *param_2,ulonglong param_3)

{
  void *_Memory;
  
  if (0x7fffffffffffffff < param_3) {
                    // WARNING: Subroutine does not return
    _invalid_parameter_noinfo_noreturn();
  }
  _Memory = param_2;
  if (0xfff < param_3 * 2) {
    if (((ulonglong)param_2 & 0x1f) != 0) {
                    // WARNING: Subroutine does not return
      _invalid_parameter_noinfo_noreturn();
    }
    _Memory = *(void **)((longlong)param_2 + -8);
    if (param_2 <= _Memory) {
                    // WARNING: Subroutine does not return
      _invalid_parameter_noinfo_noreturn();
    }
    if ((ulonglong)((longlong)param_2 - (longlong)_Memory) < 8) {
                    // WARNING: Subroutine does not return
      _invalid_parameter_noinfo_noreturn();
    }
    if (0x27 < (ulonglong)((longlong)param_2 - (longlong)_Memory)) {
                    // WARNING: Subroutine does not return
      _invalid_parameter_noinfo_noreturn();
    }
  }
  free(_Memory);
  return;
}



longlong ** FUN_180011900(longlong **param_1,longlong *param_2,ulonglong param_3)

{
  code *pcVar1;
  longlong **pplVar2;
  longlong *plVar3;
  
  plVar3 = param_1[2];
  if (plVar3 < param_2) {
    std::_Xout_of_range("invalid string position");
    pcVar1 = (code *)swi(3);
    pplVar2 = (longlong **)(*pcVar1)();
    return pplVar2;
  }
  if (param_3 < (ulonglong)((longlong)plVar3 - (longlong)param_2)) {
    if (param_3 != 0) {
      pplVar2 = param_1;
      if ((longlong *)0xf < param_1[3]) {
        pplVar2 = (longlong **)*param_1;
      }
      plVar3 = (longlong *)((longlong)plVar3 - param_3);
      if ((longlong)plVar3 - (longlong)param_2 != 0) {
        memmove((void *)((longlong)pplVar2 + (longlong)param_2),
                (void *)((longlong)(void *)((longlong)pplVar2 + (longlong)param_2) + param_3),
                (longlong)plVar3 - (longlong)param_2);
      }
      param_1[2] = plVar3;
      if ((longlong *)0xf < param_1[3]) {
        *(undefined *)((longlong)*param_1 + (longlong)plVar3) = 0;
        return param_1;
      }
      *(undefined *)((longlong)param_1 + (longlong)plVar3) = 0;
    }
    return param_1;
  }
  param_1[2] = param_2;
  if (param_1[3] < (longlong *)0x10) {
    *(undefined *)((longlong)param_1 + (longlong)param_2) = 0;
    return param_1;
  }
  *(undefined *)((longlong)*param_1 + (longlong)param_2) = 0;
  return param_1;
}



undefined8 * FUN_1800119d0(undefined8 *param_1,ulonglong param_2,ulonglong param_3)

{
  void *_Dst;
  ulonglong uVar1;
  code *pcVar2;
  undefined8 *puVar3;
  longlong lVar4;
  
  uVar1 = param_1[2];
  if (uVar1 < param_2) {
    std::_Xout_of_range("invalid string position");
    pcVar2 = (code *)swi(3);
    puVar3 = (undefined8 *)(*pcVar2)();
    return puVar3;
  }
  if (param_3 < uVar1 - param_2) {
    if (param_3 != 0) {
      puVar3 = param_1;
      if (7 < (ulonglong)param_1[3]) {
        puVar3 = (undefined8 *)*param_1;
      }
      lVar4 = uVar1 - param_3;
      _Dst = (void *)((longlong)puVar3 + param_2 * 2);
      if (lVar4 - param_2 != 0) {
        memmove(_Dst,(void *)((longlong)_Dst + param_3 * 2),(lVar4 - param_2) * 2);
      }
      param_1[2] = lVar4;
      puVar3 = param_1;
      if (7 < (ulonglong)param_1[3]) {
        puVar3 = (undefined8 *)*param_1;
      }
      *(undefined2 *)((longlong)puVar3 + lVar4 * 2) = 0;
    }
    return param_1;
  }
  param_1[2] = param_2;
  puVar3 = param_1;
  if (7 < (ulonglong)param_1[3]) {
    puVar3 = (undefined8 *)*param_1;
  }
  *(undefined2 *)((longlong)puVar3 + param_2 * 2) = 0;
  return param_1;
}



undefined CSharp_IConverter_ConvertRaw__SWIG_0
                    (void *param_1,Enum param_2,int param_3,uint param_4,float *param_5,Enum param_6
                    ,int param_7,int param_8,undefined4 *param_9,undefined4 *param_10)

{
  undefined uVar1;
  
                    // 0x11a80  13  CSharp_IConverter_ConvertRaw__SWIG_0
  uVar1 = FUN_1800163a0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8 != 0,param_9
                        ,param_10);
  return uVar1;
}



undefined CSharp_IConverter_ConvertRaw__SWIG_1
                    (void *param_1,Enum *param_2,uint param_3,float *param_4,Enum *param_5,
                    int param_6,undefined4 *param_7,undefined4 *param_8)

{
  undefined uVar1;
  
                    // 0x11ae0  14  CSharp_IConverter_ConvertRaw__SWIG_1
  if (param_2 != (Enum *)0x0) {
    if (param_5 != (Enum *)0x0) {
      uVar1 = FUN_1800163b0(param_1,*param_2,param_3,param_4,*param_5,param_6 != 0,param_7,param_8);
      return uVar1;
    }
  }
  (*DAT_1800650c8)("Attempt to dereference null Graphine::Core::DataType::Enum",0);
  return 0;
}



void CSharp_IConverter_FixedConversion_RGBAToBGRA(longlong param_1,uint param_2,longlong param_3)

{
                    // 0x11b70  15  CSharp_IConverter_FixedConversion_RGBAToBGRA
  FUN_1800163d0(param_1,(ulonglong)param_2,param_3);
  return;
}



void CSharp_IConverter_GetScanLine__SWIG_0(longlong *param_1)

{
                    // 0x11b80  16  CSharp_IConverter_GetScanLine__SWIG_0
                    // 0x11b80  39  CSharp_IImage_Resize
                    // WARNING: Could not recover jumptable at 0x000180011b83. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x18))();
  return;
}



void CSharp_IConverter_GetScanLine__SWIG_1(longlong *param_1)

{
                    // 0x11b90  17  CSharp_IConverter_GetScanLine__SWIG_1
                    // WARNING: Could not recover jumptable at 0x000180011b93. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x10))();
  return;
}



void CSharp_IConverter_GetScanLines__SWIG_0
               (longlong *param_1,undefined param_2,undefined param_3,undefined param_4,
               undefined8 param_5)

{
                    // 0x11ba0  18  CSharp_IConverter_GetScanLines__SWIG_0
                    // WARNING: Could not recover jumptable at 0x000180011bac. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x28))();
  return;
}



void CSharp_IConverter_GetScanLines__SWIG_1(longlong *param_1)

{
                    // 0x11bb0  19  CSharp_IConverter_GetScanLines__SWIG_1
  (**(code **)(*param_1 + 0x28))();
  return;
}



void CSharp_IConverter_GetScanLines__SWIG_2
               (longlong *param_1,undefined param_2,undefined param_3,undefined param_4,
               undefined param_5,undefined param_6,undefined8 param_7)

{
                    // 0x11bd0  20  CSharp_IConverter_GetScanLines__SWIG_2
                    // WARNING: Could not recover jumptable at 0x000180011bdc. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x20))();
  return;
}



void CSharp_IConverter_GetScanLines__SWIG_3
               (longlong *param_1,undefined param_2,undefined param_3,undefined param_4,
               undefined4 param_5,undefined8 param_6)

{
                    // 0x11be0  21  CSharp_IConverter_GetScanLines__SWIG_3
  (**(code **)(*param_1 + 0x20))();
  return;
}



undefined CSharp_IConverter_IsLossy(longlong *param_1)

{
  undefined uVar1;
  
                    // 0x11c10  22  CSharp_IConverter_IsLossy
  uVar1 = (**(code **)(*param_1 + 8))();
  return uVar1;
}



void CSharp_IImage_Close(longlong *param_1)

{
                    // 0x11c30  23  CSharp_IImage_Close
                    // WARNING: Could not recover jumptable at 0x000180011c33. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x38))();
  return;
}



void CSharp_IImage_FlipHorizontal(longlong *param_1)

{
                    // 0x11c40  24  CSharp_IImage_FlipHorizontal
                    // WARNING: Could not recover jumptable at 0x000180011c43. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x20))();
  return;
}



void CSharp_IImage_FlipVertical(longlong *param_1)

{
                    // 0x11c50  25  CSharp_IImage_FlipVertical
                    // WARNING: Could not recover jumptable at 0x000180011c53. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x28))();
  return;
}



void CSharp_IImage_GetImageData__SWIG_0(longlong *param_1,undefined8 param_2,undefined4 param_3)

{
                    // 0x11c60  26  CSharp_IImage_GetImageData__SWIG_0
                    // WARNING: Could not recover jumptable at 0x000180011c66. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x68))(param_1,param_2,param_3);
  return;
}



void CSharp_IImage_GetImageData__SWIG_1(longlong *param_1,undefined8 param_2)

{
                    // 0x11c70  27  CSharp_IImage_GetImageData__SWIG_1
                    // WARNING: Could not recover jumptable at 0x000180011c76. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x68))(param_1,param_2,0);
  return;
}



void CSharp_IImage_GetImageData__SWIG_2
               (longlong *param_1,undefined param_2,undefined param_3,undefined param_4,
               undefined8 param_5)

{
                    // 0x11c80  28  CSharp_IImage_GetImageData__SWIG_2
                    // WARNING: Could not recover jumptable at 0x000180011c8c. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x60))();
  return;
}



void CSharp_IImage_GetImageData__SWIG_3(longlong *param_1)

{
                    // 0x11c90  29  CSharp_IImage_GetImageData__SWIG_3
  (**(code **)(*param_1 + 0x60))();
  return;
}



void CSharp_IImage_GetScanLine__SWIG_0(longlong *param_1)

{
                    // 0x11cb0  30  CSharp_IImage_GetScanLine__SWIG_0
                    // WARNING: Could not recover jumptable at 0x000180011cb3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x48))();
  return;
}



void CSharp_IImage_GetScanLine__SWIG_1(longlong *param_1)

{
                    // 0x11cc0  31  CSharp_IImage_GetScanLine__SWIG_1
                    // WARNING: Could not recover jumptable at 0x000180011cc3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x40))();
  return;
}



void CSharp_IImage_GetScanLines__SWIG_0
               (longlong *param_1,undefined param_2,undefined param_3,undefined param_4,
               undefined8 param_5)

{
                    // 0x11cd0  32  CSharp_IImage_GetScanLines__SWIG_0
                    // WARNING: Could not recover jumptable at 0x000180011cdc. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x58))();
  return;
}



void CSharp_IImage_GetScanLines__SWIG_1(longlong *param_1)

{
                    // 0x11ce0  33  CSharp_IImage_GetScanLines__SWIG_1
  (**(code **)(*param_1 + 0x58))();
  return;
}



void CSharp_IImage_GetScanLines__SWIG_2
               (longlong *param_1,undefined param_2,undefined param_3,undefined param_4,
               undefined param_5,undefined param_6,undefined8 param_7)

{
                    // 0x11d00  34  CSharp_IImage_GetScanLines__SWIG_2
                    // WARNING: Could not recover jumptable at 0x000180011d0c. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x50))();
  return;
}



void CSharp_IImage_GetScanLines__SWIG_3
               (longlong *param_1,undefined param_2,undefined param_3,undefined param_4,
               undefined4 param_5,undefined8 param_6)

{
                    // 0x11d10  35  CSharp_IImage_GetScanLines__SWIG_3
  (**(code **)(*param_1 + 0x50))();
  return;
}



void CSharp_IImage_GetSpec(longlong *param_1)

{
                    // 0x11d40  36  CSharp_IImage_GetSpec
                    // WARNING: Could not recover jumptable at 0x000180011d43. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x30))();
  return;
}



void CSharp_IImage_Open__SWIG_0(longlong *param_1,void **param_2)

{
  void *pvVar1;
  undefined auStack_58 [32];
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x11d50  37  CSharp_IImage_Open__SWIG_0
  local_18 = DAT_180065150 ^ (ulonglong)auStack_58;
  if (param_2 == (void **)0x0) {
    (*DAT_1800650c8)("null wstring");
    __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
    return;
  }
  pvVar1 = (void *)0x0;
  local_20 = 7;
  local_28 = 0;
  local_38._0_2_ = 0;
  if (*(short *)param_2 != 0) {
    pvVar1 = (void *)0xffffffffffffffff;
    do {
      pvVar1 = (void *)((longlong)pvVar1 + 1);
    } while (*(short *)((longlong)param_2 + (longlong)pvVar1 * 2) != 0);
  }
  FUN_180011740((void **)&local_38,param_2,pvVar1);
  (**(code **)(*param_1 + 0x10))(param_1,&local_38);
  if (7 < local_20) {
    FUN_180011890(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
  return;
}



void CSharp_IImage_Open__SWIG_1(longlong *param_1,undefined8 param_2,undefined4 param_3)

{
                    // 0x11e10  38  CSharp_IImage_Open__SWIG_1
                    // WARNING: Could not recover jumptable at 0x000180011e16. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 8))(param_1,param_2,param_3);
  return;
}



undefined8 CSharp_ImageFactory_Create(undefined8 *param_1)

{
  undefined8 *puVar1;
  
                    // 0x11e20  40  CSharp_ImageFactory_Create
  puVar1 = (undefined8 *)operator_new(0x10);
  if (puVar1 != (undefined8 *)0x0) {
    puVar1 = FUN_180017240(puVar1);
  }
  *param_1 = puVar1;
  return 0;
}



void CSharp_ImageFactory_CreateConverter
               (undefined8 param_1,undefined4 param_2,undefined4 param_3,void **param_4,
               void **param_5,int param_6,longlong **param_7)

{
  short sVar1;
  void *pvVar2;
  void *pvVar3;
  undefined auStackY_c8 [32];
  undefined2 local_88;
  undefined6 uStack_86;
  undefined8 local_78;
  ulonglong local_70;
  undefined2 local_68;
  undefined6 uStack_66;
  undefined8 local_58;
  ulonglong local_50;
  ulonglong local_48;
  
                    // 0x11e30  41  CSharp_ImageFactory_CreateConverter
  local_48 = DAT_180065150 ^ (ulonglong)auStackY_c8;
  if (param_4 == (void **)0x0) {
    (*DAT_1800650c8)("null wstring",0);
  }
  else {
    pvVar2 = (void *)0xffffffffffffffff;
    local_50 = 7;
    local_58 = 0;
    local_68 = 0;
    pvVar3 = (void *)0x0;
    if (*(short *)param_4 != 0) {
      pvVar3 = (void *)0xffffffffffffffff;
      do {
        pvVar3 = (void *)((longlong)pvVar3 + 1);
      } while (*(short *)((longlong)param_4 + (longlong)pvVar3 * 2) != 0);
    }
    FUN_180011740((void **)&local_68,param_4,pvVar3);
    if (param_5 == (void **)0x0) {
      (*DAT_1800650c8)("null wstring",0);
    }
    else {
      local_70 = 7;
      local_78 = 0;
      local_88 = 0;
      sVar1 = *(short *)param_5;
      pvVar3 = (void *)0x0;
      while (sVar1 != 0) {
        pvVar2 = (void *)((longlong)pvVar2 + 1);
        pvVar3 = pvVar2;
        sVar1 = *(short *)((longlong)param_5 + (longlong)pvVar2 * 2);
      }
      FUN_180011740((void **)&local_88,param_5,pvVar3);
      FUN_180017120(param_1,param_2,param_3,&local_68,&local_88,param_6 != 0,param_7);
      if (7 < local_70) {
        FUN_180011890(&local_88,(void *)CONCAT62(uStack_86,local_88),local_70 + 1);
      }
      local_70 = 7;
      local_78 = 0;
      local_88 = 0;
    }
    if (7 < local_50) {
      FUN_180011890(&local_68,(void *)CONCAT62(uStack_66,local_68),local_50 + 1);
    }
  }
  __security_check_cookie(local_48 ^ (ulonglong)auStackY_c8);
  return;
}



undefined8 CSharp_ImageFactory_GetNumSupportedFormats(void)

{
                    // 0x11fe0  42  CSharp_ImageFactory_GetNumSupportedFormats
  return 0xd;
}



void CSharp_ImageFactory_GetSupportedFormatExtension(uint param_1)

{
  undefined *puVar1;
  
                    // 0x11ff0  43  CSharp_ImageFactory_GetSupportedFormatExtension
  puVar1 = FUN_180017210(param_1);
                    // WARNING: Could not recover jumptable at 0x000180012000. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_180065e90)(puVar1);
  return;
}



undefined CSharp_ImageFactory_IsConvertable(int param_1,int param_2)

{
  undefined uVar1;
  
                    // 0x12010  44  CSharp_ImageFactory_IsConvertable
  uVar1 = thunk_FUN_180016870(param_1,param_2);
  return uVar1;
}



undefined4 CSharp_Spec_GetChannelFormat(longlong param_1)

{
                    // 0x12030  45  CSharp_Spec_GetChannelFormat
  return *(undefined4 *)(param_1 + 0x18);
}



void CSharp_Spec_GetChannelName(longlong param_1,int param_2)

{
  void *pvVar1;
  ulonglong **ppuVar2;
  void *pvVar3;
  byte *pbVar4;
  undefined auStack_78 [32];
  undefined8 local_58;
  undefined8 local_48;
  ulonglong local_40;
  byte local_38;
  undefined7 uStack_37;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x12040  46  CSharp_Spec_GetChannelName
  local_18 = DAT_180065150 ^ (ulonglong)auStack_78;
  local_40 = 0xf;
  local_48 = 0;
  local_58._0_1_ = 0;
  ppuVar2 = FUN_1800128e0(param_1,(ulonglong **)&local_38,param_2);
  if ((ulonglong **)&local_58 != ppuVar2) {
    FUN_1800113a0((ulonglong **)&local_58,ppuVar2,(ulonglong *)0x0,(ulonglong *)0xffffffffffffffff);
  }
  if (0xf < local_20) {
    pvVar1 = (void *)CONCAT71(uStack_37,local_38);
    pvVar3 = pvVar1;
    if (0xfff < local_20 + 1) {
      if ((local_38 & 0x1f) != 0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      pvVar3 = *(void **)((longlong)pvVar1 - 8);
      if (pvVar1 <= pvVar3) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if ((ulonglong)((longlong)pvVar1 - (longlong)pvVar3) < 8) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if (0x27 < (ulonglong)((longlong)pvVar1 - (longlong)pvVar3)) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
    }
    free(pvVar3);
  }
  pbVar4 = (byte *)&local_58;
  local_20 = 0xf;
  if (0xf < local_40) {
    pbVar4 = (byte *)CONCAT71(local_58._1_7_,(byte)local_58);
  }
  local_28 = 0;
  local_38 = 0;
  (*DAT_180065e90)(pbVar4);
  if (0xf < local_40) {
    pvVar1 = (void *)CONCAT71(local_58._1_7_,(byte)local_58);
    pvVar3 = pvVar1;
    if (0xfff < local_40 + 1) {
      if (((byte)local_58 & 0x1f) != 0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      pvVar3 = *(void **)((longlong)pvVar1 - 8);
      if (pvVar1 <= pvVar3) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if ((ulonglong)((longlong)pvVar1 - (longlong)pvVar3) < 8) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if (0x27 < (ulonglong)((longlong)pvVar1 - (longlong)pvVar3)) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
    }
    free(pvVar3);
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_78);
  return;
}



void CSharp_Spec_GetChannelNames(longlong param_1)

{
  void *pvVar1;
  ulonglong **ppuVar2;
  void *pvVar3;
  byte *pbVar4;
  undefined auStack_78 [32];
  undefined8 local_58;
  undefined8 local_48;
  ulonglong local_40;
  byte local_38;
  undefined7 uStack_37;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x121a0  47  CSharp_Spec_GetChannelNames
  local_18 = DAT_180065150 ^ (ulonglong)auStack_78;
  local_40 = 0xf;
  local_48 = 0;
  local_58._0_1_ = 0;
  ppuVar2 = FUN_180012930(param_1,(ulonglong **)&local_38);
  if ((ulonglong **)&local_58 != ppuVar2) {
    FUN_1800113a0((ulonglong **)&local_58,ppuVar2,(ulonglong *)0x0,(ulonglong *)0xffffffffffffffff);
  }
  if (0xf < local_20) {
    pvVar1 = (void *)CONCAT71(uStack_37,local_38);
    pvVar3 = pvVar1;
    if (0xfff < local_20 + 1) {
      if ((local_38 & 0x1f) != 0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      pvVar3 = *(void **)((longlong)pvVar1 - 8);
      if (pvVar1 <= pvVar3) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if ((ulonglong)((longlong)pvVar1 - (longlong)pvVar3) < 8) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if (0x27 < (ulonglong)((longlong)pvVar1 - (longlong)pvVar3)) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
    }
    free(pvVar3);
  }
  pbVar4 = (byte *)&local_58;
  local_20 = 0xf;
  if (0xf < local_40) {
    pbVar4 = (byte *)CONCAT71(local_58._1_7_,(byte)local_58);
  }
  local_28 = 0;
  local_38 = 0;
  (*DAT_180065e90)(pbVar4);
  if (0xf < local_40) {
    pvVar1 = (void *)CONCAT71(local_58._1_7_,(byte)local_58);
    pvVar3 = pvVar1;
    if (0xfff < local_40 + 1) {
      if (((byte)local_58 & 0x1f) != 0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      pvVar3 = *(void **)((longlong)pvVar1 - 8);
      if (pvVar1 <= pvVar3) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if ((ulonglong)((longlong)pvVar1 - (longlong)pvVar3) < 8) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if (0x27 < (ulonglong)((longlong)pvVar1 - (longlong)pvVar3)) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
    }
    free(pvVar3);
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_78);
  return;
}



longlong CSharp_Spec_GetChannelSize(longlong param_1)

{
  int iVar1;
  
                    // 0x122f0  48  CSharp_Spec_GetChannelSize
  iVar1 = Graphine::Core::DataTypeInfo::GetChannelSize(*(Enum *)(param_1 + 0x18));
  return (longlong)iVar1;
}



undefined4 CSharp_Spec_GetHeight(longlong param_1)

{
                    // 0x12300  49  CSharp_Spec_GetHeight
  return *(undefined4 *)(param_1 + 0xc);
}



uint CSharp_Spec_GetLevelHeight(longlong param_1,byte param_2)

{
  uint uVar1;
  uint uVar2;
  
                    // 0x12310  50  CSharp_Spec_GetLevelHeight
  uVar2 = *(uint *)(param_1 + 0xc) >> (param_2 & 0x1f);
  uVar1 = 1;
  if (1 < uVar2) {
    uVar1 = uVar2;
  }
  return uVar1;
}



undefined8 CSharp_Spec_GetLevelPitch(longlong param_1,uint param_2)

{
                    // 0x12320  51  CSharp_Spec_GetLevelPitch
  return *(undefined8 *)(param_1 + 0x20 + (ulonglong)param_2 * 8);
}



uint CSharp_Spec_GetLevelWidth(longlong param_1,byte param_2)

{
  uint uVar1;
  uint uVar2;
  
                    // 0x12330  52  CSharp_Spec_GetLevelWidth
  uVar2 = *(uint *)(param_1 + 8) >> (param_2 & 0x1f);
  uVar1 = 1;
  if (1 < uVar2) {
    uVar1 = uVar2;
  }
  return uVar1;
}



undefined4 CSharp_Spec_GetNumChannels(longlong param_1)

{
                    // 0x12340  53  CSharp_Spec_GetNumChannels
  return *(undefined4 *)(param_1 + 0x1c);
}



undefined4 CSharp_Spec_GetNumFaces(longlong param_1)

{
                    // 0x12350  54  CSharp_Spec_GetNumFaces
  return *(undefined4 *)(param_1 + 0x14);
}



undefined4 CSharp_Spec_GetNumLevels(longlong param_1)

{
                    // 0x12360  55  CSharp_Spec_GetNumLevels
  return *(undefined4 *)(param_1 + 0x10);
}



undefined8 CSharp_Spec_GetPitch(longlong param_1)

{
                    // 0x12370  56  CSharp_Spec_GetPitch
  return *(undefined8 *)(param_1 + 0x20);
}



int CSharp_Spec_GetPixelSize(longlong param_1)

{
  int iVar1;
  
                    // 0x12380  57  CSharp_Spec_GetPixelSize
  iVar1 = Graphine::Core::DataTypeInfo::GetChannelSize(*(Enum *)(param_1 + 0x18));
  return iVar1 * *(int *)(param_1 + 0x1c);
}



undefined4 CSharp_Spec_GetWidth(longlong param_1)

{
                    // 0x12390  58  CSharp_Spec_GetWidth
  return *(undefined4 *)(param_1 + 8);
}



void CSharp_Spec_SetChannelName(longlong param_1,ulonglong **param_2,int param_3)

{
  void *pvVar1;
  void *_Memory;
  ulonglong *puVar2;
  undefined auStack_78 [32];
  undefined local_58;
  undefined8 local_48;
  undefined8 local_40;
  byte local_38;
  undefined7 uStack_37;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x123a0  59  CSharp_Spec_SetChannelName
  local_18 = DAT_180065150 ^ (ulonglong)auStack_78;
  local_20 = 0xf;
  local_28 = 0;
  local_38 = 0;
  if (param_2 == (ulonglong **)0x0) {
    (*DAT_1800650c8)("null string");
  }
  else {
    if (*(char *)param_2 == '\0') {
      puVar2 = (ulonglong *)0x0;
    }
    else {
      puVar2 = (ulonglong *)0xffffffffffffffff;
      do {
        puVar2 = (ulonglong *)((longlong)puVar2 + 1);
      } while (*(char *)((longlong)param_2 + (longlong)puVar2) != '\0');
    }
    FUN_1800114d0((ulonglong **)&local_38,param_2,puVar2);
    local_40 = 0xf;
    local_48 = 0;
    local_58 = 0;
    FUN_1800113a0((ulonglong **)&local_58,(ulonglong **)&local_38,(ulonglong *)0x0,
                  (ulonglong *)0xffffffffffffffff);
    FUN_180012ad0(param_1,(ulonglong **)&local_58,param_3);
  }
  if (0xf < local_20) {
    pvVar1 = (void *)CONCAT71(uStack_37,local_38);
    _Memory = pvVar1;
    if (0xfff < local_20 + 1) {
      if ((local_38 & 0x1f) != 0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      _Memory = *(void **)((longlong)pvVar1 - 8);
      if (pvVar1 <= _Memory) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if ((ulonglong)((longlong)pvVar1 - (longlong)_Memory) < 8) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if (0x27 < (ulonglong)((longlong)pvVar1 - (longlong)_Memory)) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
    }
    free(_Memory);
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_78);
  return;
}



void CSharp_delete_IConverter(undefined8 *param_1)

{
                    // 0x124e0  61  CSharp_delete_IConverter
                    // 0x124e0  62  CSharp_delete_IImage
                    // 0x124e0  64  CSharp_delete_Spec
  if (param_1 != (undefined8 *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0001800124ed. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)*param_1)(param_1,1);
    return;
  }
  return;
}



void CSharp_new_ImageFactory(void)

{
                    // 0x12500  65  CSharp_new_ImageFactory
  operator_new(1);
  return;
}



void CSharp_new_Spec__SWIG_0(void)

{
  undefined8 *puVar1;
  
                    // 0x12510  66  CSharp_new_Spec__SWIG_0
  puVar1 = (undefined8 *)operator_new(0x120);
  if (puVar1 != (undefined8 *)0x0) {
    FUN_1800127a0(puVar1);
    return;
  }
  return;
}



void CSharp_new_Spec__SWIG_1
               (uint param_1,undefined4 param_2,uint param_3,undefined4 param_4,Enum param_5,
               int param_6)

{
  undefined8 *puVar1;
  
                    // 0x12540  67  CSharp_new_Spec__SWIG_1
  puVar1 = (undefined8 *)operator_new(0x120);
  if (puVar1 != (undefined8 *)0x0) {
    FUN_180012690(puVar1,param_1,param_2,param_3,param_4,param_5,param_6);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void SWIGRegisterExceptionArgumentCallbacks_GrimWrapperCPP
               (undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
                    // 0x125b0  68  SWIGRegisterExceptionArgumentCallbacks_GrimWrapperCPP
  _DAT_1800650b8 = param_1;
  DAT_1800650c8 = param_2;
  _DAT_1800650d8 = param_3;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void SWIGRegisterExceptionCallbacks_GrimWrapperCPP
               (undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
               undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
               undefined8 param_9,undefined8 param_10,undefined8 param_11)

{
                    // 0x125d0  69  SWIGRegisterExceptionCallbacks_GrimWrapperCPP
  _DAT_180065048 = param_5;
  _DAT_180065058 = param_6;
  _DAT_180065068 = param_7;
  _DAT_180065078 = param_8;
  _DAT_180065088 = param_9;
  _DAT_180065098 = param_10;
  _DAT_1800650a8 = param_11;
  _DAT_180065008 = param_1;
  _DAT_180065018 = param_2;
  _DAT_180065028 = param_3;
  _DAT_180065038 = param_4;
  return;
}



void SWIGRegisterStringCallback_GrimWrapperCPP(undefined8 param_1)

{
                    // 0x12650  70  SWIGRegisterStringCallback_GrimWrapperCPP
  DAT_180065e90 = param_1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void SWIGRegisterWStringCallback_GrimWrapperCPP(undefined8 param_1)

{
                    // 0x12660  71  SWIGRegisterWStringCallback_GrimWrapperCPP
  _DAT_180065e98 = param_1;
  return;
}



undefined8 *
FUN_180012690(undefined8 *param_1,uint param_2,undefined4 param_3,uint param_4,undefined4 param_5,
             Enum param_6,int param_7)

{
  int iVar1;
  uint *puVar2;
  uint uVar3;
  ulonglong *puVar4;
  uint local_48 [2];
  uint local_40 [2];
  undefined8 local_38;
  
  local_38 = 0xfffffffffffffffe;
  *param_1 = Graphine::Grim::Spec::vftable;
  _eh_vector_constructor_iterator_
            (param_1 + 0x14,0x20,4,(_func_void_void_ptr *)&LAB_180012670,FUN_180010f50);
  *(uint *)(param_1 + 1) = param_2;
  *(undefined4 *)((longlong)param_1 + 0xc) = param_3;
  *(undefined4 *)((longlong)param_1 + 0x14) = param_5;
  *(uint *)(param_1 + 2) = param_4;
  *(Enum *)(param_1 + 3) = param_6;
  *(int *)((longlong)param_1 + 0x1c) = param_7;
  uVar3 = 0;
  if (param_4 != 0) {
    puVar4 = param_1 + 4;
    do {
      local_48[0] = param_2 >> ((byte)uVar3 & 0x1f);
      local_40[0] = 1;
      puVar2 = local_48;
      if (local_48[0] < 2) {
        puVar2 = local_40;
      }
      iVar1 = Graphine::Core::DataTypeInfo::GetChannelSize(param_6);
      *puVar4 = (ulonglong)(iVar1 * *puVar2 * param_7);
      uVar3 = uVar3 + 1;
      puVar4 = puVar4 + 1;
    } while (uVar3 < param_4);
  }
  return param_1;
}



undefined8 * FUN_1800127a0(undefined8 *param_1)

{
  *param_1 = Graphine::Grim::Spec::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0x7fffffff;
  _eh_vector_constructor_iterator_
            (param_1 + 0x14,0x20,4,(_func_void_void_ptr *)&LAB_180012670,FUN_180010f50);
  Graphine::Platform::MemoryClear(param_1 + 4,0x80);
  return param_1;
}



void FUN_180012820(undefined8 *param_1)

{
  *param_1 = Graphine::Grim::Spec::vftable;
  _eh_vector_destructor_iterator_(param_1 + 0x14,0x20,4,FUN_180010f50);
  return;
}



undefined8 * FUN_180012860(undefined8 *param_1,uint param_2)

{
  *param_1 = Graphine::Grim::Spec::vftable;
  _eh_vector_destructor_iterator_(param_1 + 0x14,0x20,4,FUN_180010f50);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined4 FUN_1800128d0(longlong param_1)

{
  return *(undefined4 *)(param_1 + 0x18);
}



ulonglong ** FUN_1800128e0(longlong param_1,ulonglong **param_2,int param_3)

{
  param_2[3] = (ulonglong *)0xf;
  param_2[2] = (ulonglong *)0x0;
  *(undefined *)param_2 = 0;
  FUN_1800113a0(param_2,(ulonglong **)(((longlong)param_3 + 5) * 0x20 + param_1),(ulonglong *)0x0,
                (ulonglong *)0xffffffffffffffff);
  return param_2;
}



ulonglong ** FUN_180012930(longlong param_1,ulonglong **param_2)

{
  ulonglong **ppuVar1;
  uint uVar2;
  ulonglong uVar3;
  
  uVar3 = 0;
  param_2[3] = (ulonglong *)0xf;
  param_2[2] = (ulonglong *)0x0;
  ppuVar1 = param_2;
  if ((ulonglong *)0xf < param_2[3]) {
    ppuVar1 = (ulonglong **)*param_2;
  }
  *(undefined *)ppuVar1 = 0;
  FUN_1800114d0(param_2,(ulonglong **)&DAT_18001c568,(ulonglong *)0x0);
  if (*(int *)(param_1 + 0x1c) != 0) {
    do {
      FUN_180012b40(param_2,(undefined8 *)((uVar3 + 5) * 0x20 + param_1),0,0xffffffffffffffff);
      uVar2 = (int)uVar3 + 1;
      uVar3 = (ulonglong)uVar2;
    } while (uVar2 < *(uint *)(param_1 + 0x1c));
  }
  return param_2;
}



longlong FUN_1800129e0(longlong param_1)

{
  int iVar1;
  
  iVar1 = Graphine::Core::DataTypeInfo::GetChannelSize(*(Enum *)(param_1 + 0x18));
  return (longlong)iVar1;
}



undefined4 FUN_180012a00(longlong param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}



uint FUN_180012a10(longlong param_1,byte param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = *(uint *)(param_1 + 0xc) >> (param_2 & 0x1f);
  uVar1 = 1;
  if (1 < uVar2) {
    uVar1 = uVar2;
  }
  return uVar1;
}



undefined8 FUN_180012a30(longlong param_1,uint param_2)

{
  return *(undefined8 *)(param_1 + 0x20 + (ulonglong)param_2 * 8);
}



uint FUN_180012a40(longlong param_1,byte param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = *(uint *)(param_1 + 8) >> (param_2 & 0x1f);
  uVar1 = 1;
  if (1 < uVar2) {
    uVar1 = uVar2;
  }
  return uVar1;
}



undefined4 FUN_180012a60(longlong param_1)

{
  return *(undefined4 *)(param_1 + 0x1c);
}



undefined4 FUN_180012a70(longlong param_1)

{
  return *(undefined4 *)(param_1 + 0x14);
}



undefined4 FUN_180012a80(longlong param_1)

{
  return *(undefined4 *)(param_1 + 0x10);
}



undefined8 FUN_180012a90(longlong param_1)

{
  return *(undefined8 *)(param_1 + 0x20);
}



int FUN_180012aa0(longlong param_1)

{
  int iVar1;
  
  iVar1 = Graphine::Core::DataTypeInfo::GetChannelSize(*(Enum *)(param_1 + 0x18));
  return iVar1 * *(int *)(param_1 + 0x1c);
}



undefined4 FUN_180012ac0(longlong param_1)

{
  return *(undefined4 *)(param_1 + 8);
}



void FUN_180012ad0(longlong param_1,ulonglong **param_2,int param_3)

{
  ulonglong **ppuVar1;
  undefined auStack_48 [32];
  undefined8 local_28;
  ulonglong **local_20;
  ulonglong local_18;
  
  local_28 = 0xfffffffffffffffe;
  local_18 = DAT_180065150 ^ (ulonglong)auStack_48;
  ppuVar1 = (ulonglong **)(((longlong)param_3 + 5) * 0x20 + param_1);
  local_20 = param_2;
  if (ppuVar1 != param_2) {
    FUN_1800113a0(ppuVar1,param_2,(ulonglong *)0x0,(ulonglong *)0xffffffffffffffff);
  }
  FUN_180010f50(param_2);
  __security_check_cookie(local_18 ^ (ulonglong)auStack_48);
  return;
}



ulonglong **
FUN_180012b40(ulonglong **param_1,undefined8 *param_2,ulonglong param_3,ulonglong param_4)

{
  ulonglong *puVar1;
  ulonglong *puVar2;
  code *pcVar3;
  ulonglong **ppuVar4;
  ulonglong uVar5;
  
  if ((ulonglong)param_2[2] < param_3) {
    std::_Xout_of_range("invalid string position");
    pcVar3 = (code *)swi(3);
    ppuVar4 = (ulonglong **)(*pcVar3)();
    return ppuVar4;
  }
  puVar2 = param_1[2];
  uVar5 = param_2[2] - param_3;
  if (uVar5 < param_4) {
    param_4 = uVar5;
  }
  if (param_4 < ~(ulonglong)puVar2) {
    puVar1 = (ulonglong *)((longlong)puVar2 + param_4);
    if (param_4 != 0) {
      if (puVar1 == (ulonglong *)0xffffffffffffffff) {
        std::_Xlength_error("string too long");
        pcVar3 = (code *)swi(3);
        ppuVar4 = (ulonglong **)(*pcVar3)();
        return ppuVar4;
      }
      if (param_1[3] < puVar1) {
        FUN_180010fe0(param_1,puVar1,puVar2);
        if (puVar1 == (ulonglong *)0x0) {
          return param_1;
        }
      }
      else if (puVar1 == (ulonglong *)0x0) {
        param_1[2] = (ulonglong *)0x0;
        if ((ulonglong *)0xf < param_1[3]) {
          *(undefined *)*param_1 = 0;
          return param_1;
        }
        *(undefined *)param_1 = 0;
        return param_1;
      }
      if (0xf < (ulonglong)param_2[3]) {
        param_2 = (undefined8 *)*param_2;
      }
      ppuVar4 = param_1;
      if ((ulonglong *)0xf < param_1[3]) {
        ppuVar4 = (ulonglong **)*param_1;
      }
      if (param_4 != 0) {
        memcpy((void *)((longlong)ppuVar4 + (longlong)param_1[2]),
               (void *)((longlong)param_2 + param_3),param_4);
      }
      param_1[2] = puVar1;
      ppuVar4 = param_1;
      if ((ulonglong *)0xf < param_1[3]) {
        ppuVar4 = (ulonglong **)*param_1;
      }
      *(undefined *)((longlong)ppuVar4 + (longlong)puVar1) = 0;
    }
    return param_1;
  }
  std::_Xlength_error("string too long");
  pcVar3 = (code *)swi(3);
  ppuVar4 = (ulonglong **)(*pcVar3)();
  return ppuVar4;
}



// WARNING: Removing unreachable block (ram,0x000180012d2d)

void FUN_180012c60(byte param_1,short *param_2)

{
  ushort uVar1;
  short sVar2;
  ulonglong uVar3;
  float fVar4;
  
  fVar4 = (float)(uint)param_1 / 255.0;
  if (fVar4 == 0.0) {
    uVar3 = (ulonglong)((uint)fVar4 >> 0x10);
  }
  else {
    sVar2 = *(short *)((longlong)&half::_eLut + (ulonglong)((uint)fVar4 >> 0x17) * 2);
    if (sVar2 == 0) {
      uVar1 = half::convert((int)fVar4);
      uVar3 = (ulonglong)uVar1;
    }
    else {
      uVar3 = (ulonglong)
              (ushort)((short)(((uint)fVar4 & 0x7fffff) + 0xfff +
                               (((uint)fVar4 & 0x7fffff) >> 0xd & 1) >> 0xd) + sVar2);
    }
  }
  fVar4 = 1.0 - *(float *)((longlong)&half::_toFloat + uVar3 * 4);
  if (fVar4 == 0.0) {
    sVar2 = (short)((uint)fVar4 >> 0x10);
  }
  else {
    sVar2 = *(short *)((longlong)&half::_eLut + (ulonglong)((uint)fVar4 >> 0x17) * 2);
    if (sVar2 != 0) {
      *param_2 = (short)(((uint)fVar4 & 0x7fffff) + 0xfff + (((uint)fVar4 & 0x7fffff) >> 0xd & 1) >>
                        0xd) + sVar2;
      return;
    }
    sVar2 = half::convert((int)fVar4);
  }
  *param_2 = sVar2;
  return;
}



// WARNING: Removing unreachable block (ram,0x000180012e8d)

void FUN_180012dc0(ushort param_1,short *param_2)

{
  ushort uVar1;
  short sVar2;
  ulonglong uVar3;
  float fVar4;
  
  fVar4 = (float)(uint)param_1 / 65535.0;
  if (fVar4 == 0.0) {
    uVar3 = (ulonglong)((uint)fVar4 >> 0x10);
  }
  else {
    sVar2 = *(short *)((longlong)&half::_eLut + (ulonglong)((uint)fVar4 >> 0x17) * 2);
    if (sVar2 == 0) {
      uVar1 = half::convert((int)fVar4);
      uVar3 = (ulonglong)uVar1;
    }
    else {
      uVar3 = (ulonglong)
              (ushort)((short)(((uint)fVar4 & 0x7fffff) + 0xfff +
                               (((uint)fVar4 & 0x7fffff) >> 0xd & 1) >> 0xd) + sVar2);
    }
  }
  fVar4 = 1.0 - *(float *)((longlong)&half::_toFloat + uVar3 * 4);
  if (fVar4 == 0.0) {
    sVar2 = (short)((uint)fVar4 >> 0x10);
  }
  else {
    sVar2 = *(short *)((longlong)&half::_eLut + (ulonglong)((uint)fVar4 >> 0x17) * 2);
    if (sVar2 != 0) {
      *param_2 = (short)(((uint)fVar4 & 0x7fffff) + 0xfff + (((uint)fVar4 & 0x7fffff) >> 0xd & 1) >>
                        0xd) + sVar2;
      return;
    }
    sVar2 = half::convert((int)fVar4);
  }
  *param_2 = sVar2;
  return;
}



// WARNING: Removing unreachable block (ram,0x000180012ff1)

void FUN_180012f20(ulonglong param_1,short *param_2)

{
  ushort uVar1;
  short sVar2;
  ulonglong uVar3;
  float fVar4;
  
  fVar4 = (float)(param_1 & 0xffffffff) / 4.294967e+09;
  if (fVar4 == 0.0) {
    uVar3 = (ulonglong)((uint)fVar4 >> 0x10);
  }
  else {
    sVar2 = *(short *)((longlong)&half::_eLut + (ulonglong)((uint)fVar4 >> 0x17) * 2);
    if (sVar2 == 0) {
      uVar1 = half::convert((int)fVar4);
      uVar3 = (ulonglong)uVar1;
    }
    else {
      uVar3 = (ulonglong)
              (ushort)((short)(((uint)fVar4 & 0x7fffff) + 0xfff +
                               (((uint)fVar4 & 0x7fffff) >> 0xd & 1) >> 0xd) + sVar2);
    }
  }
  fVar4 = 1.0 - *(float *)((longlong)&half::_toFloat + uVar3 * 4);
  if (fVar4 == 0.0) {
    sVar2 = (short)((uint)fVar4 >> 0x10);
  }
  else {
    sVar2 = *(short *)((longlong)&half::_eLut + (ulonglong)((uint)fVar4 >> 0x17) * 2);
    if (sVar2 != 0) {
      *param_2 = (short)(((uint)fVar4 & 0x7fffff) + 0xfff + (((uint)fVar4 & 0x7fffff) >> 0xd & 1) >>
                        0xd) + sVar2;
      return;
    }
    sVar2 = half::convert((int)fVar4);
  }
  *param_2 = sVar2;
  return;
}



// WARNING: Removing unreachable block (ram,0x00018001313b)

void FUN_180013080(float param_1,short *param_2)

{
  ushort uVar1;
  short sVar2;
  ulonglong uVar3;
  float fVar4;
  
  if (param_1 == 0.0) {
    uVar3 = (ulonglong)((uint)param_1 >> 0x10);
  }
  else {
    sVar2 = *(short *)((longlong)&half::_eLut + (ulonglong)((uint)param_1 >> 0x17) * 2);
    if (sVar2 == 0) {
      uVar1 = half::convert((int)param_1);
      uVar3 = (ulonglong)uVar1;
    }
    else {
      uVar3 = (ulonglong)
              (ushort)((short)(((uint)param_1 & 0x7fffff) + 0xfff +
                               (((uint)param_1 & 0x7fffff) >> 0xd & 1) >> 0xd) + sVar2);
    }
  }
  fVar4 = 1.0 - *(float *)((longlong)&half::_toFloat + uVar3 * 4);
  if (fVar4 == 0.0) {
    sVar2 = (short)((uint)fVar4 >> 0x10);
  }
  else {
    sVar2 = *(short *)((longlong)&half::_eLut + (ulonglong)((uint)fVar4 >> 0x17) * 2);
    if (sVar2 != 0) {
      *param_2 = (short)(((uint)fVar4 & 0x7fffff) + 0xfff + (((uint)fVar4 & 0x7fffff) >> 0xd & 1) >>
                        0xd) + sVar2;
      return;
    }
    sVar2 = half::convert((int)fVar4);
  }
  *param_2 = sVar2;
  return;
}



// WARNING: Removing unreachable block (ram,0x000180013231)

void FUN_1800131d0(ushort param_1,short *param_2)

{
  short sVar1;
  float fVar2;
  
  fVar2 = 1.0 - *(float *)((longlong)&half::_toFloat + (ulonglong)param_1 * 4);
  if (fVar2 == 0.0) {
    *param_2 = (short)((uint)fVar2 >> 0x10);
    return;
  }
  sVar1 = *(short *)((longlong)&half::_eLut + (ulonglong)((uint)fVar2 >> 0x17) * 2);
  if (sVar1 != 0) {
    *param_2 = (short)(((uint)fVar2 & 0x7fffff) + 0xfff + (((uint)fVar2 & 0x7fffff) >> 0xd & 1) >>
                      0xd) + sVar1;
    return;
  }
  sVar1 = half::convert((int)fVar2);
  *param_2 = sVar1;
  return;
}



void FUN_1800132e0(longlong param_1,longlong param_2,byte *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  byte bVar2;
  ulonglong uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar4 = 0;
  if (param_5 != 0) {
    do {
      uVar5 = 0;
      if (param_4 != 0) {
        uVar3 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar3 * 4);
          bVar2 = 0xff;
          if ((iVar1 < (int)param_2) &&
             (bVar2 = *(byte *)(iVar1 + param_1), *(char *)(uVar3 + param_7) != '\0')) {
            bVar2 = ~bVar2;
          }
          uVar5 = uVar5 + 1;
          *param_3 = bVar2;
          uVar3 = (ulonglong)uVar5;
          param_3 = param_3 + 1;
        } while (uVar3 < param_4);
      }
      uVar4 = uVar4 + 1;
      param_1 = param_1 + param_2;
    } while (uVar4 < param_5);
  }
  return;
}



void FUN_180013370(longlong param_1,longlong param_2,ushort *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  ushort uVar2;
  ulonglong uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar4 = 0;
  if (param_5 != 0) {
    do {
      uVar5 = 0;
      if (param_4 != 0) {
        uVar3 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar3 * 4);
          uVar2 = 0xffff;
          if ((iVar1 < (int)param_2) &&
             (uVar2 = (ushort)*(byte *)(iVar1 + param_1) << 8, *(char *)(uVar3 + param_7) != '\0'))
          {
            uVar2 = ~uVar2;
          }
          uVar5 = uVar5 + 1;
          *param_3 = uVar2;
          uVar3 = (ulonglong)uVar5;
          param_3 = param_3 + 1;
        } while (uVar3 < param_4);
      }
      uVar4 = uVar4 + 1;
      param_1 = param_1 + param_2;
    } while (uVar4 < param_5);
  }
  return;
}



void FUN_180013420(longlong param_1,longlong param_2,uint *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  uint uVar2;
  ulonglong uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar4 = 0;
  if (param_5 != 0) {
    do {
      uVar5 = 0;
      if (param_4 != 0) {
        uVar3 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar3 * 4);
          uVar2 = 0xffffffff;
          if ((iVar1 < (int)param_2) &&
             (uVar2 = (uint)*(byte *)(iVar1 + param_1) << 0x18, *(char *)(uVar3 + param_7) != '\0'))
          {
            uVar2 = ~uVar2;
          }
          uVar5 = uVar5 + 1;
          *param_3 = uVar2;
          uVar3 = (ulonglong)uVar5;
          param_3 = param_3 + 1;
        } while (uVar3 < param_4);
      }
      uVar4 = uVar4 + 1;
      param_1 = param_1 + param_2;
    } while (uVar4 < param_5);
  }
  return;
}



void FUN_1800134b0(longlong param_1,longlong param_2,float *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  ulonglong uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  float fVar6;
  
  uVar5 = 0;
  if (param_5 != 0) {
    do {
      uVar4 = 0;
      if (param_4 != 0) {
        uVar2 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar2 * 4);
          fVar6 = 1.0;
          if (iVar1 < (int)param_2) {
            uVar3 = (uint)*(byte *)(iVar1 + param_1);
            if (*(char *)(uVar2 + param_7) == '\0') {
              fVar6 = (float)uVar3 / 255.0;
            }
            else {
              fVar6 = 1.0 - (float)uVar3 / 255.0;
            }
          }
          uVar4 = uVar4 + 1;
          *param_3 = fVar6;
          uVar2 = (ulonglong)uVar4;
          param_3 = param_3 + 1;
        } while (uVar2 < param_4);
      }
      uVar5 = uVar5 + 1;
      param_1 = param_1 + param_2;
    } while (uVar5 < param_5);
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x0001800135d6)
// WARNING: Could not reconcile some variable overlaps

void FUN_180013570(longlong param_1,longlong param_2,ushort *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  ulonglong uVar4;
  uint uVar5;
  ushort *puVar6;
  float local_res8 [2];
  uint local_res18;
  
  local_res8[0] = 1.0;
  uVar4 = 0;
  local_res18 = 0;
  if (param_5 != 0) {
    do {
      uVar5 = 0;
      uVar3 = (uint)uVar4;
      if (param_4 != 0) {
        uVar4 = 0;
        puVar6 = param_3;
        do {
          iVar2 = *(int *)(param_6 + uVar4 * 4);
          local_res8[0] = (float)((uint)local_res8[0] & 0xffff0000 | 0x3c00);
          local_res8[0]._0_2_ = 0x3c00;
          if (iVar2 < (int)param_2) {
            if (*(char *)(uVar4 + param_7) == '\0') {
              local_res8[0] = (float)(uint)*(byte *)(iVar2 + param_1) / 255.0;
              if (local_res8[0] == 0.0) {
                local_res8[0]._0_2_ = (ushort)((uint)local_res8[0] >> 0x10);
              }
              else {
                sVar1 = *(short *)((longlong)&half::_eLut +
                                  (ulonglong)((uint)local_res8[0] >> 0x17) * 2);
                if (sVar1 == 0) {
                  local_res8[0]._0_2_ = half::convert((int)local_res8[0]);
                }
                else {
                  local_res8[0]._0_2_ =
                       (short)(((uint)local_res8[0] & 0x7fffff) + 0xfff +
                               (((uint)local_res8[0] & 0x7fffff) >> 0xd & 1) >> 0xd) + sVar1;
                }
              }
            }
            else {
              FUN_180012c60(*(byte *)(iVar2 + param_1),(short *)local_res8);
            }
          }
          uVar5 = uVar5 + 1;
          param_3 = puVar6 + 1;
          uVar4 = (ulonglong)uVar5;
          *puVar6 = local_res8[0]._0_2_;
          puVar6 = param_3;
          uVar3 = local_res18;
        } while (uVar4 < param_4);
      }
      local_res18 = uVar3 + 1;
      uVar4 = (ulonglong)local_res18;
      param_1 = param_1 + param_2;
    } while (uVar4 < param_5);
  }
  return;
}



void FUN_180013770(longlong param_1,longlong param_2,char *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  char cVar2;
  ulonglong uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar4 = 0;
  if (param_5 != 0) {
    do {
      uVar5 = 0;
      if (param_4 != 0) {
        uVar3 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar3 * 4);
          cVar2 = -1;
          if (iVar1 < (int)param_2) {
            if (*(char *)(uVar3 + param_7) == '\0') {
              cVar2 = *(char *)(param_1 + 1 + (longlong)iVar1 * 2);
            }
            else {
              cVar2 = -1 - *(char *)(param_1 + 1 + (longlong)iVar1 * 2);
            }
          }
          uVar5 = uVar5 + 1;
          *param_3 = cVar2;
          uVar3 = (ulonglong)uVar5;
          param_3 = param_3 + 1;
        } while (uVar3 < param_4);
      }
      uVar4 = uVar4 + 1;
      param_1 = param_1 + param_2 * 2;
    } while (uVar4 < param_5);
  }
  return;
}



void FUN_180013820(longlong param_1,longlong param_2,ushort *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  ushort uVar2;
  ulonglong uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar4 = 0;
  if (param_5 != 0) {
    do {
      uVar5 = 0;
      if (param_4 != 0) {
        uVar3 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar3 * 4);
          uVar2 = 0xffff;
          if ((iVar1 < (int)param_2) &&
             (uVar2 = *(ushort *)(param_1 + (longlong)iVar1 * 2), *(char *)(uVar3 + param_7) != '\0'
             )) {
            uVar2 = ~uVar2;
          }
          uVar5 = uVar5 + 1;
          *param_3 = uVar2;
          uVar3 = (ulonglong)uVar5;
          param_3 = param_3 + 1;
        } while (uVar3 < param_4);
      }
      uVar4 = uVar4 + 1;
      param_1 = param_1 + param_2 * 2;
    } while (uVar4 < param_5);
  }
  return;
}



void FUN_1800138d0(longlong param_1,longlong param_2,uint *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  uint uVar2;
  ulonglong uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar4 = 0;
  if (param_5 != 0) {
    do {
      uVar5 = 0;
      if (param_4 != 0) {
        uVar3 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar3 * 4);
          uVar2 = 0xffffffff;
          if ((iVar1 < (int)param_2) &&
             (uVar2 = (uint)*(ushort *)(param_1 + (longlong)iVar1 * 2) << 0x10,
             *(char *)(uVar3 + param_7) != '\0')) {
            uVar2 = ~uVar2;
          }
          uVar5 = uVar5 + 1;
          *param_3 = uVar2;
          uVar3 = (ulonglong)uVar5;
          param_3 = param_3 + 1;
        } while (uVar3 < param_4);
      }
      uVar4 = uVar4 + 1;
      param_1 = param_1 + param_2 * 2;
    } while (uVar4 < param_5);
  }
  return;
}



void FUN_180013980(longlong param_1,longlong param_2,float *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  ulonglong uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  float fVar6;
  
  uVar5 = 0;
  if (param_5 != 0) {
    do {
      uVar4 = 0;
      if (param_4 != 0) {
        uVar2 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar2 * 4);
          fVar6 = 1.0;
          if (iVar1 < (int)param_2) {
            uVar3 = (uint)*(ushort *)(param_1 + (longlong)iVar1 * 2);
            if (*(char *)(uVar2 + param_7) == '\0') {
              fVar6 = (float)uVar3 / 65535.0;
            }
            else {
              fVar6 = 1.0 - (float)uVar3 / 65535.0;
            }
          }
          uVar4 = uVar4 + 1;
          *param_3 = fVar6;
          uVar2 = (ulonglong)uVar4;
          param_3 = param_3 + 1;
        } while (uVar2 < param_4);
      }
      uVar5 = uVar5 + 1;
      param_1 = param_1 + param_2 * 2;
    } while (uVar5 < param_5);
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x000180013ab6)
// WARNING: Could not reconcile some variable overlaps

void FUN_180013a50(longlong param_1,longlong param_2,ushort *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  ulonglong uVar4;
  uint uVar5;
  ushort *puVar6;
  float local_res8 [2];
  uint local_res18;
  
  local_res8[0] = 1.0;
  uVar4 = 0;
  local_res18 = 0;
  if (param_5 != 0) {
    do {
      uVar5 = 0;
      uVar3 = (uint)uVar4;
      if (param_4 != 0) {
        uVar4 = 0;
        puVar6 = param_3;
        do {
          iVar2 = *(int *)(param_6 + uVar4 * 4);
          local_res8[0] = (float)((uint)local_res8[0] & 0xffff0000 | 0x3c00);
          local_res8[0]._0_2_ = 0x3c00;
          if (iVar2 < (int)param_2) {
            if (*(char *)(uVar4 + param_7) == '\0') {
              local_res8[0] = (float)(uint)*(ushort *)(param_1 + (longlong)iVar2 * 2) / 65535.0;
              if (local_res8[0] == 0.0) {
                local_res8[0]._0_2_ = (ushort)((uint)local_res8[0] >> 0x10);
              }
              else {
                sVar1 = *(short *)((longlong)&half::_eLut +
                                  (ulonglong)((uint)local_res8[0] >> 0x17) * 2);
                if (sVar1 == 0) {
                  local_res8[0]._0_2_ = half::convert((int)local_res8[0]);
                }
                else {
                  local_res8[0]._0_2_ =
                       (short)(((uint)local_res8[0] & 0x7fffff) + 0xfff +
                               (((uint)local_res8[0] & 0x7fffff) >> 0xd & 1) >> 0xd) + sVar1;
                }
              }
            }
            else {
              FUN_180012dc0(*(ushort *)(param_1 + (longlong)iVar2 * 2),(short *)local_res8);
            }
          }
          uVar5 = uVar5 + 1;
          param_3 = puVar6 + 1;
          uVar4 = (ulonglong)uVar5;
          *puVar6 = local_res8[0]._0_2_;
          puVar6 = param_3;
          uVar3 = local_res18;
        } while (uVar4 < param_4);
      }
      local_res18 = uVar3 + 1;
      uVar4 = (ulonglong)local_res18;
      param_1 = param_1 + param_2 * 2;
    } while (uVar4 < param_5);
  }
  return;
}



void FUN_180013c50(longlong param_1,longlong param_2,char *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  char cVar2;
  ulonglong uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar4 = 0;
  if (param_5 != 0) {
    do {
      uVar5 = 0;
      if (param_4 != 0) {
        uVar3 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar3 * 4);
          cVar2 = -1;
          if (iVar1 < (int)param_2) {
            if (*(char *)(uVar3 + param_7) == '\0') {
              cVar2 = *(char *)(param_1 + 3 + (longlong)iVar1 * 4);
            }
            else {
              cVar2 = -1 - *(char *)(param_1 + 3 + (longlong)iVar1 * 4);
            }
          }
          uVar5 = uVar5 + 1;
          *param_3 = cVar2;
          uVar3 = (ulonglong)uVar5;
          param_3 = param_3 + 1;
        } while (uVar3 < param_4);
      }
      uVar4 = uVar4 + 1;
      param_1 = param_1 + param_2 * 4;
    } while (uVar4 < param_5);
  }
  return;
}



void FUN_180013d00(longlong param_1,longlong param_2,short *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  short sVar2;
  ulonglong uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar4 = 0;
  if (param_5 != 0) {
    do {
      uVar5 = 0;
      if (param_4 != 0) {
        uVar3 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar3 * 4);
          sVar2 = -1;
          if (iVar1 < (int)param_2) {
            if (*(char *)(uVar3 + param_7) == '\0') {
              sVar2 = *(short *)(param_1 + 2 + (longlong)iVar1 * 4);
            }
            else {
              sVar2 = -1 - *(short *)(param_1 + 2 + (longlong)iVar1 * 4);
            }
          }
          uVar5 = uVar5 + 1;
          *param_3 = sVar2;
          uVar3 = (ulonglong)uVar5;
          param_3 = param_3 + 1;
        } while (uVar3 < param_4);
      }
      uVar4 = uVar4 + 1;
      param_1 = param_1 + param_2 * 4;
    } while (uVar4 < param_5);
  }
  return;
}



void FUN_180013dc0(longlong param_1,longlong param_2,uint *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  uint uVar2;
  ulonglong uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar4 = 0;
  if (param_5 != 0) {
    do {
      uVar5 = 0;
      if (param_4 != 0) {
        uVar3 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar3 * 4);
          uVar2 = 0xffffffff;
          if ((iVar1 < (int)param_2) &&
             (uVar2 = *(uint *)(param_1 + (longlong)iVar1 * 4), *(char *)(uVar3 + param_7) != '\0'))
          {
            uVar2 = ~uVar2;
          }
          uVar5 = uVar5 + 1;
          *param_3 = uVar2;
          uVar3 = (ulonglong)uVar5;
          param_3 = param_3 + 1;
        } while (uVar3 < param_4);
      }
      uVar4 = uVar4 + 1;
      param_1 = param_1 + param_2 * 4;
    } while (uVar4 < param_5);
  }
  return;
}



void FUN_180013e60(longlong param_1,longlong param_2,float *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  ulonglong uVar2;
  uint uVar3;
  uint uVar4;
  float fVar5;
  
  uVar4 = 0;
  if (param_5 != 0) {
    do {
      uVar3 = 0;
      if (param_4 != 0) {
        uVar2 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar2 * 4);
          fVar5 = 1.0;
          if ((iVar1 < (int)param_2) &&
             (fVar5 = (float)(ulonglong)*(uint *)(param_1 + (longlong)iVar1 * 4) / 4.294967e+09,
             *(char *)(uVar2 + param_7) != '\0')) {
            fVar5 = 1.0 - fVar5;
          }
          uVar3 = uVar3 + 1;
          *param_3 = fVar5;
          uVar2 = (ulonglong)uVar3;
          param_3 = param_3 + 1;
        } while (uVar2 < param_4);
      }
      uVar4 = uVar4 + 1;
      param_1 = param_1 + param_2 * 4;
    } while (uVar4 < param_5);
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x000180013f96)
// WARNING: Could not reconcile some variable overlaps

void FUN_180013f30(longlong param_1,longlong param_2,ushort *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  ulonglong uVar4;
  uint uVar5;
  ushort *puVar6;
  float local_res8 [2];
  uint local_res18;
  
  local_res8[0] = 1.0;
  uVar4 = 0;
  local_res18 = 0;
  if (param_5 != 0) {
    do {
      uVar5 = 0;
      uVar3 = (uint)uVar4;
      if (param_4 != 0) {
        uVar4 = 0;
        puVar6 = param_3;
        do {
          iVar2 = *(int *)(param_6 + uVar4 * 4);
          local_res8[0] = (float)((uint)local_res8[0] & 0xffff0000 | 0x3c00);
          local_res8[0]._0_2_ = 0x3c00;
          if (iVar2 < (int)param_2) {
            if (*(char *)(uVar4 + param_7) == '\0') {
              local_res8[0] =
                   (float)(ulonglong)*(uint *)(param_1 + (longlong)iVar2 * 4) / 4.294967e+09;
              if (local_res8[0] == 0.0) {
                local_res8[0]._0_2_ = (ushort)((uint)local_res8[0] >> 0x10);
              }
              else {
                sVar1 = *(short *)((longlong)&half::_eLut +
                                  (ulonglong)((uint)local_res8[0] >> 0x17) * 2);
                if (sVar1 == 0) {
                  local_res8[0]._0_2_ = half::convert((int)local_res8[0]);
                }
                else {
                  local_res8[0]._0_2_ =
                       (short)(((uint)local_res8[0] & 0x7fffff) + 0xfff +
                               (((uint)local_res8[0] & 0x7fffff) >> 0xd & 1) >> 0xd) + sVar1;
                }
              }
            }
            else {
              FUN_180012f20((ulonglong)*(uint *)(param_1 + (longlong)iVar2 * 4),(short *)local_res8)
              ;
            }
          }
          uVar5 = uVar5 + 1;
          param_3 = puVar6 + 1;
          uVar4 = (ulonglong)uVar5;
          *puVar6 = local_res8[0]._0_2_;
          puVar6 = param_3;
          uVar3 = local_res18;
        } while (uVar4 < param_4);
      }
      local_res18 = uVar3 + 1;
      uVar4 = (ulonglong)local_res18;
      param_1 = param_1 + param_2 * 4;
    } while (uVar4 < param_5);
  }
  return;
}



void FUN_180014130(longlong param_1,longlong param_2,byte *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  byte bVar2;
  ulonglong uVar3;
  uint uVar4;
  uint uVar5;
  float fVar6;
  float fVar7;
  
  uVar4 = 0;
  if (param_5 != 0) {
    do {
      uVar5 = 0;
      if (param_4 != 0) {
        uVar3 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar3 * 4);
          bVar2 = 0xff;
          if (iVar1 < (int)param_2) {
            fVar7 = *(float *)(param_1 + (longlong)iVar1 * 4) * 255.0;
            if (*(char *)(uVar3 + param_7) == '\0') {
              if (fVar7 <= 255.0) {
                fVar6 = 0.0;
                if (0.0 <= fVar7) {
                  fVar6 = fVar7;
                }
              }
              else {
                fVar6 = 255.0;
              }
              bVar2 = (byte)(longlong)fVar6;
            }
            else if (fVar7 <= 255.0) {
              fVar6 = 0.0;
              if (0.0 <= fVar7) {
                fVar6 = fVar7;
              }
              bVar2 = ~(byte)(longlong)fVar6;
            }
            else {
              bVar2 = 0;
            }
          }
          uVar5 = uVar5 + 1;
          *param_3 = bVar2;
          uVar3 = (ulonglong)uVar5;
          param_3 = param_3 + 1;
        } while (uVar3 < param_4);
      }
      uVar4 = uVar4 + 1;
      param_1 = param_1 + param_2 * 4;
    } while (uVar4 < param_5);
  }
  return;
}



void FUN_180014220(longlong param_1,longlong param_2,ushort *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  ushort uVar2;
  ulonglong uVar3;
  uint uVar4;
  uint uVar5;
  float fVar6;
  float fVar7;
  
  uVar4 = 0;
  if (param_5 != 0) {
    do {
      uVar5 = 0;
      if (param_4 != 0) {
        uVar3 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar3 * 4);
          uVar2 = 0xffff;
          if (iVar1 < (int)param_2) {
            fVar7 = *(float *)(param_1 + (longlong)iVar1 * 4) * 65535.0;
            if (*(char *)(uVar3 + param_7) == '\0') {
              if (fVar7 <= 65535.0) {
                fVar6 = 0.0;
                if (0.0 <= fVar7) {
                  fVar6 = fVar7;
                }
              }
              else {
                fVar6 = 65535.0;
              }
              uVar2 = (ushort)(longlong)fVar6;
            }
            else if (fVar7 <= 65535.0) {
              fVar6 = 0.0;
              if (0.0 <= fVar7) {
                fVar6 = fVar7;
              }
              uVar2 = ~(ushort)(longlong)fVar6;
            }
            else {
              uVar2 = 0;
            }
          }
          uVar5 = uVar5 + 1;
          *param_3 = uVar2;
          uVar3 = (ulonglong)uVar5;
          param_3 = param_3 + 1;
        } while (uVar3 < param_4);
      }
      uVar4 = uVar4 + 1;
      param_1 = param_1 + param_2 * 4;
    } while (uVar4 < param_5);
  }
  return;
}



void FUN_180014310(longlong param_1,longlong param_2,uint *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  ulonglong uVar5;
  uint uVar6;
  uint uVar7;
  
  uVar6 = 0;
  if (param_5 != 0) {
    do {
      uVar7 = 0;
      if (param_4 != 0) {
        uVar5 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar5 * 4);
          uVar4 = 0xffffffff;
          if (iVar1 < (int)param_2) {
            fVar2 = *(float *)(param_1 + (longlong)iVar1 * 4) * 4.294967e+09;
            if (*(char *)(uVar5 + param_7) == '\0') {
              if (fVar2 <= 4.294967e+09) {
                fVar3 = 0.0;
                if (0.0 <= fVar2) {
                  fVar3 = fVar2;
                }
              }
              else {
                fVar3 = 4.294967e+09;
              }
              uVar4 = (uint)(longlong)fVar3;
            }
            else if (fVar2 <= 4.294967e+09) {
              fVar3 = 0.0;
              if (0.0 <= fVar2) {
                fVar3 = fVar2;
              }
              uVar4 = ~(uint)(longlong)fVar3;
            }
            else {
              uVar4 = 0;
            }
          }
          uVar7 = uVar7 + 1;
          *param_3 = uVar4;
          uVar5 = (ulonglong)uVar7;
          param_3 = param_3 + 1;
        } while (uVar5 < param_4);
      }
      uVar6 = uVar6 + 1;
      param_1 = param_1 + param_2 * 4;
    } while (uVar6 < param_5);
  }
  return;
}



void FUN_180014410(longlong param_1,longlong param_2,float *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  ulonglong uVar2;
  uint uVar3;
  uint uVar4;
  float fVar5;
  
  uVar4 = 0;
  if (param_5 != 0) {
    do {
      uVar3 = 0;
      if (param_4 != 0) {
        uVar2 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar2 * 4);
          fVar5 = 1.0;
          if (iVar1 < (int)param_2) {
            if (*(char *)(uVar2 + param_7) == '\0') {
              fVar5 = *(float *)(param_1 + (longlong)iVar1 * 4);
            }
            else {
              fVar5 = 1.0 - *(float *)(param_1 + (longlong)iVar1 * 4);
            }
          }
          uVar3 = uVar3 + 1;
          *param_3 = fVar5;
          uVar2 = (ulonglong)uVar3;
          param_3 = param_3 + 1;
        } while (uVar2 < param_4);
      }
      uVar4 = uVar4 + 1;
      param_1 = param_1 + param_2 * 4;
    } while (uVar4 < param_5);
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x000180014520)
// WARNING: Could not reconcile some variable overlaps

void FUN_1800144c0(longlong param_1,longlong param_2,ushort *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  float fVar1;
  short sVar2;
  int iVar3;
  uint uVar4;
  ulonglong uVar5;
  uint uVar6;
  ushort *puVar7;
  float local_res8 [2];
  uint local_res18;
  
  local_res8[0] = 1.0;
  uVar5 = 0;
  local_res18 = 0;
  if (param_5 != 0) {
    do {
      uVar6 = 0;
      uVar4 = (uint)uVar5;
      if (param_4 != 0) {
        uVar5 = 0;
        puVar7 = param_3;
        do {
          iVar3 = *(int *)(param_6 + uVar5 * 4);
          local_res8[0] = (float)((uint)local_res8[0] & 0xffff0000 | 0x3c00);
          local_res8[0]._0_2_ = 0x3c00;
          if (iVar3 < (int)param_2) {
            fVar1 = *(float *)(param_1 + (longlong)iVar3 * 4);
            if (*(char *)(uVar5 + param_7) == '\0') {
              local_res8[0] = fVar1;
              if (fVar1 == 0.0) {
                local_res8[0]._0_2_ = (ushort)((uint)fVar1 >> 0x10);
              }
              else {
                sVar2 = *(short *)((longlong)&half::_eLut + (ulonglong)((uint)fVar1 >> 0x17) * 2);
                if (sVar2 == 0) {
                  local_res8[0]._0_2_ = half::convert((int)fVar1);
                }
                else {
                  local_res8[0]._0_2_ =
                       (short)(((uint)fVar1 & 0x7fffff) + 0xfff +
                               (((uint)fVar1 & 0x7fffff) >> 0xd & 1) >> 0xd) + sVar2;
                }
              }
            }
            else {
              FUN_180013080(fVar1,(short *)local_res8);
            }
          }
          uVar6 = uVar6 + 1;
          param_3 = puVar7 + 1;
          uVar5 = (ulonglong)uVar6;
          *puVar7 = local_res8[0]._0_2_;
          puVar7 = param_3;
          uVar4 = local_res18;
        } while (uVar5 < param_4);
      }
      local_res18 = uVar4 + 1;
      uVar5 = (ulonglong)local_res18;
      param_1 = param_1 + param_2 * 4;
    } while (uVar5 < param_5);
  }
  return;
}



void FUN_180014690(longlong param_1,longlong param_2,byte *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  byte bVar2;
  ulonglong uVar3;
  uint uVar4;
  uint uVar5;
  float fVar6;
  float fVar7;
  
  uVar4 = 0;
  if (param_5 != 0) {
    do {
      uVar5 = 0;
      if (param_4 != 0) {
        uVar3 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar3 * 4);
          bVar2 = 0xff;
          if (iVar1 < (int)param_2) {
            fVar7 = *(float *)((longlong)&half::_toFloat +
                              (ulonglong)*(ushort *)(param_1 + (longlong)iVar1 * 2) * 4) * 255.0;
            if (*(char *)(uVar3 + param_7) == '\0') {
              if (fVar7 <= 255.0) {
                fVar6 = 0.0;
                if (0.0 <= fVar7) {
                  fVar6 = fVar7;
                }
              }
              else {
                fVar6 = 255.0;
              }
              bVar2 = (byte)(longlong)fVar6;
            }
            else if (fVar7 <= 255.0) {
              fVar6 = 0.0;
              if (0.0 <= fVar7) {
                fVar6 = fVar7;
              }
              bVar2 = ~(byte)(longlong)fVar6;
            }
            else {
              bVar2 = 0;
            }
          }
          uVar5 = uVar5 + 1;
          *param_3 = bVar2;
          uVar3 = (ulonglong)uVar5;
          param_3 = param_3 + 1;
        } while (uVar3 < param_4);
      }
      uVar4 = uVar4 + 1;
      param_1 = param_1 + param_2 * 2;
    } while (uVar4 < param_5);
  }
  return;
}



void FUN_180014780(longlong param_1,longlong param_2,ushort *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  ushort uVar2;
  ulonglong uVar3;
  uint uVar4;
  uint uVar5;
  float fVar6;
  float fVar7;
  
  uVar4 = 0;
  if (param_5 != 0) {
    do {
      uVar5 = 0;
      if (param_4 != 0) {
        uVar3 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar3 * 4);
          uVar2 = 0xffff;
          if (iVar1 < (int)param_2) {
            fVar7 = *(float *)((longlong)&half::_toFloat +
                              (ulonglong)*(ushort *)(param_1 + (longlong)iVar1 * 2) * 4) * 65535.0;
            if (*(char *)(uVar3 + param_7) == '\0') {
              if (fVar7 <= 65535.0) {
                fVar6 = 0.0;
                if (0.0 <= fVar7) {
                  fVar6 = fVar7;
                }
              }
              else {
                fVar6 = 65535.0;
              }
              uVar2 = (ushort)(longlong)fVar6;
            }
            else if (fVar7 <= 65535.0) {
              fVar6 = 0.0;
              if (0.0 <= fVar7) {
                fVar6 = fVar7;
              }
              uVar2 = ~(ushort)(longlong)fVar6;
            }
            else {
              uVar2 = 0;
            }
          }
          uVar5 = uVar5 + 1;
          *param_3 = uVar2;
          uVar3 = (ulonglong)uVar5;
          param_3 = param_3 + 1;
        } while (uVar3 < param_4);
      }
      uVar4 = uVar4 + 1;
      param_1 = param_1 + param_2 * 2;
    } while (uVar4 < param_5);
  }
  return;
}



void FUN_180014890(longlong param_1,longlong param_2,uint *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  ulonglong uVar5;
  uint uVar6;
  uint uVar7;
  
  uVar6 = 0;
  if (param_5 != 0) {
    do {
      uVar7 = 0;
      if (param_4 != 0) {
        uVar5 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar5 * 4);
          uVar4 = 0xffffffff;
          if (iVar1 < (int)param_2) {
            fVar2 = *(float *)((longlong)&half::_toFloat +
                              (ulonglong)*(ushort *)(param_1 + (longlong)iVar1 * 2) * 4) *
                    4.294967e+09;
            if (*(char *)(uVar5 + param_7) == '\0') {
              if (fVar2 <= 4.294967e+09) {
                fVar3 = 0.0;
                if (0.0 <= fVar2) {
                  fVar3 = fVar2;
                }
              }
              else {
                fVar3 = 4.294967e+09;
              }
              uVar4 = (uint)(longlong)fVar3;
            }
            else if (fVar2 <= 4.294967e+09) {
              fVar3 = 0.0;
              if (0.0 <= fVar2) {
                fVar3 = fVar2;
              }
              uVar4 = ~(uint)(longlong)fVar3;
            }
            else {
              uVar4 = 0;
            }
          }
          uVar7 = uVar7 + 1;
          *param_3 = uVar4;
          uVar5 = (ulonglong)uVar7;
          param_3 = param_3 + 1;
        } while (uVar5 < param_4);
      }
      uVar6 = uVar6 + 1;
      param_1 = param_1 + param_2 * 2;
    } while (uVar6 < param_5);
  }
  return;
}



void FUN_180014990(longlong param_1,longlong param_2,float *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  uint uVar4;
  uint uVar5;
  float fVar6;
  
  uVar5 = 0;
  if (param_5 != 0) {
    do {
      uVar4 = 0;
      if (param_4 != 0) {
        uVar2 = 0;
        do {
          iVar1 = *(int *)(param_6 + uVar2 * 4);
          fVar6 = 1.0;
          if (iVar1 < (int)param_2) {
            uVar3 = (ulonglong)*(ushort *)(param_1 + (longlong)iVar1 * 2);
            if (*(char *)(uVar2 + param_7) == '\0') {
              fVar6 = *(float *)((longlong)&half::_toFloat + uVar3 * 4);
            }
            else {
              fVar6 = 1.0 - *(float *)((longlong)&half::_toFloat + uVar3 * 4);
            }
          }
          uVar4 = uVar4 + 1;
          *param_3 = fVar6;
          uVar2 = (ulonglong)uVar4;
          param_3 = param_3 + 1;
        } while (uVar2 < param_4);
      }
      uVar5 = uVar5 + 1;
      param_1 = param_1 + param_2 * 2;
    } while (uVar5 < param_5);
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x000180014ab3)
// WARNING: Could not reconcile some variable overlaps

void FUN_180014a50(longlong param_1,longlong param_2,ushort *param_3,ulonglong param_4,
                  ulonglong param_5,longlong param_6,longlong param_7)

{
  int iVar1;
  uint uVar2;
  ulonglong uVar3;
  uint uVar4;
  ushort *puVar5;
  uint local_res8 [2];
  uint local_res18;
  
  local_res8[0] = 0x3f800000;
  uVar3 = 0;
  local_res18 = 0;
  if (param_5 != 0) {
    do {
      uVar4 = 0;
      uVar2 = (uint)uVar3;
      if (param_4 != 0) {
        uVar3 = 0;
        puVar5 = param_3;
        do {
          iVar1 = *(int *)(param_6 + uVar3 * 4);
          local_res8[0] = local_res8[0] & 0xffff0000 | 0x3c00;
          local_res8[0]._0_2_ = 0x3c00;
          if (iVar1 < (int)param_2) {
            if (*(char *)(uVar3 + param_7) == '\0') {
              local_res8[0]._0_2_ = *(ushort *)(param_1 + (longlong)iVar1 * 2);
            }
            else {
              FUN_1800131d0(*(ushort *)(param_1 + (longlong)iVar1 * 2),(short *)local_res8);
            }
          }
          uVar4 = uVar4 + 1;
          param_3 = puVar5 + 1;
          *puVar5 = (ushort)local_res8[0];
          uVar3 = (ulonglong)uVar4;
          puVar5 = param_3;
          uVar2 = local_res18;
        } while (uVar3 < param_4);
      }
      local_res18 = uVar2 + 1;
      uVar3 = (ulonglong)local_res18;
      param_1 = param_1 + param_2 * 2;
    } while (uVar3 < param_5);
  }
  return;
}



void FUN_180014b90(void **param_1)

{
  if ((void *)0x7 < param_1[3]) {
    FUN_180011890(param_1,*param_1,(longlong)param_1[3] + 1);
  }
  param_1[3] = (void *)0x7;
  param_1[2] = (void *)0x0;
  if ((void *)0x7 < param_1[3]) {
    *(undefined2 *)*param_1 = 0;
    return;
  }
  *(undefined2 *)param_1 = 0;
  return;
}



longlong FUN_180014be0(longlong param_1,longlong param_2)

{
  ulonglong **ppuVar1;
  longlong lVar2;
  undefined8 *puVar3;
  ulonglong **ppuVar4;
  
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_2 + 0x10);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x14);
  *(undefined4 *)(param_1 + 0x18) = *(undefined4 *)(param_2 + 0x18);
  puVar3 = (undefined8 *)(param_1 + 0x20);
  *(undefined4 *)(param_1 + 0x1c) = *(undefined4 *)(param_2 + 0x1c);
  lVar2 = 0x10;
  do {
    *puVar3 = *(undefined8 *)((param_2 - param_1) + (longlong)puVar3);
    puVar3 = puVar3 + 1;
    lVar2 = lVar2 + -1;
  } while (lVar2 != 0);
  ppuVar4 = (ulonglong **)(param_1 + 0xa0);
  lVar2 = 4;
  do {
    ppuVar1 = (ulonglong **)((longlong)ppuVar4 + (param_2 - param_1));
    if (ppuVar4 != ppuVar1) {
      FUN_1800113a0(ppuVar4,ppuVar1,(ulonglong *)0x0,(ulonglong *)0xffffffffffffffff);
    }
    ppuVar4 = ppuVar4 + 4;
    lVar2 = lVar2 + -1;
  } while (lVar2 != 0);
  return param_1;
}



void FUN_180014c90(void **param_1,uint param_2)

{
  bool bVar1;
  uint uVar2;
  undefined8 ****ppppuVar3;
  uint uVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  undefined8 *puVar7;
  undefined8 *puVar8;
  uint uVar9;
  undefined auStack_c8 [32];
  uint local_a8;
  void **local_a0;
  undefined8 local_98;
  undefined8 ****local_90 [2];
  ulonglong local_80;
  ulonglong local_78;
  undefined2 local_70;
  undefined6 uStack_6e;
  ulonglong local_60;
  ulonglong local_58;
  undefined2 local_50;
  undefined6 uStack_4e;
  ulonglong local_40;
  ulonglong local_38;
  ulonglong local_30;
  
  local_98 = 0xfffffffffffffffe;
  local_30 = DAT_180065150 ^ (ulonglong)auStack_c8;
  uVar9 = 0;
  local_a8 = 0;
  local_a0 = param_1;
  if ((param_2 < 5) && (uVar4 = uVar9, 0 < (int)param_2)) {
    do {
      FUN_180016fe0(local_a0,local_90,(void *)(longlong)(int)uVar9,(void *)0x1);
      local_38 = 7;
      local_40 = 0;
      local_50 = 0;
      FUN_180011740((void **)&local_50,(void **)&DAT_18001c64c,(void *)0x1);
      uVar6 = local_78;
      uVar4 = uVar4 | 1;
      puVar7 = (undefined8 *)&local_50;
      if (7 < local_38) {
        puVar7 = (undefined8 *)CONCAT62(uStack_4e,local_50);
      }
      ppppuVar3 = local_90;
      if (7 < local_78) {
        ppppuVar3 = local_90[0];
      }
      local_a8 = uVar4;
      uVar2 = FUN_180016e50((ushort *)ppppuVar3,local_80,(ushort *)puVar7,local_40);
      if (uVar2 == 0) {
        puVar7 = (undefined8 *)CONCAT62(uStack_6e,local_70);
        uVar5 = local_58;
LAB_180014dcf:
        bVar1 = false;
      }
      else {
        local_58 = 7;
        local_60 = 0;
        local_70 = 0;
        FUN_180011740((void **)&local_70,(void **)&DAT_18001c650,(void *)0x1);
        uVar5 = local_58;
        uVar6 = local_78;
        uVar4 = 3;
        puVar7 = (undefined8 *)CONCAT62(uStack_6e,local_70);
        puVar8 = (undefined8 *)&local_70;
        if (7 < local_58) {
          puVar8 = puVar7;
        }
        ppppuVar3 = local_90;
        if (7 < local_78) {
          ppppuVar3 = local_90[0];
        }
        uVar2 = FUN_180016e50((ushort *)ppppuVar3,local_80,(ushort *)puVar8,local_60);
        if (uVar2 == 0) goto LAB_180014dcf;
        bVar1 = true;
      }
      if ((uVar4 & 2) != 0) {
        uVar4 = 0;
        if (7 < uVar5) {
          FUN_180011890(&local_70,puVar7,uVar5 + 1);
          uVar6 = local_78;
        }
        local_58 = 7;
        local_60 = 0;
        local_70 = 0;
      }
      uVar4 = uVar4 & 0xfffffffe;
      if (7 < local_38) {
        FUN_180011890(&local_50,(void *)CONCAT62(uStack_4e,local_50),local_38 + 1);
        uVar6 = local_78;
      }
      if (bVar1) {
        if (7 < uVar6) {
          FUN_180011890(local_90,local_90[0],uVar6 + 1);
        }
        break;
      }
      if (7 < uVar6) {
        FUN_180011890(local_90,local_90[0],uVar6 + 1);
      }
      uVar9 = uVar9 + 1;
    } while ((int)uVar9 < (int)param_2);
  }
  __security_check_cookie(local_30 ^ (ulonglong)auStack_c8);
  return;
}



// WARNING: Type propagation algorithm not settling

void FUN_180014eb0(short **param_1,uint param_2)

{
  short **ppsVar1;
  code *pcVar2;
  undefined2 *puVar3;
  short **ppsVar4;
  short *psVar5;
  void *pvVar6;
  int iVar7;
  short *psVar8;
  undefined auStack_68 [32];
  undefined8 local_48;
  undefined8 local_40;
  void *local_30;
  void *local_28;
  ulonglong local_20;
  
  local_48 = 0xfffffffffffffffe;
  local_20 = DAT_180065150 ^ (ulonglong)auStack_68;
  if (param_2 < 5) {
    local_28 = (void *)0x7;
    iVar7 = 0;
    local_30 = (void *)0x0;
    local_40._0_2_ = 0;
    FUN_180011740((void **)&local_40,(void **)&DAT_18001c648,(void *)0x0);
    if (0 < (int)param_2) {
      do {
        if (~(ulonglong)local_30 < 2) {
          std::_Xlength_error("string too long");
          pcVar2 = (code *)swi(3);
          (*pcVar2)();
          return;
        }
        pvVar6 = (void *)((longlong)local_30 + 1);
        if ((void *)0x7ffffffffffffffe < pvVar6) {
          std::_Xlength_error("string too long");
          pcVar2 = (code *)swi(3);
          (*pcVar2)();
          return;
        }
        if (local_28 < pvVar6) {
          FUN_180011190((void **)&local_40,pvVar6,local_30);
LAB_180014f89:
          if (pvVar6 != (void *)0x0) goto LAB_180014f96;
        }
        else {
          if (pvVar6 == (void *)0x0) {
            local_30 = (void *)0x0;
            puVar3 = (undefined2 *)&local_40;
            if ((void *)0x7 < local_28) {
              puVar3 = (undefined2 *)CONCAT62(local_40._2_6_,(short)local_40);
            }
            *puVar3 = 0;
            goto LAB_180014f89;
          }
LAB_180014f96:
          puVar3 = (undefined2 *)&local_40;
          if ((void *)0x7 < local_28) {
            puVar3 = (undefined2 *)CONCAT62(local_40._2_6_,(short)local_40);
          }
          puVar3[(longlong)local_30] = (short)iVar7 + 0x30;
          local_30 = pvVar6;
          puVar3 = (undefined2 *)&local_40;
          if ((void *)0x7 < local_28) {
            puVar3 = (undefined2 *)CONCAT62(local_40._2_6_,(short)local_40);
          }
          puVar3[(longlong)pvVar6] = 0;
        }
        iVar7 = iVar7 + 1;
      } while (iVar7 < (int)param_2);
    }
    psVar8 = (short *)&local_40;
    if ((void *)0x7 < local_28) {
      psVar8 = (short *)CONCAT62(local_40._2_6_,(short)local_40);
    }
    ppsVar1 = param_1 + 2;
    if (*ppsVar1 != (short *)0x0) {
      ppsVar4 = param_1;
      if ((short *)0x7 < param_1[3]) {
        ppsVar4 = (short **)*param_1;
      }
      if ((short *)0x7 < param_1[3]) {
        param_1 = (short **)*param_1;
      }
      while ((param_1 < (short **)((longlong)ppsVar4 + (longlong)*ppsVar1 * 2) &&
             (local_30 != (void *)0x0))) {
        psVar5 = psVar8;
        pvVar6 = local_30;
        while (*psVar5 != *(short *)param_1) {
          psVar5 = psVar5 + 1;
          pvVar6 = (void *)((longlong)pvVar6 + -1);
          if (pvVar6 == (void *)0x0) goto LAB_18001506f;
        }
        param_1 = (short **)((longlong)param_1 + 2);
      }
    }
LAB_18001506f:
    if ((void *)0x7 < local_28) {
      FUN_180011890(&local_40,(short *)CONCAT62(local_40._2_6_,(short)local_40),
                    (longlong)local_28 + 1);
    }
  }
  __security_check_cookie(local_20 ^ (ulonglong)auStack_68);
  return;
}



void FUN_1800150c0(longlong param_1,void *param_2,ulonglong param_3,float *param_4)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  longlong lVar7;
  undefined4 extraout_var;
  undefined4 extraout_var_00;
  size_t _Size;
  ulonglong *puVar8;
  int *piVar9;
  ulonglong uVar10;
  float *_Dst;
  ulonglong uVar11;
  ulonglong uVar12;
  ulonglong uVar13;
  ulonglong uVar14;
  undefined auStackY_a8 [32];
  ulonglong local_50 [3];
  
  local_50[2] = DAT_180065150 ^ (ulonglong)auStackY_a8;
  uVar11 = param_3 & 0xffffffff;
  lVar7 = (**(code **)(**(longlong **)(param_1 + 0x128) + 0x30))();
  uVar2 = FUN_180012a60(lVar7);
  uVar10 = (ulonglong)uVar2;
  lVar7 = (**(code **)(**(longlong **)(param_1 + 0x128) + 0x30))();
  iVar3 = FUN_180012aa0(lVar7);
  iVar4 = FUN_180012aa0(param_1 + 8);
  uVar2 = FUN_180012a60(param_1 + 8);
  uVar12 = (ulonglong)uVar2;
  _Size = FUN_1800129e0(param_1 + 8);
  iVar6 = *(int *)(param_1 + 0x144);
  lVar7 = (**(code **)(**(longlong **)(param_1 + 0x128) + 0x30))();
  iVar5 = FUN_1800128d0(lVar7);
  uVar13 = 0;
  bVar1 = false;
  uVar14 = uVar13;
  if (uVar10 != 0) {
    do {
      if ((bVar1) || (*(char *)(uVar14 + 0x140 + param_1) != '\0')) {
        bVar1 = true;
      }
      uVar14 = (ulonglong)((int)uVar14 + 1);
    } while (uVar14 < uVar10);
  }
  if ((iVar6 != iVar5) && (*(char *)(param_1 + 0x148) != '\0')) {
    lVar7 = (**(code **)(**(longlong **)(param_1 + 0x128) + 0x30))();
    iVar6 = FUN_1800128d0(lVar7);
    if (iVar6 == 0) {
      iVar6 = *(int *)(param_1 + 0x144);
      if (iVar6 == 1) {
        FUN_180013370((longlong)param_2,uVar10,(ushort *)param_4,uVar12,uVar11,param_1 + 0x130,
                      param_1 + 0x140);
      }
      else if (iVar6 == 2) {
        FUN_180013420((longlong)param_2,uVar10,(uint *)param_4,uVar12,uVar11,param_1 + 0x130,
                      param_1 + 0x140);
      }
      else if (iVar6 == 3) {
        FUN_1800134b0((longlong)param_2,uVar10,param_4,uVar12,uVar11,param_1 + 0x130,param_1 + 0x140
                     );
      }
      else if (iVar6 == 4) {
        FUN_180013570((longlong)param_2,uVar10,(ushort *)param_4,uVar12,uVar11,param_1 + 0x130,
                      param_1 + 0x140);
      }
    }
    else if (iVar6 == 1) {
      iVar6 = *(int *)(param_1 + 0x144);
      if (iVar6 == 0) {
        FUN_180013770((longlong)param_2,uVar10,(char *)param_4,uVar12,uVar11,param_1 + 0x130,
                      param_1 + 0x140);
      }
      else if (iVar6 == 2) {
        FUN_1800138d0((longlong)param_2,uVar10,(uint *)param_4,uVar12,uVar11,param_1 + 0x130,
                      param_1 + 0x140);
      }
      else if (iVar6 == 3) {
        FUN_180013980((longlong)param_2,uVar10,param_4,uVar12,uVar11,param_1 + 0x130,param_1 + 0x140
                     );
      }
      else if (iVar6 == 4) {
        FUN_180013a50((longlong)param_2,uVar10,(ushort *)param_4,uVar12,uVar11,param_1 + 0x130,
                      param_1 + 0x140);
      }
    }
    else if (iVar6 == 2) {
      iVar6 = *(int *)(param_1 + 0x144);
      if (iVar6 == 0) {
        FUN_180013c50((longlong)param_2,uVar10,(char *)param_4,uVar12,uVar11,param_1 + 0x130,
                      param_1 + 0x140);
      }
      else if (iVar6 == 1) {
        FUN_180013d00((longlong)param_2,uVar10,(short *)param_4,uVar12,uVar11,param_1 + 0x130,
                      param_1 + 0x140);
      }
      else if (iVar6 == 3) {
        FUN_180013e60((longlong)param_2,uVar10,param_4,uVar12,uVar11,param_1 + 0x130,param_1 + 0x140
                     );
      }
      else if (iVar6 == 4) {
        FUN_180013f30((longlong)param_2,uVar10,(ushort *)param_4,uVar12,uVar11,param_1 + 0x130,
                      param_1 + 0x140);
      }
    }
    else if (iVar6 == 3) {
      iVar6 = *(int *)(param_1 + 0x144);
      if (iVar6 == 0) {
        FUN_180014130((longlong)param_2,uVar10,(byte *)param_4,uVar12,uVar11,param_1 + 0x130,
                      param_1 + 0x140);
      }
      else if (iVar6 == 1) {
        FUN_180014220((longlong)param_2,uVar10,(ushort *)param_4,uVar12,uVar11,param_1 + 0x130,
                      param_1 + 0x140);
      }
      else if (iVar6 == 2) {
        FUN_180014310((longlong)param_2,uVar10,(uint *)param_4,uVar12,uVar11,param_1 + 0x130,
                      param_1 + 0x140);
      }
      else if (iVar6 == 4) {
        FUN_1800144c0((longlong)param_2,uVar10,(ushort *)param_4,uVar12,uVar11,param_1 + 0x130,
                      param_1 + 0x140);
      }
    }
    else if (iVar6 == 4) {
      iVar6 = *(int *)(param_1 + 0x144);
      if (iVar6 == 0) {
        FUN_180014690((longlong)param_2,uVar10,(byte *)param_4,uVar12,uVar11,param_1 + 0x130,
                      param_1 + 0x140);
      }
      else if (iVar6 == 1) {
        FUN_180014780((longlong)param_2,uVar10,(ushort *)param_4,uVar12,uVar11,param_1 + 0x130,
                      param_1 + 0x140);
      }
      else if (iVar6 == 2) {
        FUN_180014890((longlong)param_2,uVar10,(uint *)param_4,uVar12,uVar11,param_1 + 0x130,
                      param_1 + 0x140);
      }
      else if (iVar6 == 3) {
        FUN_180014990((longlong)param_2,uVar10,param_4,uVar12,uVar11,param_1 + 0x130,param_1 + 0x140
                     );
      }
    }
  }
  else if ((!bVar1) || (iVar6 != iVar5)) {
    iVar6 = FUN_1800128d0(param_1 + 8);
    if (-1 < iVar6) {
      if (iVar6 < 3) {
        local_50[0] = 0xffffffffffffffff;
        local_50[1] = 0xffffffffffffffff;
      }
      else if (iVar6 == 3) {
        puVar8 = local_50;
        do {
          uVar2 = (int)uVar13 + 1;
          uVar13 = (ulonglong)uVar2;
          *(undefined4 *)puVar8 = 0x3f800000;
          puVar8 = (ulonglong *)((longlong)puVar8 + 4);
        } while ((ulonglong)((longlong)(int)uVar2 << 2) < 0x10);
      }
      else if (iVar6 == 4) {
        puVar8 = local_50;
        do {
          uVar2 = (int)uVar13 + 1;
          uVar13 = (ulonglong)uVar2;
          *(undefined2 *)puVar8 = 0x3c00;
          puVar8 = (ulonglong *)((longlong)puVar8 + 2);
        } while ((ulonglong)((longlong)(int)uVar2 * 2) < 0x10);
      }
    }
    if ((int)uVar11 != 0) {
      do {
        memcpy(local_50,param_2,CONCAT44(extraout_var,iVar3));
        if (uVar12 != 0) {
          piVar9 = (int *)(param_1 + 0x130);
          _Dst = param_4;
          uVar14 = uVar12;
          do {
            memcpy(_Dst,(ulonglong *)((longlong)local_50 + (longlong)*piVar9 * _Size),_Size);
            _Dst = (float *)((longlong)_Dst + _Size);
            piVar9 = piVar9 + 1;
            uVar14 = uVar14 - 1;
          } while (uVar14 != 0);
        }
        param_4 = (float *)((longlong)param_4 + CONCAT44(extraout_var_00,iVar4));
        param_2 = (void *)((longlong)param_2 + CONCAT44(extraout_var,iVar3));
        uVar11 = uVar11 - 1;
      } while (uVar11 != 0);
    }
  }
  else if (iVar6 == 0) {
    FUN_1800132e0((longlong)param_2,uVar10,(byte *)param_4,uVar12,uVar11,param_1 + 0x130,
                  param_1 + 0x140);
  }
  else if (iVar6 == 1) {
    FUN_180013820((longlong)param_2,uVar10,(ushort *)param_4,uVar12,uVar11,param_1 + 0x130,
                  param_1 + 0x140);
  }
  else if (iVar6 == 2) {
    FUN_180013dc0((longlong)param_2,uVar10,(uint *)param_4,uVar12,uVar11,param_1 + 0x130,
                  param_1 + 0x140);
  }
  else if (iVar6 == 3) {
    FUN_180014410((longlong)param_2,uVar10,param_4,uVar12,uVar11,param_1 + 0x130,param_1 + 0x140);
  }
  else if (iVar6 == 4) {
    FUN_180014a50((longlong)param_2,uVar10,(ushort *)param_4,uVar12,uVar11,param_1 + 0x130,
                  param_1 + 0x140);
  }
  __security_check_cookie(local_50[2] ^ (ulonglong)auStackY_a8);
  return;
}



void FUN_180015900(void *param_1,Enum param_2,int param_3,uint param_4,float *param_5,Enum param_6,
                  int param_7,char param_8,undefined4 *param_9,undefined4 *param_10)

{
  bool bVar1;
  int iVar2;
  longlong lVar3;
  ulonglong uVar4;
  undefined4 *puVar5;
  ulonglong *puVar6;
  longlong lVar7;
  ulonglong uVar8;
  size_t _Size;
  float *_Dst;
  ulonglong uVar9;
  undefined4 *puVar10;
  undefined auStackY_c8 [32];
  undefined4 local_84;
  Enum local_80;
  size_t local_78;
  longlong local_70;
  undefined4 local_68;
  undefined4 uStack_64;
  undefined4 uStack_60;
  undefined4 uStack_5c;
  ulonglong local_58 [4];
  
  local_58[2] = DAT_180065150 ^ (ulonglong)auStackY_c8;
  lVar7 = (longlong)param_3;
  local_80 = param_2;
  iVar2 = Graphine::Core::DataTypeInfo::GetChannelSize(param_2);
  local_78 = (size_t)(iVar2 * param_3);
  iVar2 = Graphine::Core::DataTypeInfo::GetChannelSize(param_6);
  uVar4 = (ulonglong)param_7;
  local_70 = (longlong)(iVar2 * param_7);
  iVar2 = Graphine::Core::DataTypeInfo::GetChannelSize(param_2);
  _Size = (size_t)iVar2;
  puVar10 = &local_68;
  if (param_9 != (undefined4 *)0x0) {
    puVar10 = param_9;
  }
  local_84 = 0;
  local_68 = 0;
  uStack_64 = 1;
  uStack_60 = 2;
  uStack_5c = 3;
  puVar5 = &local_84;
  if (param_10 != (undefined4 *)0x0) {
    puVar5 = param_10;
  }
  bVar1 = false;
  lVar3 = 0;
  if (0 < lVar7) {
    do {
      if ((bVar1) || (*(char *)((longlong)puVar5 + lVar3) != '\0')) {
        bVar1 = true;
      }
      lVar3 = lVar3 + 1;
    } while (lVar3 < lVar7);
  }
  if ((local_80 == param_6) || (param_8 == '\0')) {
    if ((bVar1) && (local_80 == param_6)) {
      if (param_6 == 0) {
        FUN_1800132e0((longlong)param_1,lVar7,(byte *)param_5,uVar4,(ulonglong)param_4,
                      (longlong)puVar10,(longlong)puVar5);
      }
      else if (param_6 == 1) {
        FUN_180013820((longlong)param_1,lVar7,(ushort *)param_5,uVar4,(ulonglong)param_4,
                      (longlong)puVar10,(longlong)puVar5);
      }
      else if (param_6 == 2) {
        FUN_180013dc0((longlong)param_1,lVar7,(uint *)param_5,uVar4,(ulonglong)param_4,
                      (longlong)puVar10,(longlong)puVar5);
      }
      else if (param_6 == 3) {
        FUN_180014410((longlong)param_1,lVar7,param_5,uVar4,(ulonglong)param_4,(longlong)puVar10,
                      (longlong)puVar5);
      }
      else if (param_6 == 4) {
        FUN_180014a50((longlong)param_1,lVar7,(ushort *)param_5,uVar4,(ulonglong)param_4,
                      (longlong)puVar10,(longlong)puVar5);
      }
    }
    else {
      if (-1 < (int)local_80) {
        if ((int)local_80 < 3) {
          local_58[0] = 0xffffffffffffffff;
          local_58[1] = 0xffffffffffffffff;
        }
        else if (local_80 == 3) {
          iVar2 = 0;
          puVar6 = local_58;
          do {
            iVar2 = iVar2 + 1;
            *(undefined4 *)puVar6 = 0x3f800000;
            puVar6 = (ulonglong *)((longlong)puVar6 + 4);
          } while ((ulonglong)((longlong)iVar2 << 2) < 0x10);
        }
        else if (local_80 == 4) {
          iVar2 = 0;
          puVar6 = local_58;
          do {
            iVar2 = iVar2 + 1;
            *(undefined2 *)puVar6 = 0x3c00;
            puVar6 = (ulonglong *)((longlong)puVar6 + 2);
          } while ((ulonglong)((longlong)iVar2 * 2) < 0x10);
        }
      }
      if (param_4 != 0) {
        uVar9 = (ulonglong)param_4;
        do {
          memcpy(local_58,param_1,local_78);
          uVar8 = 0;
          _Dst = param_5;
          if (uVar4 != 0) {
            do {
              memcpy(_Dst,(ulonglong *)((longlong)local_58 + (longlong)(int)puVar10[uVar8] * _Size),
                     _Size);
              uVar8 = uVar8 + 1;
              _Dst = (float *)((longlong)_Dst + _Size);
            } while (uVar8 < uVar4);
          }
          param_5 = (float *)((longlong)param_5 + local_70);
          param_1 = (void *)((longlong)param_1 + local_78);
          uVar9 = uVar9 - 1;
        } while (uVar9 != 0);
      }
    }
  }
  else if (local_80 == 0) {
    if (param_6 == 1) {
      FUN_180013370((longlong)param_1,lVar7,(ushort *)param_5,uVar4,(ulonglong)param_4,
                    (longlong)puVar10,(longlong)puVar5);
    }
    else if (param_6 == 2) {
      FUN_180013420((longlong)param_1,lVar7,(uint *)param_5,uVar4,(ulonglong)param_4,
                    (longlong)puVar10,(longlong)puVar5);
    }
    else if (param_6 == 3) {
      FUN_1800134b0((longlong)param_1,lVar7,param_5,uVar4,(ulonglong)param_4,(longlong)puVar10,
                    (longlong)puVar5);
    }
    else if (param_6 == 4) {
      FUN_180013570((longlong)param_1,lVar7,(ushort *)param_5,uVar4,(ulonglong)param_4,
                    (longlong)puVar10,(longlong)puVar5);
    }
  }
  else if (local_80 == 1) {
    if (param_6 == 0) {
      FUN_180013770((longlong)param_1,lVar7,(char *)param_5,uVar4,(ulonglong)param_4,
                    (longlong)puVar10,(longlong)puVar5);
    }
    else if (param_6 == 2) {
      FUN_1800138d0((longlong)param_1,lVar7,(uint *)param_5,uVar4,(ulonglong)param_4,
                    (longlong)puVar10,(longlong)puVar5);
    }
    else if (param_6 == 3) {
      FUN_180013980((longlong)param_1,lVar7,param_5,uVar4,(ulonglong)param_4,(longlong)puVar10,
                    (longlong)puVar5);
    }
    else if (param_6 == 4) {
      FUN_180013a50((longlong)param_1,lVar7,(ushort *)param_5,uVar4,(ulonglong)param_4,
                    (longlong)puVar10,(longlong)puVar5);
    }
  }
  else if (local_80 == 2) {
    if (param_6 == 0) {
      FUN_180013c50((longlong)param_1,lVar7,(char *)param_5,uVar4,(ulonglong)param_4,
                    (longlong)puVar10,(longlong)puVar5);
    }
    else if (param_6 == 1) {
      FUN_180013d00((longlong)param_1,lVar7,(short *)param_5,uVar4,(ulonglong)param_4,
                    (longlong)puVar10,(longlong)puVar5);
    }
    else if (param_6 == 3) {
      FUN_180013e60((longlong)param_1,lVar7,param_5,uVar4,(ulonglong)param_4,(longlong)puVar10,
                    (longlong)puVar5);
    }
    else if (param_6 == 4) {
      FUN_180013f30((longlong)param_1,lVar7,(ushort *)param_5,uVar4,(ulonglong)param_4,
                    (longlong)puVar10,(longlong)puVar5);
    }
  }
  else if (local_80 == 3) {
    if (param_6 == 0) {
      FUN_180014130((longlong)param_1,lVar7,(byte *)param_5,uVar4,(ulonglong)param_4,
                    (longlong)puVar10,(longlong)puVar5);
    }
    else if (param_6 == 1) {
      FUN_180014220((longlong)param_1,lVar7,(ushort *)param_5,uVar4,(ulonglong)param_4,
                    (longlong)puVar10,(longlong)puVar5);
    }
    else if (param_6 == 2) {
      FUN_180014310((longlong)param_1,lVar7,(uint *)param_5,uVar4,(ulonglong)param_4,
                    (longlong)puVar10,(longlong)puVar5);
    }
    else if (param_6 == 4) {
      FUN_1800144c0((longlong)param_1,lVar7,(ushort *)param_5,uVar4,(ulonglong)param_4,
                    (longlong)puVar10,(longlong)puVar5);
    }
  }
  else if (local_80 == 4) {
    if (param_6 == 0) {
      FUN_180014690((longlong)param_1,lVar7,(byte *)param_5,uVar4,(ulonglong)param_4,
                    (longlong)puVar10,(longlong)puVar5);
    }
    else if (param_6 == 1) {
      FUN_180014780((longlong)param_1,lVar7,(ushort *)param_5,uVar4,(ulonglong)param_4,
                    (longlong)puVar10,(longlong)puVar5);
    }
    else if (param_6 == 2) {
      FUN_180014890((longlong)param_1,lVar7,(uint *)param_5,uVar4,(ulonglong)param_4,
                    (longlong)puVar10,(longlong)puVar5);
    }
    else if (param_6 == 3) {
      FUN_180014990((longlong)param_1,lVar7,param_5,uVar4,(ulonglong)param_4,(longlong)puVar10,
                    (longlong)puVar5);
    }
  }
  __security_check_cookie(local_58[2] ^ (ulonglong)auStackY_c8);
  return;
}



undefined8
FUN_180016000(void *param_1,Enum param_2,uint param_3,float *param_4,Enum param_5,char param_6,
             undefined4 *param_7,undefined4 *param_8)

{
  char cVar1;
  undefined uVar2;
  int iVar3;
  int iVar4;
  Enum EVar5;
  int iVar6;
  Enum EVar7;
  int iVar8;
  float *_Memory;
  undefined8 extraout_RAX;
  ulonglong extraout_RAX_00;
  undefined8 uVar9;
  int *piVar10;
  undefined *puVar11;
  longlong lVar12;
  uint uVar13;
  uint uVar14;
  float fVar15;
  float fVar16;
  int local_a4 [2];
  int local_9c [23];
  
  if (param_2 == 2) {
    iVar3 = Graphine::Core::DataTypeInfo::GetPixelSize(7);
    _Memory = (float *)operator_new((ulonglong)(uint)(iVar3 << 0xb));
    uVar14 = 0;
    if (param_3 + 0x7ff >> 0xb != 0) {
      iVar3 = 0;
      do {
        uVar13 = param_3 - iVar3;
        if (0x800 < uVar13) {
          uVar13 = 0x800;
        }
        iVar4 = Graphine::Core::DataTypeInfo::GetNumChannels(7);
        EVar5 = Graphine::Core::DataTypeInfo::GetChannelDataType(7);
        iVar6 = Graphine::Core::DataTypeInfo::GetNumChannels(2);
        EVar7 = Graphine::Core::DataTypeInfo::GetChannelDataType(2);
        iVar8 = Graphine::Core::DataTypeInfo::GetPixelSize(2);
        cVar1 = FUN_180015900((void *)((ulonglong)(iVar8 * uVar14 * 0x800) + (longlong)param_1),
                              EVar7,iVar6,uVar13,_Memory,EVar5,iVar4,param_6,param_7,param_8);
        if (cVar1 == '\0') {
LAB_18001630d:
          free(_Memory);
          return extraout_RAX_00 & 0xffffffffffffff00;
        }
        lVar12 = (longlong)(int)uVar13;
        if (0 < (int)uVar13) {
          puVar11 = (undefined *)((longlong)_Memory + 2);
          do {
            fVar16 = ((float)(uint)(byte)puVar11[-2] / 255.0 +
                     (float)(uint)(byte)puVar11[-2] / 255.0) - 1.0;
            fVar15 = ((float)(uint)(byte)puVar11[-1] / 255.0 +
                     (float)(uint)(byte)puVar11[-1] / 255.0) - 1.0;
            fVar15 = (1.0 - fVar16 * fVar16) - fVar15 * fVar15;
            if (fVar15 <= 0.0) {
              fVar15 = 0.0;
            }
            else {
              fVar15 = sqrtf(fVar15);
            }
            local_9c[0] = 0xff;
            fVar15 = floorf((fVar15 * 0.5 + 0.5) * 255.0 + 0.5);
            local_a4[0] = (int)fVar15;
            piVar10 = local_a4;
            if (0xfe < (int)fVar15) {
              piVar10 = local_9c;
            }
            uVar2 = *(undefined *)piVar10;
            if (*piVar10 < 0) {
              uVar2 = 0;
            }
            *puVar11 = uVar2;
            puVar11 = puVar11 + 3;
            lVar12 = lVar12 + -1;
          } while (lVar12 != 0);
        }
        iVar4 = Graphine::Core::DataTypeInfo::GetNumChannels(param_5);
        EVar5 = Graphine::Core::DataTypeInfo::GetChannelDataType(param_5);
        iVar6 = Graphine::Core::DataTypeInfo::GetPixelSize(param_5);
        iVar8 = Graphine::Core::DataTypeInfo::GetNumChannels(7);
        EVar7 = Graphine::Core::DataTypeInfo::GetChannelDataType(7);
        cVar1 = FUN_180015900(_Memory,EVar7,iVar8,uVar13,
                              (float *)((ulonglong)(iVar6 * uVar14 * 0x800) + (longlong)param_4),
                              EVar5,iVar4,param_6,param_7,param_8);
        if (cVar1 == '\0') goto LAB_18001630d;
        iVar3 = iVar3 + 0x800;
        uVar14 = uVar14 + 1;
      } while (uVar14 < param_3 + 0x7ff >> 0xb);
    }
    free(_Memory);
    uVar9 = CONCAT71((int7)((ulonglong)extraout_RAX >> 8),1);
  }
  else {
    iVar3 = Graphine::Core::DataTypeInfo::GetNumChannels(param_5);
    EVar5 = Graphine::Core::DataTypeInfo::GetChannelDataType(param_5);
    iVar4 = Graphine::Core::DataTypeInfo::GetNumChannels(param_2);
    EVar7 = Graphine::Core::DataTypeInfo::GetChannelDataType(param_2);
    uVar9 = FUN_180015900(param_1,EVar7,iVar4,param_3,param_4,EVar5,iVar3,param_6,param_7,param_8);
  }
  return uVar9;
}



void FUN_1800163a0(void *param_1,Enum param_2,int param_3,uint param_4,float *param_5,Enum param_6,
                  int param_7,char param_8,undefined4 *param_9,undefined4 *param_10)

{
  FUN_180015900(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
  return;
}



void FUN_1800163b0(void *param_1,Enum param_2,uint param_3,float *param_4,Enum param_5,char param_6,
                  undefined4 *param_7,undefined4 *param_8)

{
  FUN_180016000(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}



void FUN_1800163d0(longlong param_1,longlong param_2,longlong param_3)

{
  undefined *puVar1;
  
  if (param_2 != 0) {
    puVar1 = (undefined *)(param_1 + 1);
    do {
      *(uint *)(puVar1 + 4 + (param_3 - param_1) + -5) =
           CONCAT31(CONCAT21(CONCAT11(puVar1[2],puVar1[-1]),*puVar1),puVar1[1]);
      param_2 = param_2 + -1;
      puVar1 = puVar1 + 4;
    } while (param_2 != 0);
  }
  return;
}



void FUN_180016420(longlong *param_1,undefined4 param_2,undefined4 param_3,undefined8 param_4,
                  undefined8 param_5)

{
  longlong lVar1;
  undefined4 uVar2;
  
  lVar1 = *param_1;
  uVar2 = FUN_180012a00((longlong)(param_1 + 1));
  (**(code **)(lVar1 + 0x20))(param_1,param_2,param_3,0,uVar2,param_4,param_5);
  return;
}



void FUN_180016490(longlong *param_1,undefined8 param_2,undefined8 param_3)

{
  (**(code **)(*param_1 + 0x30))(param_1,0,0,param_2,param_3);
  return;
}



int FUN_1800164b0(longlong param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 float *param_5)

{
  int iVar1;
  uint uVar2;
  longlong lVar3;
  undefined4 extraout_var;
  void *_Memory;
  
  if (param_5 == (float *)0x0) {
    return 7;
  }
  lVar3 = (**(code **)(**(longlong **)(param_1 + 0x128) + 0x30))();
  iVar1 = FUN_180012aa0(lVar3);
  uVar2 = FUN_180012a40(param_1 + 8,(byte)param_3);
  _Memory = operator_new((ulonglong)uVar2 * CONCAT44(extraout_var,iVar1));
  iVar1 = (**(code **)(**(longlong **)(param_1 + 0x128) + 0x40))
                    (*(longlong **)(param_1 + 0x128),param_2,param_3,param_4,_Memory);
  if (iVar1 == 0) {
    uVar2 = FUN_180012a40(param_1 + 8,(byte)param_3);
    FUN_1800150c0(param_1,_Memory,(ulonglong)uVar2,param_5);
    free(_Memory);
    iVar1 = 0;
  }
  else {
    free(_Memory);
  }
  return iVar1;
}



void FUN_1800165a0(longlong *param_1,undefined4 param_2,undefined8 param_3)

{
  (**(code **)(*param_1 + 0x10))(param_1,0,0,param_2,param_3);
  return;
}



undefined4
FUN_1800165c0(longlong *param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5,
             longlong param_6,ulonglong param_7)

{
  undefined4 uVar1;
  ulonglong uVar2;
  
  if (param_6 == 0) {
    uVar1 = 2;
  }
  else {
    uVar2 = FUN_180012a30((longlong)(param_1 + 1),param_3);
    if ((param_7 == 0) || (uVar2 <= param_7)) {
      if (param_7 != 0) {
        uVar2 = param_7;
      }
      if (param_4 < param_5) {
        do {
          (**(code **)(*param_1 + 0x10))(param_1,param_2,param_3,param_4,param_6);
          param_6 = param_6 + uVar2;
          param_4 = param_4 + 1;
        } while (param_4 < param_5);
      }
      uVar1 = 0;
    }
    else {
      uVar1 = 7;
    }
  }
  return uVar1;
}



void FUN_180016680(longlong *param_1,undefined4 param_2,undefined4 param_3,undefined8 param_4,
                  undefined8 param_5)

{
  (**(code **)(*param_1 + 0x20))(param_1,0,0,param_2,param_3,param_4,param_5);
  return;
}



void FUN_1800166b0(longlong param_1,longlong *param_2,Enum param_3,ulonglong param_4,short **param_5
                  ,void **param_6,undefined param_7)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  uint uVar5;
  undefined4 uVar6;
  longlong lVar7;
  undefined8 *puVar8;
  uint uVar9;
  short *psVar10;
  undefined auStackY_1b8 [32];
  undefined **local_168 [20];
  undefined local_c8 [128];
  ulonglong local_48;
  
  local_48 = DAT_180065150 ^ (ulonglong)auStackY_1b8;
  psVar10 = (short *)(param_4 & 0xffffffff);
  *(Enum *)(param_1 + 0x144) = param_3;
  *(undefined *)(param_1 + 0x148) = param_7;
  if (param_2 != (longlong *)0x0) {
    lVar7 = (**(code **)(*param_2 + 0x30))(param_2);
    iVar2 = FUN_1800128d0(lVar7);
    cVar1 = FUN_180016870(iVar2,param_3);
    if (cVar1 != '\0') {
      lVar7 = (**(code **)(*param_2 + 0x30))(param_2);
      uVar3 = FUN_180012a60(lVar7);
      uVar9 = (uint)psVar10;
      uVar5 = uVar9;
      if (uVar9 < uVar3) {
        uVar5 = uVar3;
      }
      if ((((param_5[2] == psVar10) && (cVar1 = FUN_180014eb0(param_5,uVar5), cVar1 != '\0')) &&
          (FUN_180016c40(param_5,param_1 + 0x130), psVar10 <= param_6[2])) &&
         (cVar1 = FUN_180014c90(param_6,uVar9), cVar1 != '\0')) {
        FUN_180016960(param_6,param_1 + 0x140);
        *(longlong **)(param_1 + 0x128) = param_2;
        lVar7 = (**(code **)(*param_2 + 0x30))(param_2);
        uVar4 = FUN_180012a80(lVar7);
        uVar5 = FUN_180012a70(lVar7);
        uVar6 = FUN_180012a00(lVar7);
        uVar3 = FUN_180012ac0(lVar7);
        puVar8 = FUN_180012690(local_168,uVar3,uVar6,uVar5,uVar4,param_3,uVar9);
        FUN_180014be0(param_1 + 8,(longlong)puVar8);
        local_168[0] = Graphine::Grim::Spec::vftable;
        _eh_vector_destructor_iterator_(local_c8,0x20,4,FUN_180010f50);
      }
    }
  }
  __security_check_cookie(local_48 ^ (ulonglong)auStackY_1b8);
  return;
}



void FUN_180016870(int param_1,int param_2)

{
  ulonglong uVar1;
  int local_78 [24];
  ulonglong local_18;
  
  local_18 = DAT_180065150 ^ (ulonglong)local_78;
  if (param_1 != param_2) {
    uVar1 = 0;
    local_78[0] = 0;
    local_78[1] = 4;
    local_78[2] = 0;
    local_78[3] = 3;
    local_78[4] = 1;
    local_78[5] = 0;
    local_78[6] = 1;
    local_78[7] = 4;
    local_78[8] = 1;
    local_78[9] = 3;
    local_78[10] = 2;
    local_78[11] = 0;
    local_78[12] = 2;
    local_78[13] = 4;
    local_78[14] = 2;
    local_78[15] = 3;
    local_78[16] = 4;
    local_78[17] = 0;
    local_78[18] = 4;
    local_78[19] = 3;
    local_78[20] = 3;
    local_78[21] = 0;
    local_78[22] = 3;
    local_78[23] = 4;
    while ((param_1 != local_78[uVar1 * 2] || (param_2 != local_78[uVar1 * 2 + 1]))) {
      uVar1 = uVar1 + 1;
      if (0xb < uVar1) {
        __security_check_cookie(local_18 ^ (ulonglong)local_78);
        return;
      }
    }
  }
  __security_check_cookie(local_18 ^ (ulonglong)local_78);
  return;
}



ulonglong FUN_180016920(longlong param_1)

{
  int iVar1;
  int iVar2;
  longlong lVar3;
  undefined4 extraout_var;
  undefined4 extraout_var_00;
  
  lVar3 = (**(code **)(**(longlong **)(param_1 + 0x128) + 0x30))();
  iVar1 = FUN_180012aa0(lVar3);
  iVar2 = FUN_180012aa0(param_1 + 8);
  return CONCAT44(extraout_var_00,iVar2) & 0xffffffffffffff00 |
         (ulonglong)(CONCAT44(extraout_var_00,iVar2) < CONCAT44(extraout_var,iVar1));
}



void FUN_180016960(void **param_1,longlong param_2)

{
  short **ppsVar1;
  short *psVar2;
  short **ppsVar3;
  void *_Memory;
  void *pvVar4;
  ushort *puVar5;
  void *pvVar6;
  int iVar7;
  uint uVar8;
  short *psVar9;
  ushort *puVar10;
  bool bVar11;
  undefined auStack_c8 [32];
  undefined8 local_a8;
  byte local_a0;
  undefined uStack_9f;
  undefined6 uStack_9e;
  short *local_90;
  ulonglong local_88;
  ushort local_80;
  undefined6 uStack_7e;
  undefined8 local_70;
  ulonglong local_68;
  byte local_60;
  undefined uStack_5f;
  undefined6 uStack_5e;
  undefined8 local_50;
  ulonglong local_48;
  ulonglong local_40;
  
  local_a8 = 0xfffffffffffffffe;
  local_40 = DAT_180065150 ^ (ulonglong)auStack_c8;
  local_48 = 7;
  pvVar6 = (void *)0x0;
  local_50 = 0;
  local_60 = 0;
  uStack_5f = 0;
  FUN_180011740((void **)&local_60,(void **)&DAT_18001c648,(void *)0x0);
  if (param_1[2] != (void *)0x0) {
    do {
      local_88 = 7;
      local_90 = (short *)0x0;
      local_a0 = 0;
      uStack_9f = 0;
      FUN_180011740((void **)&local_a0,(void **)&DAT_18001c650,(void *)0x1);
      ppsVar3 = (short **)FUN_180016fe0(param_1,(void **)&local_80,pvVar6,(void *)0x1);
      puVar10 = (ushort *)CONCAT62(uStack_9e,CONCAT11(uStack_9f,local_a0));
      puVar5 = (ushort *)&local_a0;
      if (7 < local_88) {
        puVar5 = puVar10;
      }
      ppsVar1 = ppsVar3 + 2;
      if ((short *)0x7 < ppsVar3[3]) {
        ppsVar3 = (short **)*ppsVar3;
      }
      psVar2 = *ppsVar1;
      psVar9 = local_90;
      if (psVar2 < local_90) {
        psVar9 = psVar2;
      }
      for (; iVar7 = 0, psVar9 != (short *)0x0; psVar9 = (short *)((longlong)psVar9 + -1)) {
        if (*(ushort *)ppsVar3 != *puVar5) {
          iVar7 = 1;
          if (*(ushort *)ppsVar3 < *puVar5) {
            iVar7 = -1;
          }
          break;
        }
        ppsVar3 = (short **)((longlong)ppsVar3 + 2);
        puVar5 = puVar5 + 1;
      }
      bVar11 = iVar7 == 0;
      if (bVar11) {
        if (psVar2 < local_90) {
          uVar8 = 0xffffffff;
        }
        else {
          uVar8 = (uint)(local_90 < psVar2);
        }
        bVar11 = uVar8 == 0;
      }
      *(bool *)(param_2 + (longlong)pvVar6) = bVar11;
      if (7 < local_68) {
        pvVar4 = (void *)CONCAT62(uStack_7e,local_80);
        if (0x7fffffffffffffff < local_68 + 1) {
                    // WARNING: Subroutine does not return
          _invalid_parameter_noinfo_noreturn();
        }
        _Memory = pvVar4;
        if (0xfff < (local_68 + 1) * 2) {
          if ((local_80 & 0x1f) != 0) {
                    // WARNING: Subroutine does not return
            _invalid_parameter_noinfo_noreturn();
          }
          _Memory = *(void **)((longlong)pvVar4 - 8);
          if (pvVar4 <= _Memory) {
                    // WARNING: Subroutine does not return
            _invalid_parameter_noinfo_noreturn();
          }
          if ((ulonglong)((longlong)pvVar4 - (longlong)_Memory) < 8) {
                    // WARNING: Subroutine does not return
            _invalid_parameter_noinfo_noreturn();
          }
          if (0x27 < (ulonglong)((longlong)pvVar4 - (longlong)_Memory)) {
                    // WARNING: Subroutine does not return
            _invalid_parameter_noinfo_noreturn();
          }
        }
        free(_Memory);
        puVar10 = (ushort *)CONCAT62(uStack_9e,CONCAT11(uStack_9f,local_a0));
      }
      local_68 = 7;
      local_70 = 0;
      local_80 = 0;
      if (7 < local_88) {
        if (0x7fffffffffffffff < local_88 + 1) {
                    // WARNING: Subroutine does not return
          _invalid_parameter_noinfo_noreturn();
        }
        puVar5 = puVar10;
        if (0xfff < (local_88 + 1) * 2) {
          if ((local_a0 & 0x1f) != 0) {
                    // WARNING: Subroutine does not return
            _invalid_parameter_noinfo_noreturn();
          }
          puVar5 = *(ushort **)(puVar10 + -4);
          if (puVar10 <= puVar5) {
                    // WARNING: Subroutine does not return
            _invalid_parameter_noinfo_noreturn();
          }
          if ((ulonglong)((longlong)puVar10 - (longlong)puVar5) < 8) {
                    // WARNING: Subroutine does not return
            _invalid_parameter_noinfo_noreturn();
          }
          if (0x27 < (ulonglong)((longlong)puVar10 - (longlong)puVar5)) {
                    // WARNING: Subroutine does not return
            _invalid_parameter_noinfo_noreturn();
          }
        }
        free(puVar5);
      }
      pvVar6 = (void *)((longlong)pvVar6 + 1);
    } while (pvVar6 < param_1[2]);
  }
  if (7 < local_48) {
    pvVar6 = (void *)CONCAT62(uStack_5e,CONCAT11(uStack_5f,local_60));
    if (0x7fffffffffffffff < local_48 + 1) {
                    // WARNING: Subroutine does not return
      _invalid_parameter_noinfo_noreturn();
    }
    pvVar4 = pvVar6;
    if (0xfff < (local_48 + 1) * 2) {
      if ((local_60 & 0x1f) != 0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      pvVar4 = *(void **)((longlong)pvVar6 - 8);
      if (pvVar6 <= pvVar4) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if ((ulonglong)((longlong)pvVar6 - (longlong)pvVar4) < 8) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if (0x27 < (ulonglong)((longlong)pvVar6 - (longlong)pvVar4)) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
    }
    free(pvVar4);
  }
  __security_check_cookie(local_40 ^ (ulonglong)auStack_c8);
  return;
}



// WARNING: Type propagation algorithm not settling
// WARNING: Could not reconcile some variable overlaps

void FUN_180016c40(undefined8 *param_1,longlong param_2)

{
  void *pvVar1;
  code *pcVar2;
  undefined2 *puVar3;
  byte *pbVar4;
  undefined8 *puVar5;
  longlong lVar6;
  void *_Memory;
  ulonglong uVar7;
  uint uVar8;
  undefined auStack_88 [32];
  undefined8 local_68;
  undefined8 local_60;
  void *local_50;
  void *local_48;
  ulonglong local_40;
  ulonglong uVar9;
  
  local_68 = 0xfffffffffffffffe;
  local_40 = DAT_180065150 ^ (ulonglong)auStack_88;
  local_48 = (void *)0x7;
  uVar7 = 0;
  local_50 = (void *)0x0;
  local_60._0_1_ = 0;
  local_60._1_1_ = 0;
  FUN_180011740((void **)&local_60,(void **)&DAT_18001c648,(void *)0x0);
  uVar9 = uVar7;
  do {
    if (~(ulonglong)local_50 < 2) {
      std::_Xlength_error("string too long");
      goto LAB_180016e1f;
    }
    pvVar1 = (void *)((longlong)local_50 + 1);
    if ((void *)0x7ffffffffffffffe < pvVar1) {
      std::_Xlength_error("string too long");
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    if (local_48 < pvVar1) {
      FUN_180011190((void **)&local_60,pvVar1,local_50);
LAB_180016d0c:
      if (pvVar1 != (void *)0x0) goto LAB_180016d19;
    }
    else {
      if (pvVar1 == (void *)0x0) {
        local_50 = (void *)0x0;
        puVar3 = (undefined2 *)&local_60;
        if ((void *)0x7 < local_48) {
          puVar3 = (undefined2 *)CONCAT62(local_60._2_6_,CONCAT11(local_60._1_1_,(byte)local_60));
        }
        *puVar3 = 0;
        goto LAB_180016d0c;
      }
LAB_180016d19:
      pbVar4 = (byte *)&local_60;
      if ((void *)0x7 < local_48) {
        pbVar4 = (byte *)CONCAT62(local_60._2_6_,CONCAT11(local_60._1_1_,(byte)local_60));
      }
      *(short *)(pbVar4 + (longlong)local_50 * 2) = (short)uVar9 + 0x30;
      pbVar4 = (byte *)&local_60;
      if ((void *)0x7 < local_48) {
        pbVar4 = (byte *)CONCAT62(local_60._2_6_,CONCAT11(local_60._1_1_,(byte)local_60));
      }
      local_50 = pvVar1;
      *(undefined2 *)(pbVar4 + (longlong)pvVar1 * 2) = 0;
    }
    pvVar1 = local_48;
    uVar8 = (int)uVar9 + 1;
    uVar9 = (ulonglong)uVar8;
  } while ((int)uVar8 < 4);
  if (param_1[2] != 0) {
    do {
      puVar5 = param_1;
      if (7 < (ulonglong)param_1[3]) {
        puVar5 = (undefined8 *)*param_1;
      }
      lVar6 = FUN_180016ee0(&local_60,*(ushort *)((longlong)puVar5 + uVar7 * 2),0);
      *(int *)(param_2 + uVar7 * 4) = (int)lVar6;
      uVar7 = uVar7 + 1;
    } while (uVar7 < (ulonglong)param_1[2]);
  }
  if ((void *)0x7 < pvVar1) {
    uVar9 = (longlong)pvVar1 + 1;
    pvVar1 = (void *)CONCAT62(local_60._2_6_,CONCAT11(local_60._1_1_,(byte)local_60));
    if (0x7fffffffffffffff < uVar9) {
                    // WARNING: Subroutine does not return
      _invalid_parameter_noinfo_noreturn();
    }
    _Memory = pvVar1;
    if (0xfff < uVar9 * 2) {
      if (((byte)local_60 & 0x1f) != 0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      _Memory = *(void **)((longlong)pvVar1 - 8);
      if (pvVar1 <= _Memory) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if ((ulonglong)((longlong)pvVar1 - (longlong)_Memory) < 8) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if (0x27 < (ulonglong)((longlong)pvVar1 - (longlong)_Memory)) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
    }
    free(_Memory);
  }
LAB_180016e1f:
  __security_check_cookie(local_40 ^ (ulonglong)auStack_88);
  return;
}



uint FUN_180016e50(ushort *param_1,ulonglong param_2,ushort *param_3,ulonglong param_4)

{
  uint uVar1;
  ulonglong uVar2;
  
  uVar2 = param_4;
  if (param_2 < param_4) {
    uVar2 = param_2;
  }
  do {
    if (uVar2 == 0) {
      uVar1 = 0;
LAB_180016e75:
      if (uVar1 != 0) {
        return uVar1;
      }
      if (param_4 <= param_2) {
        return (uint)(param_4 < param_2);
      }
      return 0xffffffff;
    }
    if (*param_1 != *param_3) {
      uVar1 = 1;
      if (*param_1 < *param_3) {
        uVar1 = 0xffffffff;
      }
      goto LAB_180016e75;
    }
    param_1 = param_1 + 1;
    param_3 = param_3 + 1;
    uVar2 = uVar2 - 1;
  } while( true );
}



longlong FUN_180016ee0(undefined8 *param_1,ushort param_2,ulonglong param_3)

{
  undefined8 *puVar1;
  ushort *puVar2;
  int iVar3;
  ushort *puVar4;
  ushort *puVar5;
  ushort *puVar6;
  longlong lVar7;
  longlong lVar8;
  ushort local_res10 [4];
  
  local_res10[0] = param_2;
  if (((ulonglong)param_1[2] <= param_3) || (lVar7 = param_1[2] - param_3, lVar7 == 0)) {
    return -1;
  }
  puVar1 = param_1;
  if (7 < (ulonglong)param_1[3]) {
    puVar1 = (undefined8 *)*param_1;
  }
  puVar2 = (ushort *)((longlong)puVar1 + param_3 * 2);
  lVar8 = lVar7;
  puVar4 = puVar2;
  do {
    while (lVar7 == 0) {
      puVar2 = (ushort *)0x0;
LAB_180016f52:
      if (puVar2 == (ushort *)0x0) {
        return -1;
      }
      lVar7 = 1;
      puVar5 = local_res10;
      puVar6 = puVar2;
      while (*puVar6 == *puVar5) {
        puVar6 = puVar6 + 1;
        puVar5 = puVar5 + 1;
        lVar7 = lVar7 + -1;
        if (lVar7 == 0) goto LAB_180016f7c;
      }
      iVar3 = 1;
      if (*puVar6 < *puVar5) {
        iVar3 = -1;
      }
      if (iVar3 == 0) {
LAB_180016f7c:
        if (7 < (ulonglong)param_1[3]) {
          param_1 = (undefined8 *)*param_1;
        }
        return (longlong)puVar2 - (longlong)param_1 >> 1;
      }
      lVar7 = (longlong)puVar2 - (longlong)puVar4;
      puVar2 = puVar2 + 1;
      lVar7 = lVar8 + (-1 - (lVar7 >> 1));
      lVar8 = lVar7;
      puVar4 = puVar2;
    }
    if (*puVar2 == param_2) goto LAB_180016f52;
    puVar2 = puVar2 + 1;
    lVar7 = lVar7 + -1;
  } while( true );
}



void ** FUN_180016fe0(void **param_1,void **param_2,void *param_3,void *param_4)

{
  param_2[3] = (void *)0x7;
  param_2[2] = (void *)0x0;
  *(undefined2 *)param_2 = 0;
  FUN_180011600(param_2,param_1,param_3,param_4);
  return param_2;
}



void FUN_180017020(undefined8 *param_1)

{
  *param_1 = Graphine::Grim::IConverter::vftable;
  return;
}



undefined8 * FUN_180017030(undefined8 *param_1,uint param_2)

{
  *param_1 = Graphine::Grim::Converter::vftable;
  param_1[1] = Graphine::Grim::Spec::vftable;
  _eh_vector_destructor_iterator_(param_1 + 0x15,0x20,4,FUN_180010f50);
  *param_1 = Graphine::Grim::IConverter::vftable;
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined8 * FUN_1800170b0(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = Graphine::Grim::IConverter::vftable;
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined8 FUN_1800170e0(undefined8 *param_1)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)operator_new(0x10);
  if (puVar1 != (undefined8 *)0x0) {
    puVar1 = FUN_180017240(puVar1);
  }
  *param_1 = puVar1;
  return 0;
}



int FUN_180017120(undefined8 param_1,undefined4 param_2,undefined4 param_3,undefined8 param_4,
                 undefined8 param_5,undefined param_6,longlong **param_7)

{
  int iVar1;
  longlong *_Dst;
  
  _Dst = (longlong *)operator_new(0x150);
  if (_Dst == (longlong *)0x0) {
    _Dst = (longlong *)0x0;
  }
  else {
    memset(_Dst,0,0x150);
    *_Dst = (longlong)Graphine::Grim::Converter::vftable;
    FUN_1800127a0(_Dst + 1);
  }
  iVar1 = (**(code **)(*_Dst + 0x40))(_Dst,param_1,param_2,param_3,param_4,param_5,param_6);
  if (iVar1 == 0) {
    *param_7 = _Dst;
    iVar1 = 0;
  }
  else {
    (**(code **)*_Dst)(_Dst,1);
  }
  return iVar1;
}



undefined8 FUN_180017200(void)

{
  return 0xd;
}



undefined * FUN_180017210(uint param_1)

{
  if (param_1 < 0xd) {
    return (&PTR_DAT_1800650e0)[(int)param_1];
  }
  return (undefined *)0x0;
}



void thunk_FUN_180016870(int param_1,int param_2)

{
  ulonglong uVar1;
  int aiStack_78 [24];
  ulonglong uStack_18;
  
  uStack_18 = DAT_180065150 ^ (ulonglong)aiStack_78;
  if (param_1 != param_2) {
    uVar1 = 0;
    aiStack_78[0] = 0;
    aiStack_78[1] = 4;
    aiStack_78[2] = 0;
    aiStack_78[3] = 3;
    aiStack_78[4] = 1;
    aiStack_78[5] = 0;
    aiStack_78[6] = 1;
    aiStack_78[7] = 4;
    aiStack_78[8] = 1;
    aiStack_78[9] = 3;
    aiStack_78[10] = 2;
    aiStack_78[11] = 0;
    aiStack_78[12] = 2;
    aiStack_78[13] = 4;
    aiStack_78[14] = 2;
    aiStack_78[15] = 3;
    aiStack_78[16] = 4;
    aiStack_78[17] = 0;
    aiStack_78[18] = 4;
    aiStack_78[19] = 3;
    aiStack_78[20] = 3;
    aiStack_78[21] = 0;
    aiStack_78[22] = 3;
    aiStack_78[23] = 4;
    while ((param_1 != aiStack_78[uVar1 * 2] || (param_2 != aiStack_78[uVar1 * 2 + 1]))) {
      uVar1 = uVar1 + 1;
      if (0xb < uVar1) {
        __security_check_cookie(uStack_18 ^ (ulonglong)aiStack_78);
        return;
      }
    }
  }
  __security_check_cookie(uStack_18 ^ (ulonglong)aiStack_78);
  return;
}



undefined8 * FUN_180017240(undefined8 *param_1)

{
  param_1[1] = 0;
  *param_1 = Graphine::Grim::MixedProviderImage::vftable;
  return param_1;
}



void FUN_180017260(undefined8 *param_1)

{
  *param_1 = Graphine::Grim::IImage::vftable;
  return;
}



undefined8 * FUN_180017270(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = Graphine::Grim::IImage::vftable;
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined8 *
FUN_1800172a0(undefined8 *param_1,ulonglong param_2,undefined8 param_3,undefined8 param_4)

{
  undefined8 *puVar1;
  
  *param_1 = Graphine::Grim::MixedProviderImage::vftable;
  if ((longlong *)param_1[1] != (longlong *)0x0) {
    (**(code **)(*(longlong *)param_1[1] + 0x38))();
    puVar1 = (undefined8 *)param_1[1];
    if (puVar1 != (undefined8 *)0x0) {
      (**(code **)*puVar1)(puVar1,1);
    }
    param_1[1] = 0;
  }
  *param_1 = Graphine::Grim::IImage::vftable;
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_180017320(longlong param_1)

{
                    // WARNING: Could not recover jumptable at 0x000180017327. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)(param_1 + 8) + 0x38))();
  return;
}



void FUN_180017330(longlong param_1)

{
                    // WARNING: Could not recover jumptable at 0x000180017337. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)(param_1 + 8) + 0x20))();
  return;
}



void FUN_180017340(longlong param_1)

{
                    // WARNING: Could not recover jumptable at 0x000180017347. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)(param_1 + 8) + 0x28))();
  return;
}



void FUN_180017350(longlong param_1)

{
                    // WARNING: Could not recover jumptable at 0x000180017357. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)(param_1 + 8) + 0x60))();
  return;
}



void FUN_180017360(longlong param_1)

{
                    // WARNING: Could not recover jumptable at 0x000180017367. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)(param_1 + 8) + 0x68))();
  return;
}



void FUN_180017370(longlong param_1)

{
                    // WARNING: Could not recover jumptable at 0x000180017377. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)(param_1 + 8) + 0x40))();
  return;
}



void FUN_180017380(longlong param_1)

{
                    // WARNING: Could not recover jumptable at 0x000180017387. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)(param_1 + 8) + 0x48))();
  return;
}



void FUN_180017390(longlong param_1)

{
                    // WARNING: Could not recover jumptable at 0x000180017397. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)(param_1 + 8) + 0x50))();
  return;
}



void FUN_1800173a0(longlong param_1)

{
                    // WARNING: Could not recover jumptable at 0x0001800173a7. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)(param_1 + 8) + 0x58))();
  return;
}



void FUN_1800173b0(longlong param_1)

{
                    // WARNING: Could not recover jumptable at 0x0001800173b7. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)(param_1 + 8) + 0x30))();
  return;
}



void FUN_1800173c0(longlong param_1,undefined8 *param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  undefined8 *puVar2;
  longlong *plVar3;
  
  puVar2 = param_2;
  if (7 < (ulonglong)param_2[3]) {
    puVar2 = (undefined8 *)*param_2;
  }
  iVar1 = FreeImage_GetFileTypeU(puVar2,0,param_3,param_4,0xfffffffffffffffe);
  if (iVar1 == 0x18) {
    puVar2 = (undefined8 *)operator_new(0x158);
    if (puVar2 == (undefined8 *)0x0) {
      plVar3 = (longlong *)0x0;
    }
    else {
      plVar3 = FUN_180018720(puVar2);
    }
  }
  else {
    puVar2 = *(undefined8 **)(param_1 + 8);
    if (puVar2 != (undefined8 *)0x0) {
      (**(code **)*puVar2)(puVar2,1);
    }
    puVar2 = (undefined8 *)operator_new(0x160);
    if (puVar2 == (undefined8 *)0x0) {
      plVar3 = (longlong *)0x0;
    }
    else {
      plVar3 = FUN_180017570(puVar2);
    }
  }
  *(longlong **)(param_1 + 8) = plVar3;
                    // WARNING: Could not recover jumptable at 0x000180017465. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*plVar3 + 0x10))(plVar3,param_2);
  return;
}



undefined8 FUN_180017470(longlong param_1,undefined8 param_2,ulonglong param_3,undefined8 param_4)

{
  int iVar1;
  longlong lVar2;
  undefined8 *puVar3;
  longlong *plVar4;
  undefined8 uVar5;
  longlong *plVar6;
  
  lVar2 = FreeImage_OpenMemory(param_2,param_3 & 0xffffffff,param_3,param_4,0xfffffffffffffffe);
  if (lVar2 == 0) {
    uVar5 = 2;
  }
  else {
    iVar1 = FreeImage_GetFileTypeFromMemory(lVar2,0);
    FreeImage_CloseMemory(lVar2);
    plVar6 = (longlong *)0x0;
    if (iVar1 == 0x18) {
      puVar3 = (undefined8 *)operator_new(0x158);
      plVar4 = plVar6;
      if (puVar3 != (undefined8 *)0x0) {
        plVar4 = FUN_180018720(puVar3);
      }
      *(longlong **)(param_1 + 8) = plVar4;
      uVar5 = (**(code **)(*plVar4 + 8))(plVar4,param_2,param_3);
      if ((int)uVar5 == 0) {
        return uVar5;
      }
    }
    puVar3 = *(undefined8 **)(param_1 + 8);
    if (puVar3 != (undefined8 *)0x0) {
      (**(code **)*puVar3)(puVar3,1);
    }
    puVar3 = (undefined8 *)operator_new(0x160);
    if (puVar3 != (undefined8 *)0x0) {
      plVar6 = FUN_180017570(puVar3);
    }
    *(longlong **)(param_1 + 8) = plVar6;
    uVar5 = (**(code **)(*plVar6 + 8))(plVar6,param_2,param_3);
  }
  return uVar5;
}



void FUN_180017560(longlong param_1)

{
                    // WARNING: Could not recover jumptable at 0x000180017567. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)(param_1 + 8) + 0x18))();
  return;
}



undefined8 * FUN_180017570(undefined8 *param_1)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  
  *param_1 = Graphine::Grim::FreeImageImplementation::vftable;
  FUN_1800127a0(param_1 + 1);
  puVar1 = param_1 + 0x26;
  param_1[0x29] = 7;
  param_1[0x28] = 0;
  puVar2 = puVar1;
  if (7 < (ulonglong)param_1[0x29]) {
    puVar2 = (undefined8 *)*puVar1;
  }
  *(undefined2 *)puVar2 = 0;
  param_1[0x2b] = 0;
  param_1[0x25] = 0;
  param_1[0x28] = 0;
  if (7 < (ulonglong)param_1[0x29]) {
    puVar1 = (undefined8 *)*puVar1;
  }
  *(undefined2 *)puVar1 = 0;
  *(undefined2 *)(param_1 + 0x2a) = 0;
  return param_1;
}



void FUN_1800175f0(undefined8 *param_1)

{
  void **ppvVar1;
  
  *param_1 = Graphine::Grim::FreeImageImplementation::vftable;
  if (param_1[0x2b] != 0) {
    FUN_1800176e0((longlong)param_1);
  }
  ppvVar1 = (void **)(param_1 + 0x26);
  if (7 < (ulonglong)param_1[0x29]) {
    FUN_180011890(ppvVar1,*ppvVar1,param_1[0x29] + 1);
  }
  param_1[0x29] = 7;
  param_1[0x28] = 0;
  if (7 < (ulonglong)param_1[0x29]) {
    ppvVar1 = (void **)*ppvVar1;
  }
  *(undefined2 *)ppvVar1 = 0;
  param_1[1] = Graphine::Grim::Spec::vftable;
  _eh_vector_destructor_iterator_(param_1 + 0x15,0x20,4,FUN_180010f50);
  *param_1 = Graphine::Grim::IImage::vftable;
  return;
}



undefined8 * FUN_1800176a0(undefined8 *param_1,uint param_2)

{
  FUN_1800175f0(param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined8 FUN_1800176e0(longlong param_1)

{
  undefined8 *puVar1;
  
  if (*(longlong *)(param_1 + 0x158) != 0) {
    FreeImage_Unload();
    *(undefined8 *)(param_1 + 0x158) = 0;
  }
  if (*(longlong *)(param_1 + 0x128) != 0) {
    FreeImage_CloseMemory();
    *(undefined8 *)(param_1 + 0x128) = 0;
  }
  puVar1 = (undefined8 *)(param_1 + 0x130);
  *(undefined8 *)(param_1 + 0x140) = 0;
  if (7 < *(ulonglong *)(param_1 + 0x148)) {
    puVar1 = (undefined8 *)*puVar1;
  }
  *(undefined2 *)puVar1 = 0;
  return 0;
}



undefined8 FUN_180017750(longlong param_1)

{
  if (*(longlong *)(param_1 + 0x158) == 0) {
    return 5;
  }
  *(bool *)(param_1 + 0x151) = *(char *)(param_1 + 0x151) == '\0';
  return 0;
}



undefined8 FUN_180017780(longlong param_1)

{
  if (*(longlong *)(param_1 + 0x158) == 0) {
    return 5;
  }
  *(bool *)(param_1 + 0x150) = *(char *)(param_1 + 0x150) == '\0';
  return 0;
}



undefined8
FUN_1800177b0(longlong *param_1,int param_2,int param_3,undefined8 param_4,undefined8 param_5)

{
  undefined8 uVar1;
  
  if ((param_2 == 0) && (param_3 == 0)) {
                    // WARNING: Could not recover jumptable at 0x0001800177c4. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar1 = (**(code **)(*param_1 + 0x68))(param_1,param_4,param_5);
    return uVar1;
  }
  return 7;
}



undefined8 FUN_1800177d0(longlong *param_1,longlong param_2,undefined8 param_3)

{
  longlong lVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  
  if (param_1[0x2b] == 0) {
    return 5;
  }
  if (param_2 == 0) {
    return 7;
  }
  lVar1 = *param_1;
  uVar2 = FUN_180012a00((longlong)(param_1 + 1));
  uVar3 = (**(code **)(lVar1 + 0x58))(param_1,0,uVar2,param_2,param_3);
  return uVar3;
}



undefined8
FUN_180017860(longlong *param_1,int param_2,int param_3,undefined4 param_4,undefined8 param_5)

{
  undefined8 uVar1;
  
  if ((param_2 == 0) && (param_3 == 0)) {
                    // WARNING: Could not recover jumptable at 0x000180017874. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar1 = (**(code **)(*param_1 + 0x48))(param_1,param_4,param_5);
    return uVar1;
  }
  return 7;
}



int FUN_180017880(longlong param_1,uint param_2,void *param_3)

{
  int iVar1;
  uint uVar2;
  void *_Src;
  size_t sVar3;
  undefined4 extraout_var;
  ulonglong uVar4;
  ulonglong uVar5;
  void *_Dst;
  
  if (*(longlong *)(param_1 + 0x158) == 0) {
    return 5;
  }
  iVar1 = FreeImage_HasPixels();
  if ((iVar1 != 0) || (iVar1 = FUN_180018200(param_1), iVar1 == 0)) {
    uVar2 = FUN_180012a00(param_1 + 8);
    if (uVar2 < param_2) {
      return 6;
    }
    if (param_3 == (void *)0x0) {
      return 7;
    }
    if (*(char *)(param_1 + 0x150) != '\0') {
      iVar1 = FUN_180012a00(param_1 + 8);
      param_2 = (-1 - param_2) + iVar1;
    }
    _Src = (void *)FreeImage_GetScanLine(*(undefined8 *)(param_1 + 0x158),param_2);
    sVar3 = FUN_180012a90(param_1 + 8);
    if (*(char *)(param_1 + 0x151) == '\0') {
      memcpy(param_3,_Src,sVar3);
    }
    else {
      iVar1 = FUN_180012aa0(param_1 + 8);
      sVar3 = CONCAT44(extraout_var,iVar1);
      uVar2 = FUN_180012ac0(param_1 + 8);
      uVar4 = 0;
      uVar5 = uVar2 * sVar3;
      if (uVar5 != 0) {
        _Dst = (void *)((uVar5 - sVar3) + (longlong)param_3);
        do {
          memcpy(_Dst,(void *)(uVar4 + (longlong)_Src),sVar3);
          uVar4 = uVar4 + sVar3;
          _Dst = (void *)((longlong)_Dst - sVar3);
        } while (uVar4 < uVar5);
      }
    }
    iVar1 = 0;
  }
  return iVar1;
}



undefined8
FUN_1800179d0(longlong *param_1,int param_2,int param_3,undefined4 param_4,undefined8 param_5,
             undefined8 param_6,undefined8 param_7)

{
  undefined8 uVar1;
  
  if ((param_2 == 0) && (param_3 == 0)) {
                    // WARNING: Could not recover jumptable at 0x0001800179f6. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar1 = (**(code **)(*param_1 + 0x58))(param_1,param_4,(undefined4)param_5,param_6);
    return uVar1;
  }
  return 7;
}



int FUN_180017a00(longlong *param_1,uint param_2,uint param_3,longlong param_4,ulonglong param_5)

{
  int iVar1;
  uint uVar2;
  ulonglong uVar3;
  
  if (param_1[0x2b] == 0) {
    iVar1 = 5;
  }
  else {
    iVar1 = FreeImage_HasPixels();
    if ((iVar1 != 0) || (iVar1 = FUN_180018200((longlong)param_1), iVar1 == 0)) {
      uVar2 = FUN_180012a00((longlong)(param_1 + 1));
      if ((uVar2 < param_3) || (param_3 < param_2)) {
        iVar1 = 6;
      }
      else {
        uVar3 = FUN_180012a90((longlong)(param_1 + 1));
        if (((param_5 == 0) || (uVar3 <= param_5)) && (param_4 != 0)) {
          if (param_5 != 0) {
            uVar3 = param_5;
          }
          if (param_2 < param_3) {
            do {
              iVar1 = (**(code **)(*param_1 + 0x48))(param_1,param_2,param_4);
              param_4 = param_4 + uVar3;
              if (iVar1 != 0) {
                return iVar1;
              }
              param_2 = param_2 + 1;
            } while (param_2 < param_3);
          }
          iVar1 = 0;
        }
        else {
          iVar1 = 7;
        }
      }
    }
  }
  return iVar1;
}



longlong FUN_180017ae0(longlong param_1)

{
  return param_1 + 8;
}



void FUN_180017af0(longlong param_1)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 uVar5;
  undefined8 uVar6;
  longlong lVar7;
  undefined8 *puVar8;
  longlong **pplVar9;
  longlong **pplVar10;
  undefined auStackY_1c8 [32];
  undefined local_188;
  undefined8 local_178;
  undefined8 local_170;
  undefined8 local_160;
  undefined **local_158 [20];
  undefined local_b8 [128];
  ulonglong local_38;
  
  local_160 = 0xfffffffffffffffe;
  local_38 = DAT_180065150 ^ (ulonglong)auStackY_1c8;
  iVar1 = FreeImage_GetImageType(*(undefined8 *)(param_1 + 0x158));
  if (iVar1 != 0) {
    uVar2 = FreeImage_GetWidth(*(undefined8 *)(param_1 + 0x158));
    uVar3 = FreeImage_GetHeight(*(undefined8 *)(param_1 + 0x158));
    switch(iVar1) {
    case 1:
      iVar4 = FreeImage_GetBPP(*(undefined8 *)(param_1 + 0x158));
      if (iVar4 == 0x18) {
        puVar8 = FUN_180012690(local_158,uVar2,uVar3,1,1,0,3);
        FUN_180014be0(param_1 + 8,(longlong)puVar8);
        local_158[0] = Graphine::Grim::Spec::vftable;
        _eh_vector_destructor_iterator_(local_b8,0x20,4,FUN_180010f50);
      }
      else if (iVar4 == 0x20) {
        puVar8 = FUN_180012690(local_158,uVar2,uVar3,1,1,0,4);
        FUN_180014be0(param_1 + 8,(longlong)puVar8);
        local_158[0] = Graphine::Grim::Spec::vftable;
        _eh_vector_destructor_iterator_(local_b8,0x20,4,FUN_180010f50);
      }
      else {
        FreeImage_Unload(*(undefined8 *)(param_1 + 0x158));
        pplVar10 = (longlong **)(param_1 + 0x130);
        pplVar9 = pplVar10;
        if (7 < *(ulonglong *)(param_1 + 0x148)) {
          pplVar9 = (longlong **)*pplVar10;
        }
        uVar5 = FreeImage_GetFileTypeU(pplVar9,0);
        if (7 < *(ulonglong *)(param_1 + 0x148)) {
          pplVar10 = (longlong **)*pplVar10;
        }
        uVar6 = FreeImage_LoadU(uVar5,pplVar10,0);
        *(undefined8 *)(param_1 + 0x158) = uVar6;
        lVar7 = FreeImage_ConvertTo24Bits(uVar6);
        if (lVar7 == 0) goto LAB_18001819b;
        FreeImage_Unload(*(undefined8 *)(param_1 + 0x158));
        *(longlong *)(param_1 + 0x158) = lVar7;
        puVar8 = FUN_180012690(local_158,uVar2,uVar3,1,1,0,3);
        FUN_180014be0(param_1 + 8,(longlong)puVar8);
        local_158[0] = Graphine::Grim::Spec::vftable;
        _eh_vector_destructor_iterator_(local_b8,0x20,4,FUN_180010f50);
      }
      break;
    case 2:
      puVar8 = FUN_180012690(local_158,uVar2,uVar3,1,1,1,1);
      FUN_180014be0(param_1 + 8,(longlong)puVar8);
      local_158[0] = Graphine::Grim::Spec::vftable;
      _eh_vector_destructor_iterator_(local_b8,0x20,4,FUN_180010f50);
      break;
    default:
      goto LAB_18001819b;
    case 4:
      puVar8 = FUN_180012690(local_158,uVar2,uVar3,1,1,2,1);
      FUN_180014be0(param_1 + 8,(longlong)puVar8);
      local_158[0] = Graphine::Grim::Spec::vftable;
      _eh_vector_destructor_iterator_(local_b8,0x20,4,FUN_180010f50);
      break;
    case 6:
      puVar8 = FUN_180012690(local_158,uVar2,uVar3,1,1,3,1);
      FUN_180014be0(param_1 + 8,(longlong)puVar8);
      local_158[0] = Graphine::Grim::Spec::vftable;
      _eh_vector_destructor_iterator_(local_b8,0x20,4,FUN_180010f50);
      break;
    case 9:
      puVar8 = FUN_180012690(local_158,uVar2,uVar3,1,1,1,3);
      FUN_180014be0(param_1 + 8,(longlong)puVar8);
      local_158[0] = Graphine::Grim::Spec::vftable;
      _eh_vector_destructor_iterator_(local_b8,0x20,4,FUN_180010f50);
      break;
    case 10:
      puVar8 = FUN_180012690(local_158,uVar2,uVar3,1,1,1,4);
      FUN_180014be0(param_1 + 8,(longlong)puVar8);
      local_158[0] = Graphine::Grim::Spec::vftable;
      _eh_vector_destructor_iterator_(local_b8,0x20,4,FUN_180010f50);
      break;
    case 0xb:
      puVar8 = FUN_180012690(local_158,uVar2,uVar3,1,1,3,3);
      FUN_180014be0(param_1 + 8,(longlong)puVar8);
      local_158[0] = Graphine::Grim::Spec::vftable;
      _eh_vector_destructor_iterator_(local_b8,0x20,4,FUN_180010f50);
      break;
    case 0xc:
      puVar8 = FUN_180012690(local_158,uVar2,uVar3,1,1,3,4);
      FUN_180014be0(param_1 + 8,(longlong)puVar8);
      local_158[0] = Graphine::Grim::Spec::vftable;
      _eh_vector_destructor_iterator_(local_b8,0x20,4,FUN_180010f50);
    }
    lVar7 = param_1 + 8;
    local_170 = 0xf;
    local_178 = 0;
    local_188 = 0;
    FUN_1800114d0((ulonglong **)&local_188,(ulonglong **)&DAT_18001ca98,(ulonglong *)0x1);
    if (iVar1 == 1) {
      FUN_180012ad0(lVar7,(ulonglong **)&local_188,2);
      local_170 = 0xf;
      local_178 = 0;
      local_188 = 0;
      FUN_1800114d0((ulonglong **)&local_188,(ulonglong **)&DAT_18001ca9c,(ulonglong *)0x1);
      FUN_180012ad0(lVar7,(ulonglong **)&local_188,1);
      local_170 = 0xf;
      local_178 = 0;
      local_188 = 0;
      FUN_1800114d0((ulonglong **)&local_188,(ulonglong **)&DAT_18001caa0,(ulonglong *)0x1);
      iVar1 = 0;
    }
    else {
      FUN_180012ad0(lVar7,(ulonglong **)&local_188,0);
      local_170 = 0xf;
      local_178 = 0;
      local_188 = 0;
      FUN_1800114d0((ulonglong **)&local_188,(ulonglong **)&DAT_18001ca9c,(ulonglong *)0x1);
      FUN_180012ad0(lVar7,(ulonglong **)&local_188,1);
      local_170 = 0xf;
      local_178 = 0;
      local_188 = 0;
      FUN_1800114d0((ulonglong **)&local_188,(ulonglong **)&DAT_18001caa0,(ulonglong *)0x1);
      iVar1 = 2;
    }
    FUN_180012ad0(lVar7,(ulonglong **)&local_188,iVar1);
    local_170 = 0xf;
    local_178 = 0;
    local_188 = 0;
    FUN_1800114d0((ulonglong **)&local_188,(ulonglong **)&DAT_18001caa4,(ulonglong *)0x1);
    FUN_180012ad0(lVar7,(ulonglong **)&local_188,3);
  }
LAB_18001819b:
  __security_check_cookie(local_38 ^ (ulonglong)auStackY_1c8);
  return;
}



undefined4 FUN_180018200(longlong param_1)

{
  int iVar1;
  longlong lVar2;
  undefined8 uVar3;
  longlong **pplVar4;
  longlong **pplVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  
  if ((*(longlong *)(param_1 + 0x158) != 0) && (iVar1 = FreeImage_HasPixels(), iVar1 != 0)) {
    return 0;
  }
  if (*(longlong *)(param_1 + 0x158) != 0) {
    FreeImage_Unload();
    *(undefined8 *)(param_1 + 0x158) = 0;
  }
  uVar6 = 5;
  if (*(longlong *)(param_1 + 0x128) != 0) {
    iVar1 = FreeImage_GetFileTypeFromMemory(*(longlong *)(param_1 + 0x128),0);
    if (iVar1 == 2) {
      uVar3 = 2;
      iVar1 = 2;
    }
    else {
      uVar3 = 0;
    }
    lVar2 = FreeImage_LoadFromMemory(iVar1,*(undefined8 *)(param_1 + 0x128),uVar3);
    *(longlong *)(param_1 + 0x158) = lVar2;
    uVar6 = 2;
    if (lVar2 != 0) {
      uVar6 = 5;
    }
    goto LAB_18001833e;
  }
  if (*(longlong *)(param_1 + 0x140) == 0) goto LAB_18001833e;
  pplVar5 = (longlong **)(param_1 + 0x130);
  pplVar4 = pplVar5;
  if (7 < *(ulonglong *)(param_1 + 0x148)) {
    pplVar4 = (longlong **)*pplVar5;
  }
  iVar1 = FreeImage_GetFileTypeU(pplVar4,0);
  if (iVar1 == -1) {
    pplVar4 = pplVar5;
    if (7 < *(ulonglong *)(param_1 + 0x148)) {
      pplVar4 = (longlong **)*pplVar5;
    }
    iVar1 = FreeImage_GetFIFFromFilenameU(pplVar4);
  }
  if (iVar1 == 2) {
    if (7 < *(ulonglong *)(param_1 + 0x148)) {
      pplVar5 = (longlong **)*pplVar5;
    }
    uVar3 = 2;
    iVar1 = 2;
LAB_18001831a:
    uVar3 = FreeImage_LoadU(iVar1,pplVar5,uVar3);
    *(undefined8 *)(param_1 + 0x158) = uVar3;
  }
  else if (iVar1 != -1) {
    if (7 < *(ulonglong *)(param_1 + 0x148)) {
      pplVar5 = (longlong **)*pplVar5;
    }
    uVar3 = 0;
    goto LAB_18001831a;
  }
  uVar6 = 5;
  if (*(longlong *)(param_1 + 0x158) == 0) {
    uVar6 = 0xc;
  }
LAB_18001833e:
  uVar7 = 0;
  if (*(longlong *)(param_1 + 0x158) == 0) {
    uVar7 = uVar6;
  }
  return uVar7;
}



int FUN_180018370(longlong *param_1,void **param_2)

{
  int iVar1;
  int iVar2;
  longlong lVar3;
  void **ppvVar4;
  void **ppvVar5;
  FILE *local_res8;
  
  if (param_1[0x2b] != 0) {
    (**(code **)(*param_1 + 0x38))();
  }
  ppvVar5 = (void **)(param_1 + 0x26);
  if (ppvVar5 != param_2) {
    FUN_180011600(ppvVar5,param_2,(void *)0x0,(void *)0xffffffffffffffff);
  }
  *(undefined2 *)(param_1 + 0x2a) = 0;
  ppvVar4 = ppvVar5;
  if (7 < (ulonglong)param_1[0x29]) {
    ppvVar4 = (void **)*ppvVar5;
  }
  _wfopen_s(&local_res8,(wchar_t *)ppvVar4,L"rb");
  if (local_res8 == (FILE *)0x0) {
    return 1;
  }
  fclose(local_res8);
  ppvVar4 = ppvVar5;
  if (7 < (ulonglong)param_1[0x29]) {
    ppvVar4 = (void **)*ppvVar5;
  }
  iVar1 = FreeImage_GetFileTypeU(ppvVar4,0);
  if (iVar1 == -1) {
    ppvVar4 = ppvVar5;
    if (7 < (ulonglong)param_1[0x29]) {
      ppvVar4 = (void **)*ppvVar5;
    }
    iVar1 = FreeImage_GetFIFFromFilenameU(ppvVar4);
    if (iVar1 == -1) {
      return 3;
    }
  }
  iVar2 = FreeImage_FIFSupportsReading(iVar1);
  if (iVar2 == 0) {
    return 4;
  }
  iVar2 = FreeImage_FIFSupportsNoPixels(iVar1);
  if (iVar2 == 0) {
    iVar1 = FUN_180018200((longlong)param_1);
    if (iVar1 != 0) {
      return iVar1;
    }
  }
  else {
    if (7 < (ulonglong)param_1[0x29]) {
      ppvVar5 = (void **)*ppvVar5;
    }
    lVar3 = FreeImage_LoadU(iVar1,ppvVar5,0x8000);
    param_1[0x2b] = lVar3;
  }
  if (param_1[0x2b] != 0) {
    iVar1 = FUN_180017af0((longlong)param_1);
    if (iVar1 != 0) {
      (**(code **)(*param_1 + 0x38))(param_1);
      return iVar1;
    }
    return 0;
  }
  return 0xc;
}



int FUN_180018510(longlong *param_1,longlong param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  longlong lVar3;
  
  if (param_1[0x2b] != 0) {
    (**(code **)(*param_1 + 0x38))();
  }
  *(undefined2 *)(param_1 + 0x2a) = 0;
  if (param_2 == 0) {
    return 7;
  }
  lVar3 = FreeImage_OpenMemory(param_2,param_3);
  if (lVar3 != 0) {
    iVar1 = FreeImage_GetFileTypeFromMemory(lVar3,0);
    if (iVar1 == -1) {
      FreeImage_CloseMemory(lVar3);
      return 3;
    }
    iVar2 = FreeImage_FIFSupportsReading(iVar1);
    if (iVar2 == 0) {
      FreeImage_CloseMemory(lVar3);
      return 4;
    }
    iVar2 = FreeImage_FIFSupportsNoPixels(iVar1);
    if (iVar2 == 0) {
      iVar1 = FUN_180018200((longlong)param_1);
      if (iVar1 != 0) {
        return iVar1;
      }
    }
    else {
      lVar3 = FreeImage_LoadFromMemory(iVar1,lVar3,0x8000);
      param_1[0x2b] = lVar3;
    }
    if (param_1[0x2b] != 0) {
      iVar1 = FUN_180017af0((longlong)param_1);
      if (iVar1 == 0) {
        return 0;
      }
      (**(code **)(*param_1 + 0x38))(param_1);
      return iVar1;
    }
  }
  return 2;
}



int FUN_180018660(longlong param_1,int param_2,int param_3)

{
  int iVar1;
  longlong lVar2;
  
  iVar1 = FreeImage_GetWidth(*(undefined8 *)(param_1 + 0x158));
  if ((iVar1 != param_2) ||
     (iVar1 = FreeImage_GetHeight(*(undefined8 *)(param_1 + 0x158)), iVar1 != param_3)) {
    iVar1 = FreeImage_HasPixels(*(undefined8 *)(param_1 + 0x158));
    if ((iVar1 == 0) && (iVar1 = FUN_180018200(param_1), iVar1 != 0)) {
      return iVar1;
    }
    lVar2 = FreeImage_Rescale(*(undefined8 *)(param_1 + 0x158),param_2,param_3,1);
    if (lVar2 == 0) {
      return 4;
    }
    FreeImage_Unload(*(undefined8 *)(param_1 + 0x158));
    *(longlong *)(param_1 + 0x158) = lVar2;
    FUN_180017af0(param_1);
  }
  return 0;
}



undefined8 * FUN_180018720(undefined8 *param_1)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  
  *param_1 = Graphine::Grim::DirectXTexImplementation::vftable;
  FUN_1800127a0(param_1 + 1);
  puVar1 = param_1 + 0x25;
  param_1[0x28] = 7;
  param_1[0x27] = 0;
  puVar2 = puVar1;
  if (7 < (ulonglong)param_1[0x28]) {
    puVar2 = (undefined8 *)*puVar1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined2 *)(param_1 + 0x29) = 0;
  param_1[0x2a] = 0;
  param_1[0x27] = 0;
  if (7 < (ulonglong)param_1[0x28]) {
    puVar1 = (undefined8 *)*puVar1;
  }
  *(undefined2 *)puVar1 = 0;
  return param_1;
}



void FUN_1800187a0(undefined8 *param_1)

{
  void **ppvVar1;
  
  *param_1 = Graphine::Grim::DirectXTexImplementation::vftable;
  if (param_1[0x2a] != 0) {
    FUN_180018890((longlong)param_1);
  }
  ppvVar1 = (void **)(param_1 + 0x25);
  if (7 < (ulonglong)param_1[0x28]) {
    FUN_180011890(ppvVar1,*ppvVar1,param_1[0x28] + 1);
  }
  param_1[0x28] = 7;
  param_1[0x27] = 0;
  if (7 < (ulonglong)param_1[0x28]) {
    ppvVar1 = (void **)*ppvVar1;
  }
  *(undefined2 *)ppvVar1 = 0;
  param_1[1] = Graphine::Grim::Spec::vftable;
  _eh_vector_destructor_iterator_(param_1 + 0x15,0x20,4,FUN_180010f50);
  *param_1 = Graphine::Grim::IImage::vftable;
  return;
}



undefined8 * FUN_180018850(undefined8 *param_1,uint param_2)

{
  FUN_1800187a0(param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined8 FUN_180018890(longlong param_1)

{
  undefined8 *puVar1;
  
  puVar1 = *(undefined8 **)(param_1 + 0x150);
  if (puVar1 != (undefined8 *)0x0) {
    FUN_1800020c0(puVar1);
    free(puVar1);
    *(undefined8 *)(param_1 + 0x150) = 0;
  }
  puVar1 = (undefined8 *)(param_1 + 0x128);
  *(undefined8 *)(param_1 + 0x138) = 0;
  if (7 < *(ulonglong *)(param_1 + 0x140)) {
    puVar1 = (undefined8 *)*puVar1;
  }
  *(undefined2 *)puVar1 = 0;
  *(undefined2 *)(param_1 + 0x148) = 0;
  return 0;
}



ulonglong FUN_180018910(undefined4 param_1)

{
  switch(param_1) {
  case 2:
  case 6:
  case 10:
  case 0x10:
  case 0x1a:
  case 0x22:
  case 0x28:
  case 0x29:
  case 0x36:
    return 1;
  default:
    return 0;
  }
}



undefined8 FUN_180018980(undefined4 param_1,undefined8 *param_2)

{
  *param_2 = 0;
  switch(param_1) {
  case 1:
  case 2:
  case 3:
  case 4:
  case 9:
  case 10:
  case 0xb:
  case 0xc:
  case 0xd:
  case 0xe:
  case 0x17:
  case 0x18:
  case 0x19:
  case 0x1b:
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
  case 0x20:
    *param_2 = &DAT_18001cc38;
    return 0;
  case 5:
  case 6:
  case 7:
  case 8:
  case 0x1a:
    *param_2 = &DAT_18001cc40;
    return 0;
  case 0xf:
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x21:
  case 0x22:
  case 0x23:
  case 0x24:
  case 0x25:
  case 0x26:
  case 0x2c:
  case 0x30:
  case 0x31:
  case 0x32:
  case 0x33:
  case 0x34:
    *param_2 = &DAT_18001cc44;
    return 0;
  case 0x27:
  case 0x29:
  case 0x2a:
  case 0x2b:
  case 0x35:
  case 0x36:
  case 0x38:
  case 0x39:
  case 0x3a:
  case 0x3b:
  case 0x3c:
  case 0x3d:
  case 0x3e:
  case 0x3f:
  case 0x40:
  case 0x42:
    *param_2 = &DAT_18001ca98;
    return 0;
  case 0x28:
  case 0x37:
    *param_2 = &DAT_18001cc48;
    return 0;
  case 0x41:
    *param_2 = &DAT_18001caa4;
    return 0;
  case 0x55:
    *param_2 = &DAT_18001cc4c;
    return 0;
  case 0x56:
  case 0x57:
  case 0x58:
  case 0x5a:
  case 0x5b:
  case 0x5c:
  case 0x5d:
  case 0x73:
    *param_2 = &DAT_18001cc50;
    return 0;
  default:
    return 4;
  }
}



undefined8 FUN_180018ac0(int param_1,undefined4 *param_2)

{
  longlong lVar1;
  ulonglong uVar2;
  
  if ((0x45 < param_1) && ((param_1 < 0x55 || (param_1 - 0x5eU < 6)))) {
    return 0xd;
  }
  lVar1 = FUN_1800013d0(param_1);
  uVar2 = FUN_180018910(param_1);
  if ((char)uVar2 == '\0') {
    if (lVar1 == 8) {
      *param_2 = 0;
      return 0;
    }
    if (lVar1 == 0x10) {
      *param_2 = 1;
      return 0;
    }
    if (lVar1 == 0x20) {
      *param_2 = 2;
      return 0;
    }
  }
  else {
    if (lVar1 == 0x10) {
      *param_2 = 4;
      return 0;
    }
    if (lVar1 == 0x20) {
      *param_2 = 3;
      return 0;
    }
  }
  return 3;
}



undefined8 FUN_180018bc0(longlong param_1)

{
  if (*(longlong *)(param_1 + 0x150) == 0) {
    return 5;
  }
  *(bool *)(param_1 + 0x149) = *(char *)(param_1 + 0x149) == '\0';
  return 0;
}



undefined8 FUN_180018bf0(longlong param_1)

{
  if (*(longlong *)(param_1 + 0x150) == 0) {
    return 5;
  }
  *(bool *)(param_1 + 0x148) = *(char *)(param_1 + 0x148) == '\0';
  return 0;
}



undefined8
FUN_180018c20(longlong *param_1,undefined4 param_2,undefined4 param_3,longlong param_4,
             undefined8 param_5)

{
  longlong lVar1;
  uint uVar2;
  undefined8 uVar3;
  
  if (param_1[0x2a] == 0) {
    uVar3 = 5;
  }
  else if (param_4 == 0) {
    uVar3 = 7;
  }
  else {
    lVar1 = *param_1;
    uVar2 = FUN_180012a10((longlong)(param_1 + 1),(byte)param_3);
    uVar3 = (**(code **)(lVar1 + 0x50))(param_1,param_2,param_3,0,uVar2,param_4,param_5);
  }
  return uVar3;
}



void FUN_180018cb0(longlong *param_1,undefined8 param_2,undefined8 param_3)

{
  (**(code **)(*param_1 + 0x60))(param_1,0,0,param_2,param_3);
  return;
}



undefined8 FUN_180018cd0(longlong param_1,uint param_2,uint param_3,ulonglong param_4,void *param_5)

{
  uint uVar1;
  int iVar2;
  longlong lVar3;
  undefined4 extraout_var;
  byte bVar4;
  void *_Dst;
  void *_Src;
  ulonglong uVar5;
  ulonglong uVar6;
  size_t _Size;
  
  uVar5 = param_4 & 0xffffffff;
  if (*(longlong *)(param_1 + 0x150) == 0) {
    return 5;
  }
  uVar1 = FUN_180012a70(param_1 + 8);
  if ((param_2 < uVar1) && (uVar1 = FUN_180012a80(param_1 + 8), param_3 < uVar1)) {
    bVar4 = (byte)param_3;
    uVar1 = FUN_180012a10(param_1 + 8,bVar4);
    if ((uint)uVar5 < uVar1) {
      if (param_5 == (void *)0x0) {
        return 7;
      }
      lVar3 = FUN_180002130(*(longlong *)(param_1 + 0x150),(ulonglong)param_3,(ulonglong)param_2,0);
      if (*(char *)(param_1 + 0x148) != '\0') {
        uVar1 = FUN_180012a10(param_1 + 8,bVar4);
        uVar5 = (ulonglong)((-1 - (uint)uVar5) + uVar1);
      }
      _Src = (void *)(uVar5 * *(size_t *)(lVar3 + 0x18) + *(longlong *)(lVar3 + 0x28));
      if (*(char *)(param_1 + 0x149) == '\0') {
        memcpy(param_5,_Src,*(size_t *)(lVar3 + 0x18));
      }
      else {
        iVar2 = FUN_180012aa0(param_1 + 8);
        _Size = CONCAT44(extraout_var,iVar2);
        uVar1 = FUN_180012a40(param_1 + 8,bVar4);
        uVar5 = 0;
        uVar6 = uVar1 * _Size;
        if (uVar6 != 0) {
          _Dst = (void *)((uVar6 - _Size) + (longlong)param_5);
          do {
            memcpy(_Dst,(void *)(uVar5 + (longlong)_Src),_Size);
            uVar5 = uVar5 + _Size;
            _Dst = (void *)((longlong)_Dst - _Size);
          } while (uVar5 < uVar6);
        }
      }
      return 0;
    }
  }
  return 6;
}



void FUN_180018e30(longlong *param_1,undefined4 param_2,undefined8 param_3)

{
  (**(code **)(*param_1 + 0x40))(param_1,0,0,param_2,param_3);
  return;
}



undefined8
FUN_180018e50(longlong *param_1,uint param_2,uint param_3,uint param_4,uint param_5,longlong param_6
             ,ulonglong param_7)

{
  uint uVar1;
  undefined8 uVar2;
  ulonglong uVar3;
  
  if (param_1[0x2a] == 0) {
    return 5;
  }
  uVar1 = FUN_180012a70((longlong)(param_1 + 1));
  if ((param_2 < uVar1) && (uVar1 = FUN_180012a80((longlong)(param_1 + 1)), param_3 < uVar1)) {
    uVar1 = FUN_180012a10((longlong)(param_1 + 1),(byte)param_3);
    if ((uVar1 < param_5) || (param_5 <= param_4)) {
      uVar2 = 6;
    }
    else {
      uVar3 = FUN_180012a30((longlong)(param_1 + 1),param_3);
      if (((param_7 == 0) || (uVar3 <= param_7)) && (param_6 != 0)) {
        if (param_7 != 0) {
          uVar3 = param_7;
        }
        do {
          uVar2 = (**(code **)(*param_1 + 0x40))(param_1,param_2,param_3,param_4,param_6);
          param_6 = param_6 + uVar3;
          if ((int)uVar2 != 0) {
            return uVar2;
          }
          param_4 = param_4 + 1;
        } while (param_4 < param_5);
      }
      else {
        uVar2 = 7;
      }
    }
  }
  else {
    uVar2 = 6;
  }
  return uVar2;
}



void FUN_180018f60(longlong *param_1,undefined4 param_2,undefined4 param_3,undefined8 param_4,
                  undefined8 param_5)

{
  (**(code **)(*param_1 + 0x50))(param_1,0,0,param_2,param_3,param_4,param_5);
  return;
}



void FUN_180018f90(longlong param_1)

{
  undefined4 uVar1;
  uint uVar2;
  longlong lVar3;
  void *pvVar4;
  undefined8 uVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  undefined8 *puVar8;
  void *_Memory;
  undefined auStackY_1d8 [32];
  longlong local_198;
  undefined local_190;
  undefined8 local_180;
  undefined8 local_178;
  undefined8 local_170;
  byte local_168;
  undefined uStack_167;
  undefined6 uStack_166;
  undefined8 local_158;
  ulonglong local_150;
  undefined **local_148 [20];
  undefined local_a8 [128];
  ulonglong local_28;
  
  local_170 = 0xfffffffffffffffe;
  local_28 = DAT_180065150 ^ (ulonglong)auStackY_1d8;
  lVar3 = *(longlong *)(param_1 + 0x150);
  uVar1 = *(undefined4 *)(lVar3 + 0x28);
  uVar2 = *(uint *)(lVar3 + 0x30);
  uVar5 = FUN_180018ac0(*(int *)(lVar3 + 0x40),(undefined4 *)&local_198);
  if ((int)uVar5 == 0) {
    uVar6 = FUN_1800012c0(*(undefined4 *)(lVar3 + 0x40));
    uVar7 = FUN_1800013d0(*(undefined4 *)(lVar3 + 0x40));
    puVar8 = FUN_180012690(local_148,*(uint *)(lVar3 + 0x10),*(undefined4 *)(lVar3 + 0x18),uVar2,
                           uVar1,(Enum)local_198,(int)(uVar6 / uVar7));
    FUN_180014be0(param_1 + 8,(longlong)puVar8);
    local_148[0] = Graphine::Grim::Spec::vftable;
    _eh_vector_destructor_iterator_(local_a8,0x20,4,FUN_180010f50);
    uVar6 = 0;
    local_198 = 0;
    uVar5 = FUN_180018980(*(undefined4 *)(lVar3 + 0x40),&local_198);
    lVar3 = local_198;
    if ((int)uVar5 == 0) {
      uVar7 = 0xffffffffffffffff;
      do {
        uVar7 = uVar7 + 1;
      } while (*(char *)(local_198 + uVar7) != '\0');
      if (uVar7 != 0) {
        do {
          local_168 = *(byte *)(uVar6 + lVar3);
          local_150 = 0xf;
          local_158 = 1;
          uStack_167 = 0;
          local_178 = 0xf;
          local_180 = 0;
          local_190 = 0;
          FUN_1800113a0((ulonglong **)&local_190,(ulonglong **)&local_168,(ulonglong *)0x0,
                        (ulonglong *)0xffffffffffffffff);
          FUN_180012ad0(param_1 + 8,(ulonglong **)&local_190,(int)uVar6);
          if (0xf < local_150) {
            pvVar4 = (void *)CONCAT62(uStack_166,CONCAT11(uStack_167,local_168));
            _Memory = pvVar4;
            if (0xfff < local_150 + 1) {
              if ((local_168 & 0x1f) != 0) {
                    // WARNING: Subroutine does not return
                _invalid_parameter_noinfo_noreturn();
              }
              _Memory = *(void **)((longlong)pvVar4 - 8);
              if (pvVar4 <= _Memory) {
                    // WARNING: Subroutine does not return
                _invalid_parameter_noinfo_noreturn();
              }
              if ((ulonglong)((longlong)pvVar4 - (longlong)_Memory) < 8) {
                    // WARNING: Subroutine does not return
                _invalid_parameter_noinfo_noreturn();
              }
              if (0x27 < (ulonglong)((longlong)pvVar4 - (longlong)_Memory)) {
                    // WARNING: Subroutine does not return
                _invalid_parameter_noinfo_noreturn();
              }
            }
            free(_Memory);
          }
          uVar6 = uVar6 + 1;
        } while (uVar6 < uVar7);
      }
    }
  }
  __security_check_cookie(local_28 ^ (ulonglong)auStackY_1d8);
  return;
}



void FUN_1800191a0(longlong param_1,undefined8 *param_2)

{
  undefined8 *puVar1;
  int iVar2;
  ulonglong *puVar3;
  ulonglong *puVar4;
  ulonglong uVar5;
  undefined auStackY_88 [32];
  undefined4 local_48 [12];
  int local_18;
  ulonglong local_10;
  
  local_10 = DAT_180065150 ^ (ulonglong)auStackY_88;
  puVar1 = *(undefined8 **)(param_1 + 0x150);
  if (puVar1 != (undefined8 *)0x0) {
    FUN_1800020c0(puVar1);
    free(puVar1);
  }
  puVar3 = (ulonglong *)operator_new(0x58);
  puVar4 = (ulonglong *)0x0;
  if (puVar3 != (ulonglong *)0x0) {
    *puVar3 = 0;
    puVar3[1] = 0;
    puVar3[9] = 0;
    puVar3[10] = 0;
    puVar4 = puVar3;
  }
  *(ulonglong **)(param_1 + 0x150) = puVar4;
  if (puVar4 != (ulonglong *)0x0) {
    if (7 < (ulonglong)param_2[3]) {
      param_2 = (undefined8 *)*param_2;
    }
    iVar2 = FUN_180003aa0((LPCWSTR)param_2,0,local_48,puVar4);
    if (-1 < iVar2) {
      if ((0x45 < local_18) && ((local_18 < 0x55 || (local_18 - 0x5eU < 6)))) {
        puVar4 = (ulonglong *)operator_new(0x58);
        if (puVar4 == (ulonglong *)0x0) goto LAB_18001934e;
        *puVar4 = 0;
        puVar4[1] = 0;
        puVar4[9] = 0;
        puVar4[10] = 0;
        uVar5 = FUN_180006f50((*(ulonglong **)(param_1 + 0x150))[9],
                              **(ulonglong **)(param_1 + 0x150),local_48,0,puVar4);
        if ((int)uVar5 < 0) {
          FUN_1800020c0(puVar4);
          free(puVar4);
          goto LAB_18001934e;
        }
        puVar1 = *(undefined8 **)(param_1 + 0x150);
        if (puVar1 != (undefined8 *)0x0) {
          FUN_1800020c0(puVar1);
          free(puVar1);
        }
        *(ulonglong **)(param_1 + 0x150) = puVar4;
      }
      *(undefined2 *)(param_1 + 0x148) = 0;
      FUN_180018f90(param_1);
    }
  }
LAB_18001934e:
  __security_check_cookie(local_10 ^ (ulonglong)auStackY_88);
  return;
}



void FUN_180019370(longlong param_1,int *param_2,ulonglong param_3)

{
  undefined8 *_Memory;
  ulonglong *puVar1;
  ulonglong *puVar2;
  ulonglong uVar3;
  undefined auStackY_98 [32];
  undefined4 local_58 [14];
  ulonglong local_20;
  
  local_20 = DAT_180065150 ^ (ulonglong)auStackY_98;
  _Memory = *(undefined8 **)(param_1 + 0x150);
  if (_Memory != (undefined8 *)0x0) {
    FUN_1800020c0(_Memory);
    free(_Memory);
  }
  puVar1 = (ulonglong *)operator_new(0x58);
  puVar2 = (ulonglong *)0x0;
  if (puVar1 != (ulonglong *)0x0) {
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[9] = 0;
    puVar1[10] = 0;
    puVar2 = puVar1;
  }
  *(ulonglong **)(param_1 + 0x150) = puVar2;
  if ((puVar2 != (ulonglong *)0x0) &&
     (uVar3 = FUN_180003910(param_2,param_3,0,local_58,puVar2), -1 < (int)uVar3)) {
    *(undefined2 *)(param_1 + 0x148) = 0;
    FUN_180018f90(param_1);
  }
  __security_check_cookie(local_20 ^ (ulonglong)auStackY_98);
  return;
}



undefined8 FUN_180019470(longlong param_1,int param_2,int param_3)

{
  int iVar1;
  ulonglong *puVar2;
  ulonglong *_Memory;
  
  if ((*(ulonglong *)(*(longlong *)(param_1 + 0x150) + 0x10) != (longlong)param_2) ||
     (*(ulonglong *)(*(longlong *)(param_1 + 0x150) + 0x18) != (longlong)param_3)) {
    puVar2 = (ulonglong *)operator_new(0x58);
    _Memory = (ulonglong *)0x0;
    if (puVar2 != (ulonglong *)0x0) {
      *puVar2 = 0;
      puVar2[1] = 0;
      puVar2[9] = 0;
      puVar2[10] = 0;
      _Memory = puVar2;
    }
    puVar2 = *(ulonglong **)(param_1 + 0x150);
    iVar1 = FUN_180006590(puVar2[9],*puVar2,(longlong)(puVar2 + 2),(longlong)param_2,
                          (longlong)param_3,0.0,_Memory);
    if (iVar1 < 0) {
      if (_Memory != (ulonglong *)0x0) {
        FUN_1800020c0(_Memory);
        free(_Memory);
      }
      if (iVar1 != -0x7ff8fff2) {
        if (iVar1 == -0x7ff8ffa9) {
          return 7;
        }
        return 10;
      }
      return 9;
    }
    FUN_1800020c0(*(undefined8 **)(param_1 + 0x150));
    *(ulonglong **)(param_1 + 0x150) = _Memory;
    FUN_180018f90(param_1);
  }
  return 0;
}



longlong * FUN_180019580(longlong *param_1,char param_2)

{
  longlong *plVar1;
  bool bVar2;
  int iVar3;
  longlong lVar4;
  int iVar5;
  longlong lVar6;
  int iVar7;
  
  iVar5 = 0;
  plVar1 = *(longlong **)((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 8))();
  }
  if (((*(int *)((longlong)*(int *)(*param_1 + 4) + 0x10 + (longlong)param_1) == 0) &&
      (plVar1 = *(longlong **)((longlong)*(int *)(*param_1 + 4) + 0x50 + (longlong)param_1),
      plVar1 != (longlong *)0x0)) && (plVar1 != param_1)) {
    std::basic_ostream<char,struct_std::char_traits<char>_>::flush
              ((basic_ostream_char_struct_std__char_traits_char___ *)plVar1);
  }
  lVar4 = (longlong)*(int *)(*param_1 + 4);
  if (*(int *)(lVar4 + 0x10 + (longlong)param_1) == 0) {
    lVar6 = *(longlong *)(lVar4 + 0x28 + (longlong)param_1);
    if (lVar6 < 2) {
      lVar6 = 0;
    }
    else {
      lVar6 = lVar6 + -1;
    }
    iVar7 = 4;
    if ((*(uint *)(lVar4 + 0x18 + (longlong)param_1) & 0x1c0) == 0x40) {
LAB_18001966a:
      iVar3 = std::basic_streambuf<char,struct_std::char_traits<char>_>::sputc
                        (*(basic_streambuf_char_struct_std__char_traits_char___ **)
                          ((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1),param_2);
      if (iVar3 == -1) {
        iVar5 = iVar7;
      }
      for (; (iVar5 == 0 && (0 < lVar6)); lVar6 = lVar6 + -1) {
        iVar3 = std::basic_streambuf<char,struct_std::char_traits<char>_>::sputc
                          (*(basic_streambuf_char_struct_std__char_traits_char___ **)
                            ((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1),
                           *(char *)((longlong)*(int *)(*param_1 + 4) + 0x58 + (longlong)param_1));
        if (iVar3 == -1) {
          iVar5 = iVar7;
        }
      }
    }
    else {
      while (iVar5 == 0) {
        if (lVar6 < 1) goto LAB_18001966a;
        iVar3 = std::basic_streambuf<char,struct_std::char_traits<char>_>::sputc
                          (*(basic_streambuf_char_struct_std__char_traits_char___ **)
                            ((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1),
                           *(char *)((longlong)*(int *)(*param_1 + 4) + 0x58 + (longlong)param_1));
        if (iVar3 == -1) {
          iVar5 = iVar7;
        }
        lVar6 = lVar6 + -1;
      }
    }
  }
  *(undefined8 *)((longlong)*(int *)(*param_1 + 4) + 0x28 + (longlong)param_1) = 0;
  std::basic_ios<char,struct_std::char_traits<char>_>::setstate
            ((basic_ios_char_struct_std__char_traits_char___ *)
             ((longlong)*(int *)(*param_1 + 4) + (longlong)param_1),iVar5,false);
  bVar2 = std::uncaught_exception();
  if (!bVar2) {
    std::basic_ostream<char,struct_std::char_traits<char>_>::_Osfx
              ((basic_ostream_char_struct_std__char_traits_char___ *)param_1);
  }
  plVar1 = *(longlong **)((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x10))();
  }
  return param_1;
}



void FUN_180019740(longlong **param_1)

{
  longlong *plVar1;
  
  plVar1 = *(longlong **)((longlong)*(int *)(**param_1 + 4) + 0x48 + (longlong)*param_1);
  if (plVar1 != (longlong *)0x0) {
                    // WARNING: Could not recover jumptable at 0x000180019768. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x10))();
    return;
  }
  return;
}



void FUN_180019780(longlong **param_1)

{
  longlong *plVar1;
  bool bVar2;
  
  bVar2 = std::uncaught_exception();
  if (!bVar2) {
    std::basic_ostream<char,struct_std::char_traits<char>_>::_Osfx
              ((basic_ostream_char_struct_std__char_traits_char___ *)*param_1);
  }
  plVar1 = *(longlong **)((longlong)*(int *)(**param_1 + 4) + 0x48 + (longlong)*param_1);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x10))();
  }
  return;
}



// class std::basic_istream<char,struct std::char_traits<char> > & __ptr64 __cdecl operator>>(class
// std::basic_istream<char,struct std::char_traits<char> > & __ptr64,class half & __ptr64)

basic_istream_char_struct_std__char_traits_char___ * __cdecl
operator__(basic_istream_char_struct_std__char_traits_char___ *param_1,half *param_2)

{
  short sVar1;
  float local_res10 [2];
  
                    // 0x197d0  1
                    // ??5@YAAEAV?$basic_istream@DU?$char_traits@D@std@@@std@@AEAV01@AEAVhalf@@@Z
  std::basic_istream<char,struct_std::char_traits<char>_>::operator__(param_1,local_res10);
  if (local_res10[0] == 0.0) {
    *(short *)param_2 = (short)((uint)local_res10[0] >> 0x10);
    return param_1;
  }
  sVar1 = *(short *)((longlong)&half::_eLut + (ulonglong)((uint)local_res10[0] >> 0x17) * 2);
  if (sVar1 == 0) {
    sVar1 = half::convert((int)local_res10[0]);
    *(short *)param_2 = sVar1;
    return param_1;
  }
  *(short *)param_2 =
       (short)((int)(((uint)local_res10[0] & 0x7fffff) + 0xfff +
                    ((int)((uint)local_res10[0] & 0x7fffff) >> 0xd & 1U)) >> 0xd) + sVar1;
  return param_1;
}



// class std::basic_ostream<char,struct std::char_traits<char> > & __ptr64 __cdecl operator<<(class
// std::basic_ostream<char,struct std::char_traits<char> > & __ptr64,class half)

basic_ostream_char_struct_std__char_traits_char___ * __cdecl
operator__(basic_ostream_char_struct_std__char_traits_char___ *param_1,half param_2)

{
  undefined in_DH;
  
                    // 0x19880  2
                    // ??6@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@std@@AEAV01@Vhalf@@@Z
  std::basic_ostream<char,struct_std::char_traits<char>_>::operator__
            (param_1,*(float *)((longlong)&half::_toFloat + (ulonglong)CONCAT11(in_DH,param_2) * 4))
  ;
  return param_1;
}



// public: unsigned short __cdecl half::bits(void)const __ptr64

ushort __thiscall half::bits(half *this)

{
                    // 0x198b0  5  ?bits@half@@QEBAGXZ
  return *(ushort *)this;
}



// private: static short __cdecl half::convert(int)

short __cdecl half::convert(int param_1)

{
  byte bVar1;
  ushort uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  
                    // 0x198c0  6  ?convert@half@@CAFH@Z
  uVar5 = param_1 & 0x7fffff;
  uVar3 = param_1 >> 0x17 & 0xff;
  uVar2 = (ushort)((uint)param_1 >> 0x10) & 0x8000;
  iVar4 = uVar3 - 0x70;
  if (iVar4 < 1) {
    if (-0xb < iVar4) {
      bVar1 = -(char)iVar4 + 0xe;
      return (ushort)((int)((1 << (-(char)iVar4 + 0xdU & 0x1f)) + (uVar5 | 0x800000) + -1 +
                           ((int)(uVar5 | 0x800000) >> (bVar1 & 0x1f) & 1U)) >> (bVar1 & 0x1f)) |
             uVar2;
    }
  }
  else {
    uVar6 = (int)uVar5 >> 0xd;
    if (iVar4 == 0x8f) {
      if (uVar5 != 0) {
        return (ushort)(uVar6 == 0) | (ushort)uVar6 | uVar2 | 0x7c00;
      }
    }
    else {
      uVar5 = (uVar6 & 1) + 0xfff + uVar5;
      if (uVar5 >> 0x17 != 0) {
        uVar5 = 0;
        iVar4 = uVar3 - 0x6f;
      }
      if (iVar4 < 0x1f) {
        return (ushort)((int)uVar5 >> 0xd) | (ushort)(iVar4 << 10) | uVar2;
      }
      overflow();
    }
    uVar2 = uVar2 | 0x7c00;
  }
  return uVar2;
}



// private: static float __cdecl half::overflow(void)

float __cdecl half::overflow(void)

{
  longlong lVar1;
  float local_res8;
  
                    // 0x199a0  7  ?overflow@half@@CAMXZ
  lVar1 = 10;
  local_res8 = 1e+10;
  do {
    local_res8 = local_res8 * local_res8;
    lVar1 = lVar1 + -1;
  } while (lVar1 != 0);
  return local_res8;
}



// void __cdecl printBits(class std::basic_ostream<char,struct std::char_traits<char> > &
// __ptr64,float)

void __cdecl printBits(basic_ostream_char_struct_std__char_traits_char___ *param_1,float param_2)

{
  int iVar1;
  
                    // 0x199f0  8
                    // ?printBits@@YAXAEAV?$basic_ostream@DU?$char_traits@D@std@@@std@@M@Z
  iVar1 = 0x1f;
  do {
    FUN_180019580((longlong *)param_1,(byte)((uint)param_2 >> ((byte)iVar1 & 0x1f)) & 1 | 0x30);
    if ((iVar1 - 0x17U & 0xfffffff7) == 0) {
      FUN_180019580((longlong *)param_1,' ');
    }
    iVar1 = iVar1 + -1;
  } while (-1 < iVar1);
  return;
}



// void __cdecl printBits(class std::basic_ostream<char,struct std::char_traits<char> > &
// __ptr64,class half)

void __cdecl printBits(basic_ostream_char_struct_std__char_traits_char___ *param_1,half param_2)

{
  undefined7 in_register_00000011;
  int iVar1;
  
                    // 0x19a50  9
                    // ?printBits@@YAXAEAV?$basic_ostream@DU?$char_traits@D@std@@@std@@Vhalf@@@Z
  iVar1 = 0xf;
  do {
    FUN_180019580((longlong *)param_1,
                  (byte)((ushort)CONCAT71(in_register_00000011,param_2) >> ((byte)iVar1 & 0x1f)) & 1
                  | 0x30);
    if ((iVar1 == 0xf) || (iVar1 == 10)) {
      FUN_180019580((longlong *)param_1,' ');
    }
    iVar1 = iVar1 + -1;
  } while (-1 < iVar1);
  return;
}



// void __cdecl printBits(char * __ptr64 const,float)

void __cdecl printBits(char *param_1,float param_2)

{
  byte *pbVar1;
  int iVar2;
  
                    // 0x19ab0  10  ?printBits@@YAXQEADM@Z
  iVar2 = 0x1f;
  pbVar1 = (byte *)param_1;
  do {
    *pbVar1 = (byte)((uint)param_2 >> ((byte)iVar2 & 0x1f)) & 1 | 0x30;
    if ((iVar2 - 0x17U & 0xfffffff7) == 0) {
      pbVar1 = pbVar1 + 1;
      *pbVar1 = 0x20;
    }
    pbVar1 = pbVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (-1 < iVar2);
  param_1[0x22] = '\0';
  return;
}



// void __cdecl printBits(char * __ptr64 const,class half)

void __cdecl printBits(char *param_1,half param_2)

{
  byte *pbVar1;
  undefined in_DH;
  int iVar2;
  
                    // 0x19b10  11  ?printBits@@YAXQEADVhalf@@@Z
  iVar2 = 0xf;
  pbVar1 = (byte *)param_1;
  do {
    *pbVar1 = (byte)(CONCAT11(in_DH,param_2) >> ((byte)iVar2 & 0x1f)) & 1 | 0x30;
    if ((iVar2 == 0xf) || (iVar2 == 10)) {
      pbVar1 = pbVar1 + 1;
      *pbVar1 = 0x20;
    }
    pbVar1 = pbVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (-1 < iVar2);
  param_1[0x12] = '\0';
  return;
}



// public: void __cdecl half::setBits(unsigned short) __ptr64

void __thiscall half::setBits(half *this,ushort param_1)

{
                    // 0x19b60  12  ?setBits@half@@QEAAXG@Z
  *(ushort *)this = param_1;
  return;
}



// Library Function - Single Match
//  void * __ptr64 __cdecl operator new(unsigned __int64)
// 
// Library: Visual Studio 2015 Release

void * __cdecl operator_new(__uint64 param_1)

{
  int iVar1;
  void *pvVar2;
  
  while (pvVar2 = malloc(param_1), pvVar2 == (void *)0x0) {
    iVar1 = _callnewh(param_1);
    if (iVar1 == 0) {
      if (param_1 == 0xffffffffffffffff) {
        FUN_18001a36c();
      }
      else {
        FUN_18001a34c();
      }
    }
  }
  return pvVar2;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae54. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



// Library Function - Single Match
//  __GSHandlerCheck
// 
// Library: Visual Studio 2015 Release

undefined8
__GSHandlerCheck(undefined8 param_1,ulonglong param_2,undefined8 param_3,longlong param_4)

{
  __GSHandlerCheckCommon(param_2,param_4,*(uint **)(param_4 + 0x38));
  return 1;
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



// Library Function - Single Match
//  __security_check_cookie
// 
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

void __cdecl __security_check_cookie(uintptr_t _StackCookie)

{
  if ((_StackCookie == DAT_180065150) && ((short)(_StackCookie >> 0x30) == 0)) {
    return;
  }
  __report_gsfailure(_StackCookie);
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
    if (DAT_180065ea4 < 1) {
      uVar6 = 0;
    }
    else {
      DAT_180065ea4 = DAT_180065ea4 + -1;
      uVar8 = __scrt_acquire_startup_lock();
      if (_DAT_180066420 != 2) {
        uVar7 = 0;
        __scrt_fastfail(7);
      }
      __scrt_dllmain_uninitialize_c();
      _DAT_180066420 = 0;
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
      if (_DAT_180066420 != 0) {
        __scrt_fastfail(7);
      }
      _DAT_180066420 = 1;
      uVar8 = __scrt_dllmain_before_initialize_c();
      if ((char)uVar8 != '\0') {
        _RTC_Initialize();
        atexit(&LAB_18001abac);
        FUN_18001a9c8();
        atexit(&LAB_18001a9d8);
        __scrt_initialize_default_local_stdio_options();
        iVar5 = _initterm_e(&DAT_18001c368,&DAT_18001c370);
        if ((iVar5 == 0) && (uVar9 = __scrt_dllmain_after_initialize_c(), (char)uVar9 != '\0')) {
          _initterm(&DAT_18001c350,&DAT_18001c360);
          _DAT_180066420 = 2;
          bVar2 = false;
        }
      }
      __scrt_release_startup_lock((char)uVar7);
      if (!bVar2) {
        ppcVar10 = (code **)FUN_18001aa10();
        if ((*ppcVar10 != (code *)0x0) &&
           (uVar7 = __scrt_is_nonwritable_in_current_image((longlong)ppcVar10), (char)uVar7 != '\0')
           ) {
          pcVar1 = *ppcVar10;
          _guard_check_icall();
          (*pcVar1)(param_1,2,param_3);
        }
        DAT_180065ea4 = DAT_180065ea4 + 1;
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



int FUN_180019e64(HINSTANCE__ *param_1,ulong param_2,void *param_3)

{
  int iVar1;
  undefined8 uVar2;
  
  if ((param_2 == 0) && (DAT_180065ea4 < 1)) {
    iVar1 = 0;
  }
  else if ((1 < param_2 - 1) ||
          ((iVar1 = dllmain_raw(param_1,param_2,param_3), iVar1 != 0 &&
           (iVar1 = dllmain_crt_dispatch(param_1,param_2,param_3), iVar1 != 0)))) {
    uVar2 = FUN_18001a9a4(param_1,param_2);
    iVar1 = (int)uVar2;
    if ((param_2 == 1) && (iVar1 == 0)) {
      FUN_18001a9a4(param_1,0);
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



// WARNING: Removing unreachable block (ram,0x000180019f89)
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
  FUN_180019e64(param_1,param_2,param_3);
  return;
}



// Library Function - Single Match
//  void __cdecl `eh vector constructor iterator'(void * __ptr64,unsigned __int64,unsigned
// __int64,void (__cdecl*)(void * __ptr64),void (__cdecl*)(void * __ptr64))
// 
// Library: Visual Studio 2015 Release

void __cdecl
_eh_vector_constructor_iterator_
          (void *param_1,__uint64 param_2,__uint64 param_3,_func_void_void_ptr *param_4,
          _func_void_void_ptr *param_5)

{
  __uint64 _Var1;
  
  for (_Var1 = 0; _Var1 != param_3; _Var1 = _Var1 + 1) {
    _guard_check_icall();
    (*param_4)(param_1);
    param_1 = (void *)((longlong)param_1 + param_2);
  }
  return;
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



undefined8 * FUN_18001a1b0(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = type_info::vftable;
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void * __cdecl operator_new(__uint64 param_1)

{
  int iVar1;
  void *pvVar2;
  
  while (pvVar2 = malloc(param_1), pvVar2 == (void *)0x0) {
    iVar1 = _callnewh(param_1);
    if (iVar1 == 0) {
      if (param_1 == 0xffffffffffffffff) {
        FUN_18001a36c();
      }
      else {
        FUN_18001a34c();
      }
    }
  }
  return pvVar2;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae54. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae54. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



void thunk_FUN_18001ac00(__uint64 param_1)

{
  operator_new(param_1);
  return;
}



undefined8 * FUN_18001a1fc(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy(param_2 + 8);
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



undefined8 * FUN_18001a23c(undefined8 *param_1)

{
  param_1[2] = 0;
  param_1[1] = "bad allocation";
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



undefined8 * FUN_18001a25c(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy(param_2 + 8);
  *param_1 = std::bad_array_new_length::vftable;
  return param_1;
}



undefined8 * FUN_18001a29c(undefined8 *param_1)

{
  param_1[2] = 0;
  param_1[1] = "bad array new length";
  *param_1 = std::bad_array_new_length::vftable;
  return param_1;
}



// Library Function - Single Match
//  public: __cdecl std::exception::exception(class std::exception const & __ptr64) __ptr64
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

exception * __thiscall std::exception::exception(exception *this,exception *param_1)

{
  *(undefined ***)this = vftable;
  *(undefined8 *)(this + 8) = 0;
  *(undefined8 *)(this + 0x10) = 0;
  __std_exception_copy(param_1 + 8);
  return this;
}



undefined8 * FUN_18001a308(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = std::exception::vftable;
  __std_exception_destroy(param_1 + 1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_18001a34c(void)

{
  undefined8 local_28 [5];
  
  FUN_18001a23c(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_180062b00);
}



void FUN_18001a36c(void)

{
  undefined8 local_28 [5];
  
  FUN_18001a29c(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_180062b88);
}



char * FUN_18001a38c(longlong param_1)

{
  char *pcVar1;
  
  pcVar1 = "Unknown exception";
  if (*(longlong *)(param_1 + 8) != 0) {
    pcVar1 = *(char **)(param_1 + 8);
  }
  return pcVar1;
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
                    // WARNING: Could not recover jumptable at 0x00018001a3cd. Too many branches
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
  *(undefined8 *)(puVar3 + -8) = 0x18001a3fe;
  capture_previous_context((PCONTEXT)&DAT_180065f50);
  _DAT_180065ec0 = *(undefined8 *)(puVar3 + 0x38);
  _DAT_180065fe8 = puVar3 + 0x40;
  _DAT_180065fd0 = *(undefined8 *)(puVar3 + 0x40);
  _DAT_180065eb0 = 0xc0000409;
  _DAT_180065eb4 = 1;
  _DAT_180065ec8 = 1;
  DAT_180065ed0 = 2;
  *(undefined8 *)(puVar3 + 0x20) = DAT_180065150;
  *(undefined8 *)(puVar3 + 0x28) = DAT_180065158;
  *(undefined8 *)(puVar3 + -8) = 0x18001a4a0;
  DAT_180066048 = _DAT_180065ec0;
  __raise_securityfailure((_EXCEPTION_POINTERS *)&PTR_DAT_18005d2f0);
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
LAB_18001a54a:
    uVar3 = (ulonglong)pvVar2 & 0xffffffffffffff00;
  }
  else {
    do {
      LOCK();
      bVar1 = DAT_180066428 == 0;
      DAT_180066428 = DAT_180066428 ^ (ulonglong)bVar1 * (DAT_180066428 ^ (ulonglong)StackBase);
      pvVar2 = (void *)(!bVar1 * DAT_180066428);
      if (bVar1) goto LAB_18001a54a;
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
    uVar3 = FUN_18001ade8();
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
  
  cVar1 = FUN_18001aea4();
  if (cVar1 != '\0') {
    cVar1 = FUN_18001aea4();
    if (cVar1 != '\0') {
      return 1;
    }
    FUN_18001aea4();
  }
  return 0;
}



// Library Function - Single Match
//  __scrt_dllmain_crt_thread_detach
// 
// Library: Visual Studio 2015 Release

undefined __scrt_dllmain_crt_thread_detach(void)

{
  FUN_18001aea4();
  FUN_18001aea4();
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
    _execute_onexit_table(&DAT_180066430);
    return;
  }
  uVar2 = CSharp_autoPitch_get();
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
  FUN_18001aea4();
  FUN_18001aea4();
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
    DAT_180066460 = 1;
  }
  __isa_available_init();
  uVar1 = FUN_18001aea4();
  if ((char)uVar1 != '\0') {
    uVar1 = FUN_18001aea4();
    if ((char)uVar1 != '\0') {
      return uVar1 & 0xffffffffffffff00 | 1;
    }
    uVar1 = FUN_18001aea4();
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
      bVar2 = 0x40 - ((byte)DAT_180065150 & 0x3f) & 0x3f;
      _DAT_180066440 = (0xffffffffffffffffU >> bVar2 | -1L << 0x40 - bVar2) ^ DAT_180065150;
      local_28 = (undefined4)_DAT_180066440;
      uStack_24 = (undefined4)(_DAT_180066440 >> 0x20);
      _DAT_180066430 = local_28;
      uRam0000000180066434 = uStack_24;
      uRam0000000180066438 = local_28;
      uRam000000018006643c = uStack_24;
      _DAT_180066448 = local_28;
      uRam000000018006644c = uStack_24;
      uRam0000000180066450 = local_28;
      uRam0000000180066454 = uStack_24;
      _DAT_180066458 = _DAT_180066440;
    }
    else {
      uVar4 = _initialize_onexit_table(&DAT_180066430);
      if ((int)uVar4 == 0) {
        uVar4 = _initialize_onexit_table(&DAT_180066448);
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



// WARNING: Removing unreachable block (ram,0x00018001a832)
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
  for (pIVar3 = &IMAGE_SECTION_HEADER_180000240; pIVar3 != (IMAGE_SECTION_HEADER *)&DAT_180000358;
      pIVar3 = pIVar3 + 1) {
    if (((ulonglong)(uint)pIVar3->VirtualAddress <= param_1 - 0x180000000U) &&
       (uVar1 = (ulonglong)((pIVar3->Misc).PhysicalAddress + pIVar3->VirtualAddress),
       param_1 - 0x180000000U < uVar1)) goto LAB_18001a81b;
  }
  pIVar3 = (IMAGE_SECTION_HEADER *)0x0;
LAB_18001a81b:
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
    DAT_180066428 = 0;
  }
  return;
}



// Library Function - Single Match
//  __scrt_uninitialize_crt
// 
// Library: Visual Studio 2015 Release

undefined __scrt_uninitialize_crt(undefined8 param_1,char param_2)

{
  if ((DAT_180066460 == '\0') || (param_2 == '\0')) {
    FUN_18001aea4();
    FUN_18001aea4();
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
  
  bVar2 = (byte)DAT_180065150 & 0x3f;
  if (((DAT_180065150 ^ _DAT_180066430) >> bVar2 | (DAT_180065150 ^ _DAT_180066430) << 0x40 - bVar2)
      == 0xffffffffffffffff) {
    iVar1 = _crt_atexit();
  }
  else {
    iVar1 = _register_onexit_function(&DAT_180066430,_Func);
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
  if (DAT_180065150 == 0x2b992ddfa232) {
    GetSystemTimeAsFileTime(&local_res10);
    local_res8 = local_res10;
    DVar1 = GetCurrentThreadId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    DVar1 = GetCurrentProcessId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    QueryPerformanceCounter((LARGE_INTEGER *)&local_res18);
    DAT_180065150 =
         ((ulonglong)local_res18 << 0x20 ^ CONCAT44(uStackX_1c,local_res18) ^ (ulonglong)local_res8
         ^ (ulonglong)&local_res8) & 0xffffffffffff;
    if (DAT_180065150 == 0x2b992ddfa232) {
      DAT_180065150 = 0x2b992ddfa233;
    }
  }
  DAT_180065158 = ~DAT_180065150;
  return;
}



undefined8 FUN_18001a9a4(HMODULE param_1,int param_2)

{
  if (param_2 == 1) {
    DisableThreadLibraryCalls(param_1);
  }
  return 1;
}



void FUN_18001a9c8(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001a9cf. Too many branches
                    // WARNING: Treating indirect jump as call
  InitializeSListHead(&DAT_180066470);
  return;
}



undefined * FUN_18001a9e4(void)

{
  return &DAT_180066480;
}



undefined * FUN_18001a9ec(void)

{
  return &DAT_180066488;
}



// Library Function - Single Match
//  __scrt_initialize_default_local_stdio_options
// 
// Library: Visual Studio 2015 Release

void __scrt_initialize_default_local_stdio_options(void)

{
  ulonglong *puVar1;
  
  puVar1 = (ulonglong *)FUN_18001a9e4();
  *puVar1 = *puVar1 | 4;
  puVar1 = (ulonglong *)FUN_18001a9ec();
  *puVar1 = *puVar1 | 2;
  return;
}



undefined * FUN_18001aa10(void)

{
  return &DAT_1800664a8;
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
  _DAT_180066490 = 0;
  *(undefined8 *)(puVar4 + -8) = 0x18001aa59;
  memset(local_4d8,0,0x4d0);
  *(undefined8 *)(puVar4 + -8) = 0x18001aa63;
  RtlCaptureContext(local_4d8);
  *(undefined8 *)(puVar4 + -8) = 0x18001aa7d;
  FunctionEntry = RtlLookupFunctionEntry(local_3e0,&local_res10,(PUNWIND_HISTORY_TABLE)0x0);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0) {
    *(undefined8 *)(puVar4 + 0x38) = 0;
    *(undefined **)(puVar4 + 0x30) = local_res18;
    *(undefined **)(puVar4 + 0x28) = local_res20;
    *(undefined **)(puVar4 + 0x20) = local_4d8;
    *(undefined8 *)(puVar4 + -8) = 0x18001aabe;
    RtlVirtualUnwind(0,local_res10,local_3e0,FunctionEntry,*(PCONTEXT *)(puVar4 + 0x20),
                     *(PVOID **)(puVar4 + 0x28),*(PDWORD64 *)(puVar4 + 0x30),
                     *(PKNONVOLATILE_CONTEXT_POINTERS *)(puVar4 + 0x38));
  }
  local_440 = &stack0x00000008;
  *(undefined8 *)(puVar4 + -8) = 0x18001aaf0;
  memset(puVar4 + 0x50,0,0x98);
  *(undefined8 *)(puVar4 + 0x60) = unaff_retaddr;
  *(undefined4 *)(puVar4 + 0x50) = 0x40000015;
  *(undefined4 *)(puVar4 + 0x54) = 1;
  *(undefined8 *)(puVar4 + -8) = 0x18001ab12;
  BVar2 = IsDebuggerPresent();
  *(undefined **)(puVar4 + 0x40) = puVar4 + 0x50;
  *(undefined **)(puVar4 + 0x48) = local_4d8;
  *(undefined8 *)(puVar4 + -8) = 0x18001ab33;
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  *(undefined8 *)(puVar4 + -8) = 0x18001ab3e;
  LVar3 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)(puVar4 + 0x40));
  if (LVar3 == 0) {
    _DAT_180066490 = _DAT_180066490 & -(uint)(BVar2 == 1);
  }
  return;
}



// Library Function - Single Match
//  _RTC_Initialize
// 
// Library: Visual Studio 2015 Release

void _RTC_Initialize(void)

{
  code *pcVar1;
  code **ppcVar2;
  
  for (ppcVar2 = (code **)&DAT_180060490; ppcVar2 < &DAT_180060490; ppcVar2 = ppcVar2 + 1) {
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



void FUN_18001ac00(__uint64 param_1)

{
  operator_new(param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x00018001ad3d)
// WARNING: Removing unreachable block (ram,0x00018001aca2)
// WARNING: Removing unreachable block (ram,0x00018001ac44)
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
  DAT_18006516c = 2;
  piVar1 = (int *)cpuid_basic_info(0);
  _DAT_180065168 = 1;
  puVar2 = (uint *)cpuid_Version_info(1);
  uVar4 = puVar2[3];
  uVar5 = DAT_180066494;
  if ((piVar1[2] ^ 0x49656e69U | piVar1[3] ^ 0x6c65746eU | piVar1[1] ^ 0x756e6547U) == 0) {
    _DAT_180065170 = 0xffffffffffffffff;
    uVar6 = *puVar2 & 0xfff3ff0;
    if ((((uVar6 == 0x106c0) || (uVar6 == 0x20660)) || (uVar6 == 0x20670)) ||
       ((uVar5 = DAT_180066494 | 4, uVar6 - 0x30650 < 0x21 &&
        ((0x100010001U >> ((ulonglong)(uVar6 - 0x30650) & 0x3f) & 1) != 0)))) {
      uVar5 = DAT_180066494 | 5;
    }
  }
  DAT_180066494 = uVar5;
  if (((piVar1[1] ^ 0x68747541U | piVar1[2] ^ 0x69746e65U | piVar1[3] ^ 0x444d4163U) == 0) &&
     (0x600eff < (*puVar2 & 0xff00f00))) {
    DAT_180066494 = DAT_180066494 | 4;
  }
  if (6 < *piVar1) {
    lVar3 = cpuid_Extended_Feature_Enumeration_info(7);
    local_20 = *(uint *)(lVar3 + 4);
    if ((local_20 >> 9 & 1) != 0) {
      DAT_180066494 = DAT_180066494 | 2;
    }
  }
  if ((uVar4 >> 0x14 & 1) != 0) {
    _DAT_180065168 = 2;
    DAT_18006516c = 6;
    if ((((uVar4 >> 0x1b & 1) != 0) && ((uVar4 >> 0x1c & 1) != 0)) && ((in_XCR0 & 6) == 6)) {
      DAT_18006516c = 0xe;
      _DAT_180065168 = 3;
      if ((local_20 & 0x20) != 0) {
        _DAT_180065168 = 5;
        DAT_18006516c = 0x2e;
      }
    }
  }
  return 0;
}



undefined8 FUN_18001ade8(void)

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
  return _DAT_180065180 != 0;
}



void _guard_check_icall(void)

{
  return;
}



void _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae00. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  _CxxThrowException(pExceptionObject,pThrowInfo);
  return;
}



void __CxxFrameHandler3(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae06. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler3();
  return;
}



void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001ae0c. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}



void Unwind_18001ae12(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae12. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_terminate();
  return;
}



void _purecall(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae18. Too many branches
                    // WARNING: Treating indirect jump as call
  _purecall();
  return;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001ae1e. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



void __std_exception_copy(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae2a. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_exception_copy();
  return;
}



void __std_exception_destroy(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae30. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_exception_destroy();
  return;
}



float __cdecl floorf(float _X)

{
  float fVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001ae3c. Too many branches
                    // WARNING: Treating indirect jump as call
  fVar1 = floorf(_X);
  return fVar1;
}



float __cdecl sqrtf(float _X)

{
  float fVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001ae42. Too many branches
                    // WARNING: Treating indirect jump as call
  fVar1 = sqrtf(_X);
  return fVar1;
}



int __cdecl _callnewh(size_t _Size)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001ae48. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _callnewh(_Size);
  return iVar1;
}



void * __cdecl malloc(size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001ae4e. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = malloc(_Size);
  return pvVar1;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae54. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae5a. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



void _initterm_e(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae60. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm_e();
  return;
}



void terminate(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae66. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  terminate();
  return;
}



void _seh_filter_dll(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae6c. Too many branches
                    // WARNING: Treating indirect jump as call
  _seh_filter_dll();
  return;
}



void _configure_narrow_argv(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae72. Too many branches
                    // WARNING: Treating indirect jump as call
  _configure_narrow_argv();
  return;
}



void _initialize_narrow_environment(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae78. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_narrow_environment();
  return;
}



void _initialize_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae7e. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_onexit_table();
  return;
}



void _register_onexit_function(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae84. Too many branches
                    // WARNING: Treating indirect jump as call
  _register_onexit_function();
  return;
}



void _execute_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae8a. Too many branches
                    // WARNING: Treating indirect jump as call
  _execute_onexit_table();
  return;
}



void _crt_atexit(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae90. Too many branches
                    // WARNING: Treating indirect jump as call
  _crt_atexit();
  return;
}



void __cdecl _cexit(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae96. Too many branches
                    // WARNING: Treating indirect jump as call
  _cexit();
  return;
}



BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001ae9c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = IsProcessorFeaturePresent(ProcessorFeature);
  return BVar1;
}



undefined FUN_18001aea4(void)

{
  return 1;
}



undefined8 CSharp_autoPitch_get(void)

{
                    // 0x1aeb0  60  CSharp_autoPitch_get
  return 0;
}



float __cdecl powf(float _X,float _Y)

{
  float fVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001aeb4. Too many branches
                    // WARNING: Treating indirect jump as call
  fVar1 = powf(_X,_Y);
  return fVar1;
}



// WARNING: This is an inlined function

void _guard_dispatch_icall(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
                    // WARNING: Could not recover jumptable at 0x00018001aed0. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void Unwind_18001aee0(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x68));
  return;
}



void Unwind_18001aeec(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x60));
  return;
}



void Unwind_18001aef8(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x58));
  return;
}



void Unwind_18001af04(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x40));
  return;
}



void Unwind_18001af10(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x48));
  return;
}



void Unwind_18001af20(undefined8 param_1,longlong param_2)

{
  FUN_1800020c0((undefined8 *)(param_2 + 0x40));
  return;
}



void Unwind_18001af2c(undefined8 param_1,longlong param_2)

{
  FUN_1800020c0((undefined8 *)(param_2 + 0xb0));
  return;
}



void Unwind_18001af40(undefined8 param_1,longlong param_2)

{
  FUN_1800021b0((void **)(param_2 + 0x68));
  return;
}



void Unwind_18001af4c(undefined8 param_1,longlong param_2)

{
  free(*(void **)(param_2 + 0xd8));
  return;
}



void Unwind_18001af70(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x40));
  return;
}



void Unwind_18001af80(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x70));
  return;
}



void Unwind_18001af8c(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x48));
  return;
}



void Unwind_18001af98(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x78));
  return;
}



void Unwind_18001afa4(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x38));
  return;
}



void Unwind_18001afb0(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x30));
  return;
}



void Unwind_18001afbc(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x30));
  return;
}



void Unwind_18001afc8(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x50));
  return;
}



void Unwind_18001afd4(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x38));
  return;
}



void Unwind_18001afe0(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x30));
  return;
}



void Unwind_18001afec(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x30));
  return;
}



void Unwind_18001aff8(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x30));
  return;
}



void Unwind_18001b004(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x68));
  return;
}



void Unwind_18001b010(undefined8 param_1,longlong param_2)

{
  FUN_1800069d0((longlong **)(param_2 + 0x40));
  return;
}



undefined * Catch_All_18001b020(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  void *pvVar2;
  
  lVar1 = *(longlong *)(param_2 + 0x68);
  *(longlong *)(param_2 + 0x68) = lVar1;
  pvVar2 = FUN_1800112b0(*(undefined8 *)(param_2 + 0x60),lVar1 + 1);
  *(void **)(param_2 + 0x78) = pvVar2;
  return &DAT_1800110ab;
}



// WARNING: Removing unreachable block (ram,0x00018001b07b)

void Catch_All_18001b053(undefined8 param_1,longlong param_2)

{
  void *pvVar1;
  void *_Memory;
  ulonglong **ppuVar2;
  
  ppuVar2 = *(ulonglong ***)(param_2 + 0x60);
  if ((ulonglong *)0xf < ppuVar2[3]) {
    pvVar1 = *ppuVar2;
    _Memory = pvVar1;
    if (0xfff < (longlong)ppuVar2[3] + 1U) {
      if (((ulonglong)pvVar1 & 0x1f) != 0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      _Memory = *(void **)((longlong)pvVar1 - 8);
      if (pvVar1 <= _Memory) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if ((ulonglong)((longlong)pvVar1 - (longlong)_Memory) < 8) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if (0x27 < (ulonglong)((longlong)pvVar1 - (longlong)_Memory)) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
    }
    free(_Memory);
  }
  ppuVar2[3] = (ulonglong *)0xf;
  ppuVar2[2] = (ulonglong *)0x0;
  if ((ulonglong *)0xf < ppuVar2[3]) {
    ppuVar2 = (ulonglong **)*ppuVar2;
  }
  *(undefined *)ppuVar2 = 0;
                    // WARNING: Subroutine does not return
  _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
}



undefined * Catch_All_18001b100(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  void *pvVar2;
  
  lVar1 = *(longlong *)(param_2 + 0x68);
  *(longlong *)(param_2 + 0x68) = lVar1;
  pvVar2 = FUN_180011320(*(undefined8 *)(param_2 + 0x60),lVar1 + 1);
  *(void **)(param_2 + 0x78) = pvVar2;
  return &DAT_180011214;
}



void Catch_All_18001b133(undefined8 param_1,longlong param_2)

{
  void **ppvVar1;
  
  ppvVar1 = *(void ***)(param_2 + 0x60);
  if ((void *)0x7 < ppvVar1[3]) {
    FUN_180011890(ppvVar1,*ppvVar1,(longlong)ppvVar1[3] + 1);
  }
  ppvVar1[3] = (void *)0x7;
  ppvVar1[2] = (void *)0x0;
  if ((void *)0x7 < ppvVar1[3]) {
    ppvVar1 = (void **)*ppvVar1;
  }
  *(undefined2 *)ppvVar1 = 0;
                    // WARNING: Subroutine does not return
  _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
}



void Unwind_18001b190(undefined8 param_1,longlong param_2)

{
  _eh_vector_destructor_iterator_
            ((void *)(*(longlong *)(param_2 + 0x80) + 0xa0),0x20,4,FUN_180010f50);
  return;
}



void Unwind_18001b1d0(undefined8 param_1,longlong param_2)

{
  _eh_vector_destructor_iterator_
            ((void *)(*(longlong *)(param_2 + 0x50) + 0xa0),0x20,4,FUN_180010f50);
  return;
}



void Unwind_18001b210(undefined8 param_1,longlong param_2)

{
  if ((*(uint *)(param_2 + 0x20) & 1) != 0) {
    *(uint *)(param_2 + 0x20) = *(uint *)(param_2 + 0x20) & 0xfffffffe;
    FUN_180010f50(*(ulonglong ***)(param_2 + 0x48));
  }
  return;
}



void Unwind_18001b240(undefined8 param_1,longlong param_2)

{
  FUN_180010f50(*(ulonglong ***)(param_2 + 0x28));
  return;
}



void Unwind_18001b250(undefined8 param_1,longlong param_2)

{
  FUN_180014b90((void **)(param_2 + 0x38));
  return;
}



void Unwind_18001b25c(undefined8 param_1,longlong param_2)

{
  if ((*(uint *)(param_2 + 0x20) & 1) != 0) {
    *(uint *)(param_2 + 0x20) = *(uint *)(param_2 + 0x20) & 0xfffffffe;
    FUN_180014b90((void **)(param_2 + 0x78));
  }
  return;
}



void Unwind_18001b290(undefined8 param_1,longlong param_2)

{
  FUN_180014b90((void **)(param_2 + 0x28));
  return;
}



void Unwind_18001b2a0(undefined8 param_1,longlong param_2)

{
  FUN_180012820((undefined8 *)(param_2 + 0x50));
  return;
}



void Unwind_18001b2b0(undefined8 param_1,longlong param_2)

{
  FUN_180014b90((void **)(param_2 + 0x68));
  return;
}



void Unwind_18001b2bc(undefined8 param_1,longlong param_2)

{
  FUN_180014b90((void **)(param_2 + 0x28));
  return;
}



void Unwind_18001b2d0(undefined8 param_1,longlong param_2)

{
  free(*(void **)(param_2 + 0x40));
  return;
}



void Unwind_18001b2f0(undefined8 param_1,longlong param_2)

{
  free(*(void **)(param_2 + 0x48));
  return;
}



void Unwind_18001b30d(undefined8 param_1,longlong param_2)

{
  FUN_180017020(*(undefined8 **)(param_2 + 0x48));
  return;
}



void Unwind_18001b320(undefined8 param_1,longlong param_2)

{
  free(*(void **)(param_2 + 0x48));
  return;
}



void Unwind_18001b33d(undefined8 param_1,longlong param_2)

{
  free(*(void **)(param_2 + 0x48));
  return;
}



void Unwind_18001b360(undefined8 param_1,longlong param_2)

{
  free(*(void **)(param_2 + 0x68));
  return;
}



void Unwind_18001b37d(undefined8 param_1,longlong param_2)

{
  free(*(void **)(param_2 + 0x68));
  return;
}



void Unwind_18001b3a0(undefined8 param_1,longlong param_2)

{
  FUN_180017260(*(undefined8 **)(param_2 + 0x40));
  return;
}



void Unwind_18001b3b0(undefined8 param_1,longlong param_2)

{
  FUN_180012820((undefined8 *)(param_2 + 0x70));
  return;
}



void Unwind_18001b3bc(undefined8 param_1,longlong param_2)

{
  FUN_180012820((undefined8 *)(param_2 + 0x70));
  return;
}



void Unwind_18001b3c8(undefined8 param_1,longlong param_2)

{
  FUN_180012820((undefined8 *)(param_2 + 0x70));
  return;
}



void Unwind_18001b3d4(undefined8 param_1,longlong param_2)

{
  FUN_180012820((undefined8 *)(param_2 + 0x70));
  return;
}



void Unwind_18001b3e0(undefined8 param_1,longlong param_2)

{
  FUN_180012820((undefined8 *)(param_2 + 0x70));
  return;
}



void Unwind_18001b3ec(undefined8 param_1,longlong param_2)

{
  FUN_180012820((undefined8 *)(param_2 + 0x70));
  return;
}



void Unwind_18001b3f8(undefined8 param_1,longlong param_2)

{
  FUN_180012820((undefined8 *)(param_2 + 0x70));
  return;
}



void Unwind_18001b404(undefined8 param_1,longlong param_2)

{
  FUN_180012820((undefined8 *)(param_2 + 0x70));
  return;
}



void Unwind_18001b410(undefined8 param_1,longlong param_2)

{
  FUN_180012820((undefined8 *)(param_2 + 0x70));
  return;
}



void Unwind_18001b41c(undefined8 param_1,longlong param_2)

{
  FUN_180012820((undefined8 *)(param_2 + 0x70));
  return;
}



void Unwind_18001b430(undefined8 param_1,longlong param_2)

{
  FUN_180012820((undefined8 *)(param_2 + 0x90));
  return;
}



void Unwind_18001b43c(undefined8 param_1,longlong param_2)

{
  FUN_180010f50((ulonglong **)(param_2 + 0x70));
  return;
}



void Unwind_18001b450(undefined8 param_1,longlong param_2)

{
  FUN_180019740((longlong **)(param_2 + 0x28));
  return;
}



void Unwind_18001b45c(undefined8 param_1,longlong param_2)

{
  FUN_180019780((longlong **)(param_2 + 0x28));
  return;
}



undefined * Catch_All_18001b468(undefined8 param_1,longlong param_2)

{
  std::basic_ios<char,struct_std::char_traits<char>_>::setstate
            ((basic_ios_char_struct_std__char_traits_char___ *)
             ((longlong)*(int *)(**(longlong **)(param_2 + 0x70) + 4) +
             (longlong)*(longlong **)(param_2 + 0x70)),4,true);
  return &DAT_1800196c1;
}



void Unwind_18001b4a0(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae12. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_terminate();
  return;
}



void Unwind_18001b4a5(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae12. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_terminate();
  return;
}



void Unwind_18001b4b0(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001ae12. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_terminate();
  return;
}



void FUN_18001b4cc(undefined8 param_1,longlong param_2)

{
  __scrt_dllmain_uninitialize_critical();
  __scrt_release_startup_lock(*(char *)(param_2 + 0x38));
  return;
}



void FUN_18001b4e8(undefined8 *param_1,longlong param_2)

{
  __scrt_dllmain_exception_filter
            (*(undefined8 *)(param_2 + 0x60),*(int *)(param_2 + 0x68),
             *(undefined8 *)(param_2 + 0x70),dllmain_crt_dispatch,*(undefined4 *)*param_1,param_1);
  return;
}



void FUN_18001b51e(undefined8 param_1,longlong param_2)

{
  if (*(char *)(param_2 + 0x20) == '\0') {
    __ArrayUnwind(*(void **)(param_2 + 0x50),*(__uint64 *)(param_2 + 0x58),
                  *(__uint64 *)(param_2 + 0x28),*(_func_void_void_ptr **)(param_2 + 0x70));
  }
  return;
}



void FUN_18001b54a(undefined8 param_1,longlong param_2)

{
  if (*(char *)(param_2 + 0x20) == '\0') {
    __ArrayUnwind(*(void **)(param_2 + 0x60),*(__uint64 *)(param_2 + 0x68),
                  *(__uint64 *)(param_2 + 0x70),*(_func_void_void_ptr **)(param_2 + 0x78));
  }
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



undefined * Catch_All_18001b5cf(void)

{
  return &DAT_18001ac15;
}


