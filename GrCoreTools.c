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

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

typedef int __ehstate_t;

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

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    ImageBaseOffset32 action;
};

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

typedef struct _s_IPToStateMapEntry _s_IPToStateMapEntry, *P_s_IPToStateMapEntry;

struct _s_IPToStateMapEntry {
    ImageBaseOffset32 Ip;
    __ehstate_t state;
};

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef struct _s_IPToStateMapEntry IPToStateMapEntry;

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

typedef struct _s_HandlerType HandlerType;

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Class Structure
};


// WARNING! conflicting data type names: /guiddef.h/GUID - /GUID

typedef struct _GUID _GUID, *P_GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

typedef long LONG;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (* PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT * PCONTEXT;

typedef ulong DWORD;

typedef void * PVOID;

typedef ulonglong ULONG_PTR;

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

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef union _ULARGE_INTEGER _ULARGE_INTEGER, *P_ULARGE_INTEGER;

typedef union _ULARGE_INTEGER ULARGE_INTEGER;

typedef struct _struct_22 _struct_22, *P_struct_22;

typedef struct _struct_23 _struct_23, *P_struct_23;

struct _struct_23 {
    DWORD LowPart;
    DWORD HighPart;
};

struct _struct_22 {
    DWORD LowPart;
    DWORD HighPart;
};

union _ULARGE_INTEGER {
    struct _struct_22 s;
    struct _struct_23 u;
    ULONGLONG QuadPart;
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

typedef void * HANDLE;

typedef long HRESULT;

typedef ULARGE_INTEGER * PULARGE_INTEGER;

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

typedef struct IHashProgress IHashProgress, *PIHashProgress;

struct IHashProgress { // PlaceHolder Class Structure
};

typedef struct IHashAlgorithm IHashAlgorithm, *PIHashAlgorithm;

struct IHashAlgorithm { // PlaceHolder Class Structure
};

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[68];
};

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

typedef int BOOL;

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


// WARNING! conflicting data type names: /Demangler/Graphine/GUID - /GUID

typedef struct DataTypeInfo DataTypeInfo, *PDataTypeInfo;

struct DataTypeInfo { // PlaceHolder Structure
};

typedef struct MD5Calculation MD5Calculation, *PMD5Calculation;

struct MD5Calculation { // PlaceHolder Structure
};

typedef struct MD5Hash MD5Hash, *PMD5Hash;

struct MD5Hash { // PlaceHolder Structure
};

typedef enum Enum {
} Enum;

typedef struct basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_> basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>, *Pbasic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>;

struct basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_> { // PlaceHolder Structure
};

typedef int (* _onexit_t)(void);

typedef int errno_t;

typedef ulonglong size_t;




void ** FUN_180001000(void **param_1,void **param_2)

{
  void *pvVar1;
  
  pvVar1 = (void *)0x0;
  param_1[3] = (void *)0x7;
  param_1[2] = (void *)0x0;
  *(undefined2 *)param_1 = 0;
  if (*(short *)param_2 != 0) {
    pvVar1 = (void *)0xffffffffffffffff;
    do {
      pvVar1 = (void *)((longlong)pvVar1 + 1);
    } while (*(short *)((longlong)param_2 + (longlong)pvVar1 * 2) != 0);
  }
  FUN_180001c60(param_1,param_2,pvVar1);
  return param_1;
}



// public: __cdecl Graphine::Core::IHashAlgorithm::IHashAlgorithm(class
// Graphine::Core::IHashAlgorithm && __ptr64) __ptr64

IHashAlgorithm * __thiscall
Graphine::Core::IHashAlgorithm::IHashAlgorithm(IHashAlgorithm *this,IHashAlgorithm *param_1)

{
                    // 0x1050  1  ??0IHashAlgorithm@Core@Graphine@@QEAA@$$QEAV012@@Z
                    // 0x1050  2  ??0IHashAlgorithm@Core@Graphine@@QEAA@AEBV012@@Z
                    // 0x1050  3  ??0IHashAlgorithm@Core@Graphine@@QEAA@XZ
  *(undefined ***)this = vftable;
  return this;
}



// public: __cdecl Graphine::Core::IHashProgress::IHashProgress(class Graphine::Core::IHashProgress
// const & __ptr64) __ptr64

IHashProgress * __thiscall
Graphine::Core::IHashProgress::IHashProgress(IHashProgress *this,IHashProgress *param_1)

{
                    // 0x1060  4  ??0IHashProgress@Core@Graphine@@QEAA@AEBV012@@Z
                    // 0x1060  5  ??0IHashProgress@Core@Graphine@@QEAA@XZ
  *(undefined ***)this = vftable;
  return this;
}



// public: virtual __cdecl Graphine::Core::IHashProgress::~IHashProgress(void) __ptr64

void __thiscall Graphine::Core::IHashProgress::_IHashProgress(IHashProgress *this)

{
                    // 0x1070  7  ??1IHashProgress@Core@Graphine@@UEAA@XZ
  *(undefined ***)this = vftable;
  return;
}



// public: class Graphine::Core::DataTypeInfo & __ptr64 __cdecl
// Graphine::Core::DataTypeInfo::operator=(class Graphine::Core::DataTypeInfo && __ptr64) __ptr64

DataTypeInfo * __thiscall
Graphine::Core::DataTypeInfo::operator_(DataTypeInfo *this,DataTypeInfo *param_1)

{
                    // 0x1080  9  ??4DataTypeInfo@Core@Graphine@@QEAAAEAV012@$$QEAV012@@Z
                    // 0x1080  10  ??4DataTypeInfo@Core@Graphine@@QEAAAEAV012@AEBV012@@Z
                    // 0x1080  11  ??4DiskManagement@Core@Graphine@@QEAAAEAV012@$$QEAV012@@Z
                    // 0x1080  12  ??4DiskManagement@Core@Graphine@@QEAAAEAV012@AEBV012@@Z
                    // 0x1080  13  ??4GuidBuilder@Core@Graphine@@QEAAAEAV012@$$QEAV012@@Z
                    // 0x1080  14  ??4GuidBuilder@Core@Graphine@@QEAAAEAV012@AEBV012@@Z
                    // 0x1080  15  ??4IHashAlgorithm@Core@Graphine@@QEAAAEAV012@$$QEAV012@@Z
                    // 0x1080  16  ??4IHashAlgorithm@Core@Graphine@@QEAAAEAV012@AEBV012@@Z
                    // 0x1080  17  ??4IHashProgress@Core@Graphine@@QEAAAEAV012@AEBV012@@Z
                    // 0x1080  19  ??4MD5Checker@Core@Graphine@@QEAAAEAV012@$$QEAV012@@Z
                    // 0x1080  20  ??4MD5Checker@Core@Graphine@@QEAAAEAV012@AEBV012@@Z
  return this;
}



// public: class Graphine::Core::MD5Calculation & __ptr64 __cdecl
// Graphine::Core::MD5Calculation::operator=(class Graphine::Core::MD5Calculation const & __ptr64)
// __ptr64

MD5Calculation * __thiscall
Graphine::Core::MD5Calculation::operator_(MD5Calculation *this,MD5Calculation *param_1)

{
                    // 0x1090  18  ??4MD5Calculation@Core@Graphine@@QEAAAEAV012@AEBV012@@Z
  *(undefined8 *)this = *(undefined8 *)param_1;
  return this;
}



// public: struct Graphine::Core::MD5Hash & __ptr64 __cdecl
// Graphine::Core::MD5Hash::operator=(struct Graphine::Core::MD5Hash && __ptr64) __ptr64

MD5Hash * __thiscall Graphine::Core::MD5Hash::operator_(MD5Hash *this,MD5Hash *param_1)

{
  MD5Hash *pMVar1;
  longlong lVar2;
  
                    // 0x10a0  21  ??4MD5Hash@Core@Graphine@@QEAAAEAU012@$$QEAU012@@Z
  lVar2 = 0x10;
  pMVar1 = this;
  do {
    *pMVar1 = pMVar1[(longlong)param_1 - (longlong)this];
    pMVar1 = pMVar1 + 1;
    lVar2 = lVar2 + -1;
  } while (lVar2 != 0);
  return this;
}



// public: struct Graphine::Core::MD5Hash & __ptr64 __cdecl
// Graphine::Core::MD5Hash::operator=(struct Graphine::Core::MD5Hash const & __ptr64) __ptr64

MD5Hash * __thiscall Graphine::Core::MD5Hash::operator_(MD5Hash *this,MD5Hash *param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  
                    // 0x10d0  22  ??4MD5Hash@Core@Graphine@@QEAAAEAU012@AEBU012@@Z
  uVar1 = *(undefined4 *)(param_1 + 4);
  uVar2 = *(undefined4 *)(param_1 + 8);
  uVar3 = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)this = *(undefined4 *)param_1;
  *(undefined4 *)(this + 4) = uVar1;
  *(undefined4 *)(this + 8) = uVar2;
  *(undefined4 *)(this + 0xc) = uVar3;
  return this;
}



undefined8 * FUN_1800010e0(undefined8 *param_1,uint param_2)

{
  if ((param_2 & 2) == 0) {
    *param_1 = Graphine::Core::IHashProgress::vftable;
    if ((param_2 & 1) != 0) {
      free(param_1);
    }
  }
  else {
    _eh_vector_destructor_iterator_
              (param_1,8,param_1[-1],Graphine::Core::IHashProgress::_IHashProgress);
    if ((param_2 & 1) != 0) {
      free(param_1 + -1);
    }
    param_1 = param_1 + -1;
  }
  return param_1;
}



// public: static enum Graphine::Core::ChannelDataType::Enum __cdecl
// Graphine::Core::DataTypeInfo::GetChannelDataType(enum Graphine::Core::DataType::Enum)

Enum __cdecl Graphine::Core::DataTypeInfo::GetChannelDataType(Enum param_1)

{
                    // 0x1170  30
                    // ?GetChannelDataType@DataTypeInfo@Core@Graphine@@SA?AW4Enum@ChannelDataType@23@W44DataType@23@@Z
  switch(param_1) {
  case 0:
  case 1:
  case 2:
  case 3:
  case 4:
  case 5:
  case 6:
  case 7:
  case 8:
    return 0;
  case 9:
  case 10:
  case 0xb:
  case 0xc:
    return 1;
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
  case 0x17:
  case 0x18:
    return 3;
  case 0x19:
  case 0x1a:
    return 4;
  default:
    return 0x7fffffff;
  }
}



// public: static int __cdecl Graphine::Core::DataTypeInfo::GetChannelSize(enum
// Graphine::Core::ChannelDataType::Enum)

int __cdecl Graphine::Core::DataTypeInfo::GetChannelSize(Enum param_1)

{
                    // 0x11e0  31
                    // ?GetChannelSize@DataTypeInfo@Core@Graphine@@SAHW4Enum@ChannelDataType@23@@Z
  if (param_1 == 0) {
    return 1;
  }
  if (param_1 != 1) {
    if ((param_1 == 2) || (param_1 == 3)) {
      return 4;
    }
    if (param_1 != 4) {
      return 0;
    }
  }
  return 2;
}



// public: static int __cdecl Graphine::Core::DataTypeInfo::GetChannelSize(enum
// Graphine::Core::DataType::Enum)

int __cdecl Graphine::Core::DataTypeInfo::GetChannelSize(Enum param_1)

{
  Enum EVar1;
  
                    // 0x1210  32
                    // ?GetChannelSize@DataTypeInfo@Core@Graphine@@SAHW4Enum@DataType@23@@Z
  EVar1 = GetChannelDataType(param_1);
  if (EVar1 == 0) {
    return 1;
  }
  if (EVar1 != 1) {
    if ((EVar1 == 2) || (EVar1 == 3)) {
      return 4;
    }
    if (EVar1 != 4) {
      return 0;
    }
  }
  return 2;
}



// public: static enum Graphine::Core::DataType::Enum __cdecl
// Graphine::Core::DataTypeInfo::GetDatatype(enum Graphine::Core::ChannelDataType::Enum,int,int)

Enum __cdecl Graphine::Core::DataTypeInfo::GetDatatype(Enum param_1,int param_2,int param_3)

{
  Enum in_EAX;
  Enum EVar1;
  
                    // 0x1260  33
                    // ?GetDatatype@DataTypeInfo@Core@Graphine@@SA?AW4Enum@DataType@23@W44ChannelDataType@23@HH@Z
  if (param_2 == 1) {
    if (param_1 == 0) {
      return 5;
    }
    if (param_1 == 1) {
      return 9;
    }
    if (param_1 == 2) {
      return 0xd;
    }
    if (param_1 == 3) {
      return 0xe;
    }
  }
  else {
    if (param_2 != 2) {
      if (param_2 != 3) {
        if (param_2 != 4) {
          return 0x7fffffff;
        }
        if (param_1 == 0) {
          if ((param_3 & 8U) == 0) {
            return 8;
          }
          EVar1 = 4;
          if ((param_3 & 1U) != 0) {
            EVar1 = 1;
          }
          return EVar1;
        }
        if (param_1 == 1) {
          return 0xc;
        }
        if (param_1 != 2) {
          if (param_1 == 3) {
            EVar1 = 0x16;
            if ((param_3 & 8U) != 0) {
              EVar1 = 0x18;
            }
            return EVar1;
          }
          if (param_1 != 4) {
            return in_EAX;
          }
          return 0x1a;
        }
        return 0x15;
      }
      if (param_1 == 0) {
        if ((param_3 & 8U) == 0) {
          return 7;
        }
        EVar1 = 3;
        if ((param_3 & 1U) != 0) {
          EVar1 = 0;
        }
        return EVar1;
      }
      if (param_1 == 1) {
        return 0xb;
      }
      if (param_1 == 2) {
        return 0x11;
      }
      if (param_1 != 3) {
        if (param_1 != 4) {
          return in_EAX;
        }
        return 0x19;
      }
      EVar1 = 0x12;
      if ((param_3 & 8U) != 0) {
        EVar1 = 0x14;
      }
      return EVar1;
    }
    if (param_1 == 0) {
      return ~(param_3 * 2) & 4U | 2;
    }
    if (param_1 == 1) {
      return 10;
    }
    if (param_1 == 2) {
      return 0xf;
    }
    if (param_1 == 3) {
      return 0x10;
    }
  }
  if (param_1 != 4) {
    return in_EAX;
  }
  return 0x7fffffff;
}



// public: static int __cdecl Graphine::Core::DataTypeInfo::GetFlags(enum
// Graphine::Core::DataType::Enum)

int __cdecl Graphine::Core::DataTypeInfo::GetFlags(Enum param_1)

{
  int iVar1;
  
                    // 0x13a0  34  ?GetFlags@DataTypeInfo@Core@Graphine@@SAHW4Enum@DataType@23@@Z
  iVar1 = 0;
  switch(param_1) {
  case 0:
  case 1:
    return 9;
  case 2:
    return 2;
  case 3:
  case 4:
  case 0x13:
  case 0x14:
  case 0x17:
  case 0x18:
  case 0x19:
  case 0x1a:
    return 8;
  case 5:
  case 6:
  case 7:
  case 8:
  case 9:
  case 10:
  case 0xb:
  case 0xc:
  case 0xd:
  case 0xf:
  case 0x11:
  case 0x15:
    iVar1 = 4;
    break;
  case 0xe:
  case 0x10:
  case 0x12:
  case 0x16:
    return 0x10;
  }
  return iVar1;
}



// public: static int __cdecl Graphine::Core::DataTypeInfo::GetNumChannels(enum
// Graphine::Core::DataType::Enum)

int __cdecl Graphine::Core::DataTypeInfo::GetNumChannels(Enum param_1)

{
                    // 0x1420  37
                    // ?GetNumChannels@DataTypeInfo@Core@Graphine@@SAHW4Enum@DataType@23@@Z
  switch(param_1) {
  case 0:
  case 3:
  case 7:
  case 0xb:
  case 0x11:
  case 0x12:
  case 0x13:
  case 0x14:
  case 0x19:
    return 3;
  case 1:
  case 4:
  case 8:
  case 0xc:
  case 0x15:
  case 0x16:
  case 0x17:
  case 0x18:
  case 0x1a:
    return 4;
  case 2:
  case 6:
  case 10:
  case 0xf:
  case 0x10:
    return 2;
  case 5:
  case 9:
  case 0xd:
  case 0xe:
    return 1;
  default:
    return 0;
  }
}



// public: static int __cdecl Graphine::Core::DataTypeInfo::GetPixelSize(enum
// Graphine::Core::DataType::Enum)

int __cdecl Graphine::Core::DataTypeInfo::GetPixelSize(Enum param_1)

{
  Enum EVar1;
  int iVar2;
  int iVar3;
  
                    // 0x1490  38
                    // ?GetPixelSize@DataTypeInfo@Core@Graphine@@SAHW4Enum@DataType@23@@Z
  EVar1 = GetChannelDataType(param_1);
  if (EVar1 == 0) {
    iVar3 = 1;
    goto LAB_1800014d0;
  }
  if (EVar1 != 1) {
    if ((EVar1 == 2) || (EVar1 == 3)) {
      iVar3 = 4;
      goto LAB_1800014d0;
    }
    if (EVar1 != 4) {
      iVar3 = 0;
      goto LAB_1800014d0;
    }
  }
  iVar3 = 2;
LAB_1800014d0:
  iVar2 = GetNumChannels(param_1);
  return iVar2 * iVar3;
}



// public: static bool __cdecl Graphine::Core::DataTypeInfo::IsLinear(enum
// Graphine::Core::DataType::Enum)

bool __cdecl Graphine::Core::DataTypeInfo::IsLinear(Enum param_1)

{
  int iVar1;
  
                    // 0x14f0  40  ?IsLinear@DataTypeInfo@Core@Graphine@@SA_NW4Enum@DataType@23@@Z
  iVar1 = GetFlags(param_1);
  return (bool)(~(byte)iVar1 & 1);
}



// public: static class std::basic_string<wchar_t,struct std::char_traits<wchar_t>,class
// std::allocator<wchar_t> > const __cdecl Graphine::Core::DataTypeInfo::ToString(enum
// Graphine::Core::DataType::Enum)

basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t___ __cdecl
Graphine::Core::DataTypeInfo::ToString(Enum param_1)

{
  basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t___ bVar1;
  undefined4 in_register_0000000c;
  void **ppvVar2;
  undefined4 in_EDX;
  
                    // 0x1510  44
                    // ?ToString@DataTypeInfo@Core@Graphine@@SA?BV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@W4Enum@DataType@23@@Z
  ppvVar2 = (void **)CONCAT44(in_register_0000000c,param_1);
  bVar1 = SUB41(param_1,0);
  switch(in_EDX) {
  case 0:
    ppvVar2[2] = (void *)0x0;
    ppvVar2[3] = (void *)0x7;
    *(undefined2 *)ppvVar2 = 0;
    FUN_180001c60(ppvVar2,(void **)L"R8G8B8_SRGB",(void *)0xb);
    return bVar1;
  case 1:
    ppvVar2[2] = (void *)0x0;
    ppvVar2[3] = (void *)0x7;
    *(undefined2 *)ppvVar2 = 0;
    FUN_180001c60(ppvVar2,(void **)L"R8G8B8A8_SRGB",(void *)0xd);
    return bVar1;
  case 2:
    ppvVar2[2] = (void *)0x0;
    ppvVar2[3] = (void *)0x7;
    *(undefined2 *)ppvVar2 = 0;
    FUN_180001c60(ppvVar2,(void **)L"X8Y8Z0_TANGENT",(void *)0xe);
    return bVar1;
  case 3:
    ppvVar2[2] = (void *)0x0;
    ppvVar2[3] = (void *)0x7;
    *(undefined2 *)ppvVar2 = 0;
    FUN_180001c60(ppvVar2,(void **)L"R8G8B8_LINEAR",(void *)0xd);
    return bVar1;
  case 4:
    ppvVar2[2] = (void *)0x0;
    ppvVar2[3] = (void *)0x7;
    *(undefined2 *)ppvVar2 = 0;
    FUN_180001c60(ppvVar2,(void **)L"R8G8B8A8_LINEAR",(void *)0xf);
    return bVar1;
  case 5:
    ppvVar2[2] = (void *)0x0;
    ppvVar2[3] = (void *)0x7;
    *(undefined2 *)ppvVar2 = 0;
    FUN_180001c60(ppvVar2,(void **)&DAT_180005358,(void *)0x2);
    return bVar1;
  case 6:
    ppvVar2[2] = (void *)0x0;
    ppvVar2[3] = (void *)0x7;
    *(undefined2 *)ppvVar2 = 0;
    FUN_180001c60(ppvVar2,(void **)L"X8Y8",(void *)0x4);
    return bVar1;
  case 7:
    ppvVar2[2] = (void *)0x0;
    ppvVar2[3] = (void *)0x7;
    *(undefined2 *)ppvVar2 = 0;
    FUN_180001c60(ppvVar2,(void **)L"X8Y8Z8",(void *)0x6);
    return bVar1;
  case 8:
    ppvVar2[2] = (void *)0x0;
    ppvVar2[3] = (void *)0x7;
    *(undefined2 *)ppvVar2 = 0;
    FUN_180001c60(ppvVar2,(void **)L"X8Y8Z8W8",(void *)0x8);
    return bVar1;
  case 9:
    ppvVar2[2] = (void *)0x0;
    ppvVar2[3] = (void *)0x7;
    *(undefined2 *)ppvVar2 = 0;
    FUN_180001c60(ppvVar2,(void **)&DAT_180005398,(void *)0x3);
    return bVar1;
  case 10:
    ppvVar2[2] = (void *)0x0;
    ppvVar2[3] = (void *)0x7;
    *(undefined2 *)ppvVar2 = 0;
    FUN_180001c60(ppvVar2,(void **)L"X16Y16",(void *)0x6);
    return bVar1;
  case 0xb:
    ppvVar2[2] = (void *)0x0;
    ppvVar2[3] = (void *)0x7;
    *(undefined2 *)ppvVar2 = 0;
    FUN_180001c60(ppvVar2,(void **)L"X16Y16Z16",(void *)0x9);
    return bVar1;
  case 0xc:
    ppvVar2[2] = (void *)0x0;
    ppvVar2[3] = (void *)0x7;
    *(undefined2 *)ppvVar2 = 0;
    FUN_180001c60(ppvVar2,(void **)L"X16Y16Z16W16",(void *)0xc);
    return bVar1;
  case 0xd:
    ppvVar2[2] = (void *)0x0;
    ppvVar2[3] = (void *)0x7;
    *(undefined2 *)ppvVar2 = 0;
    FUN_180001c60(ppvVar2,(void **)&DAT_1800053e8,(void *)0x3);
    return bVar1;
  case 0xe:
    FUN_180001000(ppvVar2,(void **)L"X32_FLOAT");
    return bVar1;
  case 0xf:
    FUN_180001000(ppvVar2,(void **)L"X32Y32");
    return bVar1;
  case 0x10:
    FUN_180001000(ppvVar2,(void **)L"X32Y32_FLOAT");
    return bVar1;
  case 0x11:
    FUN_180001000(ppvVar2,(void **)L"X32Y32Z32");
    return bVar1;
  case 0x12:
    FUN_180001000(ppvVar2,(void **)L"X32Y32Z32_FLOAT");
    return bVar1;
  case 0x13:
    FUN_180001000(ppvVar2,(void **)L"R32G32B32");
    return bVar1;
  case 0x14:
    FUN_180001000(ppvVar2,(void **)L"R32G32B32_FLOAT");
    return bVar1;
  case 0x15:
    FUN_180001000(ppvVar2,(void **)L"X32Y32Z32W32");
    return bVar1;
  case 0x16:
    FUN_180001000(ppvVar2,(void **)L"X32Y32Z32W32_FLOAT");
    return bVar1;
  case 0x17:
    FUN_180001000(ppvVar2,(void **)L"R32G32B32A32");
    return bVar1;
  case 0x18:
    FUN_180001000(ppvVar2,(void **)L"R32G32B32A32_FLOAT");
    return bVar1;
  case 0x19:
    FUN_180001000(ppvVar2,(void **)L"R16G16B16_FLOAT");
    return bVar1;
  case 0x1a:
    FUN_180001000(ppvVar2,(void **)L"R16G16B16A16_FLOAT");
    return bVar1;
  default:
    FUN_180001000(ppvVar2,(void **)0x0);
    return bVar1;
  }
}



void FUN_180001980(void **param_1,void *param_2,void *param_3)

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
  _Dst = (void **)FUN_180001aa0(param_1,(longlong)param_2 + 1);
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
    FUN_180001db0(param_1,*param_1,(longlong)param_1[3] + 1);
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



void * FUN_180001aa0(undefined8 param_1,ulonglong param_2)

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



void ** FUN_180001b20(void **param_1,void **param_2,void *param_3,void *param_4)

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
    FUN_180001e20(param_1,0,(ulonglong)param_3);
  }
  else {
    if ((void *)0x7ffffffffffffffe < param_4) {
      std::_Xlength_error("string too long");
      pcVar1 = (code *)swi(3);
      ppvVar2 = (void **)(*pcVar1)();
      return ppvVar2;
    }
    if (param_1[3] < param_4) {
      FUN_180001980(param_1,param_4,param_1[2]);
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



void ** FUN_180001c60(void **param_1,void **param_2,void *param_3)

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
        ppvVar3 = FUN_180001b20(param_1,param_1,(void *)((longlong)param_2 - (longlong)ppvVar3 >> 1)
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
    FUN_180001980(param_1,param_3,param_1[2]);
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



void FUN_180001db0(undefined8 param_1,void *param_2,ulonglong param_3)

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



undefined8 * FUN_180001e20(undefined8 *param_1,ulonglong param_2,ulonglong param_3)

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



void FUN_180001ed0(void **param_1)

{
  if ((void *)0x7 < param_1[3]) {
    FUN_180001db0(param_1,*param_1,(longlong)param_1[3] + 1);
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



// public: static void __cdecl Graphine::Core::MD5Checker::Abort(void)

void __cdecl Graphine::Core::MD5Checker::Abort(void)

{
                    // 0x1f20  25  ?Abort@MD5Checker@Core@Graphine@@SAXXZ
  DAT_1800081c0 = 1;
  return;
}



// public: static void __cdecl Graphine::Core::MD5Checker::CalculateChecksum(class
// std::basic_string<wchar_t,struct std::char_traits<wchar_t>,class std::allocator<wchar_t> > const
// & __ptr64,struct Graphine::Core::MD5Hash & __ptr64,class Graphine::Core::IHashProgress * __ptr64)

void __cdecl
Graphine::Core::MD5Checker::CalculateChecksum
          (basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t___
           *param_1,MD5Hash *param_2,IHashProgress *param_3)

{
  longlong lVar1;
  int iVar2;
  __uint64 _Size;
  longlong lVar3;
  uchar *_DstBuf;
  longlong lVar4;
  longlong _Offset;
  longlong lVar5;
  FILE *local_res8;
  MD5Calculation local_res10 [8];
  
                    // 0x1f30  27
                    // ?CalculateChecksum@MD5Checker@Core@Graphine@@SAXAEBV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@AEAUMD5Hash@23@PEAVIHashProgress@23@@Z
  MD5Calculation::MD5Calculation(local_res10);
  _Size = MD5Calculation::HashLength(local_res10);
  memset(param_2,0,_Size);
  DAT_1800081c0 = '\0';
  _Offset = 0;
  local_res8 = (FILE *)0x0;
  if (7 < *(ulonglong *)(param_1 + 0x18)) {
    param_1 = *(basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t___
                **)param_1;
  }
  _wfopen_s(&local_res8,(wchar_t *)param_1,L"rb");
  if ((local_res8 != (FILE *)0x0) && (iVar2 = ferror(local_res8), iVar2 == 0)) {
    if (param_3 != (IHashProgress *)0x0) {
      (***(code ***)param_3)(param_3);
    }
    _fseeki64(local_res8,0,2);
    lVar3 = _ftelli64(local_res8);
    _DstBuf = (uchar *)operator_new(0x100000);
    _fseeki64(local_res8,0,0);
    lVar4 = _Offset;
    lVar5 = _Offset;
    if (0x100000 < lVar3) {
      do {
        fread(_DstBuf,1,0x100000,local_res8);
        iVar2 = ferror(local_res8);
        if (iVar2 != 0) goto LAB_1800020b4;
        MD5Calculation::AddBytes(local_res10,_DstBuf,0x100000);
        _Offset = lVar4 + 0x100000;
        _fseeki64(local_res8,_Offset,0);
        if (param_3 != (IHashProgress *)0x0) {
          (**(code **)(*(longlong *)param_3 + 8))(param_3,(double)((lVar5 + 0x6400000) / lVar3));
        }
        if (DAT_1800081c0 != '\0') goto LAB_1800020b4;
        lVar1 = lVar4 + 0x200000;
        lVar4 = _Offset;
        lVar5 = lVar5 + 0x6400000;
      } while (lVar1 < lVar3);
    }
    fread(_DstBuf,1,lVar3 - _Offset,local_res8);
    iVar2 = ferror(local_res8);
    if (iVar2 == 0) {
      MD5Calculation::AddBytes(local_res10,_DstBuf,lVar3 - _Offset & 0xffffffff);
      free(_DstBuf);
      fclose(local_res8);
      if (param_3 != (IHashProgress *)0x0) {
        (**(code **)(*(longlong *)param_3 + 0x10))(param_3);
      }
      MD5Calculation::GetHash(local_res10,(uchar *)param_2);
    }
    else {
LAB_1800020b4:
      free(_DstBuf);
      fclose(local_res8);
    }
  }
  MD5Calculation::_MD5Calculation(local_res10);
  return;
}



// WARNING: Type propagation algorithm not settling
// public: static bool __cdecl Graphine::Core::DiskManagement::GetFreeDiskSpace(class
// std::basic_string<wchar_t,struct std::char_traits<wchar_t>,class std::allocator<wchar_t> > const
// & __ptr64,unsigned __int64 & __ptr64)

bool __cdecl
Graphine::Core::DiskManagement::GetFreeDiskSpace
          (basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t___
           *param_1,__uint64 *param_2)

{
  undefined extraout_AL;
  LPCWSTR pWVar1;
  LPCWSTR pWVar2;
  undefined auStack_68 [32];
  ULARGE_INTEGER local_48;
  ULARGE_INTEGER local_40;
  undefined8 local_38;
  undefined8 local_30;
  longlong local_20;
  ulonglong local_18;
  ulonglong local_10;
  
                    // 0x2150  35
                    // ?GetFreeDiskSpace@DiskManagement@Core@Graphine@@SA_NAEBV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@AEA_K@Z
  local_38 = 0xfffffffffffffffe;
  local_10 = DAT_180008040 ^ (ulonglong)auStack_68;
  local_18 = 7;
  local_20 = 0;
  local_30._0_2_ = L'\0';
  FUN_180001b20((void **)&local_30,(void **)param_1,(void *)0x0,(void *)0xffffffffffffffff);
  pWVar2 = (LPCWSTR)CONCAT62(local_30._2_6_,(WCHAR)local_30);
  pWVar1 = (LPCWSTR)&local_30;
  if (7 < local_18) {
    pWVar1 = pWVar2;
  }
  if (pWVar1[local_20 + -1] != L'\\') {
    FUN_180002400((void **)&local_30,(void **)&DAT_180005600,1);
    pWVar2 = (LPCWSTR)CONCAT62(local_30._2_6_,(WCHAR)local_30);
  }
  local_40.QuadPart = 0;
  local_48.QuadPart = 0;
  pWVar1 = (LPCWSTR)&local_30;
  if (7 < local_18) {
    pWVar1 = pWVar2;
  }
  GetDiskFreeSpaceExW(pWVar1,(PULARGE_INTEGER)param_2,&local_40,&local_48);
  if (7 < local_18) {
    FUN_180001db0(&local_30,(void *)CONCAT62(local_30._2_6_,(WCHAR)local_30),local_18 + 1);
  }
  __security_check_cookie(local_10 ^ (ulonglong)auStack_68);
  return (bool)extraout_AL;
}



// WARNING: Could not reconcile some variable overlaps
// public: static void __cdecl Graphine::Core::GuidBuilder::NewGuid(struct Graphine::GUID & __ptr64)

void __cdecl Graphine::Core::GuidBuilder::NewGuid(GUID *param_1)

{
  undefined auStack_58 [32];
  GUID local_38;
  ulong local_28;
  undefined4 uStack_24;
  undefined8 uStack_20;
  ulonglong local_18;
  
                    // 0x2250  41  ?NewGuid@GuidBuilder@Core@Graphine@@SAXAEAUGUID@3@@Z
  local_18 = DAT_180008040 ^ (ulonglong)auStack_58;
  CoCreateGuid(&local_38);
  local_28 = local_38.Data1;
  uStack_24 = CONCAT22(local_38.Data3,local_38.Data2);
  uStack_20 = local_38.Data4;
  uStack_20._0_4_ = SUB84(local_38.Data4,0);
  uStack_20._4_4_ = (undefined4)((ulonglong)local_38.Data4 >> 0x20);
  *(ulong *)param_1 = local_38.Data1;
  *(undefined4 *)(param_1 + 4) = uStack_24;
  *(undefined4 *)(param_1 + 8) = (undefined4)uStack_20;
  *(undefined4 *)(param_1 + 0xc) = uStack_20._4_4_;
  __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
  return;
}



// public: static bool __cdecl Graphine::Core::MD5Checker::Validate(class
// std::basic_string<wchar_t,struct std::char_traits<wchar_t>,class std::allocator<wchar_t> > const
// & __ptr64,struct Graphine::Core::MD5Hash & __ptr64,class Graphine::Core::IHashProgress * __ptr64)

bool __cdecl
Graphine::Core::MD5Checker::Validate
          (basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t___
           *param_1,MD5Hash *param_2,IHashProgress *param_3)

{
                    // 0x22c0  45
                    // ?Validate@MD5Checker@Core@Graphine@@SA_NAEBV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@AEAUMD5Hash@23@PEAVIHashProgress@23@@Z
  CalculateChecksum(param_1,param_2,param_3);
  return true;
}



void ** FUN_1800022d0(void **param_1,undefined8 *param_2,ulonglong param_3,ulonglong param_4)

{
  void *pvVar1;
  void *pvVar2;
  code *pcVar3;
  void **ppvVar4;
  ulonglong uVar5;
  
  if ((ulonglong)param_2[2] < param_3) {
    std::_Xout_of_range("invalid string position");
    pcVar3 = (code *)swi(3);
    ppvVar4 = (void **)(*pcVar3)();
    return ppvVar4;
  }
  pvVar2 = param_1[2];
  uVar5 = param_2[2] - param_3;
  if (uVar5 < param_4) {
    param_4 = uVar5;
  }
  if (param_4 < ~(ulonglong)pvVar2) {
    pvVar1 = (void *)((longlong)pvVar2 + param_4);
    if (param_4 != 0) {
      if ((void *)0x7ffffffffffffffe < pvVar1) {
        std::_Xlength_error("string too long");
        pcVar3 = (code *)swi(3);
        ppvVar4 = (void **)(*pcVar3)();
        return ppvVar4;
      }
      if (param_1[3] < pvVar1) {
        FUN_180001980(param_1,pvVar1,pvVar2);
        if (pvVar1 == (void *)0x0) {
          return param_1;
        }
      }
      else if (pvVar1 == (void *)0x0) {
        param_1[2] = (void *)0x0;
        ppvVar4 = param_1;
        if ((void *)0x7 < param_1[3]) {
          ppvVar4 = (void **)*param_1;
        }
        *(undefined2 *)ppvVar4 = 0;
        return param_1;
      }
      if (7 < (ulonglong)param_2[3]) {
        param_2 = (undefined8 *)*param_2;
      }
      ppvVar4 = param_1;
      if ((void *)0x7 < param_1[3]) {
        ppvVar4 = (void **)*param_1;
      }
      if (param_4 != 0) {
        memcpy((void *)((longlong)ppvVar4 + (longlong)param_1[2] * 2),
               (void *)((longlong)param_2 + param_3 * 2),param_4 * 2);
      }
      param_1[2] = pvVar1;
      ppvVar4 = param_1;
      if ((void *)0x7 < param_1[3]) {
        ppvVar4 = (void **)*param_1;
      }
      *(undefined2 *)((longlong)ppvVar4 + (longlong)pvVar1 * 2) = 0;
    }
    return param_1;
  }
  std::_Xlength_error("string too long");
  pcVar3 = (code *)swi(3);
  ppvVar4 = (void **)(*pcVar3)();
  return ppvVar4;
}



void ** FUN_180002400(void **param_1,void **param_2,ulonglong param_3)

{
  void *pvVar1;
  void *pvVar2;
  code *pcVar3;
  void **ppvVar4;
  
  if (param_2 != (void **)0x0) {
    pvVar2 = param_1[3];
    ppvVar4 = param_1;
    if ((void *)0x7 < pvVar2) {
      ppvVar4 = (void **)*param_1;
    }
    if (ppvVar4 <= param_2) {
      ppvVar4 = param_1;
      if ((void *)0x7 < pvVar2) {
        ppvVar4 = (void **)*param_1;
      }
      if (param_2 < (void **)((longlong)ppvVar4 + (longlong)param_1[2] * 2)) {
        ppvVar4 = param_1;
        if ((void *)0x7 < pvVar2) {
          ppvVar4 = (void **)*param_1;
        }
        ppvVar4 = FUN_1800022d0(param_1,param_1,(longlong)param_2 - (longlong)ppvVar4 >> 1,param_3);
        return ppvVar4;
      }
    }
  }
  pvVar2 = param_1[2];
  if (~(ulonglong)pvVar2 <= param_3) {
    std::_Xlength_error("string too long");
    pcVar3 = (code *)swi(3);
    ppvVar4 = (void **)(*pcVar3)();
    return ppvVar4;
  }
  pvVar1 = (void *)((longlong)pvVar2 + param_3);
  if (param_3 != 0) {
    if ((void *)0x7ffffffffffffffe < pvVar1) {
      std::_Xlength_error("string too long");
      pcVar3 = (code *)swi(3);
      ppvVar4 = (void **)(*pcVar3)();
      return ppvVar4;
    }
    if (param_1[3] < pvVar1) {
      FUN_180001980(param_1,pvVar1,pvVar2);
      if (pvVar1 == (void *)0x0) {
        return param_1;
      }
    }
    else if (pvVar1 == (void *)0x0) {
      param_1[2] = (void *)0x0;
      if ((void *)0x7 < param_1[3]) {
        *(undefined2 *)*param_1 = 0;
        return param_1;
      }
      *(undefined2 *)param_1 = 0;
      return param_1;
    }
    ppvVar4 = param_1;
    if ((void *)0x7 < param_1[3]) {
      ppvVar4 = (void **)*param_1;
    }
    if (param_3 != 0) {
      memcpy((void *)((longlong)ppvVar4 + (longlong)param_1[2] * 2),param_2,param_3 * 2);
    }
    param_1[2] = pvVar1;
    ppvVar4 = param_1;
    if ((void *)0x7 < param_1[3]) {
      ppvVar4 = (void **)*param_1;
    }
    *(undefined2 *)((longlong)ppvVar4 + (longlong)pvVar1 * 2) = 0;
  }
  return param_1;
}



// public: __cdecl Graphine::Core::MD5Calculation::MD5Calculation(void) __ptr64

MD5Calculation * __thiscall Graphine::Core::MD5Calculation::MD5Calculation(MD5Calculation *this)

{
  undefined8 *puVar1;
  
                    // 0x2560  6  ??0MD5Calculation@Core@Graphine@@QEAA@XZ
  puVar1 = (undefined8 *)operator_new(0x78);
  if (puVar1 != (undefined8 *)0x0) {
    *puVar1 = MD5Hasher::vftable;
    *(undefined *)(puVar1 + 1) = 0;
    *(undefined8 *)((longlong)puVar1 + 0x4c) = 0;
    *(undefined4 *)((longlong)puVar1 + 0x54) = 0x67452301;
    *(undefined4 *)(puVar1 + 0xb) = 0xefcdab89;
    *(undefined4 *)((longlong)puVar1 + 0x5c) = 0x98badcfe;
    *(undefined4 *)(puVar1 + 0xc) = 0x10325476;
    *(undefined8 **)this = puVar1;
    return this;
  }
  *(undefined8 *)this = 0;
  return this;
}



// public: __cdecl Graphine::Core::MD5Calculation::~MD5Calculation(void) __ptr64

void __thiscall Graphine::Core::MD5Calculation::_MD5Calculation(MD5Calculation *this)

{
                    // 0x25d0  8  ??1MD5Calculation@Core@Graphine@@QEAA@XZ
  if (*(void **)this != (void *)0x0) {
    free(*(void **)this);
    *(undefined8 *)this = 0;
  }
  return;
}



// public: void __cdecl Graphine::Core::MD5Calculation::AddBytes(unsigned char const *
// __ptr64,unsigned __int64) __ptr64

void __thiscall
Graphine::Core::MD5Calculation::AddBytes(MD5Calculation *this,uchar *param_1,__uint64 param_2)

{
                    // 0x2600  26  ?AddBytes@MD5Calculation@Core@Graphine@@QEAAXPEBE_K@Z
                    // WARNING: Could not recover jumptable at 0x000180002606. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)this + 0x10))();
  return;
}



// public: static void __cdecl Graphine::Core::MD5Calculation::ComputeHash(unsigned char const *
// __ptr64,unsigned __int64,unsigned char * __ptr64,unsigned __int64 * __ptr64)

void __cdecl
Graphine::Core::MD5Calculation::ComputeHash
          (uchar *param_1,__uint64 param_2,uchar *param_3,__uint64 *param_4)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  char *pcVar4;
  __uint64 _Var5;
  undefined auStack_138 [32];
  char local_118 [68];
  undefined8 local_d4;
  undefined4 local_cc;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  undefined **local_a8;
  undefined local_a0;
  undefined8 local_5c;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  ulonglong local_28;
  
                    // 0x2620  28  ?ComputeHash@MD5Calculation@Core@Graphine@@SAXPEBE_KPEAEPEA_K@Z
  local_28 = DAT_180008040 ^ (ulonglong)auStack_138;
  local_cc = 0x67452301;
  local_a8 = MD5Hasher::vftable;
  local_a0 = 0;
  local_5c = 0;
  local_118[0] = '\0';
  local_d4 = 0;
  local_54 = 0x67452301;
  local_50 = 0xefcdab89;
  local_4c = 0x98badcfe;
  local_48 = 0x10325476;
  local_c8 = 0xefcdab89;
  local_c4 = 0x98badcfe;
  local_c0 = 0x10325476;
  FUN_180003230((longlong)local_118,param_1,(uint)param_2);
  pcVar4 = (char *)FUN_180002820(local_118);
  if (*pcVar4 == '\0') {
    *param_3 = '\0';
  }
  uVar1 = *(undefined4 *)(pcVar4 + 0x60);
  uVar2 = *(undefined4 *)(pcVar4 + 100);
  uVar3 = *(undefined4 *)(pcVar4 + 0x68);
  *(undefined4 *)param_3 = *(undefined4 *)(pcVar4 + 0x5c);
  *(undefined4 *)(param_3 + 4) = uVar1;
  *(undefined4 *)(param_3 + 8) = uVar2;
  *(undefined4 *)(param_3 + 0xc) = uVar3;
  _Var5 = (*(code *)local_a8[1])(&local_a8);
  *param_4 = _Var5;
  __security_check_cookie(local_28 ^ (ulonglong)auStack_138);
  return;
}



void FUN_180002710(longlong *param_1,void *param_2,uint param_3,undefined4 *param_4,
                  undefined8 *param_5)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  char *pcVar4;
  undefined8 uVar5;
  undefined auStack_b8 [32];
  char local_98 [68];
  undefined8 local_54;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  ulonglong local_28;
  
  local_28 = DAT_180008040 ^ (ulonglong)auStack_b8;
  local_98[0] = '\0';
  local_54 = 0;
  local_4c = 0x67452301;
  local_48 = 0xefcdab89;
  local_44 = 0x98badcfe;
  local_40 = 0x10325476;
  FUN_180003230((longlong)local_98,param_2,param_3);
  pcVar4 = (char *)FUN_180002820(local_98);
  if (*pcVar4 == '\0') {
    *(undefined *)param_4 = 0;
  }
  uVar1 = *(undefined4 *)(pcVar4 + 0x60);
  uVar2 = *(undefined4 *)(pcVar4 + 100);
  uVar3 = *(undefined4 *)(pcVar4 + 0x68);
  *param_4 = *(undefined4 *)(pcVar4 + 0x5c);
  param_4[1] = uVar1;
  param_4[2] = uVar2;
  param_4[3] = uVar3;
  uVar5 = (**(code **)(*param_1 + 8))(param_1);
  *param_5 = uVar5;
  __security_check_cookie(local_28 ^ (ulonglong)auStack_b8);
  return;
}



// public: void __cdecl Graphine::Core::MD5Calculation::GetHash(unsigned char * __ptr64) __ptr64

void __thiscall Graphine::Core::MD5Calculation::GetHash(MD5Calculation *this,uchar *param_1)

{
                    // 0x27c0  36  ?GetHash@MD5Calculation@Core@Graphine@@QEAAXPEAE@Z
                    // WARNING: Could not recover jumptable at 0x0001800027c6. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(longlong **)this + 0x18))();
  return;
}



void FUN_1800027d0(longlong param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  char *pcVar4;
  
  pcVar4 = (char *)FUN_180002820((char *)(param_1 + 8));
  if (*pcVar4 == '\0') {
    *(undefined *)param_2 = 0;
  }
  uVar1 = *(undefined4 *)(pcVar4 + 0x60);
  uVar2 = *(undefined4 *)(pcVar4 + 100);
  uVar3 = *(undefined4 *)(pcVar4 + 0x68);
  *param_2 = *(undefined4 *)(pcVar4 + 0x5c);
  param_2[1] = uVar1;
  param_2[2] = uVar2;
  param_2[3] = uVar3;
  return;
}



// public: unsigned __int64 __cdecl Graphine::Core::MD5Calculation::HashLength(void)const __ptr64

__uint64 __thiscall Graphine::Core::MD5Calculation::HashLength(MD5Calculation *this)

{
  __uint64 _Var1;
  
                    // 0x2800  39  ?HashLength@MD5Calculation@Core@Graphine@@QEBA_KXZ
                    // WARNING: Could not recover jumptable at 0x000180002806. Too many branches
                    // WARNING: Treating indirect jump as call
  _Var1 = (**(code **)(**(longlong **)this + 8))();
  return _Var1;
}



undefined8 FUN_180002810(void)

{
  return 0x10;
}



void FUN_180002820(char *param_1)

{
  uint uVar1;
  char *pcVar2;
  ulonglong uVar3;
  int iVar4;
  longlong lVar5;
  undefined auStack_38 [32];
  char local_18 [8];
  ulonglong local_10;
  
  local_10 = DAT_180008040 ^ (ulonglong)auStack_38;
  if (*param_1 == '\0') {
    lVar5 = 2;
    pcVar2 = local_18 + 2;
    uVar3 = 0;
    do {
      pcVar2[-2] = param_1[uVar3 * 4 + 0x44];
      pcVar2[-1] = param_1[uVar3 * 4 + 0x45];
      *pcVar2 = param_1[uVar3 * 4 + 0x46];
      pcVar2[1] = param_1[uVar3 * 4 + 0x47];
      lVar5 = lVar5 + -1;
      pcVar2 = pcVar2 + 4;
      uVar3 = (ulonglong)((int)uVar3 + 1);
    } while (lVar5 != 0);
    iVar4 = 0x38;
    uVar1 = *(uint *)(param_1 + 0x44) >> 3 & 0x3f;
    if (0x37 < uVar1) {
      iVar4 = 0x78;
    }
    FUN_180003230((longlong)param_1,&DAT_180008000,iVar4 - uVar1);
    FUN_180003230((longlong)param_1,local_18,8);
    lVar5 = 4;
    pcVar2 = param_1 + 0x5e;
    uVar3 = 0;
    do {
      pcVar2[-2] = param_1[uVar3 * 4 + 0x4c];
      pcVar2[-1] = param_1[uVar3 * 4 + 0x4d];
      *pcVar2 = param_1[uVar3 * 4 + 0x4e];
      pcVar2[1] = param_1[uVar3 * 4 + 0x4f];
      lVar5 = lVar5 + -1;
      pcVar2 = pcVar2 + 4;
      uVar3 = (ulonglong)((int)uVar3 + 1);
    } while (lVar5 != 0);
    *(undefined8 *)(param_1 + 1) = 0;
    *(undefined8 *)(param_1 + 9) = 0;
    *(undefined8 *)(param_1 + 0x11) = 0;
    *(undefined8 *)(param_1 + 0x19) = 0;
    *(undefined8 *)(param_1 + 0x21) = 0;
    *(undefined8 *)(param_1 + 0x29) = 0;
    *(undefined8 *)(param_1 + 0x31) = 0;
    *(undefined8 *)(param_1 + 0x39) = 0;
    *(undefined8 *)(param_1 + 0x44) = 0;
    *param_1 = '\x01';
  }
  __security_check_cookie(local_10 ^ (ulonglong)auStack_38);
  return;
}



void FUN_180002960(longlong param_1,longlong param_2)

{
  undefined2 *puVar1;
  uint uVar2;
  uint uVar3;
  ulonglong uVar4;
  uint uVar5;
  longlong lVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  int local_88 [2];
  longlong local_80;
  int local_78 [4];
  int local_68;
  int local_64;
  int local_60;
  int local_5c;
  int local_58;
  int local_54;
  int local_50;
  int local_4c;
  int local_48;
  int local_44;
  int local_40;
  int local_3c;
  ulonglong local_38;
  
  local_38 = DAT_180008040 ^ (ulonglong)local_88;
  local_88[0] = *(int *)(param_1 + 0x4c);
  uVar7 = *(uint *)(param_1 + 0x50);
  uVar4 = 0;
  uVar5 = *(uint *)(param_1 + 0x54);
  uVar3 = *(uint *)(param_1 + 0x58);
  lVar6 = 0x10;
  puVar1 = (undefined2 *)(param_2 + 2);
  do {
    local_78[uVar4] =
         CONCAT31(CONCAT21(*puVar1,*(undefined *)((longlong)puVar1 + -1)),
                  *(undefined *)(puVar1 + -1));
    uVar4 = (ulonglong)((int)uVar4 + 1);
    lVar6 = lVar6 + -1;
    puVar1 = puVar1 + 2;
  } while (lVar6 != 0);
  uVar2 = local_88[0] + -0x28955b88 + (~uVar7 & uVar3 | uVar5 & uVar7) + local_78[0];
  uVar2 = (uVar2 * 0x80 | uVar2 >> 0x19) + uVar7;
  uVar3 = uVar3 + 0xe8c7b756 + (~uVar2 & uVar5 | uVar7 & uVar2) + local_78[1];
  uVar3 = (uVar3 * 0x1000 | uVar3 >> 0x14) + uVar2;
  uVar5 = uVar5 + 0x242070db + (~uVar3 & uVar7 | uVar3 & uVar2) + local_78[2];
  uVar5 = (uVar5 >> 0xf | uVar5 * 0x20000) + uVar3;
  uVar7 = uVar7 + 0xc1bdceee + (~uVar5 & uVar2 | uVar3 & uVar5) + local_78[3];
  uVar8 = (uVar7 >> 10 | uVar7 * 0x400000) + uVar5;
  uVar7 = uVar2 + 0xf57c0faf + (~uVar8 & uVar3 | uVar5 & uVar8) + local_68;
  uVar2 = (uVar7 * 0x80 | uVar7 >> 0x19) + uVar8;
  uVar7 = uVar3 + 0x4787c62a + (~uVar2 & uVar5 | uVar8 & uVar2) + local_64;
  uVar7 = (uVar7 * 0x1000 | uVar7 >> 0x14) + uVar2;
  uVar5 = uVar5 + 0xa8304613 + (~uVar7 & uVar8 | uVar7 & uVar2) + local_60;
  uVar5 = (uVar5 >> 0xf | uVar5 * 0x20000) + uVar7;
  uVar3 = uVar8 + 0xfd469501 + (~uVar5 & uVar2 | uVar7 & uVar5) + local_5c;
  uVar3 = (uVar3 >> 10 | uVar3 * 0x400000) + uVar5;
  uVar2 = (~uVar3 & uVar7 | uVar5 & uVar3) + 0x698098d8 + local_58 + uVar2;
  uVar2 = (uVar2 * 0x80 | uVar2 >> 0x19) + uVar3;
  uVar7 = uVar7 + (~uVar2 & uVar5 | uVar3 & uVar2) + 0x8b44f7af + local_54;
  uVar7 = (uVar7 * 0x1000 | uVar7 >> 0x14) + uVar2;
  uVar5 = ((~uVar7 & uVar3 | uVar7 & uVar2) - 0xa44f) + local_50 + uVar5;
  uVar5 = (uVar5 >> 0xf | uVar5 * 0x20000) + uVar7;
  uVar3 = uVar3 + (~uVar5 & uVar2 | uVar7 & uVar5) + 0x895cd7be + local_4c;
  uVar3 = (uVar3 >> 10 | uVar3 * 0x400000) + uVar5;
  uVar2 = uVar2 + 0x6b901122 + (~uVar3 & uVar7 | uVar5 & uVar3) + local_48;
  uVar8 = (uVar2 * 0x80 | uVar2 >> 0x19) + uVar3;
  uVar7 = uVar7 + 0xfd987193 + (~uVar8 & uVar5 | uVar3 & uVar8) + local_44;
  uVar7 = (uVar7 * 0x1000 | uVar7 >> 0x14) + uVar8;
  uVar5 = uVar5 + 0xa679438e + (~uVar7 & uVar3 | uVar7 & uVar8) + local_40;
  uVar2 = (uVar5 >> 0xf | uVar5 * 0x20000) + uVar7;
  uVar3 = uVar3 + (~uVar2 & uVar8 | uVar7 & uVar2) + 0x49b40821 + local_3c;
  uVar3 = (uVar3 >> 10 | uVar3 * 0x400000) + uVar2;
  uVar8 = uVar8 + (~uVar7 & uVar2 | uVar7 & uVar3) + local_78[1] + -0x9e1da9e;
  uVar8 = (uVar8 * 0x20 | uVar8 >> 0x1b) + uVar3;
  uVar7 = (uVar2 & uVar8 | ~uVar2 & uVar3) + 0xc040b340 + local_60 + uVar7;
  uVar5 = (uVar7 * 0x200 | uVar7 >> 0x17) + uVar8;
  uVar7 = uVar2 + 0x265e5a51 + (~uVar3 & uVar8 | uVar5 & uVar3) + local_4c;
  uVar7 = (uVar7 * 0x4000 | uVar7 >> 0x12) + uVar5;
  uVar3 = uVar3 + 0xe9b6c7aa + (~uVar8 & uVar5 | uVar7 & uVar8) + local_78[0];
  uVar2 = (uVar3 >> 0xc | uVar3 * 0x100000) + uVar7;
  uVar3 = uVar8 + 0xd62f105d + (~uVar5 & uVar7 | uVar5 & uVar2) + local_64;
  uVar3 = (uVar3 * 0x20 | uVar3 >> 0x1b) + uVar2;
  uVar5 = uVar5 + 0x2441453 + (~uVar7 & uVar2 | uVar7 & uVar3) + local_50;
  uVar8 = (uVar5 * 0x200 | uVar5 >> 0x17) + uVar3;
  uVar7 = uVar7 + 0xd8a1e681 + (~uVar2 & uVar3 | uVar8 & uVar2) + local_3c;
  uVar5 = (uVar7 * 0x4000 | uVar7 >> 0x12) + uVar8;
  uVar7 = uVar2 + 0xe7d3fbc8 + (~uVar3 & uVar8 | uVar5 & uVar3) + local_68;
  uVar7 = (uVar7 >> 0xc | uVar7 * 0x100000) + uVar5;
  uVar3 = uVar3 + 0x21e1cde6 + (~uVar8 & uVar5 | uVar8 & uVar7) + local_54;
  uVar2 = (uVar3 * 0x20 | uVar3 >> 0x1b) + uVar7;
  uVar3 = uVar8 + 0xc33707d6 + (~uVar5 & uVar7 | uVar5 & uVar2) + local_40;
  uVar3 = (uVar3 * 0x200 | uVar3 >> 0x17) + uVar2;
  uVar5 = (~uVar7 & uVar2 | uVar3 & uVar7) + 0xf4d50d87 + local_78[3] + uVar5;
  uVar8 = (uVar5 * 0x4000 | uVar5 >> 0x12) + uVar3;
  uVar7 = uVar7 + 0x455a14ed + (~uVar2 & uVar3 | uVar8 & uVar2) + local_58;
  uVar5 = (uVar7 >> 0xc | uVar7 * 0x100000) + uVar8;
  uVar7 = uVar2 + 0xa9e3e905 + (~uVar3 & uVar8 | uVar3 & uVar5) + local_44;
  uVar7 = (uVar7 * 0x20 | uVar7 >> 0x1b) + uVar5;
  uVar3 = uVar3 + 0xfcefa3f8 + (~uVar8 & uVar5 | uVar8 & uVar7) + local_78[2];
  uVar3 = (uVar3 * 0x200 | uVar3 >> 0x17) + uVar7;
  uVar2 = uVar8 + 0x676f02d9 + (~uVar5 & uVar7 | uVar3 & uVar5) + local_5c;
  uVar2 = (uVar2 * 0x4000 | uVar2 >> 0x12) + uVar3;
  uVar5 = (~uVar7 & uVar3 | uVar2 & uVar7) + 0x8d2a4c8a + local_48 + uVar5;
  uVar8 = (uVar5 >> 0xc | uVar5 * 0x100000) + uVar2;
  uVar7 = uVar7 + ((uVar3 ^ uVar2 ^ uVar8) - 0x5c6be) + local_64;
  uVar7 = (uVar7 * 0x10 | uVar7 >> 0x1c) + uVar8;
  uVar3 = uVar3 + (uVar2 ^ uVar8 ^ uVar7) + 0x8771f681 + local_58;
  uVar5 = (uVar3 * 0x800 | uVar3 >> 0x15) + uVar7;
  uVar2 = uVar2 + (uVar5 ^ uVar8 ^ uVar7) + 0x6d9d6122 + local_4c;
  uVar3 = (uVar2 * 0x10000 | uVar2 >> 0x10) + uVar5;
  uVar8 = uVar8 + (uVar5 ^ uVar3 ^ uVar7) + 0xfde5380c + local_40;
  uVar2 = (uVar8 >> 9 | uVar8 * 0x800000) + uVar3;
  uVar7 = uVar7 + 0xa4beea44 + (uVar5 ^ uVar3 ^ uVar2) + local_78[1];
  uVar8 = (uVar7 * 0x10 | uVar7 >> 0x1c) + uVar2;
  uVar7 = uVar5 + 0x4bdecfa9 + (uVar3 ^ uVar2 ^ uVar8) + local_68;
  uVar7 = (uVar7 * 0x800 | uVar7 >> 0x15) + uVar8;
  uVar5 = uVar3 + 0xf6bb4b60 + (uVar7 ^ uVar2 ^ uVar8) + local_5c;
  uVar5 = (uVar5 * 0x10000 | uVar5 >> 0x10) + uVar7;
  uVar3 = uVar2 + 0xbebfbc70 + (uVar7 ^ uVar5 ^ uVar8) + local_50;
  uVar2 = (uVar3 >> 9 | uVar3 * 0x800000) + uVar5;
  uVar3 = uVar8 + 0x289b7ec6 + (uVar7 ^ uVar5 ^ uVar2) + local_44;
  uVar8 = (uVar3 * 0x10 | uVar3 >> 0x1c) + uVar2;
  uVar7 = uVar7 + 0xeaa127fa + (uVar5 ^ uVar2 ^ uVar8) + local_78[0];
  uVar7 = (uVar7 * 0x800 | uVar7 >> 0x15) + uVar8;
  uVar5 = uVar5 + (uVar7 ^ uVar2 ^ uVar8) + 0xd4ef3085 + local_78[3];
  uVar3 = (uVar5 * 0x10000 | uVar5 >> 0x10) + uVar7;
  uVar5 = uVar2 + 0x4881d05 + (uVar7 ^ uVar3 ^ uVar8) + local_60;
  uVar5 = (uVar5 >> 9 | uVar5 * 0x800000) + uVar3;
  uVar2 = uVar8 + 0xd9d4d039 + (uVar7 ^ uVar3 ^ uVar5) + local_54;
  uVar2 = (uVar2 * 0x10 | uVar2 >> 0x1c) + uVar5;
  uVar7 = (uVar3 ^ uVar5 ^ uVar2) + 0xe6db99e5 + local_48 + uVar7;
  uVar7 = (uVar7 * 0x800 | uVar7 >> 0x15) + uVar2;
  uVar3 = uVar3 + 0x1fa27cf8 + (uVar7 ^ uVar5 ^ uVar2) + local_3c;
  uVar8 = (uVar3 * 0x10000 | uVar3 >> 0x10) + uVar7;
  uVar5 = uVar5 + 0xc4ac5665 + (uVar7 ^ uVar8 ^ uVar2) + local_78[2];
  uVar3 = (uVar5 >> 9 | uVar5 * 0x800000) + uVar8;
  uVar5 = uVar2 + 0xf4292244 + ((~uVar7 | uVar3) ^ uVar8) + local_78[0];
  uVar5 = (uVar5 * 0x40 | uVar5 >> 0x1a) + uVar3;
  uVar7 = uVar7 + 0x432aff97 + ((~uVar8 | uVar5) ^ uVar3) + local_5c;
  uVar2 = (uVar7 * 0x400 | uVar7 >> 0x16) + uVar5;
  uVar7 = uVar8 + 0xab9423a7 + ((~uVar3 | uVar2) ^ uVar5) + local_40;
  uVar7 = (uVar7 * 0x8000 | uVar7 >> 0x11) + uVar2;
  uVar3 = uVar3 + 0xfc93a039 + ((~uVar5 | uVar7) ^ uVar2) + local_64;
  uVar8 = (uVar3 >> 0xb | uVar3 * 0x200000) + uVar7;
  uVar5 = uVar5 + 0x655b59c3 + ((~uVar2 | uVar8) ^ uVar7) + local_48;
  uVar3 = (uVar5 * 0x40 | uVar5 >> 0x1a) + uVar8;
  uVar5 = uVar2 + 0x8f0ccc92 + ((~uVar7 | uVar3) ^ uVar8) + local_78[3];
  uVar5 = (uVar5 * 0x400 | uVar5 >> 0x16) + uVar3;
  uVar7 = (uVar7 - 0x100b83) + ((~uVar8 | uVar5) ^ uVar3) + local_50;
  uVar2 = (uVar7 * 0x8000 | uVar7 >> 0x11) + uVar5;
  uVar7 = uVar8 + 0x85845dd1 + ((~uVar3 | uVar2) ^ uVar5) + local_78[1];
  uVar7 = (uVar7 >> 0xb | uVar7 * 0x200000) + uVar2;
  uVar3 = uVar3 + 0x6fa87e4f + ((~uVar5 | uVar7) ^ uVar2) + local_58;
  uVar3 = (uVar3 * 0x40 | uVar3 >> 0x1a) + uVar7;
  uVar5 = ((~uVar2 | uVar3) ^ uVar7) + 0xfe2ce6e0 + local_3c + uVar5;
  uVar9 = (uVar5 * 0x400 | uVar5 >> 0x16) + uVar3;
  uVar2 = uVar2 + ((~uVar7 | uVar9) ^ uVar3) + 0xa3014314 + local_60;
  uVar5 = (uVar2 * 0x8000 | uVar2 >> 0x11) + uVar9;
  uVar7 = uVar7 + 0x4e0811a1 + ((~uVar3 | uVar5) ^ uVar9) + local_44;
  uVar2 = (uVar7 >> 0xb | uVar7 * 0x200000) + uVar5;
  uVar3 = ((~uVar9 | uVar2) ^ uVar5) + 0xf7537e82 + local_68 + uVar3;
  uVar8 = (uVar3 * 0x40 | uVar3 >> 0x1a) + uVar2;
  uVar7 = uVar9 + 0xbd3af235 + ((~uVar5 | uVar8) ^ uVar2) + local_4c;
  uVar3 = (uVar7 * 0x400 | uVar7 >> 0x16) + uVar8;
  uVar7 = uVar5 + 0x2ad7d2bb + ((~uVar2 | uVar3) ^ uVar8) + local_78[2];
  *(uint *)(param_1 + 0x4c) = local_88[0] + uVar8;
  uVar5 = (uVar7 * 0x8000 | uVar7 >> 0x11) + uVar3;
  *(int *)(param_1 + 0x54) = *(int *)(param_1 + 0x54) + uVar5;
  uVar7 = uVar2 + 0xeb86d391 + ((~uVar8 | uVar5) ^ uVar3) + local_54;
  *(int *)(param_1 + 0x58) = *(int *)(param_1 + 0x58) + uVar3;
  *(uint *)(param_1 + 0x50) = (uVar7 >> 0xb | uVar7 * 0x200000) + *(int *)(param_1 + 0x50) + uVar5;
  local_80 = param_1;
  __security_check_cookie(local_38 ^ (ulonglong)local_88);
  return;
}



void FUN_180003230(longlong param_1,void *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = *(uint *)(param_1 + 0x44) >> 3 & 0x3f;
  uVar2 = *(uint *)(param_1 + 0x44) + param_3 * 8;
  *(uint *)(param_1 + 0x44) = uVar2;
  if (uVar2 < param_3 * 8) {
    *(int *)(param_1 + 0x48) = *(int *)(param_1 + 0x48) + 1;
  }
  uVar2 = -uVar1 + 0x40;
  *(int *)(param_1 + 0x48) = *(int *)(param_1 + 0x48) + (param_3 >> 0x1d);
  if (param_3 < uVar2) {
    uVar2 = 0;
  }
  else {
    memcpy((void *)(param_1 + 1 + (ulonglong)uVar1),param_2,(ulonglong)uVar2);
    FUN_180002960(param_1,param_1 + 1);
    for (uVar1 = -uVar1 + 0x80; uVar1 <= param_3; uVar1 = uVar1 + 0x40) {
      FUN_180002960(param_1,(ulonglong)uVar2 + (longlong)param_2);
      uVar2 = uVar1;
    }
    uVar1 = 0;
  }
  memcpy((void *)(param_1 + 1 + (ulonglong)uVar1),(void *)((ulonglong)uVar2 + (longlong)param_2),
         (ulonglong)(param_3 - uVar2));
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
        FUN_180003a98();
      }
      else {
        FUN_180003a78();
      }
    }
  }
  return pvVar2;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180004558. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



void __cdecl free(void *_Memory)

{
  free(_Memory);
  return;
}



undefined8 * FUN_18000341c(undefined8 *param_1,ulonglong param_2)

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
        FUN_180003a98();
      }
      else {
        FUN_180003a78();
      }
    }
  }
  return pvVar2;
}



void __cdecl free(void *_Memory)

{
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
//  __GSHandlerCheck_EH
// 
// Library: Visual Studio 2015 Release

void __GSHandlerCheck_EH(longlong param_1,ulonglong param_2,undefined8 param_3,longlong param_4)

{
  longlong lVar1;
  
  lVar1 = *(longlong *)(param_4 + 0x38);
  __GSHandlerCheckCommon(param_2,param_4,(uint *)(lVar1 + 4));
  if ((*(uint *)(lVar1 + 4) & ((*(uint *)(param_1 + 4) & 0x66) != 0) + 1) != 0) {
                    // WARNING: Subroutine does not return
    __CxxFrameHandler3(param_1,param_2,param_3,param_4);
  }
  return;
}



// Library Function - Single Match
//  __security_check_cookie
// 
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

void __cdecl __security_check_cookie(uintptr_t _StackCookie)

{
  if ((_StackCookie == DAT_180008040) && ((short)(_StackCookie >> 0x30) == 0)) {
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
    if (DAT_1800081c4 < 1) {
      uVar6 = 0;
    }
    else {
      DAT_1800081c4 = DAT_1800081c4 + -1;
      uVar8 = __scrt_acquire_startup_lock();
      if (_DAT_180008740 != 2) {
        uVar7 = 0;
        __scrt_fastfail(7);
      }
      __scrt_dllmain_uninitialize_c();
      _DAT_180008740 = 0;
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
      if (_DAT_180008740 != 0) {
        __scrt_fastfail(7);
      }
      _DAT_180008740 = 1;
      uVar8 = __scrt_dllmain_before_initialize_c();
      if ((char)uVar8 != '\0') {
        _RTC_Initialize();
        atexit(&LAB_1800042d8);
        FUN_1800040f4();
        atexit(&LAB_180004104);
        __scrt_initialize_default_local_stdio_options();
        iVar5 = _initterm_e(&DAT_1800051f0,&DAT_1800051f8);
        if ((iVar5 == 0) && (uVar9 = __scrt_dllmain_after_initialize_c(), (char)uVar9 != '\0')) {
          _initterm(&DAT_1800051e0,&DAT_1800051e8);
          _DAT_180008740 = 2;
          bVar2 = false;
        }
      }
      __scrt_release_startup_lock((char)uVar7);
      if (!bVar2) {
        ppcVar10 = (code **)FUN_18000413c();
        if ((*ppcVar10 != (code *)0x0) &&
           (uVar7 = __scrt_is_nonwritable_in_current_image((longlong)ppcVar10), (char)uVar7 != '\0')
           ) {
          pcVar1 = *ppcVar10;
          _guard_check_icall();
          (*pcVar1)(param_1,2,param_3);
        }
        DAT_1800081c4 = DAT_1800081c4 + 1;
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



int FUN_180003794(HINSTANCE__ *param_1,ulong param_2,void *param_3)

{
  int iVar1;
  undefined8 uVar2;
  
  if ((param_2 == 0) && (DAT_1800081c4 < 1)) {
    iVar1 = 0;
  }
  else if ((1 < param_2 - 1) ||
          ((iVar1 = dllmain_raw(param_1,param_2,param_3), iVar1 != 0 &&
           (iVar1 = dllmain_crt_dispatch(param_1,param_2,param_3), iVar1 != 0)))) {
    uVar2 = FUN_1800040d0(param_1,param_2);
    iVar1 = (int)uVar2;
    if ((param_2 == 1) && (iVar1 == 0)) {
      FUN_1800040d0(param_1,0);
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



// WARNING: Removing unreachable block (ram,0x0001800038b9)
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
  FUN_180003794(param_1,param_2,param_3);
  return;
}



void _guard_check_icall(void)

{
  return;
}



undefined8 * FUN_180003928(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy(param_2 + 8);
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



undefined8 * FUN_180003968(undefined8 *param_1)

{
  param_1[2] = 0;
  param_1[1] = "bad allocation";
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



undefined8 * FUN_180003988(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy(param_2 + 8);
  *param_1 = std::bad_array_new_length::vftable;
  return param_1;
}



undefined8 * FUN_1800039c8(undefined8 *param_1)

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



undefined8 * FUN_180003a34(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = std::exception::vftable;
  __std_exception_destroy(param_1 + 1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_180003a78(void)

{
  undefined8 local_28 [5];
  
  FUN_180003968(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_1800062c0);
}



void FUN_180003a98(void)

{
  undefined8 local_28 [5];
  
  FUN_1800039c8(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_180006348);
}



char * FUN_180003ab8(longlong param_1)

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
                    // WARNING: Could not recover jumptable at 0x000180003af9. Too many branches
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
  *(undefined8 *)(puVar3 + -8) = 0x180003b2a;
  capture_previous_context((PCONTEXT)&DAT_180008270);
  _DAT_1800081e0 = *(undefined8 *)(puVar3 + 0x38);
  _DAT_180008308 = puVar3 + 0x40;
  _DAT_1800082f0 = *(undefined8 *)(puVar3 + 0x40);
  _DAT_1800081d0 = 0xc0000409;
  _DAT_1800081d4 = 1;
  _DAT_1800081e8 = 1;
  DAT_1800081f0 = 2;
  *(undefined8 *)(puVar3 + 0x20) = DAT_180008040;
  *(undefined8 *)(puVar3 + 0x28) = DAT_180008048;
  *(undefined8 *)(puVar3 + -8) = 0x180003bcc;
  DAT_180008368 = _DAT_1800081e0;
  __raise_securityfailure((_EXCEPTION_POINTERS *)&PTR_DAT_1800056d0);
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
LAB_180003c76:
    uVar3 = (ulonglong)pvVar2 & 0xffffffffffffff00;
  }
  else {
    do {
      LOCK();
      bVar1 = DAT_180008748 == 0;
      DAT_180008748 = DAT_180008748 ^ (ulonglong)bVar1 * (DAT_180008748 ^ (ulonglong)StackBase);
      pvVar2 = (void *)(!bVar1 * DAT_180008748);
      if (bVar1) goto LAB_180003c76;
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
    uVar3 = FUN_1800044fc();
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
  
  cVar1 = FUN_1800045a0();
  if (cVar1 != '\0') {
    cVar1 = FUN_1800045a0();
    if (cVar1 != '\0') {
      return 1;
    }
    FUN_1800045a0();
  }
  return 0;
}



// Library Function - Single Match
//  __scrt_dllmain_crt_thread_detach
// 
// Library: Visual Studio 2015 Release

undefined __scrt_dllmain_crt_thread_detach(void)

{
  FUN_1800045a0();
  FUN_1800045a0();
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
    _execute_onexit_table(&DAT_180008750);
    return;
  }
  uVar2 = FUN_1800045a4();
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
  FUN_1800045a0();
  FUN_1800045a0();
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
    DAT_180008780 = 1;
  }
  __isa_available_init();
  uVar1 = FUN_1800045a0();
  if ((char)uVar1 != '\0') {
    uVar1 = FUN_1800045a0();
    if ((char)uVar1 != '\0') {
      return uVar1 & 0xffffffffffffff00 | 1;
    }
    uVar1 = FUN_1800045a0();
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
      bVar2 = 0x40 - ((byte)DAT_180008040 & 0x3f) & 0x3f;
      _DAT_180008760 = (0xffffffffffffffffU >> bVar2 | -1L << 0x40 - bVar2) ^ DAT_180008040;
      local_28 = (undefined4)_DAT_180008760;
      uStack_24 = (undefined4)(_DAT_180008760 >> 0x20);
      _DAT_180008750 = local_28;
      uRam0000000180008754 = uStack_24;
      uRam0000000180008758 = local_28;
      uRam000000018000875c = uStack_24;
      _DAT_180008768 = local_28;
      uRam000000018000876c = uStack_24;
      uRam0000000180008770 = local_28;
      uRam0000000180008774 = uStack_24;
      _DAT_180008778 = _DAT_180008760;
    }
    else {
      uVar4 = _initialize_onexit_table(&DAT_180008750);
      if ((int)uVar4 == 0) {
        uVar4 = _initialize_onexit_table(&DAT_180008768);
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



// WARNING: Removing unreachable block (ram,0x000180003f5e)
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
  for (pIVar3 = &IMAGE_SECTION_HEADER_180000210; pIVar3 != (IMAGE_SECTION_HEADER *)&DAT_180000328;
      pIVar3 = pIVar3 + 1) {
    if (((ulonglong)(uint)pIVar3->VirtualAddress <= param_1 - 0x180000000U) &&
       (uVar1 = (ulonglong)((pIVar3->Misc).PhysicalAddress + pIVar3->VirtualAddress),
       param_1 - 0x180000000U < uVar1)) goto LAB_180003f47;
  }
  pIVar3 = (IMAGE_SECTION_HEADER *)0x0;
LAB_180003f47:
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
    DAT_180008748 = 0;
  }
  return;
}



// Library Function - Single Match
//  __scrt_uninitialize_crt
// 
// Library: Visual Studio 2015 Release

undefined __scrt_uninitialize_crt(undefined8 param_1,char param_2)

{
  if ((DAT_180008780 == '\0') || (param_2 == '\0')) {
    FUN_1800045a0();
    FUN_1800045a0();
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
  
  bVar2 = (byte)DAT_180008040 & 0x3f;
  if (((DAT_180008040 ^ _DAT_180008750) >> bVar2 | (DAT_180008040 ^ _DAT_180008750) << 0x40 - bVar2)
      == 0xffffffffffffffff) {
    iVar1 = _crt_atexit();
  }
  else {
    iVar1 = _register_onexit_function(&DAT_180008750,_Func);
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
  if (DAT_180008040 == 0x2b992ddfa232) {
    GetSystemTimeAsFileTime(&local_res10);
    local_res8 = local_res10;
    DVar1 = GetCurrentThreadId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    DVar1 = GetCurrentProcessId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    QueryPerformanceCounter((LARGE_INTEGER *)&local_res18);
    DAT_180008040 =
         ((ulonglong)local_res18 << 0x20 ^ CONCAT44(uStackX_1c,local_res18) ^ (ulonglong)local_res8
         ^ (ulonglong)&local_res8) & 0xffffffffffff;
    if (DAT_180008040 == 0x2b992ddfa232) {
      DAT_180008040 = 0x2b992ddfa233;
    }
  }
  DAT_180008048 = ~DAT_180008040;
  return;
}



undefined8 FUN_1800040d0(HMODULE param_1,int param_2)

{
  if (param_2 == 1) {
    DisableThreadLibraryCalls(param_1);
  }
  return 1;
}



void FUN_1800040f4(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800040fb. Too many branches
                    // WARNING: Treating indirect jump as call
  InitializeSListHead(&DAT_180008790);
  return;
}



undefined * FUN_180004110(void)

{
  return &DAT_1800087a0;
}



undefined * FUN_180004118(void)

{
  return &DAT_1800087a8;
}



// Library Function - Single Match
//  __scrt_initialize_default_local_stdio_options
// 
// Library: Visual Studio 2015 Release

void __scrt_initialize_default_local_stdio_options(void)

{
  ulonglong *puVar1;
  
  puVar1 = (ulonglong *)FUN_180004110();
  *puVar1 = *puVar1 | 4;
  puVar1 = (ulonglong *)FUN_180004118();
  *puVar1 = *puVar1 | 2;
  return;
}



undefined * FUN_18000413c(void)

{
  return &DAT_1800087b8;
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
  _DAT_1800087b0 = 0;
  *(undefined8 *)(puVar4 + -8) = 0x180004185;
  memset(local_4d8,0,0x4d0);
  *(undefined8 *)(puVar4 + -8) = 0x18000418f;
  RtlCaptureContext(local_4d8);
  *(undefined8 *)(puVar4 + -8) = 0x1800041a9;
  FunctionEntry = RtlLookupFunctionEntry(local_3e0,&local_res10,(PUNWIND_HISTORY_TABLE)0x0);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0) {
    *(undefined8 *)(puVar4 + 0x38) = 0;
    *(undefined **)(puVar4 + 0x30) = local_res18;
    *(undefined **)(puVar4 + 0x28) = local_res20;
    *(undefined **)(puVar4 + 0x20) = local_4d8;
    *(undefined8 *)(puVar4 + -8) = 0x1800041ea;
    RtlVirtualUnwind(0,local_res10,local_3e0,FunctionEntry,*(PCONTEXT *)(puVar4 + 0x20),
                     *(PVOID **)(puVar4 + 0x28),*(PDWORD64 *)(puVar4 + 0x30),
                     *(PKNONVOLATILE_CONTEXT_POINTERS *)(puVar4 + 0x38));
  }
  local_440 = &stack0x00000008;
  *(undefined8 *)(puVar4 + -8) = 0x18000421c;
  memset(puVar4 + 0x50,0,0x98);
  *(undefined8 *)(puVar4 + 0x60) = unaff_retaddr;
  *(undefined4 *)(puVar4 + 0x50) = 0x40000015;
  *(undefined4 *)(puVar4 + 0x54) = 1;
  *(undefined8 *)(puVar4 + -8) = 0x18000423e;
  BVar2 = IsDebuggerPresent();
  *(undefined **)(puVar4 + 0x40) = puVar4 + 0x50;
  *(undefined **)(puVar4 + 0x48) = local_4d8;
  *(undefined8 *)(puVar4 + -8) = 0x18000425f;
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  *(undefined8 *)(puVar4 + -8) = 0x18000426a;
  LVar3 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)(puVar4 + 0x40));
  if (LVar3 == 0) {
    _DAT_1800087b0 = _DAT_1800087b0 & -(uint)(BVar2 == 1);
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
  
  for (ppcVar2 = (code **)&DAT_180005e48; ppcVar2 < &DAT_180005e48; ppcVar2 = ppcVar2 + 1) {
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
                    // 0x4330  29  ?Finished@IHashProgress@Core@Graphine@@UEAAXXZ
                    // 0x4330  42  ?Progress@IHashProgress@Core@Graphine@@UEAAXN@Z
                    // 0x4330  43  ?Started@IHashProgress@Core@Graphine@@UEAAXXZ
  return;
}



// WARNING: Removing unreachable block (ram,0x000180004451)
// WARNING: Removing unreachable block (ram,0x0001800043b6)
// WARNING: Removing unreachable block (ram,0x000180004358)
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
  DAT_18000805c = 2;
  piVar1 = (int *)cpuid_basic_info(0);
  _DAT_180008058 = 1;
  puVar2 = (uint *)cpuid_Version_info(1);
  uVar4 = puVar2[3];
  uVar5 = DAT_1800087b4;
  if ((piVar1[2] ^ 0x49656e69U | piVar1[3] ^ 0x6c65746eU | piVar1[1] ^ 0x756e6547U) == 0) {
    _DAT_180008060 = 0xffffffffffffffff;
    uVar6 = *puVar2 & 0xfff3ff0;
    if ((((uVar6 == 0x106c0) || (uVar6 == 0x20660)) || (uVar6 == 0x20670)) ||
       ((uVar5 = DAT_1800087b4 | 4, uVar6 - 0x30650 < 0x21 &&
        ((0x100010001U >> ((ulonglong)(uVar6 - 0x30650) & 0x3f) & 1) != 0)))) {
      uVar5 = DAT_1800087b4 | 5;
    }
  }
  DAT_1800087b4 = uVar5;
  if (((piVar1[1] ^ 0x68747541U | piVar1[2] ^ 0x69746e65U | piVar1[3] ^ 0x444d4163U) == 0) &&
     (0x600eff < (*puVar2 & 0xff00f00))) {
    DAT_1800087b4 = DAT_1800087b4 | 4;
  }
  if (6 < *piVar1) {
    lVar3 = cpuid_Extended_Feature_Enumeration_info(7);
    local_20 = *(uint *)(lVar3 + 4);
    if ((local_20 >> 9 & 1) != 0) {
      DAT_1800087b4 = DAT_1800087b4 | 2;
    }
  }
  if ((uVar4 >> 0x14 & 1) != 0) {
    _DAT_180008058 = 2;
    DAT_18000805c = 6;
    if ((((uVar4 >> 0x1b & 1) != 0) && ((uVar4 >> 0x1c & 1) != 0)) && ((in_XCR0 & 6) == 6)) {
      DAT_18000805c = 0xe;
      _DAT_180008058 = 3;
      if ((local_20 & 0x20) != 0) {
        _DAT_180008058 = 5;
        DAT_18000805c = 0x2e;
      }
    }
  }
  return 0;
}



undefined8 FUN_1800044fc(void)

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
  return _DAT_180008070 != 0;
}



void _purecall(void)

{
                    // WARNING: Could not recover jumptable at 0x000180004510. Too many branches
                    // WARNING: Treating indirect jump as call
  _purecall();
  return;
}



void _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo)

{
                    // WARNING: Could not recover jumptable at 0x000180004516. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  _CxxThrowException(pExceptionObject,pThrowInfo);
  return;
}



void __CxxFrameHandler3(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000451c. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler3();
  return;
}



void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180004522. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180004528. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



void __std_exception_copy(void)

{
                    // WARNING: Could not recover jumptable at 0x000180004534. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_exception_copy();
  return;
}



void __std_exception_destroy(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000453a. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_exception_destroy();
  return;
}



void terminate(void)

{
                    // WARNING: Could not recover jumptable at 0x000180004546. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  terminate();
  return;
}



int __cdecl _callnewh(size_t _Size)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000454c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _callnewh(_Size);
  return iVar1;
}



void * __cdecl malloc(size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180004552. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = malloc(_Size);
  return pvVar1;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180004558. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000455e. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



void _initterm_e(void)

{
                    // WARNING: Could not recover jumptable at 0x000180004564. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm_e();
  return;
}



void _seh_filter_dll(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000456a. Too many branches
                    // WARNING: Treating indirect jump as call
  _seh_filter_dll();
  return;
}



void _configure_narrow_argv(void)

{
                    // WARNING: Could not recover jumptable at 0x000180004570. Too many branches
                    // WARNING: Treating indirect jump as call
  _configure_narrow_argv();
  return;
}



void _initialize_narrow_environment(void)

{
                    // WARNING: Could not recover jumptable at 0x000180004576. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_narrow_environment();
  return;
}



void _initialize_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000457c. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_onexit_table();
  return;
}



void _register_onexit_function(void)

{
                    // WARNING: Could not recover jumptable at 0x000180004582. Too many branches
                    // WARNING: Treating indirect jump as call
  _register_onexit_function();
  return;
}



void _execute_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x000180004588. Too many branches
                    // WARNING: Treating indirect jump as call
  _execute_onexit_table();
  return;
}



void _crt_atexit(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000458e. Too many branches
                    // WARNING: Treating indirect jump as call
  _crt_atexit();
  return;
}



void __cdecl _cexit(void)

{
                    // WARNING: Could not recover jumptable at 0x000180004594. Too many branches
                    // WARNING: Treating indirect jump as call
  _cexit();
  return;
}



BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000459a. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = IsProcessorFeaturePresent(ProcessorFeature);
  return BVar1;
}



undefined FUN_1800045a0(void)

{
  return 1;
}



undefined8 FUN_1800045a4(void)

{
  return 0;
}



// WARNING: This is an inlined function

void _guard_dispatch_icall(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
                    // WARNING: Could not recover jumptable at 0x0001800045c0. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



undefined * Catch_All_1800045d0(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  void *pvVar2;
  
  lVar1 = *(longlong *)(param_2 + 0x68);
  *(longlong *)(param_2 + 0x68) = lVar1;
  pvVar2 = FUN_180001aa0(*(undefined8 *)(param_2 + 0x60),lVar1 + 1);
  *(void **)(param_2 + 0x78) = pvVar2;
  return &DAT_180001a04;
}



void Catch_All_180004603(undefined8 param_1,longlong param_2)

{
  void **ppvVar1;
  
  ppvVar1 = *(void ***)(param_2 + 0x60);
  if ((void *)0x7 < ppvVar1[3]) {
    FUN_180001db0(ppvVar1,*ppvVar1,(longlong)ppvVar1[3] + 1);
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



void Unwind_180004660(undefined8 param_1,longlong param_2)

{
  Graphine::Core::MD5Calculation::_MD5Calculation((MD5Calculation *)(param_2 + 0x68));
  return;
}



void Unwind_180004670(undefined8 param_1,longlong param_2)

{
  FUN_180001ed0((void **)(param_2 + 0x38));
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



void FUN_1800046e9(undefined8 param_1,longlong param_2)

{
  __scrt_release_startup_lock(*(char *)(param_2 + 0x40));
  return;
}



void FUN_180004700(undefined8 param_1,longlong param_2)

{
  __scrt_dllmain_uninitialize_critical();
  __scrt_release_startup_lock(*(char *)(param_2 + 0x38));
  return;
}



void FUN_18000471c(undefined8 *param_1,longlong param_2)

{
  __scrt_dllmain_exception_filter
            (*(undefined8 *)(param_2 + 0x60),*(int *)(param_2 + 0x68),
             *(undefined8 *)(param_2 + 0x70),dllmain_crt_dispatch,*(undefined4 *)*param_1,param_1);
  return;
}


