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
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
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

typedef struct _s_UnwindMapEntry UnwindMapEntry;

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

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[67];
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

typedef int (* _onexit_t)(void);

typedef ulonglong size_t;




void FUN_180001040(void)

{
  FUN_180001af0((undefined8 *)&DAT_1800060f0);
  atexit(&LAB_180003c30);
  return;
}



undefined8 FUN_1800010a0(undefined8 param_1)

{
  return param_1;
}



void _guard_check_icall(void)

{
  return;
}



void FUN_1800010c0(void **param_1,ulonglong param_2)

{
  void *pvVar1;
  void *_Dst;
  longlong lVar2;
  
  _Dst = FUN_180001380(param_1,param_2);
  memmove(_Dst,*param_1,(longlong)param_1[1] - (longlong)*param_1);
  pvVar1 = *param_1;
  lVar2 = ((longlong)param_1[1] - (longlong)pvVar1) / 6 +
          ((longlong)param_1[1] - (longlong)pvVar1 >> 0x3f);
  if (pvVar1 != (void *)0x0) {
    FUN_180001480(param_1,pvVar1,((longlong)param_1[2] - (longlong)pvVar1) / 0x18);
  }
  param_1[2] = (void *)((longlong)_Dst + param_2 * 0x18);
  param_1[1] = (void *)((longlong)_Dst + ((lVar2 >> 2) - (lVar2 >> 0x3f)) * 0x18);
  *param_1 = _Dst;
  return;
}



void FUN_180001190(void **param_1,ulonglong param_2)

{
  void *pvVar1;
  void *pvVar2;
  void *_Dst;
  
  _Dst = FUN_180001400(param_1,param_2);
  memmove(_Dst,*param_1,(longlong)param_1[1] - (longlong)*param_1);
  pvVar1 = *param_1;
  pvVar2 = param_1[1];
  if (pvVar1 != (void *)0x0) {
    FUN_180001500(param_1,pvVar1,(longlong)param_1[2] - (longlong)pvVar1 >> 4);
  }
  param_1[2] = (void *)(param_2 * 0x10 + (longlong)_Dst);
  param_1[1] = (void *)(((longlong)pvVar2 - (longlong)pvVar1 & 0xfffffffffffffff0U) + (longlong)_Dst
                       );
  *param_1 = _Dst;
  return;
}



void FUN_180001220(void **param_1,ulonglong param_2)

{
  code *pcVar1;
  longlong lVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  
  if (param_2 <= (ulonglong)(((longlong)param_1[2] - (longlong)param_1[1]) / 0x18)) {
    return;
  }
  lVar2 = ((longlong)param_1[1] - (longlong)*param_1) / 0x18;
  if (0xaaaaaaaaaaaaaaaU - lVar2 < param_2) {
    std::_Xlength_error("vector<T> too long");
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  uVar5 = lVar2 + param_2;
  uVar3 = ((longlong)param_1[2] - (longlong)*param_1) / 0x18;
  uVar4 = 0;
  if (uVar3 <= 0xaaaaaaaaaaaaaaa - (uVar3 >> 1)) {
    uVar4 = (uVar3 >> 1) + uVar3;
  }
  if (uVar5 <= uVar4) {
    uVar5 = uVar4;
  }
  FUN_1800010c0(param_1,uVar5);
  return;
}



void FUN_1800012f0(void **param_1,ulonglong param_2)

{
  code *pcVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  longlong lVar4;
  ulonglong uVar5;
  
  if (param_2 <= (ulonglong)((longlong)param_1[2] - (longlong)param_1[1] >> 4)) {
    return;
  }
  lVar4 = (longlong)param_1[1] - (longlong)*param_1 >> 4;
  if (0xfffffffffffffffU - lVar4 < param_2) {
    std::_Xlength_error("vector<T> too long");
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  uVar3 = param_2 + lVar4;
  uVar5 = (longlong)param_1[2] - (longlong)*param_1 >> 4;
  uVar2 = 0;
  if (uVar5 <= 0xfffffffffffffff - (uVar5 >> 1)) {
    uVar2 = (uVar5 >> 1) + uVar5;
  }
  if (uVar3 <= uVar2) {
    uVar3 = uVar2;
  }
  FUN_180001190(param_1,uVar3);
  return;
}



void * FUN_180001380(undefined8 param_1,ulonglong param_2)

{
  code *pcVar1;
  void *pvVar2;
  void *pvVar3;
  ulonglong uVar4;
  
  if (param_2 == 0) {
    pvVar2 = (void *)0x0;
  }
  else {
    if (0xaaaaaaaaaaaaaaa < param_2) {
      std::_Xbad_alloc();
      pcVar1 = (code *)swi(3);
      pvVar2 = (void *)(*pcVar1)();
      return pvVar2;
    }
    uVar4 = param_2 * 0x18;
    if (0xfff < uVar4) {
      if (uVar4 + 0x27 <= uVar4) {
        std::_Xbad_alloc();
        pcVar1 = (code *)swi(3);
        pvVar2 = (void *)(*pcVar1)();
        return pvVar2;
      }
      pvVar2 = operator_new(uVar4 + 0x27);
      if (pvVar2 == (void *)0x0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      pvVar3 = (void *)((longlong)pvVar2 + 0x27U & 0xffffffffffffffe0);
      *(void **)((longlong)pvVar3 + -8) = pvVar2;
      return pvVar3;
    }
    pvVar2 = operator_new(uVar4);
    if (pvVar2 == (void *)0x0) {
                    // WARNING: Subroutine does not return
      _invalid_parameter_noinfo_noreturn();
    }
  }
  return pvVar2;
}



void * FUN_180001400(undefined8 param_1,ulonglong param_2)

{
  code *pcVar1;
  void *pvVar2;
  void *pvVar3;
  ulonglong uVar4;
  
  if (param_2 == 0) {
    pvVar2 = (void *)0x0;
  }
  else {
    if (0xfffffffffffffff < param_2) {
      std::_Xbad_alloc();
      pcVar1 = (code *)swi(3);
      pvVar2 = (void *)(*pcVar1)();
      return pvVar2;
    }
    uVar4 = param_2 * 0x10;
    if (0xfff < uVar4) {
      if (uVar4 + 0x27 <= uVar4) {
        std::_Xbad_alloc();
        pcVar1 = (code *)swi(3);
        pvVar2 = (void *)(*pcVar1)();
        return pvVar2;
      }
      pvVar2 = operator_new(uVar4 + 0x27);
      if (pvVar2 == (void *)0x0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      pvVar3 = (void *)((longlong)pvVar2 + 0x27U & 0xffffffffffffffe0);
      *(void **)((longlong)pvVar3 + -8) = pvVar2;
      return pvVar3;
    }
    pvVar2 = operator_new(uVar4);
    if (pvVar2 == (void *)0x0) {
                    // WARNING: Subroutine does not return
      _invalid_parameter_noinfo_noreturn();
    }
  }
  return pvVar2;
}



void FUN_180001480(undefined8 param_1,void *param_2,ulonglong param_3)

{
  void *_Memory;
  
  if (0xaaaaaaaaaaaaaaa < param_3) {
                    // WARNING: Subroutine does not return
    _invalid_parameter_noinfo_noreturn();
  }
  _Memory = param_2;
  if (0xfff < param_3 * 0x18) {
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



void FUN_180001500(undefined8 param_1,void *param_2,ulonglong param_3)

{
  void *_Memory;
  
  if (0xfffffffffffffff < param_3) {
                    // WARNING: Subroutine does not return
    _invalid_parameter_noinfo_noreturn();
  }
  _Memory = param_2;
  if (0xfff < param_3 << 4) {
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



void AddFixedRectangle(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  ulonglong uVar6;
  undefined auStack_48 [32];
  undefined4 local_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  ulonglong local_18;
  
                    // 0x1570  1  AddFixedRectangle
  local_18 = DAT_180006010 ^ (ulonglong)auStack_48;
  local_28 = param_1;
  uStack_24 = param_2;
  uStack_20 = param_3;
  uStack_1c = param_4;
  if ((&local_28 < DAT_180006138) && (DAT_180006130 <= &local_28)) {
    uVar6 = (longlong)&local_28 - (longlong)DAT_180006130;
    if (DAT_180006138 == DAT_180006140) {
      FUN_1800012f0(&DAT_180006130,1);
    }
    puVar5 = DAT_180006138;
    if (DAT_180006138 != (undefined4 *)0x0) {
      puVar1 = (undefined4 *)((uVar6 & 0xfffffffffffffff0) + (longlong)DAT_180006130);
      uVar2 = puVar1[1];
      uVar3 = puVar1[2];
      uVar4 = puVar1[3];
      *DAT_180006138 = *puVar1;
      puVar5[1] = uVar2;
      puVar5[2] = uVar3;
      puVar5[3] = uVar4;
    }
  }
  else {
    if (DAT_180006138 == DAT_180006140) {
      FUN_1800012f0(&DAT_180006130,1);
    }
    puVar5 = DAT_180006138;
    if (DAT_180006138 != (undefined4 *)0x0) {
      *DAT_180006138 = local_28;
      puVar5[1] = uStack_24;
      puVar5[2] = uStack_20;
      puVar5[3] = uStack_1c;
    }
  }
  DAT_180006138 = DAT_180006138 + 4;
  __security_check_cookie(local_18 ^ (ulonglong)auStack_48);
  return;
}



// WARNING: Could not reconcile some variable overlaps

void AddRectangle(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined8 *puVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined8 *puVar5;
  undefined8 *puVar6;
  longlong lVar7;
  undefined auStack_48 [32];
  undefined8 local_28;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 local_18;
  undefined4 uStack_14;
  ulonglong local_10;
  
                    // 0x1660  2  AddRectangle
  local_10 = DAT_180006010 ^ (ulonglong)auStack_48;
  local_28 = 0;
  local_18 = 0;
  uStack_20 = param_1;
  uStack_1c = param_2;
  uStack_14 = param_3;
  if ((&local_28 < DAT_180006150) && (DAT_180006148 <= &local_28)) {
    lVar7 = ((longlong)&local_28 - (longlong)DAT_180006148) / 6 +
            ((longlong)&local_28 - (longlong)DAT_180006148 >> 0x3f);
    lVar7 = (lVar7 >> 2) - (lVar7 >> 0x3f);
    if (DAT_180006150 == DAT_180006158) {
      FUN_180001220(&DAT_180006148,1);
    }
    puVar6 = DAT_180006150;
    puVar5 = DAT_180006148;
    if (DAT_180006150 != (undefined8 *)0x0) {
      puVar1 = DAT_180006148 + lVar7 * 3;
      uVar2 = *(undefined4 *)((longlong)puVar1 + 4);
      uVar3 = *(undefined4 *)(puVar1 + 1);
      uVar4 = *(undefined4 *)((longlong)puVar1 + 0xc);
      *(undefined4 *)DAT_180006150 = *(undefined4 *)puVar1;
      *(undefined4 *)((longlong)puVar6 + 4) = uVar2;
      *(undefined4 *)(puVar6 + 1) = uVar3;
      *(undefined4 *)((longlong)puVar6 + 0xc) = uVar4;
      puVar6[2] = puVar5[lVar7 * 3 + 2];
    }
  }
  else {
    if (DAT_180006150 == DAT_180006158) {
      FUN_180001220(&DAT_180006148,1);
    }
    puVar5 = DAT_180006150;
    if (DAT_180006150 != (undefined8 *)0x0) {
      *(undefined4 *)DAT_180006150 = (undefined4)local_28;
      *(undefined4 *)((longlong)puVar5 + 4) = local_28._4_4_;
      *(undefined4 *)(puVar5 + 1) = uStack_20;
      *(undefined4 *)((longlong)puVar5 + 0xc) = uStack_1c;
      puVar5[2] = CONCAT44(uStack_14,local_18);
    }
  }
  DAT_180006150 = DAT_180006150 + 3;
  __security_check_cookie(local_10 ^ (ulonglong)auStack_48);
  return;
}



void BeginPacking(undefined4 *param_1)

{
                    // 0x17a0  3  BeginPacking
  DAT_180006150 = DAT_180006148;
  DAT_180006138 = DAT_180006130;
  FUN_180002030((undefined4 *)&DAT_1800060f0,*param_1,param_1[1]);
  DAT_1800060f8 = param_1[2] != 0;
  return;
}



void GetFixedRectangle(int param_1,undefined4 *param_2)

{
  ulonglong uVar1;
  
                    // 0x17f0  4  GetFixedRectangle
  uVar1 = (ulonglong)param_1;
  if (uVar1 < (ulonglong)(DAT_180006138 - DAT_180006130 >> 4)) {
    *(undefined8 *)(param_2 + 4) = 0;
    *param_2 = *(undefined4 *)(DAT_180006130 + uVar1 * 0x10);
    param_2[1] = *(undefined4 *)(DAT_180006130 + 4 + uVar1 * 0x10);
    param_2[2] = *(undefined4 *)(DAT_180006130 + 8 + uVar1 * 0x10);
    param_2[3] = *(undefined4 *)(DAT_180006130 + 0xc + uVar1 * 0x10);
  }
  return;
}



void GetPackedRectangle(int param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  longlong lVar5;
  ulonglong uVar6;
  
                    // 0x1850  5  GetPackedRectangle
  lVar5 = DAT_180006148;
  uVar6 = (ulonglong)param_1;
  if (uVar6 < (ulonglong)((DAT_180006150 - DAT_180006148) / 0x18)) {
    puVar1 = (undefined4 *)(DAT_180006148 + uVar6 * 0x18);
    uVar2 = puVar1[1];
    uVar3 = puVar1[2];
    uVar4 = puVar1[3];
    *param_2 = *puVar1;
    param_2[1] = uVar2;
    param_2[2] = uVar3;
    param_2[3] = uVar4;
    *(undefined8 *)(param_2 + 4) = *(undefined8 *)(lVar5 + 0x10 + uVar6 * 0x18);
  }
  return;
}



void PackRectangles(void)

{
  int iVar1;
  longlong lVar2;
  undefined4 *puVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  undefined auStackY_68 [32];
  undefined4 local_20;
  undefined4 local_1c;
  int local_18;
  int local_14;
  ulonglong local_10;
  
                    // 0x18b0  6  PackRectangles
  local_10 = DAT_180006010 ^ (ulonglong)auStackY_68;
  uVar4 = 0;
  uVar6 = uVar4;
  uVar5 = uVar4;
  if (DAT_180006138 - DAT_180006130 >> 4 != 0) {
    do {
      FUN_180002540((longlong)&DAT_1800060f0,(int *)(uVar6 + DAT_180006130));
      uVar5 = uVar5 + 1;
      uVar6 = uVar6 + 0x10;
    } while (uVar5 < (ulonglong)(DAT_180006138 - DAT_180006130 >> 4));
  }
  lVar2 = DAT_180006150 - DAT_180006148 >> 0x3f;
  uVar6 = uVar4;
  if ((DAT_180006150 - DAT_180006148) / 0x18 + lVar2 != lVar2) {
    do {
      FUN_180002110((int *)&DAT_1800060f0,(undefined (*) [16])&local_20,
                    *(int *)(uVar4 + 8 + DAT_180006148),*(int *)(uVar4 + 0xc + DAT_180006148),0,
                    *(uint *)(uVar4 + 0x14 + DAT_180006148));
      if ((local_18 == 0) || (local_14 == 0)) break;
      puVar3 = (undefined4 *)(DAT_180006148 + uVar4);
      iVar1 = puVar3[2];
      uVar6 = uVar6 + 1;
      uVar4 = uVar4 + 0x18;
      *puVar3 = local_20;
      puVar3[1] = local_1c;
      puVar3[2] = local_18;
      puVar3[3] = local_14;
      *(ulonglong *)(puVar3 + 4) = CONCAT44(puVar3[5],(uint)(local_18 != iVar1));
    } while (uVar6 < (ulonglong)((DAT_180006150 - DAT_180006148) / 0x18));
  }
  __security_check_cookie(local_10 ^ (ulonglong)auStackY_68);
  return;
}



void FUN_180001a60(void **param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  
  puVar1 = (undefined4 *)param_1[1];
  if ((param_2 < puVar1) && (puVar2 = (undefined4 *)*param_1, puVar2 <= param_2)) {
    if (puVar1 == (undefined4 *)param_1[2]) {
      FUN_1800012f0(param_1,1);
    }
    puVar1 = (undefined4 *)param_1[1];
    if (puVar1 != (undefined4 *)0x0) {
      puVar2 = (undefined4 *)
               (((longlong)param_2 - (longlong)puVar2 & 0xfffffffffffffff0U) + (longlong)*param_1);
      uVar3 = puVar2[1];
      uVar4 = puVar2[2];
      uVar5 = puVar2[3];
      *puVar1 = *puVar2;
      puVar1[1] = uVar3;
      puVar1[2] = uVar4;
      puVar1[3] = uVar5;
      param_1[1] = (void *)((longlong)param_1[1] + 0x10);
      return;
    }
  }
  else {
    if (puVar1 == (undefined4 *)param_1[2]) {
      FUN_1800012f0(param_1,1);
    }
    puVar1 = (undefined4 *)param_1[1];
    if (puVar1 != (undefined4 *)0x0) {
      uVar3 = param_2[1];
      uVar4 = param_2[2];
      uVar5 = param_2[3];
      *puVar1 = *param_2;
      puVar1[1] = uVar3;
      puVar1[2] = uVar4;
      puVar1[3] = uVar5;
    }
  }
  param_1[1] = (void *)((longlong)param_1[1] + 0x10);
  return;
}



undefined8 * FUN_180001af0(undefined8 *param_1)

{
  *(undefined *)(param_1 + 1) = 1;
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  return param_1;
}



int FUN_180001b20(int *param_1,int param_2,int param_3,int param_4,int param_5)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  ulonglong uVar6;
  int iVar7;
  int iVar8;
  
  if ((param_2 == 0) || (iVar8 = 0, param_2 + param_4 == *param_1)) {
    iVar8 = param_5;
  }
  if ((param_3 == 0) || (param_3 + param_5 == param_1[1])) {
    iVar8 = iVar8 + param_4;
  }
  uVar6 = 0;
  if (*(longlong *)(param_1 + 6) - *(longlong *)(param_1 + 4) >> 4 != 0) {
    iVar1 = param_3 + param_5;
    iVar2 = param_2 + param_4;
    piVar3 = (int *)(*(longlong *)(param_1 + 4) + 4);
    do {
      iVar7 = piVar3[-1];
      if ((iVar7 == iVar2) || (piVar3[1] + iVar7 == param_2)) {
        iVar5 = *piVar3;
        iVar4 = piVar3[2] + iVar5;
        if ((iVar4 < param_3) || (iVar1 < iVar5)) {
          iVar4 = 0;
        }
        else {
          if (iVar1 < iVar4) {
            iVar4 = iVar1;
          }
          if (iVar5 < param_3) {
            iVar5 = param_3;
          }
          iVar4 = iVar4 - iVar5;
        }
        iVar8 = iVar8 + iVar4;
      }
      if ((*piVar3 == iVar1) || (*piVar3 + piVar3[2] == param_3)) {
        iVar5 = piVar3[1] + iVar7;
        if ((iVar5 < param_2) || (iVar2 < iVar7)) {
          iVar5 = 0;
        }
        else {
          if (iVar7 < param_2) {
            iVar7 = param_2;
          }
          if (iVar2 < iVar5) {
            iVar5 = iVar2;
          }
          iVar5 = iVar5 - iVar7;
        }
        iVar8 = iVar8 + iVar5;
      }
      uVar6 = uVar6 + 1;
      piVar3 = piVar3 + 4;
    } while (uVar6 < (ulonglong)(*(longlong *)(param_1 + 6) - *(longlong *)(param_1 + 4) >> 4));
  }
  return iVar8;
}



undefined8 *
FUN_180001c30(longlong param_1,undefined8 *param_2,int param_3,int param_4,int *param_5,int *param_6
             ,int *param_7)

{
  int iVar1;
  longlong lVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  ulonglong uVar8;
  int *piVar9;
  ulonglong uVar10;
  
  *param_2 = 0;
  uVar8 = 0;
  param_2[1] = 0;
  *param_6 = 0x7fffffff;
  uVar10 = uVar8;
  if (*(longlong *)(param_1 + 0x30) - *(longlong *)(param_1 + 0x28) >> 4 != 0) {
    do {
      piVar9 = (int *)(*(longlong *)(param_1 + 0x28) + uVar10);
      if ((param_3 <= piVar9[2]) && (param_4 <= piVar9[3])) {
        uVar3 = piVar9[2] - param_3;
        uVar7 = piVar9[3] - param_4;
        uVar6 = (int)uVar3 >> 0x1f;
        iVar5 = (uVar3 ^ uVar6) - uVar6;
        uVar3 = (int)uVar7 >> 0x1f;
        iVar4 = (uVar7 ^ uVar3) - uVar3;
        iVar1 = iVar5;
        if (iVar4 < iVar5) {
          iVar1 = iVar4;
        }
        if (iVar5 < iVar4) {
          iVar5 = iVar4;
        }
        if ((iVar5 < *param_6) || ((iVar5 == *param_6 && (iVar1 < *param_5)))) {
          *param_5 = iVar1;
          *param_6 = iVar5;
          iVar1 = *param_7;
          piVar9 = (int *)(*(longlong *)(param_1 + 0x28) + uVar10);
          *(int *)(param_2 + 1) = param_3;
          *(int *)((longlong)param_2 + 0xc) = param_4;
          if (iVar1 == 0) {
            *(int *)param_2 = *piVar9;
            *(int *)((longlong)param_2 + 4) = piVar9[1];
          }
          else {
            iVar5 = *piVar9;
            if (iVar5 % iVar1 != 0) {
              iVar5 = (iVar1 - iVar5 % iVar1) + iVar5;
            }
            iVar4 = piVar9[1];
            *(int *)param_2 = iVar5;
            if (iVar4 % iVar1 == 0) {
              *(int *)((longlong)param_2 + 4) = iVar4;
            }
            else {
              *(int *)((longlong)param_2 + 4) = (iVar1 - iVar4 % iVar1) + iVar4;
            }
          }
        }
      }
      if (((*(char *)(param_1 + 8) != '\0') && (param_4 <= piVar9[2])) && (param_3 <= piVar9[3])) {
        uVar3 = piVar9[2] - param_4;
        uVar7 = piVar9[3] - param_3;
        uVar6 = (int)uVar3 >> 0x1f;
        iVar5 = (uVar3 ^ uVar6) - uVar6;
        uVar3 = (int)uVar7 >> 0x1f;
        iVar4 = (uVar7 ^ uVar3) - uVar3;
        iVar1 = iVar5;
        if (iVar4 < iVar5) {
          iVar1 = iVar4;
        }
        if (iVar5 < iVar4) {
          iVar5 = iVar4;
        }
        if ((iVar5 < *param_6) || ((iVar5 == *param_6 && (iVar1 < *param_5)))) {
          *param_5 = iVar1;
          *param_6 = iVar5;
          iVar1 = *param_7;
          *(int *)(param_2 + 1) = param_4;
          *(int *)((longlong)param_2 + 0xc) = param_3;
          if (iVar1 == 0) {
            lVar2 = *(longlong *)(param_1 + 0x28);
            *(undefined4 *)param_2 = *(undefined4 *)(lVar2 + uVar10);
            *(undefined4 *)((longlong)param_2 + 4) = *(undefined4 *)(lVar2 + 4 + uVar10);
          }
          else {
            iVar5 = *(int *)(*(longlong *)(param_1 + 0x28) + uVar10);
            if (iVar5 % iVar1 != 0) {
              iVar5 = (iVar1 - iVar5 % iVar1) + iVar5;
            }
            iVar4 = *(int *)(*(longlong *)(param_1 + 0x28) + 4 + uVar10);
            *(int *)param_2 = iVar5;
            if (iVar4 % iVar1 == 0) {
              *(int *)((longlong)param_2 + 4) = iVar4;
            }
            else {
              *(int *)((longlong)param_2 + 4) = (iVar1 - iVar4 % iVar1) + iVar4;
            }
          }
        }
      }
      uVar8 = uVar8 + 1;
      uVar10 = uVar10 + 0x10;
    } while (uVar8 < (ulonglong)(*(longlong *)(param_1 + 0x30) - *(longlong *)(param_1 + 0x28) >> 4)
            );
  }
  return param_2;
}



undefined8 *
FUN_180001e40(longlong param_1,undefined8 *param_2,int param_3,int param_4,int *param_5,int *param_6
             ,int *param_7)

{
  int iVar1;
  longlong lVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  ulonglong uVar9;
  ulonglong uVar10;
  int *piVar11;
  int iStack_34;
  int iStack_2c;
  
  *param_2 = 0;
  uVar9 = 0;
  param_2[1] = 0;
  *param_5 = 0x7fffffff;
  uVar10 = uVar9;
  if (*(longlong *)(param_1 + 0x30) - *(longlong *)(param_1 + 0x28) >> 4 != 0) {
    do {
      iVar1 = *param_7;
      if (iVar1 == 0) {
        piVar11 = (int *)(uVar9 + *(longlong *)(param_1 + 0x28));
        iVar4 = *piVar11;
        iStack_34 = piVar11[1];
        iVar5 = piVar11[2];
        iStack_2c = piVar11[3];
      }
      else {
        piVar11 = (int *)(*(longlong *)(param_1 + 0x28) + uVar9);
        iVar5 = *piVar11;
        iVar4 = iVar5;
        if (iVar5 % iVar1 != 0) {
          iVar4 = (iVar1 - iVar5 % iVar1) + iVar5;
        }
        iStack_2c = piVar11[1];
        iStack_34 = iStack_2c;
        if (iStack_2c % iVar1 != 0) {
          iStack_34 = (iVar1 - iStack_2c % iVar1) + iStack_2c;
        }
        iVar5 = (piVar11[2] - iVar4) + iVar5;
        iStack_2c = (piVar11[3] - iStack_34) + iStack_2c;
      }
      if ((param_3 <= iVar5) && (param_4 <= iStack_2c)) {
        uVar6 = iVar5 - param_3 >> 0x1f;
        iVar5 = (iVar5 - param_3 ^ uVar6) - uVar6;
        uVar6 = iStack_2c - param_4 >> 0x1f;
        iVar3 = (iStack_2c - param_4 ^ uVar6) - uVar6;
        iVar1 = iVar5;
        if (iVar3 < iVar5) {
          iVar1 = iVar3;
        }
        if (iVar5 < iVar3) {
          iVar5 = iVar3;
        }
        if ((iVar1 < *param_5) || ((iVar1 == *param_5 && (iVar5 < *param_6)))) {
          *param_5 = iVar1;
          *(int *)((longlong)param_2 + 4) = iStack_34;
          *(int *)(param_2 + 1) = param_3;
          *(int *)((longlong)param_2 + 0xc) = param_4;
          *param_6 = iVar5;
          *(int *)param_2 = iVar4;
        }
      }
      if (*(char *)(param_1 + 8) != '\0') {
        iVar1 = *(int *)(uVar9 + 8 + *(longlong *)(param_1 + 0x28));
        if ((param_4 <= iVar1) &&
           (iVar5 = *(int *)(uVar9 + 0xc + *(longlong *)(param_1 + 0x28)), param_3 <= iVar5)) {
          uVar6 = iVar1 - param_4;
          uVar8 = iVar5 - param_3;
          uVar7 = (int)uVar6 >> 0x1f;
          iVar5 = (uVar6 ^ uVar7) - uVar7;
          uVar6 = (int)uVar8 >> 0x1f;
          iVar4 = (uVar8 ^ uVar6) - uVar6;
          iVar1 = iVar5;
          if (iVar4 < iVar5) {
            iVar1 = iVar4;
          }
          if (iVar5 < iVar4) {
            iVar5 = iVar4;
          }
          if ((iVar1 < *param_5) || ((iVar1 == *param_5 && (iVar5 < *param_6)))) {
            *param_5 = iVar1;
            *param_6 = iVar5;
            lVar2 = *(longlong *)(param_1 + 0x28);
            *(int *)(param_2 + 1) = param_4;
            *(int *)((longlong)param_2 + 0xc) = param_3;
            *(undefined4 *)param_2 = *(undefined4 *)(lVar2 + uVar9);
            *(undefined4 *)((longlong)param_2 + 4) = *(undefined4 *)(lVar2 + 4 + uVar9);
          }
        }
      }
      uVar10 = uVar10 + 1;
      uVar9 = uVar9 + 0x10;
    } while (uVar10 < (ulonglong)
                      (*(longlong *)(param_1 + 0x30) - *(longlong *)(param_1 + 0x28) >> 4));
  }
  return param_2;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_180002030(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  void **ppvVar1;
  undefined4 *puVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined auStack_48 [32];
  undefined8 local_28;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  ulonglong local_18;
  
  local_18 = DAT_180006010 ^ (ulonglong)auStack_48;
  *param_1 = param_2;
  param_1[1] = param_3;
  ppvVar1 = (void **)(param_1 + 10);
  local_28 = 0;
  *(undefined8 *)(param_1 + 6) = *(undefined8 *)(param_1 + 4);
  puVar3 = (undefined8 *)*ppvVar1;
  *(undefined8 **)(param_1 + 0xc) = puVar3;
  uStack_20 = param_2;
  uStack_1c = param_3;
  if ((&local_28 < puVar3) && (puVar4 = (undefined8 *)*ppvVar1, puVar4 <= &local_28)) {
    if (puVar3 == *(undefined8 **)(param_1 + 0xe)) {
      FUN_1800012f0(ppvVar1,1);
    }
    puVar5 = *(undefined4 **)(param_1 + 0xc);
    if (puVar5 != (undefined4 *)0x0) {
      puVar2 = (undefined4 *)
               (((longlong)&local_28 - (longlong)puVar4 & 0xfffffffffffffff0U) + (longlong)*ppvVar1)
      ;
      uVar6 = puVar2[1];
      uVar7 = puVar2[2];
      uVar8 = puVar2[3];
      *puVar5 = *puVar2;
      puVar5[1] = uVar6;
      puVar5[2] = uVar7;
      puVar5[3] = uVar8;
    }
  }
  else {
    if (puVar3 == *(undefined8 **)(param_1 + 0xe)) {
      FUN_1800012f0(ppvVar1,1);
    }
    puVar5 = *(undefined4 **)(param_1 + 0xc);
    if (puVar5 != (undefined4 *)0x0) {
      *puVar5 = (undefined4)local_28;
      puVar5[1] = local_28._4_4_;
      puVar5[2] = uStack_20;
      puVar5[3] = uStack_1c;
    }
  }
  *(longlong *)(param_1 + 0xc) = *(longlong *)(param_1 + 0xc) + 0x10;
  __security_check_cookie(local_18 ^ (ulonglong)auStack_48);
  return;
}



// WARNING: Could not reconcile some variable overlaps

undefined (*) [16]
FUN_180002110(int *param_1,undefined (*param_2) [16],int param_3,int param_4,int param_5,
             uint param_6)

{
  void *_Src;
  int iVar1;
  char cVar2;
  int iVar3;
  undefined8 *puVar4;
  uint uVar5;
  ulonglong uVar6;
  uint uVar7;
  uint uVar8;
  ulonglong uVar9;
  int iVar10;
  int iVar11;
  ulonglong uVar12;
  int *piVar13;
  ulonglong local_48 [2];
  undefined8 local_38;
  undefined8 uStack_30;
  
  uVar12 = 0;
  local_48[0] = local_48[0] & 0xffffffff00000000 | (ulonglong)param_6;
  if (param_5 == 0) {
    puVar4 = FUN_180001e40((longlong)param_1,&local_38,param_3,param_4,&param_5,(int *)&param_6,
                           (int *)local_48);
LAB_180002484:
    local_38._0_4_ = *(undefined4 *)puVar4;
    local_38._4_4_ = *(undefined4 *)((longlong)puVar4 + 4);
    uStack_30._0_4_ = *(undefined4 *)(puVar4 + 1);
    uStack_30._4_4_ = *(undefined4 *)((longlong)puVar4 + 0xc);
  }
  else {
    if (param_5 == 1) {
      puVar4 = FUN_180001c30((longlong)param_1,&local_38,param_3,param_4,(int *)&param_6,&param_5,
                             (int *)local_48);
      goto LAB_180002484;
    }
    if (param_5 == 2) {
      iVar11 = 0x7fffffff;
      local_38 = 0;
      uStack_30 = 0;
      if (*(longlong *)(param_1 + 0xc) - *(longlong *)(param_1 + 10) >> 4 != 0) {
        local_48[0] = *(longlong *)(param_1 + 0xc) - *(longlong *)(param_1 + 10) >> 4;
        piVar13 = (int *)(*(longlong *)(param_1 + 10) + 0xc);
        uVar5 = param_6;
        do {
          iVar3 = piVar13[-1];
          iVar1 = *piVar13;
          iVar10 = iVar3 * iVar1 - param_3 * param_4;
          if ((param_3 <= iVar3) && (param_4 <= iVar1)) {
            uVar7 = iVar3 - param_3 >> 0x1f;
            uVar7 = (iVar3 - param_3 ^ uVar7) - uVar7;
            uVar8 = iVar1 - param_4 >> 0x1f;
            uVar8 = (iVar1 - param_4 ^ uVar8) - uVar8;
            if ((int)uVar8 < (int)uVar7) {
              uVar7 = uVar8;
            }
            if ((iVar10 < iVar11) || ((iVar10 == iVar11 && ((int)uVar7 < (int)uVar5)))) {
              local_38 = *(undefined8 *)(piVar13 + -3);
              uStack_30 = CONCAT44(param_4,param_3);
              uVar5 = uVar7;
              iVar11 = iVar10;
            }
          }
          if (((*(char *)(param_1 + 2) != '\0') && (param_4 <= iVar3)) && (param_3 <= iVar1)) {
            uVar7 = iVar3 - param_4 >> 0x1f;
            uVar7 = (iVar3 - param_4 ^ uVar7) - uVar7;
            uVar8 = iVar1 - param_3 >> 0x1f;
            uVar8 = (iVar1 - param_3 ^ uVar8) - uVar8;
            if ((int)uVar8 < (int)uVar7) {
              uVar7 = uVar8;
            }
            if ((iVar10 < iVar11) || ((iVar10 == iVar11 && ((int)uVar7 < (int)uVar5)))) {
              local_38 = *(undefined8 *)(piVar13 + -3);
              uStack_30 = CONCAT44(param_3,param_4);
              uVar5 = uVar7;
              iVar11 = iVar10;
            }
          }
          uVar12 = uVar12 + 1;
          piVar13 = piVar13 + 4;
        } while (uVar12 < local_48[0]);
      }
    }
    else {
      if (param_5 == 3) {
        iVar11 = 0x7fffffff;
        local_38 = 0;
        uStack_30 = 0;
        if (*(longlong *)(param_1 + 0xc) - *(longlong *)(param_1 + 10) >> 4 != 0) {
          piVar13 = (int *)(*(longlong *)(param_1 + 10) + 4);
          uVar5 = param_6;
          do {
            if ((param_3 <= piVar13[1]) && (param_4 <= piVar13[2])) {
              iVar3 = *piVar13 + param_4;
              if ((iVar3 < iVar11) || ((iVar3 == iVar11 && (piVar13[-1] < (int)uVar5)))) {
                uVar5 = piVar13[-1];
                local_38 = CONCAT44(*piVar13,uVar5);
                uStack_30 = CONCAT44(param_4,param_3);
                iVar11 = iVar3;
              }
            }
            if (((*(char *)(param_1 + 2) != '\0') && (param_4 <= piVar13[1])) &&
               (param_3 <= piVar13[2])) {
              iVar3 = *piVar13 + param_3;
              if ((iVar3 < iVar11) || ((iVar3 == iVar11 && (piVar13[-1] < (int)uVar5)))) {
                uVar5 = piVar13[-1];
                local_38 = CONCAT44(*piVar13,uVar5);
                uStack_30 = CONCAT44(param_3,param_4);
                iVar11 = iVar3;
              }
            }
            uVar12 = uVar12 + 1;
            piVar13 = piVar13 + 4;
          } while (uVar12 < (ulonglong)
                            (*(longlong *)(param_1 + 0xc) - *(longlong *)(param_1 + 10) >> 4));
          goto LAB_180002487;
        }
      }
      else {
        if (param_5 != 4) goto LAB_18000248b;
        iVar11 = -1;
        local_38 = 0;
        uStack_30 = 0;
        if (*(longlong *)(param_1 + 0xc) - *(longlong *)(param_1 + 10) >> 4 != 0) {
          uVar6 = *(longlong *)(param_1 + 0xc) - *(longlong *)(param_1 + 10) >> 4;
          piVar13 = (int *)(*(longlong *)(param_1 + 10) + 4);
          local_48[0] = uVar6;
          do {
            iVar3 = piVar13[1];
            if ((param_3 <= iVar3) && (param_4 <= piVar13[2])) {
              iVar3 = FUN_180001b20(param_1,piVar13[-1],*piVar13,param_3,param_4);
              if (iVar11 < iVar3) {
                local_38 = CONCAT44(*piVar13,piVar13[-1]);
                uStack_30 = CONCAT44(param_4,param_3);
                iVar11 = iVar3;
              }
              iVar3 = piVar13[1];
              uVar6 = local_48[0];
            }
            if (((param_4 <= iVar3) && (param_3 <= piVar13[2])) &&
               (iVar3 = FUN_180001b20(param_1,piVar13[-1],*piVar13,param_3,param_4),
               uVar6 = local_48[0], iVar11 < iVar3)) {
              local_38 = CONCAT44(*piVar13,piVar13[-1]);
              uStack_30 = CONCAT44(param_3,param_4);
              iVar11 = iVar3;
            }
            uVar12 = uVar12 + 1;
            piVar13 = piVar13 + 4;
          } while (uVar12 < uVar6);
        }
      }
    }
  }
LAB_180002487:
  *param_2 = CONCAT412(uStack_30._4_4_,
                       CONCAT48((undefined4)uStack_30,CONCAT44(local_38._4_4_,(undefined4)local_38))
                      );
LAB_18000248b:
  uVar12 = 0;
  if (*(int *)(*param_2 + 0xc) != 0) {
    uVar9 = *(longlong *)(param_1 + 0xc) - *(longlong *)(param_1 + 10) >> 4;
    uVar6 = uVar12;
    if (uVar9 != 0) {
      do {
        local_38 = *(undefined8 *)(uVar12 + *(longlong *)(param_1 + 10));
        uStack_30 = ((undefined8 *)(uVar12 + *(longlong *)(param_1 + 10)))[1];
        cVar2 = FUN_1800027c0((longlong)param_1,(int *)&local_38,(int *)param_2);
        if (cVar2 != '\0') {
          _Src = (void *)((longlong)(void *)(*(longlong *)(param_1 + 10) + uVar12) + 0x10);
          memmove((void *)(*(longlong *)(param_1 + 10) + uVar12),_Src,
                  *(longlong *)(param_1 + 0xc) - (longlong)_Src);
          *(longlong *)(param_1 + 0xc) = *(longlong *)(param_1 + 0xc) + -0x10;
          uVar6 = uVar6 - 1;
          uVar12 = uVar12 - 0x10;
          uVar9 = uVar9 - 1;
        }
        uVar6 = uVar6 + 1;
        uVar12 = uVar12 + 0x10;
      } while (uVar6 < uVar9);
    }
    FUN_180002670((longlong)param_1);
    FUN_180001a60((void **)(param_1 + 4),(undefined4 *)param_2);
  }
  return param_2;
}



void FUN_180002540(longlong param_1,int *param_2)

{
  void *_Src;
  int **ppiVar1;
  int *piVar2;
  undefined4 *puVar3;
  int *piVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  char cVar12;
  void *_Dst;
  ulonglong uVar13;
  ulonglong uVar14;
  ulonglong uVar15;
  int local_18;
  int iStack_14;
  int iStack_10;
  int iStack_c;
  
  uVar13 = 0;
  uVar15 = *(longlong *)(param_1 + 0x30) - *(longlong *)(param_1 + 0x28) >> 4;
  uVar14 = uVar13;
  if (uVar15 != 0) {
    do {
      piVar2 = (int *)(uVar14 + *(longlong *)(param_1 + 0x28));
      local_18 = *piVar2;
      iStack_14 = piVar2[1];
      iStack_10 = piVar2[2];
      iStack_c = piVar2[3];
      cVar12 = FUN_1800027c0(param_1,&local_18,param_2);
      if (cVar12 != '\0') {
        _Dst = (void *)(*(longlong *)(param_1 + 0x28) + uVar14);
        _Src = (void *)((longlong)_Dst + 0x10);
        memmove(_Dst,_Src,*(longlong *)(param_1 + 0x30) - (longlong)_Src);
        *(longlong *)(param_1 + 0x30) = *(longlong *)(param_1 + 0x30) + -0x10;
        uVar13 = uVar13 - 1;
        uVar14 = uVar14 - 0x10;
        uVar15 = uVar15 - 1;
      }
      uVar13 = uVar13 + 1;
      uVar14 = uVar14 + 0x10;
    } while (uVar13 < uVar15);
  }
  FUN_180002670(param_1);
  piVar2 = *(int **)(param_1 + 0x18);
  ppiVar1 = (int **)(param_1 + 0x10);
  if ((param_2 < piVar2) && (piVar4 = *ppiVar1, piVar4 <= param_2)) {
    if (piVar2 == *(int **)(param_1 + 0x20)) {
      FUN_1800012f0(ppiVar1,1);
    }
    puVar5 = *(undefined4 **)(param_1 + 0x18);
    if (puVar5 != (undefined4 *)0x0) {
      puVar3 = (undefined4 *)
               ((longlong)*ppiVar1 + ((longlong)param_2 - (longlong)piVar4 & 0xfffffffffffffff0U));
      uVar6 = puVar3[1];
      uVar7 = puVar3[2];
      uVar8 = puVar3[3];
      *puVar5 = *puVar3;
      puVar5[1] = uVar6;
      puVar5[2] = uVar7;
      puVar5[3] = uVar8;
      *(longlong *)(param_1 + 0x18) = *(longlong *)(param_1 + 0x18) + 0x10;
      return;
    }
  }
  else {
    if (piVar2 == *(int **)(param_1 + 0x20)) {
      FUN_1800012f0(ppiVar1,1);
    }
    piVar2 = *(int **)(param_1 + 0x18);
    if (piVar2 != (int *)0x0) {
      iVar9 = param_2[1];
      iVar10 = param_2[2];
      iVar11 = param_2[3];
      *piVar2 = *param_2;
      piVar2[1] = iVar9;
      piVar2[2] = iVar10;
      piVar2[3] = iVar11;
    }
  }
  *(longlong *)(param_1 + 0x18) = *(longlong *)(param_1 + 0x18) + 0x10;
  return;
}



void FUN_180002670(longlong param_1)

{
  void *pvVar1;
  ulonglong uVar2;
  void *pvVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  longlong lVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  longlong lVar9;
  
  uVar7 = 0;
  if (*(longlong *)(param_1 + 0x30) - *(longlong *)(param_1 + 0x28) >> 4 != 0) {
    uVar4 = 1;
    lVar9 = 0x10;
    uVar8 = uVar7;
    do {
      uVar5 = uVar4;
      lVar6 = lVar9;
      if (uVar4 < (ulonglong)(*(longlong *)(param_1 + 0x30) - *(longlong *)(param_1 + 0x28) >> 4)) {
        do {
          uVar2 = FUN_180002950((int *)(uVar8 + *(longlong *)(param_1 + 0x28)),
                                (int *)(lVar6 + *(longlong *)(param_1 + 0x28)));
          if ((char)uVar2 != '\0') {
            pvVar3 = (void *)(*(longlong *)(param_1 + 0x28) + uVar8);
            pvVar1 = (void *)((longlong)pvVar3 + 0x10);
            memmove(pvVar3,pvVar1,*(longlong *)(param_1 + 0x30) - (longlong)pvVar1);
            *(longlong *)(param_1 + 0x30) = *(longlong *)(param_1 + 0x30) + -0x10;
            uVar7 = uVar7 - 1;
            uVar4 = uVar4 - 1;
            lVar9 = lVar9 + -0x10;
            uVar8 = uVar8 - 0x10;
            break;
          }
          uVar2 = FUN_180002950((int *)(lVar6 + *(longlong *)(param_1 + 0x28)),
                                (int *)(uVar8 + *(longlong *)(param_1 + 0x28)));
          if ((char)uVar2 != '\0') {
            pvVar3 = (void *)(*(longlong *)(param_1 + 0x28) + lVar6);
            pvVar1 = (void *)((longlong)pvVar3 + 0x10);
            memmove(pvVar3,pvVar1,*(longlong *)(param_1 + 0x30) - (longlong)pvVar1);
            *(longlong *)(param_1 + 0x30) = *(longlong *)(param_1 + 0x30) + -0x10;
            uVar5 = uVar5 - 1;
            lVar6 = lVar6 + -0x10;
          }
          uVar5 = uVar5 + 1;
          lVar6 = lVar6 + 0x10;
        } while (uVar5 < (ulonglong)
                         (*(longlong *)(param_1 + 0x30) - *(longlong *)(param_1 + 0x28) >> 4));
      }
      uVar7 = uVar7 + 1;
      uVar4 = uVar4 + 1;
      lVar9 = lVar9 + 0x10;
      uVar8 = uVar8 + 0x10;
    } while (uVar7 < (ulonglong)(*(longlong *)(param_1 + 0x30) - *(longlong *)(param_1 + 0x28) >> 4)
            );
  }
  return;
}



void FUN_1800027c0(longlong param_1,int *param_2,int *param_3)

{
  int iVar1;
  int iVar2;
  undefined auStack_48 [32];
  int local_28;
  int iStack_24;
  int iStack_20;
  int iStack_1c;
  ulonglong local_18;
  
  local_18 = DAT_180006010 ^ (ulonglong)auStack_48;
  if ((*param_3 < *param_2 + param_2[2]) && (*param_2 < *param_3 + param_3[2])) {
    iVar1 = param_2[1];
    iVar2 = param_3[1];
    if ((iVar2 < iVar1 + param_2[3]) && (iVar1 < iVar2 + param_3[3])) {
      if (iVar1 < iVar2) {
        local_28 = *param_2;
        iStack_24 = param_2[1];
        iStack_20 = param_2[2];
        iStack_1c = iVar2 - iStack_24;
        FUN_180001a60((void **)(param_1 + 0x28),&local_28);
      }
      iVar1 = param_3[3] + param_3[1];
      if (iVar1 < param_2[1] + param_2[3]) {
        local_28 = *param_2;
        iStack_20 = param_2[2];
        iStack_1c = ((param_2[1] - param_3[3]) - param_3[1]) + param_2[3];
        iStack_24 = iVar1;
        FUN_180001a60((void **)(param_1 + 0x28),&local_28);
      }
      if ((param_3[1] < param_2[1] + param_2[3]) && (param_2[1] < param_3[1] + param_3[3])) {
        iVar1 = *param_3;
        if ((*param_2 < iVar1) && (iVar1 < *param_2 + param_2[2])) {
          local_28 = *param_2;
          iStack_24 = param_2[1];
          iStack_1c = param_2[3];
          iStack_20 = iVar1 - local_28;
          FUN_180001a60((void **)(param_1 + 0x28),&local_28);
        }
        iVar1 = param_3[2] + *param_3;
        if (iVar1 < *param_2 + param_2[2]) {
          iStack_24 = param_2[1];
          iStack_1c = param_2[3];
          iStack_20 = ((*param_2 - param_3[2]) - *param_3) + param_2[2];
          local_28 = iVar1;
          FUN_180001a60((void **)(param_1 + 0x28),&local_28);
        }
      }
    }
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_48);
  return;
}



ulonglong FUN_180002950(int *param_1,int *param_2)

{
  uint uVar1;
  ulonglong in_RAX;
  
  if (*param_2 <= *param_1) {
    if ((param_2[1] <= param_1[1]) &&
       (in_RAX = (ulonglong)(uint)param_1[2], *param_1 + param_1[2] <= *param_2 + param_2[2])) {
      uVar1 = param_1[3];
      in_RAX = (ulonglong)uVar1;
      if ((int)(param_1[1] + uVar1) <= param_2[3] + param_2[1]) {
        return CONCAT71((uint7)(uint3)(uVar1 >> 8),1);
      }
    }
  }
  return in_RAX & 0xffffffffffffff00;
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
        FUN_180003368();
      }
      else {
        FUN_180003348();
      }
    }
  }
  return pvVar2;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180003a66. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
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
LAB_180002a06:
    uVar3 = (ulonglong)pvVar2 & 0xffffffffffffff00;
  }
  else {
    do {
      LOCK();
      bVar1 = DAT_180006168 == 0;
      DAT_180006168 = DAT_180006168 ^ (ulonglong)bVar1 * (DAT_180006168 ^ (ulonglong)StackBase);
      pvVar2 = (void *)(!bVar1 * DAT_180006168);
      if (bVar1) goto LAB_180002a06;
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
    uVar3 = FUN_180003564();
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
  
  cVar1 = FUN_180003ab0();
  if (cVar1 != '\0') {
    cVar1 = FUN_180003ab0();
    if (cVar1 != '\0') {
      return 1;
    }
    FUN_180003ab0();
  }
  return 0;
}



// Library Function - Single Match
//  __scrt_dllmain_crt_thread_detach
// 
// Library: Visual Studio 2015 Release

undefined __scrt_dllmain_crt_thread_detach(void)

{
  FUN_180003ab0();
  FUN_180003ab0();
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
    _execute_onexit_table(&DAT_180006170);
    return;
  }
  uVar2 = FUN_180003ab4();
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
  FUN_180003ab0();
  FUN_180003ab0();
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
    DAT_1800061a0 = 1;
  }
  __isa_available_init();
  uVar1 = FUN_180003ab0();
  if ((char)uVar1 != '\0') {
    uVar1 = FUN_180003ab0();
    if ((char)uVar1 != '\0') {
      return uVar1 & 0xffffffffffffff00 | 1;
    }
    uVar1 = FUN_180003ab0();
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
      bVar2 = 0x40 - ((byte)DAT_180006010 & 0x3f) & 0x3f;
      _DAT_180006180 = (0xffffffffffffffffU >> bVar2 | -1L << 0x40 - bVar2) ^ DAT_180006010;
      local_28 = (undefined4)_DAT_180006180;
      uStack_24 = (undefined4)(_DAT_180006180 >> 0x20);
      _DAT_180006170 = local_28;
      uRam0000000180006174 = uStack_24;
      uRam0000000180006178 = local_28;
      uRam000000018000617c = uStack_24;
      _DAT_180006188 = local_28;
      uRam000000018000618c = uStack_24;
      uRam0000000180006190 = local_28;
      uRam0000000180006194 = uStack_24;
      _DAT_180006198 = _DAT_180006180;
    }
    else {
      uVar4 = _initialize_onexit_table(&DAT_180006170);
      if ((int)uVar4 == 0) {
        uVar4 = _initialize_onexit_table(&DAT_180006188);
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



// WARNING: Removing unreachable block (ram,0x000180002cee)
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
  for (pIVar3 = &IMAGE_SECTION_HEADER_180000208; pIVar3 != (IMAGE_SECTION_HEADER *)&DAT_180000320;
      pIVar3 = pIVar3 + 1) {
    if (((ulonglong)(uint)pIVar3->VirtualAddress <= param_1 - 0x180000000U) &&
       (uVar1 = (ulonglong)((pIVar3->Misc).PhysicalAddress + pIVar3->VirtualAddress),
       param_1 - 0x180000000U < uVar1)) goto LAB_180002cd7;
  }
  pIVar3 = (IMAGE_SECTION_HEADER *)0x0;
LAB_180002cd7:
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
    DAT_180006168 = 0;
  }
  return;
}



// Library Function - Single Match
//  __scrt_uninitialize_crt
// 
// Library: Visual Studio 2015 Release

undefined __scrt_uninitialize_crt(undefined8 param_1,char param_2)

{
  if ((DAT_1800061a0 == '\0') || (param_2 == '\0')) {
    FUN_180003ab0();
    FUN_180003ab0();
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
  
  bVar2 = (byte)DAT_180006010 & 0x3f;
  if (((DAT_180006010 ^ _DAT_180006170) >> bVar2 | (DAT_180006010 ^ _DAT_180006170) << 0x40 - bVar2)
      == 0xffffffffffffffff) {
    iVar1 = _crt_atexit();
  }
  else {
    iVar1 = _register_onexit_function(&DAT_180006170,_Func);
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
  if ((_StackCookie == DAT_180006010) && ((short)(_StackCookie >> 0x30) == 0)) {
    return;
  }
  __report_gsfailure(_StackCookie);
  return;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180003a66. Too many branches
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
    if (DAT_1800061a4 < 1) {
      uVar6 = 0;
    }
    else {
      DAT_1800061a4 = DAT_1800061a4 + -1;
      uVar8 = __scrt_acquire_startup_lock();
      if (_DAT_180006160 != 2) {
        uVar7 = 0;
        __scrt_fastfail(7);
      }
      __scrt_dllmain_uninitialize_c();
      _DAT_180006160 = 0;
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
      if (_DAT_180006160 != 0) {
        __scrt_fastfail(7);
      }
      _DAT_180006160 = 1;
      uVar8 = __scrt_dllmain_before_initialize_c();
      if ((char)uVar8 != '\0') {
        _RTC_Initialize();
        atexit(&LAB_1800039b0);
        FUN_180003914();
        atexit(&LAB_180003924);
        __scrt_initialize_default_local_stdio_options();
        iVar5 = _initterm_e(&DAT_180004198,&DAT_1800041a0);
        if ((iVar5 == 0) && (uVar9 = __scrt_dllmain_after_initialize_c(), (char)uVar9 != '\0')) {
          _initterm(&DAT_180004170,&DAT_180004190);
          _DAT_180006160 = 2;
          bVar2 = false;
        }
      }
      __scrt_release_startup_lock((char)uVar7);
      if (!bVar2) {
        ppcVar10 = (code **)FUN_18000395c();
        if ((*ppcVar10 != (code *)0x0) &&
           (uVar7 = __scrt_is_nonwritable_in_current_image((longlong)ppcVar10), (char)uVar7 != '\0')
           ) {
          pcVar1 = *ppcVar10;
          _guard_check_icall();
          (*pcVar1)(param_1,2,param_3);
        }
        DAT_1800061a4 = DAT_1800061a4 + 1;
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



int FUN_18000306c(HINSTANCE__ *param_1,ulong param_2,void *param_3)

{
  int iVar1;
  undefined8 uVar2;
  
  if ((param_2 == 0) && (DAT_1800061a4 < 1)) {
    iVar1 = 0;
  }
  else if ((1 < param_2 - 1) ||
          ((iVar1 = dllmain_raw(param_1,param_2,param_3), iVar1 != 0 &&
           (iVar1 = dllmain_crt_dispatch(param_1,param_2,param_3), iVar1 != 0)))) {
    uVar2 = FUN_1800038f0(param_1,param_2);
    iVar1 = (int)uVar2;
    if ((param_2 == 1) && (iVar1 == 0)) {
      FUN_1800038f0(param_1,0);
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



// WARNING: Removing unreachable block (ram,0x000180003191)
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
  FUN_18000306c(param_1,param_2,param_3);
  return;
}



undefined8 * FUN_1800031f8(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy(param_2 + 8);
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



undefined8 * FUN_180003238(undefined8 *param_1)

{
  param_1[2] = 0;
  param_1[1] = "bad allocation";
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



undefined8 * FUN_180003258(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy(param_2 + 8);
  *param_1 = std::bad_array_new_length::vftable;
  return param_1;
}



undefined8 * FUN_180003298(undefined8 *param_1)

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



undefined8 * FUN_180003304(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = std::exception::vftable;
  __std_exception_destroy(param_1 + 1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_180003348(void)

{
  undefined8 local_28 [5];
  
  FUN_180003238(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_180004e08);
}



void FUN_180003368(void)

{
  undefined8 local_28 [5];
  
  FUN_180003298(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_180004e90);
}



char * FUN_180003388(longlong param_1)

{
  char *pcVar1;
  
  pcVar1 = "Unknown exception";
  if (*(longlong *)(param_1 + 8) != 0) {
    pcVar1 = *(char **)(param_1 + 8);
  }
  return pcVar1;
}



// WARNING: Removing unreachable block (ram,0x0001800034b9)
// WARNING: Removing unreachable block (ram,0x00018000341e)
// WARNING: Removing unreachable block (ram,0x0001800033c0)
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
  DAT_18000602c = 2;
  piVar1 = (int *)cpuid_basic_info(0);
  _DAT_180006028 = 1;
  puVar2 = (uint *)cpuid_Version_info(1);
  uVar4 = puVar2[3];
  uVar5 = DAT_1800061a8;
  if ((piVar1[2] ^ 0x49656e69U | piVar1[3] ^ 0x6c65746eU | piVar1[1] ^ 0x756e6547U) == 0) {
    _DAT_180006030 = 0xffffffffffffffff;
    uVar6 = *puVar2 & 0xfff3ff0;
    if ((((uVar6 == 0x106c0) || (uVar6 == 0x20660)) || (uVar6 == 0x20670)) ||
       ((uVar5 = DAT_1800061a8 | 4, uVar6 - 0x30650 < 0x21 &&
        ((0x100010001U >> ((ulonglong)(uVar6 - 0x30650) & 0x3f) & 1) != 0)))) {
      uVar5 = DAT_1800061a8 | 5;
    }
  }
  DAT_1800061a8 = uVar5;
  if (((piVar1[1] ^ 0x68747541U | piVar1[2] ^ 0x69746e65U | piVar1[3] ^ 0x444d4163U) == 0) &&
     (0x600eff < (*puVar2 & 0xff00f00))) {
    DAT_1800061a8 = DAT_1800061a8 | 4;
  }
  if (6 < *piVar1) {
    lVar3 = cpuid_Extended_Feature_Enumeration_info(7);
    local_20 = *(uint *)(lVar3 + 4);
    if ((local_20 >> 9 & 1) != 0) {
      DAT_1800061a8 = DAT_1800061a8 | 2;
    }
  }
  if ((uVar4 >> 0x14 & 1) != 0) {
    _DAT_180006028 = 2;
    DAT_18000602c = 6;
    if ((((uVar4 >> 0x1b & 1) != 0) && ((uVar4 >> 0x1c & 1) != 0)) && ((in_XCR0 & 6) == 6)) {
      DAT_18000602c = 0xe;
      _DAT_180006028 = 3;
      if ((local_20 & 0x20) != 0) {
        _DAT_180006028 = 5;
        DAT_18000602c = 0x2e;
      }
    }
  }
  return 0;
}



undefined8 FUN_180003564(void)

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
  return _DAT_180006040 != 0;
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
  _DAT_1800061ac = 0;
  *(undefined8 *)(puVar4 + -8) = 0x1800035b9;
  memset(local_4d8,0,0x4d0);
  *(undefined8 *)(puVar4 + -8) = 0x1800035c3;
  RtlCaptureContext(local_4d8);
  *(undefined8 *)(puVar4 + -8) = 0x1800035dd;
  FunctionEntry = RtlLookupFunctionEntry(local_3e0,&local_res10,(PUNWIND_HISTORY_TABLE)0x0);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0) {
    *(undefined8 *)(puVar4 + 0x38) = 0;
    *(undefined **)(puVar4 + 0x30) = local_res18;
    *(undefined **)(puVar4 + 0x28) = local_res20;
    *(undefined **)(puVar4 + 0x20) = local_4d8;
    *(undefined8 *)(puVar4 + -8) = 0x18000361e;
    RtlVirtualUnwind(0,local_res10,local_3e0,FunctionEntry,*(PCONTEXT *)(puVar4 + 0x20),
                     *(PVOID **)(puVar4 + 0x28),*(PDWORD64 *)(puVar4 + 0x30),
                     *(PKNONVOLATILE_CONTEXT_POINTERS *)(puVar4 + 0x38));
  }
  local_440 = &stack0x00000008;
  *(undefined8 *)(puVar4 + -8) = 0x180003650;
  memset(puVar4 + 0x50,0,0x98);
  *(undefined8 *)(puVar4 + 0x60) = unaff_retaddr;
  *(undefined4 *)(puVar4 + 0x50) = 0x40000015;
  *(undefined4 *)(puVar4 + 0x54) = 1;
  *(undefined8 *)(puVar4 + -8) = 0x180003672;
  BVar2 = IsDebuggerPresent();
  *(undefined **)(puVar4 + 0x40) = puVar4 + 0x50;
  *(undefined **)(puVar4 + 0x48) = local_4d8;
  *(undefined8 *)(puVar4 + -8) = 0x180003693;
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  *(undefined8 *)(puVar4 + -8) = 0x18000369e;
  LVar3 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)(puVar4 + 0x40));
  if (LVar3 == 0) {
    _DAT_1800061ac = _DAT_1800061ac & -(uint)(BVar2 == 1);
  }
  return;
}



void _guard_check_icall(void)

{
  return;
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
                    // WARNING: Could not recover jumptable at 0x0001800036f5. Too many branches
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
  *(undefined8 *)(puVar3 + -8) = 0x180003726;
  capture_previous_context((PCONTEXT)&DAT_180006250);
  _DAT_1800061c0 = *(undefined8 *)(puVar3 + 0x38);
  _DAT_1800062e8 = puVar3 + 0x40;
  _DAT_1800062d0 = *(undefined8 *)(puVar3 + 0x40);
  _DAT_1800061b0 = 0xc0000409;
  _DAT_1800061b4 = 1;
  _DAT_1800061c8 = 1;
  DAT_1800061d0 = 2;
  *(undefined8 *)(puVar3 + 0x20) = DAT_180006010;
  *(undefined8 *)(puVar3 + 0x28) = DAT_180006018;
  *(undefined8 *)(puVar3 + -8) = 0x1800037c8;
  DAT_180006348 = _DAT_1800061c0;
  __raise_securityfailure((_EXCEPTION_POINTERS *)&PTR_DAT_1800042c8);
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
  if (DAT_180006010 == 0x2b992ddfa232) {
    GetSystemTimeAsFileTime(&local_res10);
    local_res8 = local_res10;
    DVar1 = GetCurrentThreadId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    DVar1 = GetCurrentProcessId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    QueryPerformanceCounter((LARGE_INTEGER *)&local_res18);
    DAT_180006010 =
         ((ulonglong)local_res18 << 0x20 ^ CONCAT44(uStackX_1c,local_res18) ^ (ulonglong)local_res8
         ^ (ulonglong)&local_res8) & 0xffffffffffff;
    if (DAT_180006010 == 0x2b992ddfa232) {
      DAT_180006010 = 0x2b992ddfa233;
    }
  }
  DAT_180006018 = ~DAT_180006010;
  return;
}



undefined8 FUN_1800038f0(HMODULE param_1,int param_2)

{
  if (param_2 == 1) {
    DisableThreadLibraryCalls(param_1);
  }
  return 1;
}



void FUN_180003914(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000391b. Too many branches
                    // WARNING: Treating indirect jump as call
  InitializeSListHead(&DAT_180006720);
  return;
}



undefined * FUN_180003930(void)

{
  return &DAT_180006730;
}



undefined * FUN_180003938(void)

{
  return &DAT_180006738;
}



// Library Function - Single Match
//  __scrt_initialize_default_local_stdio_options
// 
// Library: Visual Studio 2015 Release

void __scrt_initialize_default_local_stdio_options(void)

{
  ulonglong *puVar1;
  
  puVar1 = (ulonglong *)FUN_180003930();
  *puVar1 = *puVar1 | 4;
  puVar1 = (ulonglong *)FUN_180003938();
  *puVar1 = *puVar1 | 2;
  return;
}



undefined * FUN_18000395c(void)

{
  return &DAT_180006740;
}



// Library Function - Single Match
//  _RTC_Initialize
// 
// Library: Visual Studio 2015 Release

void _RTC_Initialize(void)

{
  code *pcVar1;
  code **ppcVar2;
  
  for (ppcVar2 = (code **)&DAT_180004920; ppcVar2 < &DAT_180004920; ppcVar2 = ppcVar2 + 1) {
    pcVar1 = *ppcVar2;
    if (pcVar1 != (code *)0x0) {
      _guard_check_icall();
      (*pcVar1)();
    }
  }
  return;
}



undefined8 * FUN_1800039fc(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = type_info::vftable;
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo)

{
                    // WARNING: Could not recover jumptable at 0x000180003a30. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  _CxxThrowException(pExceptionObject,pThrowInfo);
  return;
}



void __std_exception_copy(void)

{
                    // WARNING: Could not recover jumptable at 0x000180003a42. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_exception_copy();
  return;
}



void __std_exception_destroy(void)

{
                    // WARNING: Could not recover jumptable at 0x000180003a48. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_exception_destroy();
  return;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180003a4e. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



int __cdecl _callnewh(size_t _Size)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180003a5a. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _callnewh(_Size);
  return iVar1;
}



void * __cdecl malloc(size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180003a60. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = malloc(_Size);
  return pvVar1;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180003a66. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



void _seh_filter_dll(void)

{
                    // WARNING: Could not recover jumptable at 0x000180003a6c. Too many branches
                    // WARNING: Treating indirect jump as call
  _seh_filter_dll();
  return;
}



void _configure_narrow_argv(void)

{
                    // WARNING: Could not recover jumptable at 0x000180003a72. Too many branches
                    // WARNING: Treating indirect jump as call
  _configure_narrow_argv();
  return;
}



void _initialize_narrow_environment(void)

{
                    // WARNING: Could not recover jumptable at 0x000180003a78. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_narrow_environment();
  return;
}



void _initialize_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x000180003a7e. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_onexit_table();
  return;
}



void _register_onexit_function(void)

{
                    // WARNING: Could not recover jumptable at 0x000180003a84. Too many branches
                    // WARNING: Treating indirect jump as call
  _register_onexit_function();
  return;
}



void _execute_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x000180003a8a. Too many branches
                    // WARNING: Treating indirect jump as call
  _execute_onexit_table();
  return;
}



void _crt_atexit(void)

{
                    // WARNING: Could not recover jumptable at 0x000180003a90. Too many branches
                    // WARNING: Treating indirect jump as call
  _crt_atexit();
  return;
}



void __cdecl _cexit(void)

{
                    // WARNING: Could not recover jumptable at 0x000180003a96. Too many branches
                    // WARNING: Treating indirect jump as call
  _cexit();
  return;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x000180003a9c. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



void _initterm_e(void)

{
                    // WARNING: Could not recover jumptable at 0x000180003aa2. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm_e();
  return;
}



BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180003aa8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = IsProcessorFeaturePresent(ProcessorFeature);
  return BVar1;
}



undefined FUN_180003ab0(void)

{
  return 1;
}



undefined8 FUN_180003ab4(void)

{
  return 0;
}



// WARNING: This is an inlined function

void _guard_dispatch_icall(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
                    // WARNING: Could not recover jumptable at 0x000180003ad0. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void Catch_All_180003ae0(undefined8 param_1,longlong param_2)

{
  FUN_180001480(*(undefined8 *)(param_2 + 0x50),*(void **)(param_2 + 0x60),
                *(ulonglong *)(param_2 + 0x58));
                    // WARNING: Subroutine does not return
  _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
}



void Catch_All_180003b10(undefined8 param_1,longlong param_2)

{
  FUN_180001500(*(undefined8 *)(param_2 + 0x50),*(void **)(param_2 + 0x60),
                *(ulonglong *)(param_2 + 0x58));
                    // WARNING: Subroutine does not return
  _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
}



void FUN_180003b50(undefined8 param_1,longlong param_2)

{
  __scrt_release_startup_lock(*(char *)(param_2 + 0x40));
  return;
}



void FUN_180003b67(undefined8 param_1,longlong param_2)

{
  __scrt_dllmain_uninitialize_critical();
  __scrt_release_startup_lock(*(char *)(param_2 + 0x38));
  return;
}



void FUN_180003b83(undefined8 *param_1,longlong param_2)

{
  __scrt_dllmain_exception_filter
            (*(undefined8 *)(param_2 + 0x60),*(int *)(param_2 + 0x68),
             *(undefined8 *)(param_2 + 0x70),dllmain_crt_dispatch,*(undefined4 *)*param_1,param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180003bc0(void)

{
  if (DAT_180006130 != (void *)0x0) {
    _guard_check_icall();
    _guard_check_icall();
    FUN_180001500(&DAT_180006130,DAT_180006130,DAT_180006140 - (longlong)DAT_180006130 >> 4);
    DAT_180006140 = 0;
    _DAT_180006130 = ZEXT816(0);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180003d10(void)

{
  if (DAT_180006148 != (void *)0x0) {
    _guard_check_icall();
    _guard_check_icall();
    FUN_180001480(&DAT_180006148,DAT_180006148,(DAT_180006158 - (longlong)DAT_180006148) / 0x18);
    DAT_180006158 = 0;
    _DAT_180006148 = ZEXT816(0);
  }
  return;
}


