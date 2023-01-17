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


// WARNING! conflicting data type names: /Demangler/Graphine/GUID - /GUID

typedef struct IHashProgress IHashProgress, *PIHashProgress;

struct IHashProgress { // PlaceHolder Structure
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

typedef ulonglong size_t;




IHashProgress * FUN_180001000(IHashProgress *param_1,uint param_2)

{
  Graphine::Core::IHashProgress::_IHashProgress(param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_180001040(void **param_1,void *param_2,void *param_3)

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
  _Dst = (void **)FUN_180001160(param_1,(longlong)param_2 + 1);
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
    FUN_180001470(param_1,*param_1,(longlong)param_1[3] + 1);
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



void * FUN_180001160(undefined8 param_1,ulonglong param_2)

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



void ** FUN_1800011e0(void **param_1,void **param_2,void *param_3,void *param_4)

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
    FUN_1800014e0(param_1,0,(ulonglong)param_3);
  }
  else {
    if ((void *)0x7ffffffffffffffe < param_4) {
      std::_Xlength_error("string too long");
      pcVar1 = (code *)swi(3);
      ppvVar2 = (void **)(*pcVar1)();
      return ppvVar2;
    }
    if (param_1[3] < param_4) {
      FUN_180001040(param_1,param_4,param_1[2]);
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



void ** FUN_180001320(void **param_1,void **param_2,void *param_3)

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
        ppvVar3 = FUN_1800011e0(param_1,param_1,(void *)((longlong)param_2 - (longlong)ppvVar3 >> 1)
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
    FUN_180001040(param_1,param_3,param_1[2]);
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



void FUN_180001470(undefined8 param_1,void *param_2,ulonglong param_3)

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



undefined8 * FUN_1800014e0(undefined8 *param_1,ulonglong param_2,ulonglong param_3)

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



Enum __cdecl Graphine::Core::DataTypeInfo::CSharp_DataTypeInfo_GetChannelDataType(Enum param_1)

{
  Enum EVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180001590. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x1590  1  CSharp_DataTypeInfo_GetChannelDataType
  EVar1 = GetChannelDataType(param_1);
  return EVar1;
}



int __cdecl Graphine::Core::DataTypeInfo::CSharp_DataTypeInfo_GetChannelSize__SWIG_0(Enum param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001800015a0. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x15a0  2  CSharp_DataTypeInfo_GetChannelSize__SWIG_0
  iVar1 = GetChannelSize(param_1);
  return iVar1;
}



int __cdecl Graphine::Core::DataTypeInfo::CSharp_DataTypeInfo_GetChannelSize__SWIG_1(Enum param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001800015b0. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x15b0  3  CSharp_DataTypeInfo_GetChannelSize__SWIG_1
  iVar1 = GetChannelSize(param_1);
  return iVar1;
}



Enum __cdecl
Graphine::Core::DataTypeInfo::CSharp_DataTypeInfo_GetDatatype(Enum param_1,int param_2,int param_3)

{
  Enum EVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001800015c0. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x15c0  4  CSharp_DataTypeInfo_GetDatatype
  EVar1 = GetDatatype(param_1,param_2,param_3);
  return EVar1;
}



int __cdecl Graphine::Core::DataTypeInfo::CSharp_DataTypeInfo_GetFlags(Enum param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001800015d0. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x15d0  5  CSharp_DataTypeInfo_GetFlags
  iVar1 = GetFlags(param_1);
  return iVar1;
}



int __cdecl Graphine::Core::DataTypeInfo::CSharp_DataTypeInfo_GetNumChannels(Enum param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001800015e0. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x15e0  6  CSharp_DataTypeInfo_GetNumChannels
  iVar1 = GetNumChannels(param_1);
  return iVar1;
}



int __cdecl Graphine::Core::DataTypeInfo::CSharp_DataTypeInfo_GetPixelSize(Enum param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001800015f0. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x15f0  7  CSharp_DataTypeInfo_GetPixelSize
  iVar1 = GetPixelSize(param_1);
  return iVar1;
}



bool CSharp_DataTypeInfo_IsLinear(Enum param_1)

{
  bool bVar1;
  
                    // 0x1600  8  CSharp_DataTypeInfo_IsLinear
  bVar1 = Graphine::Core::DataTypeInfo::IsLinear(param_1);
  return bVar1;
}



void CSharp_DataTypeInfo_ToString(void)

{
  basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t___ bVar1;
  undefined7 extraout_var;
  undefined2 *puVar2;
  undefined auStack_78 [32];
  undefined8 local_58;
  undefined8 local_48;
  ulonglong local_40;
  undefined2 local_38;
  undefined6 uStack_36;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x1620  9  CSharp_DataTypeInfo_ToString
  local_18 = DAT_1800060e0 ^ (ulonglong)auStack_78;
  local_40 = 7;
  local_48 = 0;
  local_58._0_2_ = 0;
  bVar1 = Graphine::Core::DataTypeInfo::ToString((Enum)&local_38);
  if ((void **)&local_58 != (void **)CONCAT71(extraout_var,bVar1)) {
    FUN_1800011e0((void **)&local_58,(void **)CONCAT71(extraout_var,bVar1),(void *)0x0,
                  (void *)0xffffffffffffffff);
  }
  if (7 < local_20) {
    FUN_180001470(&local_38,(void *)CONCAT62(uStack_36,local_38),local_20 + 1);
  }
  puVar2 = (undefined2 *)&local_58;
  local_20 = 7;
  if (7 < local_40) {
    puVar2 = (undefined2 *)CONCAT62(local_58._2_6_,(undefined2)local_58);
  }
  local_28 = 0;
  local_38 = 0;
  (*DAT_1800061f8)(puVar2);
  if (7 < local_40) {
    FUN_180001470(&local_58,(void *)CONCAT62(local_58._2_6_,(undefined2)local_58),local_40 + 1);
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_78);
  return;
}



void CSharp_DiskManagement_GetFreeDiskSpace(void **param_1,__uint64 *param_2)

{
  void *pvVar1;
  undefined auStack_58 [32];
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x1700  10  CSharp_DiskManagement_GetFreeDiskSpace
  local_18 = DAT_1800060e0 ^ (ulonglong)auStack_58;
  if (param_1 == (void **)0x0) {
    (*DAT_1800060c8)("null wstring",0);
    __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
    return;
  }
  pvVar1 = (void *)0x0;
  local_20 = 7;
  local_28 = 0;
  local_38._0_2_ = 0;
  if (*(short *)param_1 != 0) {
    pvVar1 = (void *)0xffffffffffffffff;
    do {
      pvVar1 = (void *)((longlong)pvVar1 + 1);
    } while (*(short *)((longlong)param_1 + (longlong)pvVar1 * 2) != 0);
  }
  FUN_180001320((void **)&local_38,param_1,pvVar1);
  Graphine::Core::DiskManagement::GetFreeDiskSpace
            ((basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t___
              *)&local_38,param_2);
  if (7 < local_20) {
    FUN_180001470(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
  return;
}



undefined8 CSharp_GR_MAX_CONFIG_LENGTH_get(void)

{
                    // 0x17c0  11  CSharp_GR_MAX_CONFIG_LENGTH_get
  return 0x400;
}



undefined8 CSharp_GR_MAX_MESSAGE_LENGTH_get(void)

{
                    // 0x17d0  12  CSharp_GR_MAX_MESSAGE_LENGTH_get
  return 0x200;
}



undefined8 CSharp_GR_MAX_PATH_get(void)

{
                    // 0x17e0  13  CSharp_GR_MAX_PATH_get
  return 0x104;
}



void __cdecl Graphine::Core::GuidBuilder::CSharp_GuidBuilder_NewGuid(GUID *param_1)

{
                    // WARNING: Could not recover jumptable at 0x0001800017f0. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x17f0  14  CSharp_GuidBuilder_NewGuid
  NewGuid(param_1);
  return;
}



void CSharp_IHashAlgorithm_AddBytes(longlong *param_1,undefined8 param_2,undefined4 param_3)

{
                    // 0x1800  15  CSharp_IHashAlgorithm_AddBytes
                    // WARNING: Could not recover jumptable at 0x000180001806. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x10))(param_1,param_2,param_3);
  return;
}



void CSharp_IHashAlgorithm_ComputeHash(undefined8 *param_1,undefined8 param_2,undefined4 param_3)

{
                    // 0x1810  16  CSharp_IHashAlgorithm_ComputeHash
                    // WARNING: Could not recover jumptable at 0x000180001816. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)*param_1)(param_1,param_2,param_3);
  return;
}



void CSharp_IHashAlgorithm_GetHash(longlong *param_1)

{
                    // 0x1820  17  CSharp_IHashAlgorithm_GetHash
                    // WARNING: Could not recover jumptable at 0x000180001823. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x18))();
  return;
}



void CSharp_IHashProgress_Finished(longlong *param_1)

{
                    // 0x1830  19  CSharp_IHashProgress_Finished
                    // WARNING: Could not recover jumptable at 0x000180001833. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x10))();
  return;
}



void CSharp_IHashAlgorithm_HashLength(longlong *param_1)

{
                    // 0x1840  18  CSharp_IHashAlgorithm_HashLength
                    // 0x1840  20  CSharp_IHashProgress_Progress
                    // WARNING: Could not recover jumptable at 0x000180001843. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 8))();
  return;
}



void CSharp_IHashProgress_Started(undefined8 *param_1)

{
                    // 0x1850  21  CSharp_IHashProgress_Started
                    // WARNING: Could not recover jumptable at 0x000180001853. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)*param_1)();
  return;
}



undefined8 CSharp_MAX_CHANNELS_get(void)

{
                    // 0x1860  22  CSharp_MAX_CHANNELS_get
                    // 0x1860  23  CSharp_MAX_CHANNEL_SIZE_get
                    // 0x1860  24  CSharp_MAX_NUM_LAYERS_get
  return 4;
}



undefined8 CSharp_MAX_NUM_LEVELS_get(void)

{
                    // 0x1870  25  CSharp_MAX_NUM_LEVELS_get
  return 0xe;
}



void CSharp_MD5Calculation_AddBytes(MD5Calculation *param_1,uchar *param_2,uint param_3)

{
                    // 0x1880  26  CSharp_MD5Calculation_AddBytes
                    // WARNING: Could not recover jumptable at 0x000180001883. Too many branches
                    // WARNING: Treating indirect jump as call
  Graphine::Core::MD5Calculation::AddBytes(param_1,param_2,(ulonglong)param_3);
  return;
}



void CSharp_MD5Calculation_ComputeHash(uchar *param_1,uint param_2,uchar *param_3,__uint64 *param_4)

{
                    // 0x1890  27  CSharp_MD5Calculation_ComputeHash
                    // WARNING: Could not recover jumptable at 0x000180001892. Too many branches
                    // WARNING: Treating indirect jump as call
  Graphine::Core::MD5Calculation::ComputeHash(param_1,(ulonglong)param_2,param_3,param_4);
  return;
}



void __thiscall
Graphine::Core::MD5Calculation::CSharp_MD5Calculation_GetHash(MD5Calculation *this,uchar *param_1)

{
                    // WARNING: Could not recover jumptable at 0x0001800018a0. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x18a0  28  CSharp_MD5Calculation_GetHash
  GetHash(this,param_1);
  return;
}



__uint64 __thiscall
Graphine::Core::MD5Calculation::CSharp_MD5Calculation_HashLength(MD5Calculation *this)

{
  __uint64 _Var1;
  
                    // WARNING: Could not recover jumptable at 0x0001800018b0. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x18b0  29  CSharp_MD5Calculation_HashLength
  _Var1 = HashLength(this);
  return _Var1;
}



void __cdecl Graphine::Core::MD5Checker::CSharp_MD5Checker_Abort(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800018c0. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x18c0  30  CSharp_MD5Checker_Abort
  Abort();
  return;
}



void CSharp_MD5Checker_CalculateChecksum__SWIG_0
               (void **param_1,MD5Hash *param_2,IHashProgress *param_3)

{
  void *pvVar1;
  undefined auStack_58 [32];
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x18d0  31  CSharp_MD5Checker_CalculateChecksum__SWIG_0
  local_18 = DAT_1800060e0 ^ (ulonglong)auStack_58;
  if (param_1 == (void **)0x0) {
    (*DAT_1800060c8)("null wstring",0);
  }
  else {
    pvVar1 = (void *)0x0;
    local_20 = 7;
    local_28 = 0;
    local_38._0_2_ = 0;
    if (*(short *)param_1 != 0) {
      pvVar1 = (void *)0xffffffffffffffff;
      do {
        pvVar1 = (void *)((longlong)pvVar1 + 1);
      } while (*(short *)((longlong)param_1 + (longlong)pvVar1 * 2) != 0);
    }
    FUN_180001320((void **)&local_38,param_1,pvVar1);
    Graphine::Core::MD5Checker::CalculateChecksum
              ((basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t___
                *)&local_38,param_2,param_3);
    if (7 < local_20) {
      FUN_180001470(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
    }
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
  return;
}



void CSharp_MD5Checker_CalculateChecksum__SWIG_1(void **param_1,MD5Hash *param_2)

{
  void *pvVar1;
  undefined auStack_58 [32];
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x1990  32  CSharp_MD5Checker_CalculateChecksum__SWIG_1
  local_18 = DAT_1800060e0 ^ (ulonglong)auStack_58;
  if (param_1 == (void **)0x0) {
    (*DAT_1800060c8)("null wstring",0);
    __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
    return;
  }
  pvVar1 = (void *)0x0;
  local_20 = 7;
  local_28 = 0;
  local_38._0_2_ = 0;
  if (*(short *)param_1 != 0) {
    pvVar1 = (void *)0xffffffffffffffff;
    do {
      pvVar1 = (void *)((longlong)pvVar1 + 1);
    } while (*(short *)((longlong)param_1 + (longlong)pvVar1 * 2) != 0);
  }
  FUN_180001320((void **)&local_38,param_1,pvVar1);
  Graphine::Core::MD5Checker::CalculateChecksum
            ((basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t___
              *)&local_38,param_2,(IHashProgress *)0x0);
  if (7 < local_20) {
    FUN_180001470(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
  return;
}



void CSharp_MD5Checker_Validate__SWIG_0(void **param_1,MD5Hash *param_2,IHashProgress *param_3)

{
  void *pvVar1;
  undefined auStack_58 [32];
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x1a50  33  CSharp_MD5Checker_Validate__SWIG_0
  local_18 = DAT_1800060e0 ^ (ulonglong)auStack_58;
  if (param_1 == (void **)0x0) {
    (*DAT_1800060c8)("null wstring",0);
  }
  else {
    pvVar1 = (void *)0x0;
    local_20 = 7;
    local_28 = 0;
    local_38._0_2_ = 0;
    if (*(short *)param_1 != 0) {
      pvVar1 = (void *)0xffffffffffffffff;
      do {
        pvVar1 = (void *)((longlong)pvVar1 + 1);
      } while (*(short *)((longlong)param_1 + (longlong)pvVar1 * 2) != 0);
    }
    FUN_180001320((void **)&local_38,param_1,pvVar1);
    Graphine::Core::MD5Checker::Validate
              ((basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t___
                *)&local_38,param_2,param_3);
    if (7 < local_20) {
      FUN_180001470(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
    }
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
  return;
}



void CSharp_MD5Checker_Validate__SWIG_1(void **param_1,MD5Hash *param_2)

{
  void *pvVar1;
  undefined auStack_58 [32];
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x1b20  34  CSharp_MD5Checker_Validate__SWIG_1
  local_18 = DAT_1800060e0 ^ (ulonglong)auStack_58;
  if (param_1 == (void **)0x0) {
    (*DAT_1800060c8)("null wstring",0);
    __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
    return;
  }
  pvVar1 = (void *)0x0;
  local_20 = 7;
  local_28 = 0;
  local_38._0_2_ = 0;
  if (*(short *)param_1 != 0) {
    pvVar1 = (void *)0xffffffffffffffff;
    do {
      pvVar1 = (void *)((longlong)pvVar1 + 1);
    } while (*(short *)((longlong)param_1 + (longlong)pvVar1 * 2) != 0);
  }
  FUN_180001320((void **)&local_38,param_1,pvVar1);
  Graphine::Core::MD5Checker::Validate
            ((basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t___
              *)&local_38,param_2,(IHashProgress *)0x0);
  if (7 < local_20) {
    FUN_180001470(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
  return;
}



void CSharp_delete_IHashProgress(longlong *param_1)

{
                    // 0x1c00  39  CSharp_delete_IHashProgress
  if (param_1 != (longlong *)0x0) {
                    // WARNING: Could not recover jumptable at 0x000180001c0d. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*param_1 + 0x18))(param_1,1);
    return;
  }
  return;
}



void CSharp_delete_MD5Calculation(MD5Calculation *param_1)

{
                    // 0x1c20  40  CSharp_delete_MD5Calculation
  if (param_1 != (MD5Calculation *)0x0) {
    Graphine::Core::MD5Calculation::_MD5Calculation(param_1);
    free(param_1);
  }
  return;
}



void CSharp_new_DataTypeInfo(void)

{
                    // 0x1c50  42  CSharp_new_DataTypeInfo
                    // 0x1c50  43  CSharp_new_DiskManagement
                    // 0x1c50  44  CSharp_new_GuidBuilder
                    // 0x1c50  47  CSharp_new_MD5Checker
  operator_new(1);
  return;
}



undefined8 * CSharp_new_IHashProgress(void)

{
  undefined8 *this;
  
                    // 0x1c60  45  CSharp_new_IHashProgress
  this = (undefined8 *)operator_new(8);
  if (this != (undefined8 *)0x0) {
    *this = 0;
    Graphine::Core::IHashProgress::IHashProgress((IHashProgress *)this);
    *this = Graphine::Core::IHashProgress::vftable;
    return this;
  }
  return (undefined8 *)0x0;
}



void CSharp_new_MD5Calculation(void)

{
  MD5Calculation *this;
  
                    // 0x1ca0  46  CSharp_new_MD5Calculation
  this = (MD5Calculation *)operator_new(8);
  if (this != (MD5Calculation *)0x0) {
                    // WARNING: Could not recover jumptable at 0x000180001cba. Too many branches
                    // WARNING: Treating indirect jump as call
    Graphine::Core::MD5Calculation::MD5Calculation(this);
    return;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void SWIGRegisterExceptionArgumentCallbacks_GrCoreToolsCPP
               (undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
                    // 0x1cd0  48  SWIGRegisterExceptionArgumentCallbacks_GrCoreToolsCPP
  _DAT_1800060b8 = param_1;
  DAT_1800060c8 = param_2;
  _DAT_1800060d8 = param_3;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void SWIGRegisterExceptionCallbacks_GrCoreToolsCPP
               (undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
               undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
               undefined8 param_9,undefined8 param_10,undefined8 param_11)

{
                    // 0x1cf0  49  SWIGRegisterExceptionCallbacks_GrCoreToolsCPP
  _DAT_180006048 = param_5;
  _DAT_180006058 = param_6;
  _DAT_180006068 = param_7;
  _DAT_180006078 = param_8;
  _DAT_180006088 = param_9;
  _DAT_180006098 = param_10;
  _DAT_1800060a8 = param_11;
  _DAT_180006008 = param_1;
  _DAT_180006018 = param_2;
  _DAT_180006028 = param_3;
  _DAT_180006038 = param_4;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void SWIGRegisterStringCallback_GrCoreToolsCPP(undefined8 param_1)

{
                    // 0x1d70  50  SWIGRegisterStringCallback_GrCoreToolsCPP
  _DAT_1800061f0 = param_1;
  return;
}



void SWIGRegisterWStringCallback_GrCoreToolsCPP(undefined8 param_1)

{
                    // 0x1d80  51  SWIGRegisterWStringCallback_GrCoreToolsCPP
  DAT_1800061f8 = param_1;
  return;
}



void __thiscall Graphine::Core::IHashProgress::Finished(IHashProgress *this)

{
                    // WARNING: Could not recover jumptable at 0x000180001d88. Too many branches
                    // WARNING: Treating indirect jump as call
  Finished(this);
  return;
}



void __thiscall Graphine::Core::IHashProgress::Progress(IHashProgress *this,double param_1)

{
                    // WARNING: Could not recover jumptable at 0x000180001d8e. Too many branches
                    // WARNING: Treating indirect jump as call
  Progress(this,param_1);
  return;
}



void __thiscall Graphine::Core::IHashProgress::Started(IHashProgress *this)

{
                    // WARNING: Could not recover jumptable at 0x000180001d94. Too many branches
                    // WARNING: Treating indirect jump as call
  Started(this);
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
        FUN_1800023cc();
      }
      else {
        FUN_1800023ac();
      }
    }
  }
  return pvVar2;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180002e7c. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
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
//  __security_check_cookie
// 
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

void __cdecl __security_check_cookie(uintptr_t _StackCookie)

{
  if ((_StackCookie == DAT_1800060e0) && ((short)(_StackCookie >> 0x30) == 0)) {
    return;
  }
  __report_gsfailure(_StackCookie);
  return;
}



undefined8 * FUN_180001ea4(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = type_info::vftable;
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
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
    if (DAT_180006200 < 1) {
      uVar6 = 0;
    }
    else {
      DAT_180006200 = DAT_180006200 + -1;
      uVar8 = __scrt_acquire_startup_lock();
      if (_DAT_180006780 != 2) {
        uVar7 = 0;
        __scrt_fastfail(7);
      }
      __scrt_dllmain_uninitialize_c();
      _DAT_180006780 = 0;
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
      if (_DAT_180006780 != 0) {
        __scrt_fastfail(7);
      }
      _DAT_180006780 = 1;
      uVar8 = __scrt_dllmain_before_initialize_c();
      if ((char)uVar8 != '\0') {
        _RTC_Initialize();
        atexit(&LAB_180002c0c);
        FUN_180002a28();
        atexit(&LAB_180002a38);
        __scrt_initialize_default_local_stdio_options();
        iVar5 = _initterm_e(&DAT_180003260,&DAT_180003268);
        if ((iVar5 == 0) && (uVar9 = __scrt_dllmain_after_initialize_c(), (char)uVar9 != '\0')) {
          _initterm(&DAT_180003250,&DAT_180003258);
          _DAT_180006780 = 2;
          bVar2 = false;
        }
      }
      __scrt_release_startup_lock((char)uVar7);
      if (!bVar2) {
        ppcVar10 = (code **)FUN_180002a70();
        if ((*ppcVar10 != (code *)0x0) &&
           (uVar7 = __scrt_is_nonwritable_in_current_image((longlong)ppcVar10), (char)uVar7 != '\0')
           ) {
          pcVar1 = *ppcVar10;
          _guard_check_icall();
          (*pcVar1)(param_1,2,param_3);
        }
        DAT_180006200 = DAT_180006200 + 1;
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



int FUN_1800020d0(HINSTANCE__ *param_1,ulong param_2,void *param_3)

{
  int iVar1;
  undefined8 uVar2;
  
  if ((param_2 == 0) && (DAT_180006200 < 1)) {
    iVar1 = 0;
  }
  else if ((1 < param_2 - 1) ||
          ((iVar1 = dllmain_raw(param_1,param_2,param_3), iVar1 != 0 &&
           (iVar1 = dllmain_crt_dispatch(param_1,param_2,param_3), iVar1 != 0)))) {
    uVar2 = FUN_180002a04(param_1,param_2);
    iVar1 = (int)uVar2;
    if ((param_2 == 1) && (iVar1 == 0)) {
      FUN_180002a04(param_1,0);
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



// WARNING: Removing unreachable block (ram,0x0001800021f5)
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
  FUN_1800020d0(param_1,param_2,param_3);
  return;
}



undefined8 * FUN_18000225c(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy(param_2 + 8);
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



undefined8 * FUN_18000229c(undefined8 *param_1)

{
  param_1[2] = 0;
  param_1[1] = "bad allocation";
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



undefined8 * FUN_1800022bc(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy(param_2 + 8);
  *param_1 = std::bad_array_new_length::vftable;
  return param_1;
}



undefined8 * FUN_1800022fc(undefined8 *param_1)

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



undefined8 * FUN_180002368(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = std::exception::vftable;
  __std_exception_destroy(param_1 + 1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_1800023ac(void)

{
  undefined8 local_28 [5];
  
  FUN_18000229c(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_180003c48);
}



void FUN_1800023cc(void)

{
  undefined8 local_28 [5];
  
  FUN_1800022fc(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_180003cd0);
}



char * FUN_1800023ec(longlong param_1)

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
                    // WARNING: Could not recover jumptable at 0x00018000242d. Too many branches
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
  *(undefined8 *)(puVar3 + -8) = 0x18000245e;
  capture_previous_context((PCONTEXT)&DAT_1800062b0);
  _DAT_180006220 = *(undefined8 *)(puVar3 + 0x38);
  _DAT_180006348 = puVar3 + 0x40;
  _DAT_180006330 = *(undefined8 *)(puVar3 + 0x40);
  _DAT_180006210 = 0xc0000409;
  _DAT_180006214 = 1;
  _DAT_180006228 = 1;
  DAT_180006230 = 2;
  *(undefined8 *)(puVar3 + 0x20) = DAT_1800060e0;
  *(undefined8 *)(puVar3 + 0x28) = DAT_1800060e8;
  *(undefined8 *)(puVar3 + -8) = 0x180002500;
  DAT_1800063a8 = _DAT_180006220;
  __raise_securityfailure((_EXCEPTION_POINTERS *)&PTR_DAT_1800033b8);
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
LAB_1800025aa:
    uVar3 = (ulonglong)pvVar2 & 0xffffffffffffff00;
  }
  else {
    do {
      LOCK();
      bVar1 = DAT_180006788 == 0;
      DAT_180006788 = DAT_180006788 ^ (ulonglong)bVar1 * (DAT_180006788 ^ (ulonglong)StackBase);
      pvVar2 = (void *)(!bVar1 * DAT_180006788);
      if (bVar1) goto LAB_1800025aa;
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
    uVar3 = FUN_180002e28();
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
  
  cVar1 = FUN_180002ec4();
  if (cVar1 != '\0') {
    cVar1 = FUN_180002ec4();
    if (cVar1 != '\0') {
      return 1;
    }
    FUN_180002ec4();
  }
  return 0;
}



// Library Function - Single Match
//  __scrt_dllmain_crt_thread_detach
// 
// Library: Visual Studio 2015 Release

undefined __scrt_dllmain_crt_thread_detach(void)

{
  FUN_180002ec4();
  FUN_180002ec4();
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
    _execute_onexit_table(&DAT_180006790);
    return;
  }
  uVar2 = FUN_180002ec8();
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
  FUN_180002ec4();
  FUN_180002ec4();
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
    DAT_1800067c0 = 1;
  }
  __isa_available_init();
  uVar1 = FUN_180002ec4();
  if ((char)uVar1 != '\0') {
    uVar1 = FUN_180002ec4();
    if ((char)uVar1 != '\0') {
      return uVar1 & 0xffffffffffffff00 | 1;
    }
    uVar1 = FUN_180002ec4();
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
      bVar2 = 0x40 - ((byte)DAT_1800060e0 & 0x3f) & 0x3f;
      _DAT_1800067a0 = (0xffffffffffffffffU >> bVar2 | -1L << 0x40 - bVar2) ^ DAT_1800060e0;
      local_28 = (undefined4)_DAT_1800067a0;
      uStack_24 = (undefined4)(_DAT_1800067a0 >> 0x20);
      _DAT_180006790 = local_28;
      uRam0000000180006794 = uStack_24;
      uRam0000000180006798 = local_28;
      uRam000000018000679c = uStack_24;
      _DAT_1800067a8 = local_28;
      uRam00000001800067ac = uStack_24;
      uRam00000001800067b0 = local_28;
      uRam00000001800067b4 = uStack_24;
      _DAT_1800067b8 = _DAT_1800067a0;
    }
    else {
      uVar4 = _initialize_onexit_table(&DAT_180006790);
      if ((int)uVar4 == 0) {
        uVar4 = _initialize_onexit_table(&DAT_1800067a8);
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



// WARNING: Removing unreachable block (ram,0x000180002892)
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
  for (pIVar3 = &IMAGE_SECTION_HEADER_180000218; pIVar3 != (IMAGE_SECTION_HEADER *)&DAT_180000330;
      pIVar3 = pIVar3 + 1) {
    if (((ulonglong)(uint)pIVar3->VirtualAddress <= param_1 - 0x180000000U) &&
       (uVar1 = (ulonglong)((pIVar3->Misc).PhysicalAddress + pIVar3->VirtualAddress),
       param_1 - 0x180000000U < uVar1)) goto LAB_18000287b;
  }
  pIVar3 = (IMAGE_SECTION_HEADER *)0x0;
LAB_18000287b:
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
    DAT_180006788 = 0;
  }
  return;
}



// Library Function - Single Match
//  __scrt_uninitialize_crt
// 
// Library: Visual Studio 2015 Release

undefined __scrt_uninitialize_crt(undefined8 param_1,char param_2)

{
  if ((DAT_1800067c0 == '\0') || (param_2 == '\0')) {
    FUN_180002ec4();
    FUN_180002ec4();
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
  
  bVar2 = (byte)DAT_1800060e0 & 0x3f;
  if (((DAT_1800060e0 ^ _DAT_180006790) >> bVar2 | (DAT_1800060e0 ^ _DAT_180006790) << 0x40 - bVar2)
      == 0xffffffffffffffff) {
    iVar1 = _crt_atexit();
  }
  else {
    iVar1 = _register_onexit_function(&DAT_180006790,_Func);
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
  if (DAT_1800060e0 == 0x2b992ddfa232) {
    GetSystemTimeAsFileTime(&local_res10);
    local_res8 = local_res10;
    DVar1 = GetCurrentThreadId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    DVar1 = GetCurrentProcessId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    QueryPerformanceCounter((LARGE_INTEGER *)&local_res18);
    DAT_1800060e0 =
         ((ulonglong)local_res18 << 0x20 ^ CONCAT44(uStackX_1c,local_res18) ^ (ulonglong)local_res8
         ^ (ulonglong)&local_res8) & 0xffffffffffff;
    if (DAT_1800060e0 == 0x2b992ddfa232) {
      DAT_1800060e0 = 0x2b992ddfa233;
    }
  }
  DAT_1800060e8 = ~DAT_1800060e0;
  return;
}



undefined8 FUN_180002a04(HMODULE param_1,int param_2)

{
  if (param_2 == 1) {
    DisableThreadLibraryCalls(param_1);
  }
  return 1;
}



void FUN_180002a28(void)

{
                    // WARNING: Could not recover jumptable at 0x000180002a2f. Too many branches
                    // WARNING: Treating indirect jump as call
  InitializeSListHead(&DAT_1800067d0);
  return;
}



undefined * FUN_180002a44(void)

{
  return &DAT_1800067e0;
}



undefined * FUN_180002a4c(void)

{
  return &DAT_1800067e8;
}



// Library Function - Single Match
//  __scrt_initialize_default_local_stdio_options
// 
// Library: Visual Studio 2015 Release

void __scrt_initialize_default_local_stdio_options(void)

{
  ulonglong *puVar1;
  
  puVar1 = (ulonglong *)FUN_180002a44();
  *puVar1 = *puVar1 | 4;
  puVar1 = (ulonglong *)FUN_180002a4c();
  *puVar1 = *puVar1 | 2;
  return;
}



undefined * FUN_180002a70(void)

{
  return &DAT_1800067f8;
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
  _DAT_1800067f0 = 0;
  *(undefined8 *)(puVar4 + -8) = 0x180002ab9;
  memset(local_4d8,0,0x4d0);
  *(undefined8 *)(puVar4 + -8) = 0x180002ac3;
  RtlCaptureContext(local_4d8);
  *(undefined8 *)(puVar4 + -8) = 0x180002add;
  FunctionEntry = RtlLookupFunctionEntry(local_3e0,&local_res10,(PUNWIND_HISTORY_TABLE)0x0);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0) {
    *(undefined8 *)(puVar4 + 0x38) = 0;
    *(undefined **)(puVar4 + 0x30) = local_res18;
    *(undefined **)(puVar4 + 0x28) = local_res20;
    *(undefined **)(puVar4 + 0x20) = local_4d8;
    *(undefined8 *)(puVar4 + -8) = 0x180002b1e;
    RtlVirtualUnwind(0,local_res10,local_3e0,FunctionEntry,*(PCONTEXT *)(puVar4 + 0x20),
                     *(PVOID **)(puVar4 + 0x28),*(PDWORD64 *)(puVar4 + 0x30),
                     *(PKNONVOLATILE_CONTEXT_POINTERS *)(puVar4 + 0x38));
  }
  local_440 = &stack0x00000008;
  *(undefined8 *)(puVar4 + -8) = 0x180002b50;
  memset(puVar4 + 0x50,0,0x98);
  *(undefined8 *)(puVar4 + 0x60) = unaff_retaddr;
  *(undefined4 *)(puVar4 + 0x50) = 0x40000015;
  *(undefined4 *)(puVar4 + 0x54) = 1;
  *(undefined8 *)(puVar4 + -8) = 0x180002b72;
  BVar2 = IsDebuggerPresent();
  *(undefined **)(puVar4 + 0x40) = puVar4 + 0x50;
  *(undefined **)(puVar4 + 0x48) = local_4d8;
  *(undefined8 *)(puVar4 + -8) = 0x180002b93;
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  *(undefined8 *)(puVar4 + -8) = 0x180002b9e;
  LVar3 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)(puVar4 + 0x40));
  if (LVar3 == 0) {
    _DAT_1800067f0 = _DAT_1800067f0 & -(uint)(BVar2 == 1);
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
  
  for (ppcVar2 = (code **)&DAT_180003988; ppcVar2 < &DAT_180003988; ppcVar2 = ppcVar2 + 1) {
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



// WARNING: Removing unreachable block (ram,0x000180002d7d)
// WARNING: Removing unreachable block (ram,0x000180002ce2)
// WARNING: Removing unreachable block (ram,0x000180002c84)
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
  DAT_1800060fc = 2;
  piVar1 = (int *)cpuid_basic_info(0);
  _DAT_1800060f8 = 1;
  puVar2 = (uint *)cpuid_Version_info(1);
  uVar4 = puVar2[3];
  uVar5 = DAT_1800067f4;
  if ((piVar1[2] ^ 0x49656e69U | piVar1[3] ^ 0x6c65746eU | piVar1[1] ^ 0x756e6547U) == 0) {
    _DAT_180006100 = 0xffffffffffffffff;
    uVar6 = *puVar2 & 0xfff3ff0;
    if ((((uVar6 == 0x106c0) || (uVar6 == 0x20660)) || (uVar6 == 0x20670)) ||
       ((uVar5 = DAT_1800067f4 | 4, uVar6 - 0x30650 < 0x21 &&
        ((0x100010001U >> ((ulonglong)(uVar6 - 0x30650) & 0x3f) & 1) != 0)))) {
      uVar5 = DAT_1800067f4 | 5;
    }
  }
  DAT_1800067f4 = uVar5;
  if (((piVar1[1] ^ 0x68747541U | piVar1[2] ^ 0x69746e65U | piVar1[3] ^ 0x444d4163U) == 0) &&
     (0x600eff < (*puVar2 & 0xff00f00))) {
    DAT_1800067f4 = DAT_1800067f4 | 4;
  }
  if (6 < *piVar1) {
    lVar3 = cpuid_Extended_Feature_Enumeration_info(7);
    local_20 = *(uint *)(lVar3 + 4);
    if ((local_20 >> 9 & 1) != 0) {
      DAT_1800067f4 = DAT_1800067f4 | 2;
    }
  }
  if ((uVar4 >> 0x14 & 1) != 0) {
    _DAT_1800060f8 = 2;
    DAT_1800060fc = 6;
    if ((((uVar4 >> 0x1b & 1) != 0) && ((uVar4 >> 0x1c & 1) != 0)) && ((in_XCR0 & 6) == 6)) {
      DAT_1800060fc = 0xe;
      _DAT_1800060f8 = 3;
      if ((local_20 & 0x20) != 0) {
        _DAT_1800060f8 = 5;
        DAT_1800060fc = 0x2e;
      }
    }
  }
  return 0;
}



undefined8 FUN_180002e28(void)

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
  return _DAT_180006110 != 0;
}



void _guard_check_icall(void)

{
  return;
}



void _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo)

{
                    // WARNING: Could not recover jumptable at 0x000180002e40. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  _CxxThrowException(pExceptionObject,pThrowInfo);
  return;
}



void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180002e4c. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}



void __std_exception_copy(void)

{
                    // WARNING: Could not recover jumptable at 0x000180002e58. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_exception_copy();
  return;
}



void __std_exception_destroy(void)

{
                    // WARNING: Could not recover jumptable at 0x000180002e5e. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_exception_destroy();
  return;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180002e6a. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



int __cdecl _callnewh(size_t _Size)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180002e70. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _callnewh(_Size);
  return iVar1;
}



void * __cdecl malloc(size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180002e76. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = malloc(_Size);
  return pvVar1;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180002e7c. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x000180002e82. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



void _initterm_e(void)

{
                    // WARNING: Could not recover jumptable at 0x000180002e88. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm_e();
  return;
}



void _seh_filter_dll(void)

{
                    // WARNING: Could not recover jumptable at 0x000180002e8e. Too many branches
                    // WARNING: Treating indirect jump as call
  _seh_filter_dll();
  return;
}



void _configure_narrow_argv(void)

{
                    // WARNING: Could not recover jumptable at 0x000180002e94. Too many branches
                    // WARNING: Treating indirect jump as call
  _configure_narrow_argv();
  return;
}



void _initialize_narrow_environment(void)

{
                    // WARNING: Could not recover jumptable at 0x000180002e9a. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_narrow_environment();
  return;
}



void _initialize_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x000180002ea0. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_onexit_table();
  return;
}



void _register_onexit_function(void)

{
                    // WARNING: Could not recover jumptable at 0x000180002ea6. Too many branches
                    // WARNING: Treating indirect jump as call
  _register_onexit_function();
  return;
}



void _execute_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x000180002eac. Too many branches
                    // WARNING: Treating indirect jump as call
  _execute_onexit_table();
  return;
}



void _crt_atexit(void)

{
                    // WARNING: Could not recover jumptable at 0x000180002eb2. Too many branches
                    // WARNING: Treating indirect jump as call
  _crt_atexit();
  return;
}



void __cdecl _cexit(void)

{
                    // WARNING: Could not recover jumptable at 0x000180002eb8. Too many branches
                    // WARNING: Treating indirect jump as call
  _cexit();
  return;
}



BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180002ebe. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = IsProcessorFeaturePresent(ProcessorFeature);
  return BVar1;
}



undefined FUN_180002ec4(void)

{
  return 1;
}



undefined8 FUN_180002ec8(void)

{
  return 0;
}



// WARNING: This is an inlined function

void _guard_dispatch_icall(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
                    // WARNING: Could not recover jumptable at 0x000180002ee0. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



undefined * Catch_All_180002ef0(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  void *pvVar2;
  
  lVar1 = *(longlong *)(param_2 + 0x68);
  *(longlong *)(param_2 + 0x68) = lVar1;
  pvVar2 = FUN_180001160(*(undefined8 *)(param_2 + 0x60),lVar1 + 1);
  *(void **)(param_2 + 0x78) = pvVar2;
  return &DAT_1800010c4;
}



void Catch_All_180002f23(undefined8 param_1,longlong param_2)

{
  void **ppvVar1;
  
  ppvVar1 = *(void ***)(param_2 + 0x60);
  if ((void *)0x7 < ppvVar1[3]) {
    FUN_180001470(ppvVar1,*ppvVar1,(longlong)ppvVar1[3] + 1);
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



void FUN_180002f8d(undefined8 param_1,longlong param_2)

{
  __scrt_dllmain_uninitialize_critical();
  __scrt_release_startup_lock(*(char *)(param_2 + 0x38));
  return;
}



void FUN_180002fa9(undefined8 *param_1,longlong param_2)

{
  __scrt_dllmain_exception_filter
            (*(undefined8 *)(param_2 + 0x60),*(int *)(param_2 + 0x68),
             *(undefined8 *)(param_2 + 0x70),dllmain_crt_dispatch,*(undefined4 *)*param_1,param_1);
  return;
}


