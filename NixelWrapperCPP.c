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

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef int __ehstate_t;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    ImageBaseOffset32 action;
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

typedef struct _s_HandlerType HandlerType;

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

typedef struct ErrorInfo ErrorInfo, *PErrorInfo;

struct ErrorInfo { // PlaceHolder Structure
};

typedef struct ITileSoupBuilder ITileSoupBuilder, *PITileSoupBuilder;

struct ITileSoupBuilder { // PlaceHolder Structure
};

typedef struct IGtsFileReader IGtsFileReader, *PIGtsFileReader;

struct IGtsFileReader { // PlaceHolder Structure
};

typedef struct ILayerIndexCollection ILayerIndexCollection, *PILayerIndexCollection;

struct ILayerIndexCollection { // PlaceHolder Structure
};

typedef struct BuildHeader BuildHeader, *PBuildHeader;

struct BuildHeader { // PlaceHolder Structure
};

typedef struct ITileSoupFileReader ITileSoupFileReader, *PITileSoupFileReader;

struct ITileSoupFileReader { // PlaceHolder Structure
};

typedef struct NixelInitializationInfo NixelInitializationInfo, *PNixelInitializationInfo;

struct NixelInitializationInfo { // PlaceHolder Structure
};

typedef struct ITiledRasterData ITiledRasterData, *PITiledRasterData;

struct ITiledRasterData { // PlaceHolder Structure
};

typedef struct Color Color, *PColor;

struct Color { // PlaceHolder Structure
};

typedef struct RasterTileDimension RasterTileDimension, *PRasterTileDimension;

struct RasterTileDimension { // PlaceHolder Structure
};

typedef struct ITiledRasterDataRead ITiledRasterDataRead, *PITiledRasterDataRead;

struct ITiledRasterDataRead { // PlaceHolder Structure
};

typedef struct Layout Layout, *PLayout;

struct Layout { // PlaceHolder Structure
};

typedef struct IPackedSoupFileCollection IPackedSoupFileCollection, *PIPackedSoupFileCollection;

struct IPackedSoupFileCollection { // PlaceHolder Structure
};

typedef struct ITileOrder ITileOrder, *PITileOrder;

struct ITileOrder { // PlaceHolder Structure
};

typedef struct ITiledBuildParameters ITiledBuildParameters, *PITiledBuildParameters;

struct ITiledBuildParameters { // PlaceHolder Structure
};

typedef struct TiledTopology TiledTopology, *PTiledTopology;

struct TiledTopology { // PlaceHolder Structure
};

typedef struct LibraryVersionInfo LibraryVersionInfo, *PLibraryVersionInfo;

struct LibraryVersionInfo { // PlaceHolder Structure
};

typedef struct ITileSetRebuilder ITileSetRebuilder, *PITileSetRebuilder;

struct ITileSetRebuilder { // PlaceHolder Structure
};

typedef struct ICodecLogger ICodecLogger, *PICodecLogger;

struct ICodecLogger { // PlaceHolder Structure
};

typedef struct IBuildCallback IBuildCallback, *PIBuildCallback;

struct IBuildCallback { // PlaceHolder Structure
};

typedef struct IBuildProgressTracker IBuildProgressTracker, *PIBuildProgressTracker;

struct IBuildProgressTracker { // PlaceHolder Structure
};

typedef struct IMipmapGenerator IMipmapGenerator, *PIMipmapGenerator;

struct IMipmapGenerator { // PlaceHolder Structure
};

typedef enum Enum {
} Enum;

typedef struct basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_> basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>, *Pbasic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>;

struct basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_> { // PlaceHolder Structure
};

typedef struct vector<class_std::basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>,class_std::allocator<class_std::basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>_>_> vector<class_std::basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>,class_std::allocator<class_std::basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>_>_>, *Pvector<class_std::basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>,class_std::allocator<class_std::basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>_>_>;

struct vector<class_std::basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>,class_std::allocator<class_std::basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>_>_> { // PlaceHolder Structure
};

typedef int (* _onexit_t)(void);

typedef ulonglong size_t;




undefined8 * FUN_180001000(undefined8 *param_1,ulonglong **param_2,ulonglong **param_3)

{
  ulonglong **ppuVar1;
  ulonglong uVar2;
  
  if (*(char *)param_3 == '\0') {
    uVar2 = 0;
  }
  else {
    uVar2 = 0xffffffffffffffff;
    do {
      uVar2 = uVar2 + 1;
    } while (*(char *)((longlong)param_3 + uVar2) != '\0');
  }
  ppuVar1 = FUN_1800030f0(param_2,param_3,uVar2);
  param_1[3] = 0xf;
  param_1[2] = 0;
  *(undefined *)param_1 = 0;
  FUN_1800023b0(param_1,ppuVar1);
  return param_1;
}



void FUN_180001070(void **param_1,void **param_2,void **param_3)

{
  code *pcVar1;
  void *pvVar2;
  void **ppvVar3;
  ulonglong uVar4;
  
  uVar4 = (longlong)param_3 - (longlong)param_2 >> 5;
  *param_1 = (void *)0x0;
  param_1[1] = (void *)0x0;
  param_1[2] = (void *)0x0;
  if (uVar4 != 0) {
    if (0x7ffffffffffffff < uVar4) {
      std::_Xlength_error("vector<T> too long");
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    pvVar2 = FUN_180002ed0(param_1,uVar4);
    *param_1 = pvVar2;
    param_1[1] = pvVar2;
    param_1[2] = (void *)(uVar4 * 0x20 + (longlong)*param_1);
    ppvVar3 = FUN_180001740(param_2,param_3,(void **)*param_1);
    param_1[1] = ppvVar3;
  }
  return;
}



void FUN_180001120(ulonglong *param_1,ulonglong *param_2)

{
  void *pvVar1;
  ulonglong uVar2;
  ulonglong *puVar3;
  void *_Memory;
  ulonglong *puVar4;
  
  if (param_1 != param_2) {
    puVar4 = param_1 + 3;
    do {
      if (7 < *puVar4) {
        pvVar1 = (void *)puVar4[-3];
        uVar2 = *puVar4 + 1;
        if (0x7fffffffffffffff < uVar2) {
                    // WARNING: Subroutine does not return
          _invalid_parameter_noinfo_noreturn();
        }
        _Memory = pvVar1;
        if (0xfff < uVar2 * 2) {
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
      *puVar4 = 7;
      puVar4[-1] = 0;
      if (*puVar4 < 8) {
        puVar3 = puVar4 + -3;
      }
      else {
        puVar3 = (ulonglong *)puVar4[-3];
      }
      *(undefined2 *)puVar3 = 0;
      puVar3 = puVar4 + 1;
      puVar4 = puVar4 + 4;
    } while (puVar3 != param_2);
  }
  return;
}



void FUN_180001200(ulonglong **param_1,undefined8 *param_2,void **param_3,void **param_4)

{
  ulonglong *puVar1;
  ulonglong *puVar2;
  code *pcVar3;
  ulonglong *puVar4;
  void **ppvVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  longlong lVar10;
  
  uVar9 = (longlong)param_4 - (longlong)param_3 >> 5;
  if (uVar9 != 0) {
    ppvVar5 = (void **)param_1[1];
    if ((ulonglong)((longlong)param_1[2] - (longlong)ppvVar5 >> 5) < uVar9) {
      lVar10 = (longlong)ppvVar5 - (longlong)*param_1 >> 5;
      if (0x7ffffffffffffffU - lVar10 < uVar9) {
        std::_Xlength_error("vector<T> too long");
        pcVar3 = (code *)swi(3);
        (*pcVar3)();
        return;
      }
      uVar8 = lVar10 + uVar9;
      uVar7 = (longlong)param_1[2] - (longlong)*param_1 >> 5;
      uVar6 = 0;
      if (uVar7 <= 0x7ffffffffffffff - (uVar7 >> 1)) {
        uVar6 = (uVar7 >> 1) + uVar7;
      }
      if (uVar8 <= uVar6) {
        uVar8 = uVar6;
      }
      puVar4 = (ulonglong *)FUN_180002ed0(param_1,uVar8);
      ppvVar5 = (void **)FUN_180001860(*param_1,param_2,puVar4);
      ppvVar5 = FUN_1800017d0(param_3,param_4,ppvVar5);
      FUN_180001860(param_2,param_1[1],ppvVar5);
      puVar1 = param_1[1];
      puVar2 = *param_1;
      if (puVar2 != (ulonglong *)0x0) {
        FUN_180001120(puVar2,puVar1);
        FUN_180003730(param_1,*param_1,(longlong)param_1[2] - (longlong)*param_1 >> 5);
      }
      param_1[2] = puVar4 + uVar8 * 4;
      param_1[1] = puVar4 + (uVar9 + ((longlong)puVar1 - (longlong)puVar2 >> 5)) * 4;
      *param_1 = puVar4;
    }
    else {
      FUN_1800017d0(param_3,param_4,ppvVar5);
      FUN_180001630((longlong)param_2,(longlong)param_1[1],(longlong)(param_1[1] + uVar9 * 4));
      param_1[1] = param_1[1] + uVar9 * 4;
    }
  }
  return;
}



ulonglong ** FUN_180001400(ulonglong **param_1,ulonglong **param_2,ulonglong **param_3)

{
  ulonglong *puVar1;
  ulonglong uVar2;
  ulonglong **ppuVar3;
  ulonglong *_Memory;
  ulonglong **ppuVar4;
  
  ppuVar4 = param_3;
  if (param_1 != param_2) {
    do {
      param_3 = ppuVar4 + -4;
      param_2 = param_2 + -4;
      if (param_3 != param_2) {
        if ((ulonglong *)0x7 < ppuVar4[-1]) {
          puVar1 = *param_3;
          uVar2 = (longlong)ppuVar4[-1] + 1;
          if (0x7fffffffffffffff < uVar2) {
                    // WARNING: Subroutine does not return
            _invalid_parameter_noinfo_noreturn();
          }
          _Memory = puVar1;
          if (0xfff < uVar2 * 2) {
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
        ppuVar4[-1] = (ulonglong *)0x7;
        ppuVar4[-2] = (ulonglong *)0x0;
        ppuVar3 = param_3;
        if ((ulonglong *)0x7 < ppuVar4[-1]) {
          ppuVar3 = (ulonglong **)*param_3;
        }
        *(undefined2 *)ppuVar3 = 0;
        FUN_180002440(param_3,param_2);
      }
      ppuVar4 = param_3;
    } while (param_1 != param_2);
  }
  return param_3;
}



void ** FUN_180001510(void **param_1,void **param_2,void **param_3)

{
  void **ppvVar1;
  
  if (param_1 != param_2) {
    do {
      if (param_3 != param_1) {
        if ((void *)0x7 < param_3[3]) {
          FUN_1800037a0(param_3,*param_3,(longlong)param_3[3] + 1);
        }
        param_3[3] = (void *)0x7;
        param_3[2] = (void *)0x0;
        ppvVar1 = param_3;
        if ((void *)0x7 < param_3[3]) {
          ppvVar1 = (void **)*param_3;
        }
        *(undefined2 *)ppvVar1 = 0;
        FUN_180002440(param_3,param_1);
      }
      param_3 = param_3 + 4;
      param_1 = param_1 + 4;
    } while (param_1 != param_2);
  }
  return param_3;
}



void FUN_1800015b0(longlong param_1,longlong param_2)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  undefined8 uVar4;
  undefined8 *puVar5;
  undefined8 *puVar6;
  
  if (param_1 != param_2) {
    puVar5 = (undefined8 *)(param_2 + 0x18);
    puVar6 = (undefined8 *)(param_1 + 0x18);
    do {
      puVar1 = puVar5 + -4;
      puVar2 = puVar5 + -7;
      if (puVar6 + -3 == puVar2) {
        return;
      }
      FUN_180002d70(puVar6 + -3,puVar2);
      uVar4 = puVar6[-1];
      puVar6[-1] = puVar5[-5];
      puVar5[-5] = uVar4;
      uVar4 = *puVar6;
      *puVar6 = *puVar1;
      *puVar1 = uVar4;
      puVar3 = puVar6 + 1;
      puVar5 = puVar1;
      puVar6 = puVar6 + 4;
    } while (puVar3 != puVar2);
  }
  return;
}



longlong FUN_180001630(longlong param_1,longlong param_2,longlong param_3)

{
  if (param_1 == param_2) {
    return param_3;
  }
  if (param_2 == param_3) {
    return param_1;
  }
  FUN_1800015b0(param_1,param_2);
  FUN_1800015b0(param_2,param_3);
  FUN_1800015b0(param_1,param_3);
  return param_1 + (param_3 - param_2 & 0xffffffffffffffe0U);
}



void FUN_1800016b0(void **param_1,longlong param_2,void **param_3)

{
  void **ppvVar1;
  
  for (; param_2 != 0; param_2 = param_2 + -1) {
    if (param_1 != (void **)0x0) {
      param_1[3] = (void *)0x7;
      param_1[2] = (void *)0x0;
      ppvVar1 = param_1;
      if ((void *)0x7 < param_1[3]) {
        ppvVar1 = (void **)*param_1;
      }
      *(undefined2 *)ppvVar1 = 0;
      FUN_1800034a0(param_1,param_3,(void *)0x0,(void *)0xffffffffffffffff);
    }
    param_1 = param_1 + 4;
  }
  return;
}



void ** FUN_180001740(void **param_1,void **param_2,void **param_3)

{
  void **ppvVar1;
  
  for (; param_1 != param_2; param_1 = param_1 + 4) {
    if (param_3 != (void **)0x0) {
      param_3[3] = (void *)0x7;
      param_3[2] = (void *)0x0;
      ppvVar1 = param_3;
      if ((void *)0x7 < param_3[3]) {
        ppvVar1 = (void **)*param_3;
      }
      *(undefined2 *)ppvVar1 = 0;
      FUN_1800034a0(param_3,param_1,(void *)0x0,(void *)0xffffffffffffffff);
    }
    param_3 = param_3 + 4;
  }
  return param_3;
}



void ** FUN_1800017d0(void **param_1,void **param_2,void **param_3)

{
  void **ppvVar1;
  
  for (; param_1 != param_2; param_1 = param_1 + 4) {
    if (param_3 != (void **)0x0) {
      param_3[3] = (void *)0x7;
      param_3[2] = (void *)0x0;
      ppvVar1 = param_3;
      if ((void *)0x7 < param_3[3]) {
        ppvVar1 = (void **)*param_3;
      }
      *(undefined2 *)ppvVar1 = 0;
      FUN_1800034a0(param_3,param_1,(void *)0x0,(void *)0xffffffffffffffff);
    }
    param_3 = param_3 + 4;
  }
  return param_3;
}



undefined8 * FUN_180001860(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3)

{
  if (param_1 != param_2) {
    do {
      if (param_3 != (undefined8 *)0x0) {
        param_3[3] = 7;
        param_3[2] = 0;
        *(undefined2 *)param_3 = 0;
        FUN_180002440(param_3,param_1);
      }
      param_3 = param_3 + 4;
      param_1 = param_1 + 4;
    } while (param_1 != param_2);
  }
  return param_3;
}



void ** FUN_1800018e0(void **param_1,longlong *param_2)

{
  code *pcVar1;
  void **ppvVar2;
  void *pvVar3;
  ulonglong uVar4;
  
  *param_1 = (void *)0x0;
  param_1[1] = (void *)0x0;
  param_1[2] = (void *)0x0;
  uVar4 = param_2[1] - *param_2 >> 5;
  *param_1 = (void *)0x0;
  param_1[1] = (void *)0x0;
  param_1[2] = (void *)0x0;
  if (uVar4 != 0) {
    if (0x7ffffffffffffff < uVar4) {
      std::_Xlength_error("vector<T> too long");
      pcVar1 = (code *)swi(3);
      ppvVar2 = (void **)(*pcVar1)();
      return ppvVar2;
    }
    pvVar3 = FUN_180002ed0(param_1,uVar4);
    *param_1 = pvVar3;
    param_1[1] = pvVar3;
    param_1[2] = (void *)(uVar4 * 0x20 + (longlong)*param_1);
    ppvVar2 = FUN_1800017d0((void **)*param_2,(void **)param_2[1],(void **)*param_1);
    param_1[1] = ppvVar2;
  }
  return param_1;
}



undefined8 * FUN_1800019a0(undefined8 *param_1,longlong param_2)

{
  *param_1 = Swig::DirectorException::vftable;
  param_1[4] = 0xf;
  param_1[3] = 0;
  *(undefined *)(param_1 + 1) = 0;
  FUN_180003240((ulonglong **)(param_1 + 1),(ulonglong **)(param_2 + 8),(ulonglong *)0x0,
                (ulonglong *)0xffffffffffffffff);
  return param_1;
}



undefined8 * FUN_1800019f0(undefined8 *param_1,longlong param_2)

{
  *param_1 = Swig::DirectorException::vftable;
  param_1[4] = 0xf;
  param_1[3] = 0;
  *(undefined *)(param_1 + 1) = 0;
  FUN_180003240((ulonglong **)(param_1 + 1),(ulonglong **)(param_2 + 8),(ulonglong *)0x0,
                (ulonglong *)0xffffffffffffffff);
  *param_1 = Swig::DirectorPureVirtualException::vftable;
  return param_1;
}



void FUN_180001a40(undefined8 *param_1,ulonglong **param_2)

{
  ulonglong **ppuVar1;
  void *pvVar2;
  ulonglong **ppuVar3;
  ulonglong **ppuVar4;
  void *pvVar5;
  undefined auStack_78 [32];
  undefined8 local_58;
  byte local_50;
  undefined7 uStack_4f;
  undefined8 local_40;
  ulonglong local_38;
  byte local_30;
  undefined7 uStack_2f;
  undefined8 local_20;
  ulonglong local_18;
  ulonglong local_10;
  
  local_58 = 0xfffffffffffffffe;
  local_10 = DAT_18000f0e0 ^ (ulonglong)auStack_78;
  local_38 = 0xf;
  local_40 = 0;
  local_50 = 0;
  FUN_180003370((ulonglong **)&local_50,(ulonglong **)"Attempt to invoke pure virtual method ",
                (ulonglong *)0x26);
  ppuVar3 = (ulonglong **)FUN_180001000((undefined8 *)&local_30,(ulonglong **)&local_50,param_2);
  *param_1 = Swig::DirectorException::vftable;
  ppuVar1 = (ulonglong **)(param_1 + 1);
  param_1[4] = 0xf;
  param_1[3] = 0;
  ppuVar4 = ppuVar1;
  if (0xf < (ulonglong)param_1[4]) {
    ppuVar4 = (ulonglong **)*ppuVar1;
  }
  *(undefined *)ppuVar4 = 0;
  FUN_180003240(ppuVar1,ppuVar3,(ulonglong *)0x0,(ulonglong *)0xffffffffffffffff);
  if (0xf < local_18) {
    pvVar2 = (void *)CONCAT71(uStack_2f,local_30);
    pvVar5 = pvVar2;
    if (0xfff < local_18 + 1) {
      if ((local_30 & 0x1f) != 0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      pvVar5 = *(void **)((longlong)pvVar2 - 8);
      if (pvVar2 <= pvVar5) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if ((ulonglong)((longlong)pvVar2 - (longlong)pvVar5) < 8) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if (0x27 < (ulonglong)((longlong)pvVar2 - (longlong)pvVar5)) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
    }
    free(pvVar5);
  }
  local_18 = 0xf;
  local_20 = 0;
  local_30 = 0;
  if (0xf < local_38) {
    pvVar2 = (void *)CONCAT71(uStack_4f,local_50);
    pvVar5 = pvVar2;
    if (0xfff < local_38 + 1) {
      if ((local_50 & 0x1f) != 0) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      pvVar5 = *(void **)((longlong)pvVar2 - 8);
      if (pvVar2 <= pvVar5) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if ((ulonglong)((longlong)pvVar2 - (longlong)pvVar5) < 8) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
      if (0x27 < (ulonglong)((longlong)pvVar2 - (longlong)pvVar5)) {
                    // WARNING: Subroutine does not return
        _invalid_parameter_noinfo_noreturn();
      }
    }
    free(pvVar5);
  }
  *param_1 = Swig::DirectorPureVirtualException::vftable;
  __security_check_cookie(local_10 ^ (ulonglong)auStack_78);
  return;
}



undefined8 * FUN_180001be0(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy(param_2 + 8);
  return param_1;
}



undefined8 * FUN_180001c20(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy(param_2 + 8);
  *param_1 = std::invalid_argument::vftable;
  return param_1;
}



void FUN_180001ce0(ulonglong **param_1)

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



void FUN_180001d70(void **param_1)

{
  if ((void *)0x7 < param_1[3]) {
    FUN_1800037a0(param_1,*param_1,(longlong)param_1[3] + 1);
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



undefined8 * FUN_180001e00(undefined8 *param_1,uint param_2)

{
  *param_1 = Swig::DirectorException::vftable;
  FUN_180001ce0((ulonglong **)(param_1 + 1));
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined8 * FUN_180001e50(undefined8 *param_1,uint param_2)

{
  *param_1 = SwigDirector_IBuildCallback::vftable;
  Graphine::Nixel::IBuildCallback::_IBuildCallback((IBuildCallback *)param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined8 * FUN_180001e90(undefined8 *param_1,uint param_2)

{
  *param_1 = SwigDirector_IBuildProgressTracker::vftable;
  Graphine::Nixel::IBuildProgressTracker::_IBuildProgressTracker((IBuildProgressTracker *)param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined8 * FUN_180001ed0(undefined8 *param_1,uint param_2)

{
  *param_1 = SwigDirector_ICodecLogger::vftable;
  Graphine::Nixel::ICodecLogger::_ICodecLogger((ICodecLogger *)param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined8 * FUN_180001f10(undefined8 *param_1,uint param_2)

{
  *param_1 = SwigDirector_IMipmapGenerator::vftable;
  Graphine::Nixel::IMipmapGenerator::_IMipmapGenerator((IMipmapGenerator *)param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined8 * FUN_180001f50(undefined8 *param_1,uint param_2)

{
  *param_1 = SwigDirector_ITileOrder::vftable;
  Graphine::Nixel::ITileOrder::_ITileOrder((ITileOrder *)param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined8 * FUN_180001f90(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = std::exception::vftable;
  __std_exception_destroy(param_1 + 1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_180001fe0(longlong param_1)

{
  undefined auStack_58 [32];
  undefined8 local_38 [5];
  ulonglong local_10;
  
  local_10 = DAT_18000f0e0 ^ (ulonglong)auStack_58;
  if (*(code **)(param_1 + 0x20) != (code *)0x0) {
    (**(code **)(param_1 + 0x20))();
    __security_check_cookie(local_10 ^ (ulonglong)auStack_58);
    return;
  }
  FUN_180001a40(local_38,(ulonglong **)"Graphine::Nixel::ITileOrder::Count");
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_38,(ThrowInfo *)&DAT_18000ad38);
}



void FUN_180002040(longlong param_1,undefined4 param_2)

{
  if (*(code **)(param_1 + 0x10) != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00018000204b. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(param_1 + 0x10))(param_2);
    return;
  }
  return;
}



void FUN_180002050(longlong param_1,undefined8 param_2,undefined4 param_3,undefined4 param_4,
                  undefined4 param_5,undefined8 param_6,undefined8 param_7,undefined4 param_8,
                  undefined4 param_9,undefined4 param_10,undefined4 param_11)

{
  undefined auStack_98 [32];
  undefined8 local_78;
  undefined8 local_70;
  undefined4 local_68;
  undefined4 local_60;
  undefined4 local_58;
  undefined4 local_50;
  undefined8 local_48 [5];
  ulonglong local_20;
  
  local_20 = DAT_18000f0e0 ^ (ulonglong)auStack_98;
  if (*(code **)(param_1 + 8) != (code *)0x0) {
    local_50 = param_11;
    local_58 = param_10;
    local_60 = param_9;
    local_68 = param_8;
    local_70 = param_7;
    local_78 = param_6;
    (**(code **)(param_1 + 8))(param_2,param_3,param_4,param_5);
    __security_check_cookie(local_20 ^ (ulonglong)auStack_98);
    return;
  }
  FUN_180001a40(local_48,(ulonglong **)"Graphine::Nixel::IMipmapGenerator::GenerateMipmapData");
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_48,(ThrowInfo *)&DAT_18000ad38);
}



void FUN_180002110(longlong param_1,undefined8 param_2,undefined8 *param_3)

{
  undefined8 uVar1;
  
  if (*(longlong *)(param_1 + 8) != 0) {
    if (7 < (ulonglong)param_3[3]) {
      param_3 = (undefined8 *)*param_3;
    }
    uVar1 = (*DAT_18000f4f8)(param_3);
    (**(code **)(param_1 + 8))(param_2,uVar1);
  }
  return;
}



void FUN_180002150(longlong param_1,undefined8 param_2,undefined8 *param_3)

{
  undefined8 uVar1;
  
  if (*(longlong *)(param_1 + 0x18) != 0) {
    if (7 < (ulonglong)param_3[3]) {
      param_3 = (undefined8 *)*param_3;
    }
    uVar1 = (*DAT_18000f4f8)(param_3);
    (**(code **)(param_1 + 0x18))(param_2,uVar1);
  }
  return;
}



void FUN_180002190(longlong param_1,undefined8 param_2,undefined8 *param_3)

{
  undefined8 uVar1;
  
  if (*(longlong *)(param_1 + 0x10) != 0) {
    if (7 < (ulonglong)param_3[3]) {
      param_3 = (undefined8 *)*param_3;
    }
    uVar1 = (*DAT_18000f4f8)(param_3);
    (**(code **)(param_1 + 0x10))(param_2,uVar1);
  }
  return;
}



void FUN_1800021d0(longlong param_1,undefined8 param_2)

{
  undefined auStack_58 [32];
  undefined8 local_38 [5];
  ulonglong local_10;
  
  local_10 = DAT_18000f0e0 ^ (ulonglong)auStack_58;
  if (*(code **)(param_1 + 0x10) != (code *)0x0) {
    (**(code **)(param_1 + 0x10))(param_2);
    __security_check_cookie(local_10 ^ (ulonglong)auStack_58);
    return;
  }
  FUN_180001a40(local_38,(ulonglong **)"Graphine::Nixel::ITileOrder::Next");
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_38,(ThrowInfo *)&DAT_18000ad38);
}



void FUN_180002230(longlong param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4)

{
  undefined auStack_58 [32];
  undefined8 local_38 [5];
  ulonglong local_10;
  
  local_10 = DAT_18000f0e0 ^ (ulonglong)auStack_58;
  if (*(code **)(param_1 + 0x18) != (code *)0x0) {
    (**(code **)(param_1 + 0x18))(param_2,param_3,param_4);
    __security_check_cookie(local_10 ^ (ulonglong)auStack_58);
    return;
  }
  FUN_180001a40(local_38,(ulonglong **)"Graphine::Nixel::ITileOrder::Next");
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_38,(ThrowInfo *)&DAT_18000ad38);
}



void FUN_1800022a0(longlong param_1,undefined4 param_2,undefined4 param_3)

{
  if (*(code **)(param_1 + 0x28) == (code *)0x0) {
    return;
  }
                    // WARNING: Could not recover jumptable at 0x0001800022b3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(param_1 + 0x28))(param_2,param_3);
  return;
}



void FUN_1800022c0(longlong param_1,undefined8 param_2)

{
  if (*(code **)(param_1 + 0x28) == (code *)0x0) {
    return;
  }
                    // WARNING: Could not recover jumptable at 0x0001800022cd. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(param_1 + 0x28))(param_2);
  return;
}



undefined8 FUN_1800022d0(longlong param_1,undefined8 param_2,undefined4 param_3)

{
  undefined8 uVar1;
  
  if (*(code **)(param_1 + 0x20) == (code *)0x0) {
    return 1;
  }
                    // WARNING: Could not recover jumptable at 0x0001800022e8. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = (**(code **)(param_1 + 0x20))(param_2,param_3);
  return uVar1;
}



void FUN_1800022f0(longlong param_1,undefined8 param_2)

{
  if (*(code **)(param_1 + 0x18) != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0001800022fc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(param_1 + 0x18))(param_2);
    return;
  }
  return;
}



void FUN_180002300(longlong param_1,undefined4 param_2,undefined4 param_3)

{
  if (*(code **)(param_1 + 0x20) != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x000180002312. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(param_1 + 0x20))(param_2,param_3);
    return;
  }
  return;
}



void FUN_180002320(longlong param_1,undefined8 param_2,undefined4 param_3)

{
  if (*(code **)(param_1 + 0x18) != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x000180002332. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(param_1 + 0x18))(param_2,param_3);
    return;
  }
  return;
}



void FUN_180002340(longlong param_1)

{
  undefined auStack_58 [32];
  undefined8 local_38 [5];
  ulonglong local_10;
  
  local_10 = DAT_18000f0e0 ^ (ulonglong)auStack_58;
  if (*(code **)(param_1 + 8) != (code *)0x0) {
    (**(code **)(param_1 + 8))();
    __security_check_cookie(local_10 ^ (ulonglong)auStack_58);
    return;
  }
  FUN_180001a40(local_38,(ulonglong **)"Graphine::Nixel::ITileOrder::Reset");
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_38,(ThrowInfo *)&DAT_18000ad38);
}



void FUN_1800023a0(longlong param_1,undefined4 param_2)

{
  if (*(code **)(param_1 + 8) != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0001800023ab. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(param_1 + 8))(param_2);
    return;
  }
  return;
}



void FUN_1800023b0(undefined8 *param_1,undefined8 *param_2)

{
  if ((ulonglong)param_2[3] < 0x10) {
    if (param_2[2] + 1 != 0) {
      memmove(param_1,param_2,param_2[2] + 1);
    }
  }
  else {
    if (param_1 != (undefined8 *)0x0) {
      *param_1 = *param_2;
    }
    *param_2 = 0;
  }
  param_1[2] = param_2[2];
  param_1[3] = param_2[3];
  param_2[3] = 0xf;
  param_2[2] = 0;
  if (0xf < (ulonglong)param_2[3]) {
    *(undefined *)*param_2 = 0;
    return;
  }
  *(undefined *)param_2 = 0;
  return;
}



void FUN_180002440(undefined8 *param_1,undefined8 *param_2)

{
  if ((ulonglong)param_2[3] < 8) {
    if (param_2[2] + 1 != 0) {
      memmove(param_1,param_2,(param_2[2] + 1) * 2);
    }
  }
  else {
    if (param_1 != (undefined8 *)0x0) {
      *param_1 = *param_2;
    }
    *param_2 = 0;
  }
  param_1[2] = param_2[2];
  param_1[3] = param_2[3];
  param_2[3] = 7;
  param_2[2] = 0;
  if (7 < (ulonglong)param_2[3]) {
    *(undefined2 *)*param_2 = 0;
    return;
  }
  *(undefined2 *)param_2 = 0;
  return;
}



void FUN_1800024d0(void **param_1,ulonglong param_2,void **param_3)

{
  void **ppvVar1;
  code *pcVar2;
  void *pvVar3;
  
  *param_1 = (void *)0x0;
  param_1[1] = (void *)0x0;
  param_1[2] = (void *)0x0;
  if (param_2 != 0) {
    if (0x7ffffffffffffff < param_2) {
      std::_Xlength_error("vector<T> too long");
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    pvVar3 = FUN_180002ed0(param_1,param_2);
    *param_1 = pvVar3;
    param_1[1] = pvVar3;
    ppvVar1 = (void **)*param_1;
    param_1[2] = ppvVar1 + param_2 * 4;
    FUN_1800016b0(ppvVar1,param_2,param_3);
    param_1[1] = ppvVar1 + param_2 * 4;
  }
  return;
}



void FUN_180002580(ulonglong **param_1,ulonglong *param_2,ulonglong *param_3)

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



void FUN_180002730(void **param_1,void *param_2,void *param_3)

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
  _Dst = (void **)FUN_180002f50(param_1,(longlong)param_2 + 1);
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
    FUN_1800037a0(param_1,*param_1,(longlong)param_1[3] + 1);
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



void FUN_180002850(ulonglong **param_1,longlong *param_2,ulonglong **param_3,ulonglong param_4,
                  void **param_5)

{
  ulonglong *puVar1;
  code *pcVar2;
  ulonglong *puVar3;
  ulonglong *puVar4;
  longlong lVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  ulonglong **ppuVar9;
  ulonglong uVar10;
  undefined auStack_d8 [32];
  undefined local_b8;
  undefined local_b0;
  undefined local_a8;
  undefined4 local_a4;
  ulonglong **local_a0;
  ulonglong *local_98;
  longlong local_90;
  ulonglong local_88;
  void **local_80;
  longlong *local_78;
  ulonglong local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_50;
  ulonglong local_48;
  ulonglong local_40;
  
  local_68 = 0xfffffffffffffffe;
  local_40 = DAT_18000f0e0 ^ (ulonglong)auStack_d8;
  local_80 = param_5;
  puVar4 = *param_1;
  uVar10 = (longlong)param_3 - (longlong)puVar4;
  local_a0 = param_1;
  local_88 = param_4;
  local_78 = param_2;
  if (param_4 != 0) {
    puVar1 = param_1[1];
    if ((ulonglong)((longlong)param_1[2] - (longlong)puVar1 >> 5) < param_4) {
      lVar5 = (longlong)puVar1 - (longlong)puVar4 >> 5;
      if (0x7ffffffffffffffU - lVar5 < param_4) {
        std::_Xlength_error("vector<T> too long");
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return;
      }
      uVar8 = param_4 + lVar5;
      uVar7 = (longlong)param_1[2] - (longlong)puVar4 >> 5;
      uVar6 = 0;
      if (uVar7 <= 0x7ffffffffffffff - (uVar7 >> 1)) {
        uVar6 = (uVar7 >> 1) + uVar7;
      }
      if (uVar8 <= uVar6) {
        uVar8 = uVar6;
      }
      local_70 = uVar8;
      puVar3 = (ulonglong *)FUN_180002ed0(param_1,uVar8);
      lVar5 = (longlong)param_3 - (longlong)*param_1 >> 5;
      local_a4 = 0;
      local_b8 = local_a8;
      local_98 = puVar3;
      local_90 = lVar5;
      FUN_1800016b0((void **)(puVar3 + lVar5 * 4),param_4,local_80);
      local_a4 = 1;
      local_b0 = local_a8;
      local_b8 = 0;
      FUN_180001860(*param_1,param_3,puVar3);
      local_a4 = 2;
      local_b0 = local_a8;
      local_b8 = 0;
      FUN_180001860(param_3,param_1[1],puVar3 + (param_4 + lVar5) * 4);
      puVar4 = param_1[1];
      puVar1 = *param_1;
      if (puVar1 != (ulonglong *)0x0) {
        FUN_180001120(puVar1,puVar4);
        FUN_180003730(param_1,*param_1,(longlong)param_1[2] - (longlong)*param_1 >> 5);
      }
      param_1[2] = puVar3 + uVar8 * 4;
      param_1[1] = puVar3 + (param_4 + ((longlong)puVar4 - (longlong)puVar1 >> 5)) * 4;
      *param_1 = puVar3;
      param_2 = local_78;
    }
    else {
      local_48 = 7;
      local_50 = 0;
      local_60._0_2_ = 0;
      if ((ulonglong)((longlong)puVar1 - (longlong)param_3 >> 5) < param_4) {
        FUN_1800034a0((void **)&local_60,param_5,(void *)0x0,(void *)0xffffffffffffffff);
        local_b0 = local_a8;
        local_b8 = 0;
        FUN_180001860(param_3,param_1[1],param_3 + param_4 * 4);
        local_b8 = local_a8;
        FUN_1800016b0((void **)param_1[1],param_4 - ((longlong)param_1[1] - (longlong)param_3 >> 5),
                      (void **)&local_60);
        param_1[1] = param_1[1] + param_4 * 4;
        puVar4 = param_1[1];
        if (param_3 != (ulonglong **)(puVar4 + param_4 * -4)) {
          do {
            if (param_3 != (ulonglong **)&local_60) {
              FUN_1800034a0(param_3,(void **)&local_60,(void *)0x0,(void *)0xffffffffffffffff);
            }
            param_3 = param_3 + 4;
          } while (param_3 != (ulonglong **)(puVar4 + param_4 * -4));
        }
      }
      else {
        FUN_1800034a0((void **)&local_60,param_5,(void *)0x0,(void *)0xffffffffffffffff);
        ppuVar9 = (ulonglong **)param_1[1];
        local_b0 = local_a8;
        local_b8 = 0;
        puVar4 = FUN_180001860(ppuVar9 + param_4 * -4,ppuVar9,ppuVar9);
        param_1[1] = puVar4;
        FUN_180001400(param_3,ppuVar9 + param_4 * -4,ppuVar9);
        ppuVar9 = param_3;
        if (param_3 != param_3 + param_4 * 4) {
          do {
            if (ppuVar9 != (ulonglong **)&local_60) {
              FUN_1800034a0(ppuVar9,(void **)&local_60,(void *)0x0,(void *)0xffffffffffffffff);
            }
            ppuVar9 = ppuVar9 + 4;
          } while (ppuVar9 != param_3 + param_4 * 4);
        }
      }
      if (7 < local_48) {
        FUN_1800037a0(&local_60,(void *)CONCAT62(local_60._2_6_,(undefined2)local_60),local_48 + 1);
      }
    }
  }
  *param_2 = (uVar10 & 0xffffffffffffffe0) + (longlong)*param_1;
  __security_check_cookie(local_40 ^ (ulonglong)auStack_d8);
  return;
}



void FUN_180002c20(ulonglong **param_1,ulonglong param_2)

{
  ulonglong *puVar1;
  ulonglong *puVar2;
  ulonglong *puVar3;
  
  puVar3 = (ulonglong *)FUN_180002ed0(param_1,param_2);
  FUN_180001860(*param_1,param_1[1],puVar3);
  puVar1 = param_1[1];
  puVar2 = *param_1;
  if (puVar2 != (ulonglong *)0x0) {
    FUN_180001120(puVar2,puVar1);
    FUN_180003730(param_1,*param_1,(longlong)param_1[2] - (longlong)*param_1 >> 5);
  }
  param_1[2] = puVar3 + param_2 * 4;
  param_1[1] = (ulonglong *)
               (((longlong)puVar1 - (longlong)puVar2 & 0xffffffffffffffe0U) + (longlong)puVar3);
  *param_1 = puVar3;
  return;
}



void FUN_180002ce0(ulonglong **param_1,ulonglong param_2)

{
  code *pcVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  longlong lVar4;
  ulonglong uVar5;
  
  if (param_2 <= (ulonglong)((longlong)param_1[2] - (longlong)param_1[1] >> 5)) {
    return;
  }
  lVar4 = (longlong)param_1[1] - (longlong)*param_1 >> 5;
  if (0x7ffffffffffffffU - lVar4 < param_2) {
    std::_Xlength_error("vector<T> too long");
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  uVar3 = param_2 + lVar4;
  uVar5 = (longlong)param_1[2] - (longlong)*param_1 >> 5;
  uVar2 = 0;
  if (uVar5 <= 0x7ffffffffffffff - (uVar5 >> 1)) {
    uVar2 = (uVar5 >> 1) + uVar5;
  }
  if (uVar3 <= uVar2) {
    uVar3 = uVar2;
  }
  FUN_180002c20(param_1,uVar3);
  return;
}



void FUN_180002d70(undefined8 *param_1,undefined8 *param_2)

{
  undefined2 uVar1;
  undefined8 uVar2;
  longlong lVar3;
  longlong lVar4;
  
  if (7 < (ulonglong)param_1[3]) {
    if (7 < (ulonglong)param_2[3]) {
      uVar2 = *param_1;
      *param_1 = *param_2;
      *param_2 = uVar2;
      return;
    }
    uVar2 = *param_1;
    if (param_2[2] + 1 != 0) {
      memcpy(param_1,param_2,(param_2[2] + 1) * 2);
    }
    *param_2 = uVar2;
    return;
  }
  if ((ulonglong)param_2[3] < 8) {
    if ((param_1 != param_2) && (lVar3 = 0, param_1 <= param_1 + 2)) {
      lVar4 = (longlong)param_2 - (longlong)param_1;
      do {
        lVar3 = lVar3 + 1;
        uVar1 = *(undefined2 *)param_1;
        *(undefined2 *)param_1 = *(undefined2 *)(lVar4 + (longlong)param_1);
        *(undefined2 *)(lVar4 + (longlong)param_1) = uVar1;
        param_1 = (undefined8 *)((longlong)param_1 + 2);
      } while (lVar3 != 8);
      return;
    }
  }
  else {
    uVar2 = *param_2;
    if (param_1[2] + 1 != 0) {
      memcpy(param_2,param_1,(param_1[2] + 1) * 2);
    }
    *param_1 = uVar2;
  }
  return;
}



void * FUN_180002e60(undefined8 param_1,ulonglong param_2)

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



void * FUN_180002ed0(undefined8 param_1,ulonglong param_2)

{
  code *pcVar1;
  void *pvVar2;
  void *pvVar3;
  ulonglong uVar4;
  
  if (param_2 == 0) {
    pvVar2 = (void *)0x0;
  }
  else {
    if (0x7ffffffffffffff < param_2) {
      std::_Xbad_alloc();
      pcVar1 = (code *)swi(3);
      pvVar2 = (void *)(*pcVar1)();
      return pvVar2;
    }
    uVar4 = param_2 * 0x20;
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



void * FUN_180002f50(undefined8 param_1,ulonglong param_2)

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
FUN_180002fd0(ulonglong **param_1,undefined8 *param_2,ulonglong param_3,ulonglong param_4)

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
        FUN_180002580(param_1,puVar1,puVar2);
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



ulonglong ** FUN_1800030f0(ulonglong **param_1,ulonglong **param_2,ulonglong param_3)

{
  ulonglong *puVar1;
  ulonglong *puVar2;
  code *pcVar3;
  ulonglong **ppuVar4;
  
  if (param_2 != (ulonglong **)0x0) {
    puVar2 = param_1[3];
    ppuVar4 = param_1;
    if ((ulonglong *)0xf < puVar2) {
      ppuVar4 = (ulonglong **)*param_1;
    }
    if (ppuVar4 <= param_2) {
      ppuVar4 = param_1;
      if ((ulonglong *)0xf < puVar2) {
        ppuVar4 = (ulonglong **)*param_1;
      }
      if (param_2 < (ulonglong **)((longlong)ppuVar4 + (longlong)param_1[2])) {
        ppuVar4 = param_1;
        if ((ulonglong *)0xf < puVar2) {
          ppuVar4 = (ulonglong **)*param_1;
        }
        ppuVar4 = FUN_180002fd0(param_1,param_1,(longlong)param_2 - (longlong)ppuVar4,param_3);
        return ppuVar4;
      }
    }
  }
  puVar2 = param_1[2];
  if (~(ulonglong)puVar2 <= param_3) {
    std::_Xlength_error("string too long");
    pcVar3 = (code *)swi(3);
    ppuVar4 = (ulonglong **)(*pcVar3)();
    return ppuVar4;
  }
  puVar1 = (ulonglong *)((longlong)puVar2 + param_3);
  if (param_3 != 0) {
    if (puVar1 == (ulonglong *)0xffffffffffffffff) {
      std::_Xlength_error("string too long");
      pcVar3 = (code *)swi(3);
      ppuVar4 = (ulonglong **)(*pcVar3)();
      return ppuVar4;
    }
    if (param_1[3] < puVar1) {
      FUN_180002580(param_1,puVar1,puVar2);
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
    ppuVar4 = param_1;
    if ((ulonglong *)0xf < param_1[3]) {
      ppuVar4 = (ulonglong **)*param_1;
    }
    if (param_3 != 0) {
      memcpy((void *)((longlong)ppuVar4 + (longlong)param_1[2]),param_2,param_3);
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



ulonglong **
FUN_180003240(ulonglong **param_1,ulonglong **param_2,ulonglong *param_3,ulonglong *param_4)

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
    FUN_180003810((longlong **)param_1,(longlong *)0x0,(ulonglong)param_3);
  }
  else {
    if (param_4 == (ulonglong *)0xffffffffffffffff) {
      std::_Xlength_error("string too long");
      pcVar1 = (code *)swi(3);
      ppuVar2 = (ulonglong **)(*pcVar1)();
      return ppuVar2;
    }
    if (param_1[3] < param_4) {
      FUN_180002580(param_1,param_4,param_1[2]);
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



ulonglong ** FUN_180003370(ulonglong **param_1,ulonglong **param_2,ulonglong *param_3)

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
        ppuVar3 = FUN_180003240(param_1,param_1,(ulonglong *)((longlong)param_2 - (longlong)ppuVar3)
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
    FUN_180002580(param_1,param_3,param_1[2]);
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



void ** FUN_1800034a0(void **param_1,void **param_2,void *param_3,void *param_4)

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
    FUN_1800038e0(param_1,0,(ulonglong)param_3);
  }
  else {
    if ((void *)0x7ffffffffffffffe < param_4) {
      std::_Xlength_error("string too long");
      pcVar1 = (code *)swi(3);
      ppvVar2 = (void **)(*pcVar1)();
      return ppvVar2;
    }
    if (param_1[3] < param_4) {
      FUN_180002730(param_1,param_4,param_1[2]);
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



void ** FUN_1800035e0(void **param_1,void **param_2,void *param_3)

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
        ppvVar3 = FUN_1800034a0(param_1,param_1,(void *)((longlong)param_2 - (longlong)ppvVar3 >> 1)
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
    FUN_180002730(param_1,param_3,param_1[2]);
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



void FUN_180003730(undefined8 param_1,void *param_2,ulonglong param_3)

{
  void *_Memory;
  
  if (0x7ffffffffffffff < param_3) {
                    // WARNING: Subroutine does not return
    _invalid_parameter_noinfo_noreturn();
  }
  _Memory = param_2;
  if (0xfff < param_3 << 5) {
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



void FUN_1800037a0(undefined8 param_1,void *param_2,ulonglong param_3)

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



longlong ** FUN_180003810(longlong **param_1,longlong *param_2,ulonglong param_3)

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



undefined8 * FUN_1800038e0(undefined8 *param_1,ulonglong param_2,ulonglong param_3)

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



undefined8 * FUN_180003990(ulonglong **param_1,undefined8 *param_2,void **param_3,void **param_4)

{
  void **ppvVar1;
  
  if ((param_3 == (void **)*param_1) && (param_4 == (void **)param_1[1])) {
    FUN_180001120(*param_1,param_1[1]);
    param_1[1] = *param_1;
    *param_2 = param_3;
    return param_2;
  }
  if (param_3 != param_4) {
    ppvVar1 = FUN_180001510(param_4,(void **)param_1[1],param_3);
    FUN_180001120((ulonglong *)ppvVar1,param_1[1]);
    *param_2 = param_3;
    param_1[1] = (ulonglong *)ppvVar1;
    return param_2;
  }
  *param_2 = param_3;
  return param_2;
}



ulonglong ** FUN_180003a50(int param_1)

{
  code *pcVar1;
  ulonglong **ppuVar2;
  ulonglong uVar3;
  char *local_38;
  undefined local_30;
  undefined **local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  uVar3 = (ulonglong)param_1;
  if (param_1 < 0) {
    local_30 = 1;
    local_28 = std::exception::vftable;
    local_20 = 0;
    local_18 = 0;
    local_38 = "capacity";
    __std_exception_copy(&local_38,&local_20);
    local_28 = std::out_of_range::vftable;
                    // WARNING: Subroutine does not return
    _CxxThrowException(&local_28,(ThrowInfo *)&DAT_18000ac40);
  }
  ppuVar2 = (ulonglong **)operator_new(0x18);
  if (ppuVar2 != (ulonglong **)0x0) {
    *ppuVar2 = (ulonglong *)0x0;
    ppuVar2[1] = (ulonglong *)0x0;
    ppuVar2[2] = (ulonglong *)0x0;
  }
  if ((ulonglong)((longlong)ppuVar2[2] - (longlong)*ppuVar2 >> 5) < uVar3) {
    if (0x7ffffffffffffff < uVar3) {
      std::_Xlength_error("vector<T> too long");
      pcVar1 = (code *)swi(3);
      ppuVar2 = (ulonglong **)(*pcVar1)();
      return ppuVar2;
    }
    FUN_180002c20(ppuVar2,uVar3);
  }
  return ppuVar2;
}



void FUN_180003b30(ulonglong **param_1,void **param_2)

{
  void **ppvVar1;
  ulonglong *puVar2;
  void **ppvVar3;
  void **ppvVar4;
  
  ppvVar1 = (void **)param_1[1];
  if ((param_2 < ppvVar1) && (ppvVar4 = (void **)*param_1, ppvVar4 <= param_2)) {
    if (ppvVar1 == (void **)param_1[2]) {
      FUN_180002ce0(param_1,1);
    }
    ppvVar1 = (void **)param_1[1];
    puVar2 = *param_1;
    if (ppvVar1 != (void **)0x0) {
      ppvVar1[3] = (void *)0x7;
      ppvVar1[2] = (void *)0x0;
      ppvVar3 = ppvVar1;
      if ((void *)0x7 < ppvVar1[3]) {
        ppvVar3 = (void **)*ppvVar1;
      }
      *(undefined2 *)ppvVar3 = 0;
      FUN_1800034a0(ppvVar1,(void **)(((longlong)param_2 - (longlong)ppvVar4 & 0xffffffffffffffe0U)
                                     + (longlong)puVar2),(void *)0x0,(void *)0xffffffffffffffff);
    }
  }
  else {
    if (ppvVar1 == (void **)param_1[2]) {
      FUN_180002ce0(param_1,1);
    }
    ppvVar1 = (void **)param_1[1];
    if (ppvVar1 != (void **)0x0) {
      ppvVar1[3] = (void *)0x7;
      ppvVar1[2] = (void *)0x0;
      ppvVar4 = ppvVar1;
      if ((void *)0x7 < ppvVar1[3]) {
        ppvVar4 = (void **)*ppvVar1;
      }
      *(undefined2 *)ppvVar4 = 0;
      FUN_1800034a0(ppvVar1,param_2,(void *)0x0,(void *)0xffffffffffffffff);
    }
  }
  param_1[1] = param_1[1] + 4;
  return;
}



void ** FUN_180003c30(longlong *param_1,int param_2,undefined8 param_3,undefined8 param_4)

{
  longlong lVar1;
  int iVar2;
  void **ppvVar3;
  int iVar4;
  char *local_40;
  undefined local_38;
  undefined **local_30;
  undefined8 local_28;
  undefined8 local_20;
  
  iVar4 = (int)param_3;
  if (param_2 < 0) {
    local_30 = std::exception::vftable;
    local_28 = 0;
    local_20 = 0;
    local_40 = "index";
    local_38 = 1;
    __std_exception_copy(&local_40,&local_28,param_3,param_4,0xfffffffffffffffe);
    local_30 = std::out_of_range::vftable;
                    // WARNING: Subroutine does not return
    _CxxThrowException(&local_30,(ThrowInfo *)&DAT_18000ac40);
  }
  if (-1 < iVar4) {
    iVar2 = (int)(param_1[1] - *param_1 >> 5);
    if ((param_2 < iVar2 + 1) && (param_2 + iVar4 <= iVar2)) {
      ppvVar3 = (void **)operator_new(0x18);
      if (ppvVar3 != (void **)0x0) {
        lVar1 = *param_1;
        *ppvVar3 = (void *)0x0;
        ppvVar3[1] = (void *)0x0;
        ppvVar3[2] = (void *)0x0;
        FUN_180001070(ppvVar3,(void **)((longlong)param_2 * 0x20 + lVar1),
                      (void **)((longlong)iVar4 * 0x20 + (longlong)param_2 * 0x20 + lVar1));
      }
      return ppvVar3;
    }
    local_30 = std::exception::vftable;
    local_28 = 0;
    local_20 = 0;
    local_40 = "invalid range";
    local_38 = 1;
    __std_exception_copy(&local_40,&local_28,param_3,param_4,0xfffffffffffffffe);
    local_30 = std::invalid_argument::vftable;
                    // WARNING: Subroutine does not return
    _CxxThrowException(&local_30,(ThrowInfo *)&DAT_18000acd0);
  }
  local_30 = std::exception::vftable;
  local_28 = 0;
  local_20 = 0;
  local_40 = "count";
  local_38 = 1;
  __std_exception_copy(&local_40,&local_28,param_3,param_4,0xfffffffffffffffe);
  local_30 = std::out_of_range::vftable;
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_30,(ThrowInfo *)&DAT_18000ac40);
}



void FUN_180003dd0(ulonglong **param_1,int param_2,void **param_3)

{
  longlong local_res20;
  char *local_38;
  undefined local_30;
  undefined **local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  if ((-1 < param_2) && (param_2 < (int)((longlong)param_1[1] - (longlong)*param_1 >> 5) + 1)) {
    FUN_180002850(param_1,&local_res20,(ulonglong **)(*param_1 + (longlong)param_2 * 4),1,param_3);
    return;
  }
  local_30 = 1;
  local_28 = std::exception::vftable;
  local_20 = 0;
  local_18 = 0;
  local_38 = "index";
  __std_exception_copy(&local_38,&local_20);
  local_28 = std::out_of_range::vftable;
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_28,(ThrowInfo *)&DAT_18000ac40);
}



void FUN_180003e70(ulonglong **param_1,int param_2,undefined8 *param_3)

{
  char *local_38;
  undefined local_30;
  undefined **local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  if ((-1 < param_2) && (param_2 < (int)((longlong)param_1[1] - (longlong)*param_1 >> 5) + 1)) {
    FUN_180001200(param_1,*param_1 + (longlong)param_2 * 4,(void **)*param_3,(void **)param_3[1]);
    return;
  }
  local_30 = 1;
  local_28 = std::exception::vftable;
  local_20 = 0;
  local_18 = 0;
  local_38 = "index";
  __std_exception_copy(&local_38,&local_20);
  local_28 = std::out_of_range::vftable;
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_28,(ThrowInfo *)&DAT_18000ac40);
}



void FUN_180003f10(longlong *param_1,int param_2)

{
  void **ppvVar1;
  char *local_38;
  undefined local_30;
  undefined **local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  if (-1 < param_2) {
    if (param_2 < (int)((longlong)(void **)param_1[1] - *param_1 >> 5)) {
      ppvVar1 = (void **)((longlong)param_2 * 0x20 + *param_1);
      FUN_180001510(ppvVar1 + 4,(void **)param_1[1],ppvVar1);
      FUN_180001120((ulonglong *)param_1[1] + -4,(ulonglong *)param_1[1]);
      param_1[1] = param_1[1] + -0x20;
      return;
    }
  }
  local_30 = 1;
  local_28 = std::exception::vftable;
  local_20 = 0;
  local_18 = 0;
  local_38 = "index";
  __std_exception_copy(&local_38,&local_20);
  local_28 = std::out_of_range::vftable;
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_28,(ThrowInfo *)&DAT_18000ac40);
}



void FUN_180003fd0(ulonglong **param_1,int param_2,int param_3)

{
  ulonglong *puVar1;
  int iVar2;
  undefined8 local_res20;
  char *local_38;
  undefined local_30;
  undefined **local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  if (param_2 < 0) {
    local_30 = 1;
    local_28 = std::exception::vftable;
    local_20 = 0;
    local_18 = 0;
    local_38 = "index";
    __std_exception_copy(&local_38,&local_20);
    local_28 = std::out_of_range::vftable;
                    // WARNING: Subroutine does not return
    _CxxThrowException(&local_28,(ThrowInfo *)&DAT_18000ac40);
  }
  if (-1 < param_3) {
    puVar1 = *param_1;
    iVar2 = (int)((longlong)param_1[1] - (longlong)puVar1 >> 5);
    if ((param_2 < iVar2 + 1) && (param_2 + param_3 <= iVar2)) {
      FUN_180003990(param_1,&local_res20,(void **)(puVar1 + (longlong)param_2 * 4),
                    (void **)(puVar1 + ((longlong)param_2 + (longlong)param_3) * 4));
      return;
    }
    local_30 = 1;
    local_28 = std::exception::vftable;
    local_20 = 0;
    local_18 = 0;
    local_38 = "invalid range";
    __std_exception_copy(&local_38,&local_20);
    local_28 = std::invalid_argument::vftable;
                    // WARNING: Subroutine does not return
    _CxxThrowException(&local_28,(ThrowInfo *)&DAT_18000acd0);
  }
  local_30 = 1;
  local_28 = std::exception::vftable;
  local_20 = 0;
  local_18 = 0;
  local_38 = "count";
  __std_exception_copy(&local_38,&local_20);
  local_28 = std::out_of_range::vftable;
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_28,(ThrowInfo *)&DAT_18000ac40);
}



void ** FUN_180004130(void **param_1,int param_2,undefined8 param_3,undefined8 param_4)

{
  void **ppvVar1;
  char *local_30;
  undefined local_28;
  undefined **local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  if (-1 < param_2) {
    ppvVar1 = (void **)operator_new(0x18);
    if (ppvVar1 != (void **)0x0) {
      *ppvVar1 = (void *)0x0;
      ppvVar1[1] = (void *)0x0;
      ppvVar1[2] = (void *)0x0;
      FUN_1800024d0(ppvVar1,(longlong)param_2,param_1);
    }
    return ppvVar1;
  }
  local_20 = std::exception::vftable;
  local_18 = 0;
  local_10 = 0;
  local_30 = "count";
  local_28 = 1;
  __std_exception_copy(&local_30,&local_18,param_3,param_4,0xfffffffffffffffe);
  local_20 = std::out_of_range::vftable;
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_20,(ThrowInfo *)&DAT_18000ac40);
}



void FUN_1800041f0(longlong *param_1,int param_2,int param_3)

{
  longlong lVar1;
  int iVar2;
  char *local_38;
  undefined local_30;
  undefined **local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  if (param_2 < 0) {
    local_30 = 1;
    local_28 = std::exception::vftable;
    local_20 = 0;
    local_18 = 0;
    local_38 = "index";
    __std_exception_copy(&local_38,&local_20);
    local_28 = std::out_of_range::vftable;
                    // WARNING: Subroutine does not return
    _CxxThrowException(&local_28,(ThrowInfo *)&DAT_18000ac40);
  }
  if (-1 < param_3) {
    lVar1 = *param_1;
    iVar2 = (int)(param_1[1] - lVar1 >> 5);
    if ((param_2 < iVar2 + 1) && (param_2 + param_3 <= iVar2)) {
      FUN_1800015b0((longlong)param_2 * 0x20 + lVar1,
                    ((longlong)param_3 + (longlong)param_2) * 0x20 + lVar1);
      return;
    }
    local_30 = 1;
    local_28 = std::exception::vftable;
    local_20 = 0;
    local_18 = 0;
    local_38 = "invalid range";
    __std_exception_copy(&local_38,&local_20);
    local_28 = std::invalid_argument::vftable;
                    // WARNING: Subroutine does not return
    _CxxThrowException(&local_28,(ThrowInfo *)&DAT_18000acd0);
  }
  local_30 = 1;
  local_28 = std::exception::vftable;
  local_20 = 0;
  local_18 = 0;
  local_38 = "count";
  __std_exception_copy(&local_38,&local_20);
  local_28 = std::out_of_range::vftable;
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_28,(ThrowInfo *)&DAT_18000ac40);
}



void FUN_180004340(longlong *param_1,int param_2,longlong *param_3)

{
  void **ppvVar1;
  longlong lVar2;
  void **ppvVar3;
  void **ppvVar4;
  longlong lVar5;
  char *local_38;
  undefined local_30;
  undefined **local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  if (param_2 < 0) {
    local_30 = 1;
    local_28 = std::exception::vftable;
    local_20 = 0;
    local_18 = 0;
    local_38 = "index";
    __std_exception_copy(&local_38,&local_20);
    local_28 = std::out_of_range::vftable;
                    // WARNING: Subroutine does not return
    _CxxThrowException(&local_28,(ThrowInfo *)&DAT_18000ac40);
  }
  lVar2 = *param_1;
  ppvVar3 = (void **)param_3[1];
  ppvVar4 = (void **)*param_3;
  if ((ulonglong)(param_1[1] - lVar2 >> 5) <
      (ulonglong)(((longlong)ppvVar3 - (longlong)ppvVar4 >> 5) + (longlong)param_2)) {
    local_30 = 1;
    local_28 = std::exception::vftable;
    local_20 = 0;
    local_18 = 0;
    local_38 = "index";
    __std_exception_copy(&local_38,&local_20);
    local_28 = std::out_of_range::vftable;
                    // WARNING: Subroutine does not return
    _CxxThrowException(&local_28,(ThrowInfo *)&DAT_18000ac40);
  }
  if (ppvVar4 != ppvVar3) {
    lVar5 = (longlong)param_2 * 0x20 - (longlong)ppvVar4;
    do {
      ppvVar1 = (void **)(lVar5 + lVar2 + (longlong)ppvVar4);
      if (ppvVar1 != ppvVar4) {
        FUN_1800034a0(ppvVar1,ppvVar4,(void *)0x0,(void *)0xffffffffffffffff);
      }
      ppvVar4 = ppvVar4 + 4;
    } while (ppvVar4 != ppvVar3);
  }
  return;
}



longlong FUN_180004490(longlong *param_1,int param_2)

{
  char *local_38;
  undefined local_30;
  undefined **local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  if ((-1 < param_2) && (param_2 < (int)(param_1[1] - *param_1 >> 5))) {
    return (longlong)param_2 * 0x20 + *param_1;
  }
  local_30 = 1;
  local_28 = std::exception::vftable;
  local_20 = 0;
  local_18 = 0;
  local_38 = "index";
  __std_exception_copy(&local_38,&local_20);
  local_28 = std::out_of_range::vftable;
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_28,(ThrowInfo *)&DAT_18000ac40);
}



void ** FUN_180004510(void **param_1,longlong *param_2,undefined8 param_3)

{
  longlong lVar1;
  int iVar2;
  char *local_30;
  undefined local_28;
  undefined **local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  iVar2 = (int)param_3;
  if ((-1 < iVar2) && (lVar1 = *param_2, iVar2 < (int)(param_2[1] - lVar1 >> 5))) {
    param_1[2] = (void *)0x0;
    param_1[3] = (void *)0x7;
    *(undefined2 *)param_1 = 0;
    FUN_1800034a0(param_1,(void **)((longlong)iVar2 * 0x20 + lVar1),(void *)0x0,
                  (void *)0xffffffffffffffff);
    return param_1;
  }
  local_28 = 1;
  local_20 = std::exception::vftable;
  local_18 = 0;
  local_10 = 0;
  local_30 = "index";
  __std_exception_copy(&local_30,&local_18,param_3,0,0);
  local_20 = std::out_of_range::vftable;
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_20,(ThrowInfo *)&DAT_18000ac40);
}



void FUN_1800045d0(longlong *param_1,int param_2,void **param_3)

{
  void **ppvVar1;
  char *local_38;
  undefined local_30;
  undefined **local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  if ((-1 < param_2) && (param_2 < (int)(param_1[1] - *param_1 >> 5))) {
    ppvVar1 = (void **)((longlong)param_2 * 0x20 + *param_1);
    if (ppvVar1 != param_3) {
      FUN_1800034a0(ppvVar1,param_3,(void *)0x0,(void *)0xffffffffffffffff);
      return;
    }
    return;
  }
  local_30 = 1;
  local_28 = std::exception::vftable;
  local_20 = 0;
  local_18 = 0;
  local_38 = "index";
  __std_exception_copy(&local_38,&local_20);
  local_28 = std::out_of_range::vftable;
                    // WARNING: Subroutine does not return
  _CxxThrowException(&local_28,(ThrowInfo *)&DAT_18000ac40);
}



char * FUN_180004670(longlong param_1)

{
  char *pcVar1;
  
  pcVar1 = "Unknown exception";
  if (*(char **)(param_1 + 8) != (char *)0x0) {
    pcVar1 = *(char **)(param_1 + 8);
  }
  return pcVar1;
}



void _guard_check_icall(void)

{
                    // 0x4690  2  CSharp_IBuildCallback_FinishedPassSwigExplicitIBuildCallback
                    // 0x4690  8  CSharp_IBuildCallback_OnTileStartSwigExplicitIBuildCallback
                    // 0x4690  10  CSharp_IBuildCallback_StartingPassSwigExplicitIBuildCallback
                    // 0x4690  13
                    // CSharp_IBuildProgressTracker_FinishedPassSwigExplicitIBuildProgressTracker
                    // 0x4690  17
                    // CSharp_IBuildProgressTracker_ProcessedGTexSwigExplicitIBuildProgressTracker
                    // 0x4690  19
                    // CSharp_IBuildProgressTracker_ProcessedTileSwigExplicitIBuildProgressTracker
                    // 0x4690  21
                    // CSharp_IBuildProgressTracker_StartingPassSwigExplicitIBuildProgressTracker
  return;
}



void CSharp_IBuildCallback_director_connect
               (undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
               undefined8 param_5,undefined8 param_6)

{
  longlong lVar1;
  
                    // 0x46a0  11  CSharp_IBuildCallback_director_connect
  lVar1 = __RTDynamicCast(param_1,0,&Graphine::Nixel::IBuildCallback::RTTI_Type_Descriptor,
                          &SwigDirector_IBuildCallback::RTTI_Type_Descriptor,0);
  if (lVar1 != 0) {
    *(undefined8 *)(lVar1 + 0x20) = param_5;
    *(undefined8 *)(lVar1 + 0x28) = param_6;
    *(undefined8 *)(lVar1 + 8) = param_2;
    *(undefined8 *)(lVar1 + 0x10) = param_3;
    *(undefined8 *)(lVar1 + 0x18) = param_4;
  }
  return;
}



void CSharp_IBuildCallback_FinishedPass(longlong *param_1)

{
                    // 0x4710  1  CSharp_IBuildCallback_FinishedPass
                    // 0x4710  12  CSharp_IBuildProgressTracker_FinishedPass
                    // 0x4710  45  CSharp_ILayerIndexCollection_GetSize
                    // 0x4710  50  CSharp_IPackedSoupFileCollection_GetSize
                    // 0x4710  69  CSharp_ITileSetRebuilder_Begin
                    // 0x4710  87  CSharp_ITileSoupFileReader_GetMetaDataLength
                    // WARNING: Could not recover jumptable at 0x000180004713. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 8))();
  return;
}



void CSharp_IBuildCallback_OnTileCompleted(longlong *param_1)

{
                    // 0x4720  3  CSharp_IBuildCallback_OnTileCompleted
                    // 0x4720  14  CSharp_IBuildProgressTracker_OnMipLevelGenerated
                    // 0x4720  72  CSharp_ITileSetRebuilder_GetMetaData
                    // 0x4720  81  CSharp_ITileSoupBuilder_End
                    // 0x4720  103  CSharp_ITiledBuildParameters_SetMetadata
                    // WARNING: Could not recover jumptable at 0x000180004723. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x20))();
  return;
}



undefined8 CSharp_IBuildCallback_OnTileCompletedSwigExplicitIBuildCallback(void)

{
                    // 0x4730  4  CSharp_IBuildCallback_OnTileCompletedSwigExplicitIBuildCallback
                    // 0x4730  15
                    // CSharp_IBuildProgressTracker_OnMipLevelGeneratedSwigExplicitIBuildProgressTracker
  return 0;
}



void CSharp_IBuildCallback_OnTileFailed(longlong *param_1)

{
                    // 0x4740  5  CSharp_IBuildCallback_OnTileFailed
                    // 0x4740  16  CSharp_IBuildProgressTracker_ProcessedGTex
                    // 0x4740  64  CSharp_ITileOrder_Count
                    // 0x4740  71  CSharp_ITileSetRebuilder_GetBuildReport
                    // 0x4740  85  CSharp_ITileSoupBuilder_WriteTile
                    // 0x4740  89  CSharp_ITileSoupFileReader_GetTiledTopology
                    // 0x4740  95  CSharp_ITiledBuildParameters_GetMetadataSize
                    // 0x4740  108  CSharp_ITiledRasterDataRead_GetPixelSize
                    // WARNING: Could not recover jumptable at 0x000180004743. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x18))();
  return;
}



void CSharp_IBuildCallback_StartingPass(undefined8 *param_1)

{
                    // 0x4750  9  CSharp_IBuildCallback_StartingPass
                    // 0x4750  20  CSharp_IBuildProgressTracker_StartingPass
                    // 0x4750  42  CSharp_ILayerIndexCollection_Add
                    // 0x4750  48  CSharp_IPackedSoupFileCollection_Add
                    // 0x4750  67  CSharp_ITileOrder_Reset
                    // 0x4750  76  CSharp_ITileSetRebuilder_SetBuildProgressTracker
                    // 0x4750  79  CSharp_ITileSoupBuilder_Build
                    // 0x4750  86  CSharp_ITileSoupFileReader_GetMetaData
                    // 0x4750  147  CSharp_ITiled_GetTopology
                    // WARNING: Could not recover jumptable at 0x000180004753. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)*param_1)();
  return;
}



void CSharp_IBuildProgressTracker_director_connect
               (undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
               undefined8 param_5,undefined8 param_6)

{
  longlong lVar1;
  
                    // 0x4760  22  CSharp_IBuildProgressTracker_director_connect
  lVar1 = __RTDynamicCast(param_1,0,&Graphine::Nixel::IBuildProgressTracker::RTTI_Type_Descriptor,
                          &SwigDirector_IBuildProgressTracker::RTTI_Type_Descriptor,0);
  if (lVar1 != 0) {
    *(undefined8 *)(lVar1 + 0x20) = param_5;
    *(undefined8 *)(lVar1 + 0x28) = param_6;
    *(undefined8 *)(lVar1 + 8) = param_2;
    *(undefined8 *)(lVar1 + 0x10) = param_3;
    *(undefined8 *)(lVar1 + 0x18) = param_4;
  }
  return;
}



void CSharp_ICodecLogger_LogError(longlong *param_1,undefined8 param_2,void **param_3)

{
  void *pvVar1;
  undefined auStack_58 [32];
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x47d0  23  CSharp_ICodecLogger_LogError
  local_18 = DAT_18000f0e0 ^ (ulonglong)auStack_58;
  if (param_3 == (void **)0x0) {
    (*DAT_18000f0c8)("null wstring",0);
  }
  else {
    pvVar1 = (void *)0x0;
    local_20 = 7;
    local_28 = 0;
    local_38._0_2_ = 0;
    if (*(short *)param_3 != 0) {
      pvVar1 = (void *)0xffffffffffffffff;
      do {
        pvVar1 = (void *)((longlong)pvVar1 + 1);
      } while (*(short *)((longlong)param_3 + (longlong)pvVar1 * 2) != 0);
    }
    FUN_1800035e0((void **)&local_38,param_3,pvVar1);
    (**(code **)(*param_1 + 8))(param_1,param_2,&local_38);
    if (7 < local_20) {
      FUN_1800037a0(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
    }
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
  return;
}



void CSharp_ICodecLogger_LogMessage(longlong *param_1,undefined8 param_2,void **param_3)

{
  void *pvVar1;
  undefined auStack_58 [32];
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x4890  25  CSharp_ICodecLogger_LogMessage
  local_18 = DAT_18000f0e0 ^ (ulonglong)auStack_58;
  if (param_3 == (void **)0x0) {
    (*DAT_18000f0c8)("null wstring",0);
  }
  else {
    pvVar1 = (void *)0x0;
    local_20 = 7;
    local_28 = 0;
    local_38._0_2_ = 0;
    if (*(short *)param_3 != 0) {
      pvVar1 = (void *)0xffffffffffffffff;
      do {
        pvVar1 = (void *)((longlong)pvVar1 + 1);
      } while (*(short *)((longlong)param_3 + (longlong)pvVar1 * 2) != 0);
    }
    FUN_1800035e0((void **)&local_38,param_3,pvVar1);
    (**(code **)(*param_1 + 0x18))(param_1,param_2,&local_38);
    if (7 < local_20) {
      FUN_1800037a0(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
    }
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
  return;
}



void CSharp_ICodecLogger_LogWarning(longlong *param_1,undefined8 param_2,void **param_3)

{
  void *pvVar1;
  undefined auStack_58 [32];
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x4950  27  CSharp_ICodecLogger_LogWarning
  local_18 = DAT_18000f0e0 ^ (ulonglong)auStack_58;
  if (param_3 == (void **)0x0) {
    (*DAT_18000f0c8)("null wstring",0);
  }
  else {
    pvVar1 = (void *)0x0;
    local_20 = 7;
    local_28 = 0;
    local_38._0_2_ = 0;
    if (*(short *)param_3 != 0) {
      pvVar1 = (void *)0xffffffffffffffff;
      do {
        pvVar1 = (void *)((longlong)pvVar1 + 1);
      } while (*(short *)((longlong)param_3 + (longlong)pvVar1 * 2) != 0);
    }
    FUN_1800035e0((void **)&local_38,param_3,pvVar1);
    (**(code **)(*param_1 + 0x10))(param_1,param_2,&local_38);
    if (7 < local_20) {
      FUN_1800037a0(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
    }
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
  return;
}



void CSharp_ICodecLogger_LogErrorSwigExplicitICodecLogger
               (undefined8 param_1,undefined8 param_2,void **param_3)

{
  void *pvVar1;
  undefined auStack_58 [32];
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x4a10  24  CSharp_ICodecLogger_LogErrorSwigExplicitICodecLogger
                    // 0x4a10  26  CSharp_ICodecLogger_LogMessageSwigExplicitICodecLogger
                    // 0x4a10  28  CSharp_ICodecLogger_LogWarningSwigExplicitICodecLogger
  local_18 = DAT_18000f0e0 ^ (ulonglong)auStack_58;
  if (param_3 == (void **)0x0) {
    (*DAT_18000f0c8)("null wstring",0);
    __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
    return;
  }
  pvVar1 = (void *)0x0;
  local_20 = 7;
  local_28 = 0;
  local_38._0_2_ = 0;
  if (*(short *)param_3 != 0) {
    pvVar1 = (void *)0xffffffffffffffff;
    do {
      pvVar1 = (void *)((longlong)pvVar1 + 1);
    } while (*(short *)((longlong)param_3 + (longlong)pvVar1 * 2) != 0);
  }
  FUN_1800035e0((void **)&local_38,param_3,pvVar1);
  if (7 < local_20) {
    FUN_1800037a0(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
  return;
}



void CSharp_ICodecLogger_director_connect
               (undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  longlong lVar1;
  
                    // 0x4ac0  29  CSharp_ICodecLogger_director_connect
  lVar1 = __RTDynamicCast(param_1,0,&Graphine::Nixel::ICodecLogger::RTTI_Type_Descriptor,
                          &SwigDirector_ICodecLogger::RTTI_Type_Descriptor,0);
  if (lVar1 != 0) {
    *(undefined8 *)(lVar1 + 8) = param_2;
    *(undefined8 *)(lVar1 + 0x10) = param_3;
    *(undefined8 *)(lVar1 + 0x18) = param_4;
  }
  return;
}



void CSharp_IGtsFileReader_GetMetaDataLength(longlong *param_1)

{
                    // 0x4b20  33  CSharp_IGtsFileReader_GetMetaDataLength
                    // 0x4b20  102  CSharp_ITiledBuildParameters_SetLayerCodingGroup
                    // WARNING: Could not recover jumptable at 0x000180004b23. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x68))();
  return;
}



void CSharp_IGtsFileReader_GetMipTail
               (longlong *param_1,undefined param_2,undefined param_3,undefined param_4,
               undefined4 param_5,undefined8 param_6)

{
  undefined *puVar1;
  int iVar2;
  undefined auStack_48 [32];
  undefined4 local_28;
  undefined8 local_20;
  undefined local_14 [4];
  ulonglong local_10;
  
                    // 0x4b30  34  CSharp_IGtsFileReader_GetMipTail
  local_10 = DAT_18000f0e0 ^ (ulonglong)auStack_48;
  puVar1 = local_14;
  iVar2 = 0;
  do {
    iVar2 = iVar2 + 1;
    *puVar1 = 1;
    puVar1 = puVar1 + 1;
  } while (iVar2 < 4);
  local_20 = param_6;
  local_28 = param_5;
  (**(code **)(*param_1 + 0x88))();
  __security_check_cookie(local_10 ^ (ulonglong)auStack_48);
  return;
}



void CSharp_IGtsFileReader_GetPageFileInfo(longlong *param_1)

{
                    // 0x4b90  36  CSharp_IGtsFileReader_GetPageFileInfo
                    // 0x4b90  141  CSharp_ITiledRasterData_SetMipmapGenerator
                    // WARNING: Could not recover jumptable at 0x000180004b93. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x98))();
  return;
}



undefined8
CSharp_IGtsFileReader_GetThumbNailDataType(longlong *param_1,undefined8 param_2,longlong param_3)

{
  undefined8 uVar1;
  
                    // 0x4ba0  37  CSharp_IGtsFileReader_GetThumbNailDataType
  if (param_3 == 0) {
    (*DAT_18000f0c8)("Graphine::Core::DataType::Enum & type is null",0);
    return 0;
  }
                    // WARNING: Could not recover jumptable at 0x000180004bc6. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = (**(code **)(*param_1 + 0x80))();
  return uVar1;
}



void CSharp_IGtsFileReader_GetThumbnail(longlong *param_1)

{
  undefined *puVar1;
  int iVar2;
  undefined auStack_38 [36];
  undefined local_14 [4];
  ulonglong local_10;
  
                    // 0x4bd0  38  CSharp_IGtsFileReader_GetThumbnail
  local_10 = DAT_18000f0e0 ^ (ulonglong)auStack_38;
  iVar2 = 0;
  puVar1 = local_14;
  do {
    iVar2 = iVar2 + 1;
    *puVar1 = 1;
    puVar1 = puVar1 + 1;
  } while (iVar2 < 4);
  (**(code **)(*param_1 + 0x78))();
  __security_check_cookie(local_10 ^ (ulonglong)auStack_38);
  return;
}



void CSharp_IGtsFileReader_GetTileInfo(longlong *param_1)

{
                    // 0x4c20  39  CSharp_IGtsFileReader_GetTileInfo
                    // 0x4c20  105  CSharp_ITiledBuildParameters_SetTileLayerCodingGroup
                    // WARNING: Could not recover jumptable at 0x000180004c23. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x50))();
  return;
}



undefined8 CSharp_IGtsFileReader_SWIGUpcast(undefined8 param_1)

{
                    // 0x4c30  40  CSharp_IGtsFileReader_SWIGUpcast
                    // 0x4c30  101  CSharp_ITiledBuildParameters_SWIGUpcast
                    // 0x4c30  112  CSharp_ITiledRasterDataRead_SWIGUpcast
                    // 0x4c30  136  CSharp_ITiledRasterData_SWIGUpcast
  return param_1;
}



undefined CSharp_ILayerIndexCollection_Contains(longlong *param_1)

{
  undefined uVar1;
  
                    // 0x4c40  43  CSharp_ILayerIndexCollection_Contains
  uVar1 = (**(code **)(*param_1 + 0x18))();
  return uVar1;
}



void CSharp_ILayerIndexCollection_GetItem(longlong *param_1,undefined4 param_2)

{
                    // 0x4c60  44  CSharp_ILayerIndexCollection_GetItem
                    // WARNING: Could not recover jumptable at 0x000180004c65. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x10))(param_1,param_2);
  return;
}



void CSharp_IMipmapGenerator_GenerateMipmapData(undefined8 *param_1)

{
                    // 0x4c70  46  CSharp_IMipmapGenerator_GenerateMipmapData
                    // WARNING: Could not recover jumptable at 0x000180004c73. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)*param_1)();
  return;
}



void CSharp_IMipmapGenerator_director_connect(undefined8 param_1,undefined8 param_2)

{
  longlong lVar1;
  
                    // 0x4c80  47  CSharp_IMipmapGenerator_director_connect
  lVar1 = __RTDynamicCast(param_1,0,&Graphine::Nixel::IMipmapGenerator::RTTI_Type_Descriptor,
                          &SwigDirector_IMipmapGenerator::RTTI_Type_Descriptor,0);
  if (lVar1 != 0) {
    *(undefined8 *)(lVar1 + 8) = param_2;
  }
  return;
}



void CSharp_IPackedSoupFileCollection_GetItem__SWIG_0(longlong *param_1,undefined4 param_2)

{
                    // 0x4cc0  49  CSharp_IPackedSoupFileCollection_GetItem__SWIG_0
                    // WARNING: Could not recover jumptable at 0x000180004cc5. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x18))(param_1,param_2);
  return;
}



void CSharp_ITileFileFactory_CreateGtsFileReader
               (void **param_1,
               vector_class_std__basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t____class_std__allocator_class_std__basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t_______
               *param_2,uint param_3,IGtsFileReader **param_4)

{
  void *pvVar1;
  undefined auStack_68 [32];
  undefined8 local_48;
  undefined8 local_38;
  ulonglong local_30;
  ulonglong local_28;
  
                    // 0x4cd0  51  CSharp_ITileFileFactory_CreateGtsFileReader
  local_28 = DAT_18000f0e0 ^ (ulonglong)auStack_68;
  if (param_1 == (void **)0x0) {
    (*DAT_18000f0c8)("null wstring",0);
  }
  else {
    pvVar1 = (void *)0x0;
    local_30 = 7;
    local_38 = 0;
    local_48._0_2_ = 0;
    if (*(short *)param_1 != 0) {
      pvVar1 = (void *)0xffffffffffffffff;
      do {
        pvVar1 = (void *)((longlong)pvVar1 + 1);
      } while (*(short *)((longlong)param_1 + (longlong)pvVar1 * 2) != 0);
    }
    FUN_1800035e0((void **)&local_48,param_1,pvVar1);
    Graphine::Nixel::ITileFileFactory::CreateGtsFileReader
              ((basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t___
                *)&local_48,param_2,param_3,param_4);
    if (7 < local_30) {
      FUN_1800037a0(&local_48,(void *)CONCAT62(local_48._2_6_,(undefined2)local_48),local_30 + 1);
    }
  }
  __security_check_cookie(local_28 ^ (ulonglong)auStack_68);
  return;
}



Enum __cdecl
Graphine::Nixel::ITileFileFactory::CSharp_ITileFileFactory_CreateLayerIndexCollection
          (ILayerIndexCollection **param_1)

{
  Enum EVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180004da0. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x4da0  52  CSharp_ITileFileFactory_CreateLayerIndexCollection
  EVar1 = CreateLayerIndexCollection(param_1);
  return EVar1;
}



void CSharp_ITileFileFactory_CreateTileFileReader
               (void **param_1,uint param_2,ITiledRasterDataRead **param_3)

{
  void *pvVar1;
  undefined auStack_58 [32];
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x4db0  53  CSharp_ITileFileFactory_CreateTileFileReader
  local_18 = DAT_18000f0e0 ^ (ulonglong)auStack_58;
  if (param_1 == (void **)0x0) {
    (*DAT_18000f0c8)("null wstring",0);
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
    FUN_1800035e0((void **)&local_38,param_1,pvVar1);
    Graphine::Nixel::ITileFileFactory::CreateTileFileReader
              ((basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t___
                *)&local_38,param_2,param_3);
    if (7 < local_20) {
      FUN_1800037a0(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
    }
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
  return;
}



Enum __cdecl
Graphine::Nixel::ITileFileFactory::CSharp_ITileFileFactory_CreateTileSetRebuilder
          (ITileSetRebuilder **param_1)

{
  Enum EVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180004e80. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x4e80  54  CSharp_ITileFileFactory_CreateTileSetRebuilder
  EVar1 = CreateTileSetRebuilder(param_1);
  return EVar1;
}



Enum __cdecl
Graphine::Nixel::ITileFileFactory::CSharp_ITileFileFactory_CreateTileSoupBuilder
          (ITiledRasterData *param_1,ITiledBuildParameters *param_2,BuildHeader *param_3,
          ITileSoupBuilder **param_4)

{
  Enum EVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180004e90. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x4e90  55  CSharp_ITileFileFactory_CreateTileSoupBuilder
  EVar1 = CreateTileSoupBuilder(param_1,param_2,param_3,param_4);
  return EVar1;
}



Enum __cdecl
Graphine::Nixel::ITileFileFactory::CSharp_ITileFileFactory_CreateTileSoupCollection
          (IPackedSoupFileCollection **param_1)

{
  Enum EVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180004ea0. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x4ea0  56  CSharp_ITileFileFactory_CreateTileSoupCollection
  EVar1 = CreateTileSoupCollection(param_1);
  return EVar1;
}



void CSharp_ITileFileFactory_CreateTileSoupFileReader(void **param_1,ITileSoupFileReader **param_2)

{
  void *pvVar1;
  undefined auStack_58 [32];
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x4eb0  57  CSharp_ITileFileFactory_CreateTileSoupFileReader
  local_18 = DAT_18000f0e0 ^ (ulonglong)auStack_58;
  if (param_1 == (void **)0x0) {
    (*DAT_18000f0c8)("null wstring",0);
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
  FUN_1800035e0((void **)&local_38,param_1,pvVar1);
  Graphine::Nixel::ITileFileFactory::CreateTileSoupFileReader
            ((basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t___
              *)&local_38,param_2);
  if (7 < local_20) {
    FUN_1800037a0(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
  return;
}



Enum __cdecl
Graphine::Nixel::ITileFileFactory::CSharp_ITileFileFactory_CreateTiledBuildParameters
          (TiledTopology *param_1,ITiledBuildParameters **param_2)

{
  Enum EVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180004f70. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x4f70  58  CSharp_ITileFileFactory_CreateTiledBuildParameters
  EVar1 = CreateTiledBuildParameters(param_1,param_2);
  return EVar1;
}



void CSharp_ITileFileFactory_CreateTiledRasterData
               (TiledTopology *param_1,RasterTileDimension *param_2,uint param_3,void **param_4,
               ITiledRasterData **param_5)

{
  void *pvVar1;
  undefined auStackY_88 [32];
  undefined8 local_58;
  undefined8 local_48;
  ulonglong local_40;
  ulonglong local_38;
  
                    // 0x4f80  59  CSharp_ITileFileFactory_CreateTiledRasterData
  local_38 = DAT_18000f0e0 ^ (ulonglong)auStackY_88;
  if (param_4 == (void **)0x0) {
    (*DAT_18000f0c8)("null wstring",0);
  }
  else {
    pvVar1 = (void *)0x0;
    local_40 = 7;
    local_48 = 0;
    local_58._0_2_ = 0;
    if (*(short *)param_4 != 0) {
      pvVar1 = (void *)0xffffffffffffffff;
      do {
        pvVar1 = (void *)((longlong)pvVar1 + 1);
      } while (*(short *)((longlong)param_4 + (longlong)pvVar1 * 2) != 0);
    }
    FUN_1800035e0((void **)&local_58,param_4,pvVar1);
    Graphine::Nixel::ITileFileFactory::CreateTiledRasterData
              (param_1,param_2,param_3,
               (basic_string_wchar_t_struct_std__char_traits_wchar_t__class_std__allocator_wchar_t___
                *)&local_58,param_5);
    if (7 < local_40) {
      FUN_1800037a0(&local_58,(void *)CONCAT62(local_58._2_6_,(undefined2)local_58),local_40 + 1);
    }
  }
  __security_check_cookie(local_38 ^ (ulonglong)auStackY_88);
  return;
}



void __cdecl
Graphine::Nixel::ITileFileFactory::CSharp_ITileFileFactory_GetLastError(ErrorInfo *param_1)

{
                    // WARNING: Could not recover jumptable at 0x000180005050. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x5050  60  CSharp_ITileFileFactory_GetLastError
  GetLastError(param_1);
  return;
}



void __cdecl
Graphine::Nixel::ITileFileFactory::CSharp_ITileFileFactory_GetLibraryVersion
          (LibraryVersionInfo *param_1)

{
                    // WARNING: Could not recover jumptable at 0x000180005060. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x5060  61  CSharp_ITileFileFactory_GetLibraryVersion
  GetLibraryVersion(param_1);
  return;
}



Enum __cdecl
Graphine::Nixel::ITileFileFactory::CSharp_ITileFileFactory_Initialize
          (NixelInitializationInfo *param_1)

{
  Enum EVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180005070. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x5070  62  CSharp_ITileFileFactory_Initialize
  EVar1 = Initialize(param_1);
  return EVar1;
}



Enum __cdecl Graphine::Nixel::ITileFileFactory::CSharp_ITileFileFactory_Release(void)

{
  Enum EVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180005080. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x5080  63  CSharp_ITileFileFactory_Release
  EVar1 = Release();
  return EVar1;
}



undefined CSharp_ITileOrder_Next__SWIG_0(longlong *param_1)

{
  undefined uVar1;
  
                    // 0x5090  65  CSharp_ITileOrder_Next__SWIG_0
  uVar1 = (**(code **)(*param_1 + 0x10))();
  return uVar1;
}



undefined CSharp_ITileOrder_Next__SWIG_1(longlong *param_1)

{
  undefined uVar1;
  
                    // 0x50b0  66  CSharp_ITileOrder_Next__SWIG_1
  uVar1 = (**(code **)(*param_1 + 8))();
  return uVar1;
}



void CSharp_ITileOrder_director_connect
               (undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
               undefined8 param_5)

{
  longlong lVar1;
  
                    // 0x50d0  68  CSharp_ITileOrder_director_connect
  lVar1 = __RTDynamicCast(param_1,0,&Graphine::Nixel::ITileOrder::RTTI_Type_Descriptor,
                          &SwigDirector_ITileOrder::RTTI_Type_Descriptor,0);
  if (lVar1 != 0) {
    *(undefined8 *)(lVar1 + 0x20) = param_5;
    *(undefined8 *)(lVar1 + 8) = param_2;
    *(undefined8 *)(lVar1 + 0x10) = param_3;
    *(undefined8 *)(lVar1 + 0x18) = param_4;
  }
  return;
}



void CSharp_ITileSetRebuilder_Rebuild__SWIG_0(longlong *param_1)

{
                    // 0x5130  73  CSharp_ITileSetRebuilder_Rebuild__SWIG_0
                    // WARNING: Could not recover jumptable at 0x000180005133. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x10))();
  return;
}



void CSharp_ITileSetRebuilder_Rebuild__SWIG_1
               (longlong *param_1,undefined param_2,undefined param_3,undefined param_4,
               undefined8 param_5)

{
                    // 0x5140  74  CSharp_ITileSetRebuilder_Rebuild__SWIG_1
  (**(code **)(*param_1 + 0x10))();
  return;
}



void CSharp_ITileSetRebuilder_Rebuild__SWIG_2(longlong *param_1)

{
                    // 0x5170  75  CSharp_ITileSetRebuilder_Rebuild__SWIG_2
  (**(code **)(*param_1 + 0x10))();
  return;
}



void CSharp_ITileSoupBuilder_Begin(longlong *param_1)

{
                    // 0x5190  78  CSharp_ITileSoupBuilder_Begin
                    // WARNING: Could not recover jumptable at 0x000180005193. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 8))();
  return;
}



void CSharp_ITileSetRebuilder_ClearMetaDataOverride(longlong *param_1)

{
                    // 0x51a0  70  CSharp_ITileSetRebuilder_ClearMetaDataOverride
                    // 0x51a0  82  CSharp_ITileSoupBuilder_SetBuildCallback
                    // WARNING: Could not recover jumptable at 0x0001800051a3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x30))();
  return;
}



void CSharp_ITileSetRebuilder_SetMetaData(longlong *param_1)

{
                    // 0x51b0  77  CSharp_ITileSetRebuilder_SetMetaData
                    // 0x51b0  83  CSharp_ITileSoupBuilder_SetBuildProgressTracker
                    // 0x51b0  100  CSharp_ITiledBuildParameters_RemoveMetadata
                    // WARNING: Could not recover jumptable at 0x0001800051b3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x28))();
  return;
}



void CSharp_ITileSoupBuilder_SetCodecLogger(longlong *param_1)

{
                    // 0x51c0  84  CSharp_ITileSoupBuilder_SetCodecLogger
                    // WARNING: Could not recover jumptable at 0x0001800051c3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x38))();
  return;
}



void CSharp_IBuildCallback_OnTileStart(longlong *param_1)

{
                    // 0x51d0  7  CSharp_IBuildCallback_OnTileStart
                    // 0x51d0  18  CSharp_IBuildProgressTracker_ProcessedTile
                    // 0x51d0  80  CSharp_ITileSoupBuilder_EncodeTile
                    // 0x51d0  88  CSharp_ITileSoupFileReader_GetTileDimensions
                    // 0x51d0  94  CSharp_ITiledBuildParameters_GetMetadata
                    // 0x51d0  110  CSharp_ITiledRasterDataRead_GetTileDimensions
                    // WARNING: Could not recover jumptable at 0x0001800051d3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x10))();
  return;
}



void CSharp_ITiledBuildParameters_AddTileLayerCodingGroup
               (longlong *param_1,undefined4 param_2,undefined4 param_3,void **param_4,
               undefined8 param_5)

{
  void *pvVar1;
  undefined auStack_88 [32];
  undefined8 local_68;
  undefined8 local_58;
  undefined8 local_48;
  ulonglong local_40;
  ulonglong local_38;
  
                    // 0x51e0  90  CSharp_ITiledBuildParameters_AddTileLayerCodingGroup
  local_38 = DAT_18000f0e0 ^ (ulonglong)auStack_88;
  if (param_4 == (void **)0x0) {
    (*DAT_18000f0c8)("null wstring",0);
  }
  else {
    pvVar1 = (void *)0x0;
    local_40 = 7;
    local_48 = 0;
    local_58._0_2_ = 0;
    if (*(short *)param_4 != 0) {
      pvVar1 = (void *)0xffffffffffffffff;
      do {
        pvVar1 = (void *)((longlong)pvVar1 + 1);
      } while (*(short *)((longlong)param_4 + (longlong)pvVar1 * 2) != 0);
    }
    FUN_1800035e0((void **)&local_58,param_4,pvVar1);
    local_68 = param_5;
    (**(code **)(*param_1 + 0x40))(param_1,param_2,param_3,&local_58);
    if (7 < local_40) {
      FUN_1800037a0(&local_58,(void *)CONCAT62(local_58._2_6_,(undefined2)local_58),local_40 + 1);
    }
  }
  __security_check_cookie(local_38 ^ (ulonglong)auStack_88);
  return;
}



void CSharp_IGtsFileReader_SetOutputMode(longlong *param_1)

{
                    // 0x52b0  41  CSharp_IGtsFileReader_SetOutputMode
                    // 0x52b0  91  CSharp_ITiledBuildParameters_ClearAllTileLayerCodingGroups
                    // WARNING: Could not recover jumptable at 0x0001800052b3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x48))();
  return;
}



void CSharp_ITiledBuildParameters_ClearThumbnail(longlong *param_1,undefined4 *param_2)

{
  undefined4 local_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
                    // 0x52c0  92  CSharp_ITiledBuildParameters_ClearThumbnail
  local_18 = *param_2;
  uStack_14 = param_2[1];
  uStack_10 = param_2[2];
  uStack_c = param_2[3];
  (**(code **)(*param_1 + 0x38))(local_18,&local_18);
  return;
}



void CSharp_ITiledBuildParameters_EnableUniformCoding
               (longlong *param_1,undefined8 param_2,uint param_3)

{
                    // 0x52e0  93  CSharp_ITiledBuildParameters_EnableUniformCoding
                    // WARNING: Could not recover jumptable at 0x0001800052ea. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x78))(param_1,param_2,param_3 & 0xffffff00 | (uint)(param_3 != 0));
  return;
}



void CSharp_IGtsFileReader_GetMetaData(longlong *param_1)

{
                    // 0x52f0  32  CSharp_IGtsFileReader_GetMetaData
                    // 0x52f0  96  CSharp_ITiledBuildParameters_GetNumTileLayerCodingGroups
                    // WARNING: Could not recover jumptable at 0x0001800052f3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x60))();
  return;
}



void CSharp_IGtsFileReader_GetNumThumbnails(longlong *param_1)

{
                    // 0x5300  35  CSharp_IGtsFileReader_GetNumThumbnails
                    // 0x5300  97  CSharp_ITiledBuildParameters_GetTileLayerCodingGroup
                    // WARNING: Could not recover jumptable at 0x000180005303. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x70))();
  return;
}



void CSharp_IGtsFileReader_GetFlatTileInfo(longlong *param_1)

{
                    // 0x5310  30  CSharp_IGtsFileReader_GetFlatTileInfo
                    // 0x5310  98  CSharp_ITiledBuildParameters_GetTileLayerCodingGroupIndex
                    // WARNING: Could not recover jumptable at 0x000180005313. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x58))();
  return;
}



undefined CSharp_ITiledBuildParameters_IsUniformCodingEnabled(longlong *param_1)

{
  undefined uVar1;
  
                    // 0x5320  99  CSharp_ITiledBuildParameters_IsUniformCodingEnabled
  uVar1 = (**(code **)(*param_1 + 0x80))();
  return uVar1;
}



void CSharp_ITiledBuildParameters_SetThumbnail
               (longlong *param_1,undefined4 *param_2,undefined8 param_3,undefined8 param_4,
               undefined4 param_5,undefined4 param_6,undefined8 param_7,undefined4 param_8)

{
  undefined4 local_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
                    // 0x5340  104  CSharp_ITiledBuildParameters_SetThumbnail
  local_18 = *param_2;
  uStack_14 = param_2[1];
  uStack_10 = param_2[2];
  uStack_c = param_2[3];
  (**(code **)(*param_1 + 0x30))(local_18,&local_18,param_3,param_4,param_5,param_6,param_7,param_8)
  ;
  return;
}



void CSharp_ITiledRasterDataRead_GetLine(longlong *param_1)

{
                    // 0x5390  106  CSharp_ITiledRasterDataRead_GetLine
                    // WARNING: Could not recover jumptable at 0x000180005393. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x28))();
  return;
}



void CSharp_ITiledRasterDataRead_GetPixel(longlong *param_1)

{
                    // 0x53a0  107  CSharp_ITiledRasterDataRead_GetPixel
                    // WARNING: Could not recover jumptable at 0x0001800053a3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x20))();
  return;
}



void CSharp_ITiledRasterDataRead_GetRectangle(longlong *param_1)

{
                    // 0x53b0  109  CSharp_ITiledRasterDataRead_GetRectangle
                    // WARNING: Could not recover jumptable at 0x0001800053b3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x30))();
  return;
}



void CSharp_ITiledRasterDataRead_MapTileLayerRead(longlong *param_1,undefined8 param_2,uint param_3)

{
                    // 0x53c0  111  CSharp_ITiledRasterDataRead_MapTileLayerRead
                    // WARNING: Could not recover jumptable at 0x0001800053ca. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x38))(param_1,param_2,param_3 & 0xffffff00 | (uint)(param_3 != 0));
  return;
}



void CSharp_ITiledRasterDataRead_UnMapTileLayerRead(longlong *param_1)

{
                    // 0x53d0  113  CSharp_ITiledRasterDataRead_UnMapTileLayerRead
                    // WARNING: Could not recover jumptable at 0x0001800053d3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x40))();
  return;
}



void CSharp_ITiledRasterData_AllocateTile(longlong *param_1)

{
                    // 0x53e0  114  CSharp_ITiledRasterData_AllocateTile
                    // WARNING: Could not recover jumptable at 0x0001800053e3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0xc0))();
  return;
}



void CSharp_ITiledRasterData_AllocateTileLayer(longlong *param_1)

{
                    // 0x53f0  115  CSharp_ITiledRasterData_AllocateTileLayer
                    // WARNING: Could not recover jumptable at 0x0001800053f3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0xa8))();
  return;
}



void CSharp_ITiledRasterData_AutoGenerateBorderInfo(longlong *param_1)

{
                    // 0x5400  116  CSharp_ITiledRasterData_AutoGenerateBorderInfo
                    // WARNING: Could not recover jumptable at 0x000180005403. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0xd8))();
  return;
}



void CSharp_ITiledRasterData_AutoGenerateLevels(longlong *param_1)

{
                    // 0x5410  117  CSharp_ITiledRasterData_AutoGenerateLevels
                    // WARNING: Could not recover jumptable at 0x000180005413. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0xa0))();
  return;
}



void CSharp_ITiledRasterData_AutoGenerateTileLayer(longlong *param_1)

{
                    // 0x5420  118  CSharp_ITiledRasterData_AutoGenerateTileLayer
                    // WARNING: Could not recover jumptable at 0x000180005423. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0xd0))();
  return;
}



void CSharp_ITiledRasterData_ClearAssetRectangles(longlong *param_1)

{
                    // 0x5430  119  CSharp_ITiledRasterData_ClearAssetRectangles
                    // WARNING: Could not recover jumptable at 0x000180005433. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x108))();
  return;
}



void CSharp_ITiledRasterData_ClearCubemapBorderRegions(longlong *param_1)

{
                    // 0x5440  120  CSharp_ITiledRasterData_ClearCubemapBorderRegions
                    // WARNING: Could not recover jumptable at 0x000180005443. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0xe8))();
  return;
}



void CSharp_ITiledRasterData_ClearLine(longlong *param_1)

{
                    // 0x5450  121  CSharp_ITiledRasterData_ClearLine
                    // WARNING: Could not recover jumptable at 0x000180005453. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x58))();
  return;
}



void CSharp_ITiledRasterData_ClearRectangle(longlong *param_1)

{
                    // 0x5460  122  CSharp_ITiledRasterData_ClearRectangle
                    // WARNING: Could not recover jumptable at 0x000180005463. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x60))();
  return;
}



void CSharp_ITiledRasterData_ClearTileLayer(longlong *param_1)

{
                    // 0x5470  123  CSharp_ITiledRasterData_ClearTileLayer
                    // WARNING: Could not recover jumptable at 0x000180005473. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0xb8))();
  return;
}



void CSharp_ITiledRasterData_ClearUserSetRectangles(longlong *param_1)

{
                    // 0x5480  124  CSharp_ITiledRasterData_ClearUserSetRectangles
                    // WARNING: Could not recover jumptable at 0x000180005483. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0xf8))();
  return;
}



undefined8
CSharp_ITiledRasterData_GetThumbnailData
          (longlong *param_1,undefined4 *param_2,undefined8 param_3,undefined8 param_4,
          undefined8 param_5,longlong param_6)

{
  undefined8 uVar1;
  undefined4 local_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
                    // 0x5490  125  CSharp_ITiledRasterData_GetThumbnailData
  if (param_6 == 0) {
    (*DAT_18000f0c8)("Graphine::Core::DataType::Enum & type is null",0);
    return 0;
  }
  local_18 = *param_2;
  uStack_14 = param_2[1];
  uStack_10 = param_2[2];
  uStack_c = param_2[3];
  uVar1 = (**(code **)(*param_1 + 0x130))(local_18,&local_18,param_3,param_4,param_5,param_6);
  return uVar1;
}



void CSharp_ITiledRasterData_GetThumbnailNumLevels(longlong *param_1,undefined4 *param_2)

{
  undefined4 local_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
                    // 0x54e0  126  CSharp_ITiledRasterData_GetThumbnailNumLevels
  local_18 = *param_2;
  uStack_14 = param_2[1];
  uStack_10 = param_2[2];
  uStack_c = param_2[3];
  (**(code **)(*param_1 + 0x128))(local_18,&local_18);
  return;
}



void CSharp_ITiledRasterData_GetTile(longlong *param_1)

{
                    // 0x5500  127  CSharp_ITiledRasterData_GetTile
                    // WARNING: Could not recover jumptable at 0x000180005503. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x80))();
  return;
}



void CSharp_ITiledRasterData_MakePersistent(longlong *param_1)

{
                    // 0x5510  128  CSharp_ITiledRasterData_MakePersistent
                    // WARNING: Could not recover jumptable at 0x000180005513. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x110))();
  return;
}



void CSharp_ITiledRasterData_MapTileLayerWrite(longlong *param_1,undefined8 param_2,uint param_3)

{
                    // 0x5520  129  CSharp_ITiledRasterData_MapTileLayerWrite
                    // WARNING: Could not recover jumptable at 0x00018000552a. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x88))(param_1,param_2,param_3 & 0xffffff00 | (uint)(param_3 != 0));
  return;
}



void CSharp_ITiledRasterData_RegisterAssetRectangle
               (longlong *param_1,undefined param_2,undefined param_3,undefined param_4,
               undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
                    // 0x5540  130  CSharp_ITiledRasterData_RegisterAssetRectangle
  (**(code **)(*param_1 + 0x100))();
  return;
}



void CSharp_ITiledRasterData_RegisterThumbnail
               (longlong *param_1,undefined4 *param_2,undefined8 param_3,undefined8 param_4,
               undefined4 param_5,undefined4 param_6,int param_7,undefined8 param_8)

{
  undefined4 local_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
                    // 0x5580  131  CSharp_ITiledRasterData_RegisterThumbnail
  local_18 = *param_2;
  uStack_14 = param_2[1];
  uStack_10 = param_2[2];
  uStack_c = param_2[3];
  (**(code **)(*param_1 + 0x120))
            (local_18,&local_18,param_3,param_4,param_5,param_6,param_7 != 0,param_8);
  return;
}



void CSharp_ITiledRasterData_RegisterUserSetRectangle(longlong *param_1)

{
                    // 0x55e0  132  CSharp_ITiledRasterData_RegisterUserSetRectangle
                    // WARNING: Could not recover jumptable at 0x0001800055e3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0xf0))();
  return;
}



void CSharp_ITiledRasterData_RemoveTile(longlong *param_1)

{
                    // 0x55f0  133  CSharp_ITiledRasterData_RemoveTile
                    // WARNING: Could not recover jumptable at 0x0001800055f3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 200))();
  return;
}



void CSharp_ITiledRasterData_RemoveTileLayer(longlong *param_1)

{
                    // 0x5600  134  CSharp_ITiledRasterData_RemoveTileLayer
                    // WARNING: Could not recover jumptable at 0x000180005603. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0xb0))();
  return;
}



void CSharp_ITiledRasterData_RemoveTileRectangle(longlong *param_1)

{
                    // 0x5610  135  CSharp_ITiledRasterData_RemoveTileRectangle
                    // WARNING: Could not recover jumptable at 0x000180005613. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x68))();
  return;
}



void CSharp_ITiledRasterData_SetBuildProgressTracker(longlong *param_1)

{
                    // 0x5620  137  CSharp_ITiledRasterData_SetBuildProgressTracker
                    // WARNING: Could not recover jumptable at 0x000180005623. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x118))();
  return;
}



void CSharp_ITiledRasterData_SetCubemapBorderRegion(longlong *param_1)

{
                    // 0x5630  138  CSharp_ITiledRasterData_SetCubemapBorderRegion
                    // WARNING: Could not recover jumptable at 0x000180005633. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0xe0))();
  return;
}



void CSharp_ITiledRasterData_SetLine__SWIG_0(longlong *param_1)

{
                    // 0x5640  139  CSharp_ITiledRasterData_SetLine__SWIG_0
                    // WARNING: Could not recover jumptable at 0x000180005643. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x50))();
  return;
}



void CSharp_ITiledRasterData_SetLine__SWIG_1
               (longlong *param_1,undefined param_2,undefined param_3,undefined param_4,
               undefined4 param_5,undefined4 param_6,undefined8 param_7)

{
                    // 0x5650  140  CSharp_ITiledRasterData_SetLine__SWIG_1
  (**(code **)(*param_1 + 0x50))();
  return;
}



void CSharp_ITiledRasterData_SetPixel(longlong *param_1)

{
                    // 0x5690  142  CSharp_ITiledRasterData_SetPixel
                    // WARNING: Could not recover jumptable at 0x000180005693. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x48))();
  return;
}



void CSharp_ITiledRasterData_SetRectangle__SWIG_0(longlong *param_1)

{
                    // 0x56a0  143  CSharp_ITiledRasterData_SetRectangle__SWIG_0
                    // WARNING: Could not recover jumptable at 0x0001800056a3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x70))();
  return;
}



void CSharp_ITiledRasterData_SetRectangle__SWIG_1
               (longlong *param_1,undefined param_2,undefined param_3,undefined param_4,
               undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined8 param_8)

{
                    // 0x56b0  144  CSharp_ITiledRasterData_SetRectangle__SWIG_1
  (**(code **)(*param_1 + 0x70))();
  return;
}



void CSharp_ITiledRasterData_SetTile(longlong *param_1)

{
                    // 0x5700  145  CSharp_ITiledRasterData_SetTile
                    // WARNING: Could not recover jumptable at 0x00018000570a. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x78))();
  return;
}



void CSharp_IGtsFileReader_GetGtsInfo(longlong *param_1)

{
                    // 0x5710  31  CSharp_IGtsFileReader_GetGtsInfo
                    // 0x5710  146  CSharp_ITiledRasterData_UnMapTileLayerWrite
                    // WARNING: Could not recover jumptable at 0x000180005713. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x90))();
  return;
}



void CSharp_StringVector_Add(ulonglong **param_1,void **param_2)

{
  void *pvVar1;
  undefined auStack_58 [32];
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x5720  148  CSharp_StringVector_Add
  local_18 = DAT_18000f0e0 ^ (ulonglong)auStack_58;
  if (param_2 == (void **)0x0) {
    (*DAT_18000f0c8)("null wstring");
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
  FUN_1800035e0((void **)&local_38,param_2,pvVar1);
  FUN_180003b30(param_1,(void **)&local_38);
  if (7 < local_20) {
    FUN_1800037a0(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_58);
  return;
}



void CSharp_StringVector_AddRange(ulonglong **param_1,undefined8 *param_2)

{
                    // 0x57e0  149  CSharp_StringVector_AddRange
  if (param_2 == (undefined8 *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0001800057f4. Too many branches
                    // WARNING: Treating indirect jump as call
    (*DAT_18000f0c8)("std::vector< std::wstring > const & type is null");
    return;
  }
  FUN_180001200(param_1,param_1[1],(void **)*param_2,(void **)param_2[1]);
  return;
}



void CSharp_StringVector_Clear(ulonglong **param_1)

{
                    // 0x5820  150  CSharp_StringVector_Clear
  FUN_180001120(*param_1,param_1[1]);
  param_1[1] = *param_1;
  return;
}



void CSharp_StringVector_GetRange
               (longlong *param_1,int param_2,undefined8 param_3,undefined8 param_4)

{
                    // 0x5850  151  CSharp_StringVector_GetRange
  FUN_180003c30(param_1,param_2,param_3,param_4);
  return;
}



void CSharp_StringVector_Insert(ulonglong **param_1,int param_2,void **param_3)

{
  void *pvVar1;
  undefined auStack_68 [32];
  undefined8 local_48;
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x5870  152  CSharp_StringVector_Insert
  local_48 = 0xfffffffffffffffe;
  local_18 = DAT_18000f0e0 ^ (ulonglong)auStack_68;
  if (param_3 == (void **)0x0) {
    (*DAT_18000f0c8)("null wstring",0);
  }
  else {
    local_20 = 7;
    pvVar1 = (void *)0x0;
    local_28 = 0;
    local_38._0_2_ = 0;
    if (*(short *)param_3 != 0) {
      pvVar1 = (void *)0xffffffffffffffff;
      do {
        pvVar1 = (void *)((longlong)pvVar1 + 1);
      } while (*(short *)((longlong)param_3 + (longlong)pvVar1 * 2) != 0);
    }
    FUN_1800035e0((void **)&local_38,param_3,pvVar1);
    FUN_180003dd0(param_1,param_2,(void **)&local_38);
    if (7 < local_20) {
      FUN_1800037a0(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
    }
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_68);
  return;
}



void CSharp_StringVector_InsertRange
               (ulonglong **param_1,int param_2,undefined8 *param_3,undefined8 param_4)

{
                    // 0x5940  153  CSharp_StringVector_InsertRange
  if (param_3 == (undefined8 *)0x0) {
    (*DAT_18000f0c8)("std::vector< std::wstring > const & type is null",0,0,param_4,
                     0xfffffffffffffffe);
  }
  else {
    FUN_180003e70(param_1,param_2,param_3);
  }
  return;
}



void CSharp_StringVector_RemoveAt(longlong *param_1,int param_2)

{
                    // 0x5970  154  CSharp_StringVector_RemoveAt
  FUN_180003f10(param_1,param_2);
  return;
}



void CSharp_StringVector_RemoveRange(ulonglong **param_1,int param_2,int param_3)

{
                    // 0x5990  155  CSharp_StringVector_RemoveRange
  FUN_180003fd0(param_1,param_2,param_3);
  return;
}



void CSharp_StringVector_Repeat(void **param_1,int param_2,undefined8 param_3,undefined8 param_4)

{
  void *pvVar1;
  undefined auStack_68 [32];
  undefined8 local_48;
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x59b0  156  CSharp_StringVector_Repeat
  local_48 = 0xfffffffffffffffe;
  local_18 = DAT_18000f0e0 ^ (ulonglong)auStack_68;
  if (param_1 == (void **)0x0) {
    (*DAT_18000f0c8)("null wstring",0);
  }
  else {
    local_20 = 7;
    pvVar1 = (void *)0x0;
    local_28 = 0;
    local_38._0_2_ = 0;
    if (*(short *)param_1 != 0) {
      pvVar1 = (void *)0xffffffffffffffff;
      do {
        pvVar1 = (void *)((longlong)pvVar1 + 1);
      } while (*(short *)((longlong)param_1 + (longlong)pvVar1 * 2) != 0);
    }
    FUN_1800035e0((void **)&local_38,param_1,pvVar1);
    FUN_180004130((void **)&local_38,param_2,pvVar1,param_4);
    if (7 < local_20) {
      FUN_1800037a0(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
    }
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_68);
  return;
}



void CSharp_StringVector_Reverse__SWIG_0(longlong *param_1)

{
                    // 0x5a90  157  CSharp_StringVector_Reverse__SWIG_0
  FUN_1800015b0(*param_1,param_1[1]);
  return;
}



void CSharp_StringVector_Reverse__SWIG_1(longlong *param_1,int param_2,int param_3)

{
                    // 0x5aa0  158  CSharp_StringVector_Reverse__SWIG_1
  FUN_1800041f0(param_1,param_2,param_3);
  return;
}



void CSharp_StringVector_SetRange
               (longlong *param_1,int param_2,longlong *param_3,undefined8 param_4)

{
                    // 0x5ac0  159  CSharp_StringVector_SetRange
  if (param_3 == (longlong *)0x0) {
    (*DAT_18000f0c8)("std::vector< std::wstring > const & type is null",0,0,param_4,
                     0xfffffffffffffffe);
  }
  else {
    FUN_180004340(param_1,param_2,param_3);
  }
  return;
}



longlong CSharp_StringVector_capacity(longlong *param_1)

{
                    // 0x5af0  160  CSharp_StringVector_capacity
  return param_1[2] - *param_1 >> 5;
}



void CSharp_StringVector_getitem(longlong *param_1,int param_2)

{
  undefined8 *puVar1;
  
                    // 0x5b00  161  CSharp_StringVector_getitem
  puVar1 = (undefined8 *)FUN_180004490(param_1,param_2);
  if (7 < (ulonglong)puVar1[3]) {
    puVar1 = (undefined8 *)*puVar1;
  }
  (*DAT_18000f4f8)(puVar1);
  return;
}



void CSharp_StringVector_getitemcopy(longlong *param_1,uint param_2)

{
  void **ppvVar1;
  undefined2 *puVar2;
  undefined auStack_88 [32];
  undefined8 local_68;
  undefined8 local_58;
  undefined8 local_48;
  ulonglong local_40;
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x5b30  162  CSharp_StringVector_getitemcopy
  local_68 = 0xfffffffffffffffe;
  local_18 = DAT_18000f0e0 ^ (ulonglong)auStack_88;
  local_40 = 7;
  local_48 = 0;
  local_58._0_2_ = 0;
  ppvVar1 = FUN_180004510((void **)&local_38,param_1,(ulonglong)param_2);
  if ((void **)&local_58 != ppvVar1) {
    if (7 < local_40) {
      FUN_1800037a0(&local_58,(void *)CONCAT62(local_58._2_6_,(undefined2)local_58),local_40 + 1);
    }
    local_40 = 7;
    local_48 = 0;
    local_58._0_2_ = 0;
    FUN_180002440(&local_58,ppvVar1);
  }
  if (7 < local_20) {
    FUN_1800037a0(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
  }
  local_20 = 7;
  local_28 = 0;
  local_38._0_2_ = 0;
  puVar2 = (undefined2 *)&local_58;
  if (7 < local_40) {
    puVar2 = (undefined2 *)CONCAT62(local_58._2_6_,(undefined2)local_58);
  }
  (*DAT_18000f4f8)(puVar2);
  if (7 < local_40) {
    FUN_1800037a0(&local_58,(void *)CONCAT62(local_58._2_6_,(undefined2)local_58),local_40 + 1);
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_88);
  return;
}



void CSharp_StringVector_reserve(longlong *param_1,uint param_2)

{
  ulonglong *puVar1;
  ulonglong *puVar2;
  undefined8 *puVar3;
  ulonglong uVar4;
  
                    // 0x5c70  163  CSharp_StringVector_reserve
  uVar4 = (ulonglong)param_2;
  if (uVar4 <= (ulonglong)(param_1[2] - *param_1 >> 5)) {
    return;
  }
  puVar3 = (undefined8 *)FUN_180002ed0(param_1,uVar4);
  FUN_180001860((undefined8 *)*param_1,(undefined8 *)param_1[1],puVar3);
  puVar1 = (ulonglong *)param_1[1];
  puVar2 = (ulonglong *)*param_1;
  if (puVar2 != (ulonglong *)0x0) {
    FUN_180001120(puVar2,puVar1);
    FUN_180003730(param_1,(void *)*param_1,param_1[2] - (longlong)(void *)*param_1 >> 5);
  }
  param_1[2] = (longlong)(puVar3 + uVar4 * 4);
  param_1[1] = ((longlong)puVar1 - (longlong)puVar2 & 0xffffffffffffffe0U) + (longlong)puVar3;
  *param_1 = (longlong)puVar3;
  return;
}



void CSharp_StringVector_setitem(longlong *param_1,int param_2,void **param_3)

{
  void *pvVar1;
  undefined auStack_68 [32];
  undefined8 local_48;
  undefined8 local_38;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
                    // 0x5c90  164  CSharp_StringVector_setitem
  local_48 = 0xfffffffffffffffe;
  local_18 = DAT_18000f0e0 ^ (ulonglong)auStack_68;
  if (param_3 == (void **)0x0) {
    (*DAT_18000f0c8)("null wstring",0);
  }
  else {
    local_20 = 7;
    pvVar1 = (void *)0x0;
    local_28 = 0;
    local_38._0_2_ = 0;
    if (*(short *)param_3 != 0) {
      pvVar1 = (void *)0xffffffffffffffff;
      do {
        pvVar1 = (void *)((longlong)pvVar1 + 1);
      } while (*(short *)((longlong)param_3 + (longlong)pvVar1 * 2) != 0);
    }
    FUN_1800035e0((void **)&local_38,param_3,pvVar1);
    FUN_1800045d0(param_1,param_2,(void **)&local_38);
    if (7 < local_20) {
      FUN_1800037a0(&local_38,(void *)CONCAT62(local_38._2_6_,(undefined2)local_38),local_20 + 1);
    }
  }
  __security_check_cookie(local_18 ^ (ulonglong)auStack_68);
  return;
}



longlong CSharp_StringVector_size(longlong *param_1)

{
                    // 0x5d60  165  CSharp_StringVector_size
  return param_1[1] - *param_1 >> 5;
}



Enum __cdecl
Graphine::Nixel::Tools::CSharp_Tools_ConvertData__SWIG_0
          (Enum param_1,void *param_2,uint param_3,Enum param_4,void *param_5,float param_6,
          float param_7)

{
  Enum EVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180005d70. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x5d70  166  CSharp_Tools_ConvertData__SWIG_0
  EVar1 = ConvertData(param_1,param_2,param_3,param_4,param_5,param_6,param_7);
  return EVar1;
}



void CSharp_Tools_ConvertData__SWIG_1
               (Enum param_1,void *param_2,uint param_3,Enum param_4,void *param_5,float param_6)

{
                    // 0x5d80  167  CSharp_Tools_ConvertData__SWIG_1
  Graphine::Nixel::Tools::ConvertData(param_1,param_2,param_3,param_4,param_5,param_6,1.0);
  return;
}



void CSharp_Tools_ConvertData__SWIG_2
               (Enum param_1,void *param_2,uint param_3,Enum param_4,void *param_5)

{
                    // 0x5dc0  168  CSharp_Tools_ConvertData__SWIG_2
  Graphine::Nixel::Tools::ConvertData(param_1,param_2,param_3,param_4,param_5,0.0,1.0);
  return;
}



void __cdecl
Graphine::Nixel::Tools::CSharp_Tools_GetDefaultColorForLayerType(Enum param_1,Color *param_2)

{
                    // WARNING: Could not recover jumptable at 0x000180005df0. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x5df0  169  CSharp_Tools_GetDefaultColorForLayerType
  GetDefaultColorForLayerType(param_1,param_2);
  return;
}



__uint64 __cdecl
Graphine::Nixel::Tools::CSharp_Tools_GetRawTileByteSize
          (TiledTopology *param_1,RasterTileDimension *param_2)

{
  __uint64 _Var1;
  
                    // WARNING: Could not recover jumptable at 0x000180005e00. Too many branches
                    // WARNING: Treating indirect jump as call
                    // 0x5e00  170  CSharp_Tools_GetRawTileByteSize
  _Var1 = GetRawTileByteSize(param_1,param_2);
  return _Var1;
}



bool CSharp_Tools_IsConvertible(Enum param_1,Enum param_2)

{
  bool bVar1;
  
                    // 0x5e10  171  CSharp_Tools_IsConvertible
  bVar1 = Graphine::Nixel::Tools::IsConvertible(param_1,param_2);
  return bVar1;
}



bool CSharp_Tools_IsUniformData(uchar *param_1,uint param_2,uint param_3,uint param_4,uint param_5)

{
  bool bVar1;
  
                    // 0x5e30  172  CSharp_Tools_IsUniformData
  bVar1 = Graphine::Nixel::Tools::IsUniformData
                    (param_1,(ulonglong)param_2,(ulonglong)param_3,(ulonglong)param_4,
                     (ulonglong)param_5);
  return bVar1;
}



bool CSharp_Tools_IsUniformTileData(uchar *param_1,RasterTileDimension *param_2,Enum param_3)

{
  bool bVar1;
  
                    // 0x5e60  173  CSharp_Tools_IsUniformTileData
  bVar1 = Graphine::Nixel::Tools::IsUniformTileData(param_1,param_2,param_3);
  return bVar1;
}



bool CSharp_Tools_SwizzleDataChannels(Enum param_1,uint param_2,Layout *param_3,void *param_4)

{
  bool bVar1;
  
                    // 0x5e80  174  CSharp_Tools_SwizzleDataChannels
  bVar1 = Graphine::Nixel::Tools::SwizzleDataChannels(param_1,param_2,param_3,param_4);
  return bVar1;
}



void CSharp_delete_IBuildCallback(longlong *param_1)

{
                    // 0x5ea0  175  CSharp_delete_IBuildCallback
                    // 0x5ea0  176  CSharp_delete_IBuildProgressTracker
  if (param_1 != (longlong *)0x0) {
                    // WARNING: Could not recover jumptable at 0x000180005ead. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*param_1 + 0x28))(param_1,1);
    return;
  }
  return;
}



void CSharp_delete_ICodecLogger(undefined8 *param_1)

{
                    // 0x5ec0  177  CSharp_delete_ICodecLogger
  if (param_1 != (undefined8 *)0x0) {
                    // WARNING: Could not recover jumptable at 0x000180005ecd. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)*param_1)(param_1,1);
    return;
  }
  return;
}



void CSharp_delete_ILayerIndexCollection(longlong *param_1)

{
                    // 0x5ef0  179  CSharp_delete_ILayerIndexCollection
                    // 0x5ef0  181  CSharp_delete_IPackedSoupFileCollection
                    // 0x5ef0  183  CSharp_delete_ITileOrder
                    // 0x5ef0  186  CSharp_delete_ITileSoupFileReader
  if (param_1 != (longlong *)0x0) {
                    // WARNING: Could not recover jumptable at 0x000180005efd. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*param_1 + 0x20))(param_1,1);
    return;
  }
  return;
}



void CSharp_delete_ITileSetRebuilder(longlong *param_1)

{
                    // 0x5f10  184  CSharp_delete_ITileSetRebuilder
  if (param_1 != (longlong *)0x0) {
                    // WARNING: Could not recover jumptable at 0x000180005f1d. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*param_1 + 0x38))(param_1,1);
    return;
  }
  return;
}



void CSharp_delete_ITileSoupBuilder(longlong *param_1)

{
                    // 0x5f30  185  CSharp_delete_ITileSoupBuilder
  if (param_1 != (longlong *)0x0) {
                    // WARNING: Could not recover jumptable at 0x000180005f3d. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*param_1 + 0x40))(param_1,1);
    return;
  }
  return;
}



void CSharp_delete_IGtsFileReader(longlong *param_1)

{
                    // 0x5f50  178  CSharp_delete_IGtsFileReader
                    // 0x5f50  180  CSharp_delete_IMipmapGenerator
                    // 0x5f50  187  CSharp_delete_ITiled
                    // 0x5f50  188  CSharp_delete_ITiledBuildParameters
                    // 0x5f50  189  CSharp_delete_ITiledRasterData
                    // 0x5f50  190  CSharp_delete_ITiledRasterDataRead
  if (param_1 != (longlong *)0x0) {
                    // WARNING: Could not recover jumptable at 0x000180005f5d. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*param_1 + 8))(param_1,1);
    return;
  }
  return;
}



void CSharp_delete_StringVector(ulonglong **param_1)

{
                    // 0x5f70  191  CSharp_delete_StringVector
  if (param_1 != (ulonglong **)0x0) {
    if (*param_1 != (ulonglong *)0x0) {
      FUN_180001120(*param_1,param_1[1]);
      FUN_180003730(param_1,*param_1,(longlong)param_1[2] - (longlong)*param_1 >> 5);
      *param_1 = (ulonglong *)0x0;
      param_1[1] = (ulonglong *)0x0;
      param_1[2] = (ulonglong *)0x0;
    }
    free(param_1);
  }
  return;
}



undefined8 * CSharp_new_IBuildCallback(void)

{
  undefined8 *this;
  
                    // 0x5fd0  193  CSharp_new_IBuildCallback
  this = (undefined8 *)operator_new(0x30);
  if (this != (undefined8 *)0x0) {
    *this = 0;
    Graphine::Nixel::IBuildCallback::IBuildCallback((IBuildCallback *)this);
    *this = SwigDirector_IBuildCallback::vftable;
    this[1] = 0;
    this[2] = 0;
    this[3] = 0;
    this[4] = 0;
    this[5] = 0;
    return this;
  }
  return (undefined8 *)0x0;
}



undefined8 * CSharp_new_IBuildProgressTracker(void)

{
  undefined8 *this;
  
                    // 0x6030  194  CSharp_new_IBuildProgressTracker
  this = (undefined8 *)operator_new(0x30);
  if (this != (undefined8 *)0x0) {
    *this = 0;
    Graphine::Nixel::IBuildProgressTracker::IBuildProgressTracker((IBuildProgressTracker *)this);
    *this = SwigDirector_IBuildProgressTracker::vftable;
    this[1] = 0;
    this[2] = 0;
    this[3] = 0;
    this[4] = 0;
    this[5] = 0;
    return this;
  }
  return (undefined8 *)0x0;
}



undefined8 * CSharp_new_ICodecLogger(void)

{
  undefined8 *this;
  
                    // 0x6090  195  CSharp_new_ICodecLogger
  this = (undefined8 *)operator_new(0x20);
  if (this != (undefined8 *)0x0) {
    *this = 0;
    Graphine::Nixel::ICodecLogger::ICodecLogger((ICodecLogger *)this);
    *this = SwigDirector_ICodecLogger::vftable;
    this[1] = 0;
    this[2] = 0;
    this[3] = 0;
    return this;
  }
  return (undefined8 *)0x0;
}



undefined8 * CSharp_new_IMipmapGenerator(void)

{
  undefined8 *this;
  
                    // 0x60e0  196  CSharp_new_IMipmapGenerator
  this = (undefined8 *)operator_new(0x10);
  if (this != (undefined8 *)0x0) {
    *this = 0;
    Graphine::Nixel::IMipmapGenerator::IMipmapGenerator((IMipmapGenerator *)this);
    this[1] = 0;
    *this = SwigDirector_IMipmapGenerator::vftable;
    return this;
  }
  return (undefined8 *)0x0;
}



void CSharp_new_ITileFileFactory(void)

{
                    // 0x6130  197  CSharp_new_ITileFileFactory
                    // 0x6130  202  CSharp_new_Tools
  operator_new(1);
  return;
}



undefined8 * CSharp_new_ITileOrder(void)

{
  undefined8 *this;
  
                    // 0x6140  198  CSharp_new_ITileOrder
  this = (undefined8 *)operator_new(0x28);
  if (this != (undefined8 *)0x0) {
    *this = 0;
    Graphine::Nixel::ITileOrder::ITileOrder((ITileOrder *)this);
    *this = SwigDirector_ITileOrder::vftable;
    this[1] = 0;
    this[2] = 0;
    this[3] = 0;
    this[4] = 0;
    return this;
  }
  return (undefined8 *)0x0;
}



undefined8 * CSharp_new_StringVector__SWIG_0(void)

{
  undefined8 *puVar1;
  
                    // 0x61a0  199  CSharp_new_StringVector__SWIG_0
  puVar1 = (undefined8 *)operator_new(0x18);
  if (puVar1 != (undefined8 *)0x0) {
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = 0;
    return puVar1;
  }
  return (undefined8 *)0x0;
}



void ** CSharp_new_StringVector__SWIG_1(longlong *param_1)

{
  void **ppvVar1;
  
                    // 0x61d0  200  CSharp_new_StringVector__SWIG_1
  if (param_1 == (longlong *)0x0) {
    (*DAT_18000f0c8)("std::vector< std::wstring > const & type is null",0);
  }
  else {
    ppvVar1 = (void **)operator_new(0x18);
    if (ppvVar1 != (void **)0x0) {
      ppvVar1 = FUN_1800018e0(ppvVar1,param_1);
      return ppvVar1;
    }
  }
  return (void **)0x0;
}



void CSharp_new_StringVector__SWIG_2(int param_1)

{
                    // 0x6220  201  CSharp_new_StringVector__SWIG_2
  FUN_180003a50(param_1);
  return;
}



void SWIGRegisterExceptionArgumentCallbacks_NixelWrapperCPP
               (undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
                    // 0x6240  203  SWIGRegisterExceptionArgumentCallbacks_NixelWrapperCPP
  DAT_18000f0b8 = param_1;
  DAT_18000f0c8 = param_2;
  DAT_18000f0d8 = param_3;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void SWIGRegisterExceptionCallbacks_NixelWrapperCPP
               (undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
               undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
               undefined8 param_9,undefined8 param_10,undefined8 param_11)

{
                    // 0x6260  204  SWIGRegisterExceptionCallbacks_NixelWrapperCPP
  _DAT_18000f048 = param_5;
  _DAT_18000f058 = param_6;
  _DAT_18000f068 = param_7;
  _DAT_18000f078 = param_8;
  _DAT_18000f088 = param_9;
  _DAT_18000f098 = param_10;
  _DAT_18000f0a8 = param_11;
  _DAT_18000f008 = param_1;
  _DAT_18000f018 = param_2;
  _DAT_18000f028 = param_3;
  _DAT_18000f038 = param_4;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void SWIGRegisterStringCallback_NixelWrapperCPP(undefined8 param_1)

{
                    // 0x62e0  205  SWIGRegisterStringCallback_NixelWrapperCPP
  _DAT_18000f4f0 = param_1;
  return;
}



void SWIGRegisterWStringCallback_NixelWrapperCPP(undefined8 param_1)

{
                    // 0x62f0  206  SWIGRegisterWStringCallback_NixelWrapperCPP
  DAT_18000f4f8 = param_1;
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
        FUN_180006964();
      }
      else {
        FUN_180006944();
      }
    }
  }
  return pvVar2;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180007418. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180007418. Too many branches
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
  if ((_StackCookie == DAT_18000f0e0) && ((short)(_StackCookie >> 0x30) == 0)) {
    return;
  }
  __report_gsfailure(_StackCookie);
  return;
}



undefined8 * FUN_180006474(undefined8 *param_1,ulonglong param_2)

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
    if (DAT_18000f500 < 1) {
      uVar6 = 0;
    }
    else {
      DAT_18000f500 = DAT_18000f500 + -1;
      uVar8 = __scrt_acquire_startup_lock();
      if (_DAT_18000fa80 != 2) {
        uVar7 = 0;
        __scrt_fastfail(7);
      }
      __scrt_dllmain_uninitialize_c();
      _DAT_18000fa80 = 0;
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
      if (_DAT_18000fa80 != 0) {
        __scrt_fastfail(7);
      }
      _DAT_18000fa80 = 1;
      uVar8 = __scrt_dllmain_before_initialize_c();
      if ((char)uVar8 != '\0') {
        _RTC_Initialize();
        atexit(&LAB_180007190);
        FUN_180006fac();
        atexit(&LAB_180006fbc);
        __scrt_initialize_default_local_stdio_options();
        iVar5 = _initterm_e(&DAT_180008298,&DAT_1800082a0);
        if ((iVar5 == 0) && (uVar9 = __scrt_dllmain_after_initialize_c(), (char)uVar9 != '\0')) {
          _initterm(&DAT_180008288,&DAT_180008290);
          _DAT_18000fa80 = 2;
          bVar2 = false;
        }
      }
      __scrt_release_startup_lock((char)uVar7);
      if (!bVar2) {
        ppcVar10 = (code **)FUN_180006ff4();
        if ((*ppcVar10 != (code *)0x0) &&
           (uVar7 = __scrt_is_nonwritable_in_current_image((longlong)ppcVar10), (char)uVar7 != '\0')
           ) {
          pcVar1 = *ppcVar10;
          _guard_check_icall();
          (*pcVar1)(param_1,2,param_3);
        }
        DAT_18000f500 = DAT_18000f500 + 1;
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



int FUN_1800066a0(HINSTANCE__ *param_1,ulong param_2,void *param_3)

{
  int iVar1;
  undefined8 uVar2;
  
  if ((param_2 == 0) && (DAT_18000f500 < 1)) {
    iVar1 = 0;
  }
  else if ((1 < param_2 - 1) ||
          ((iVar1 = dllmain_raw(param_1,param_2,param_3), iVar1 != 0 &&
           (iVar1 = dllmain_crt_dispatch(param_1,param_2,param_3), iVar1 != 0)))) {
    uVar2 = FUN_180006f88(param_1,param_2);
    iVar1 = (int)uVar2;
    if ((param_2 == 1) && (iVar1 == 0)) {
      FUN_180006f88(param_1,0);
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



// WARNING: Removing unreachable block (ram,0x0001800067c5)
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
  FUN_1800066a0(param_1,param_2,param_3);
  return;
}



undefined8 * FUN_18000682c(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy(param_2 + 8);
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



undefined8 * FUN_18000686c(undefined8 *param_1)

{
  param_1[2] = 0;
  param_1[1] = "bad allocation";
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



undefined8 * FUN_18000688c(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy(param_2 + 8);
  *param_1 = std::bad_array_new_length::vftable;
  return param_1;
}



undefined8 * FUN_1800068cc(undefined8 *param_1)

{
  param_1[2] = 0;
  param_1[1] = "bad array new length";
  *param_1 = std::bad_array_new_length::vftable;
  return param_1;
}



undefined8 * FUN_180006900(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = std::exception::vftable;
  __std_exception_destroy(param_1 + 1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_180006944(void)

{
  undefined8 local_28 [5];
  
  FUN_18000686c(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_18000adc0);
}



void FUN_180006964(void)

{
  undefined8 local_28 [5];
  
  FUN_1800068cc(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_18000ae20);
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
                    // WARNING: Could not recover jumptable at 0x0001800069b1. Too many branches
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
  *(undefined8 *)(puVar3 + -8) = 0x1800069e2;
  capture_previous_context((PCONTEXT)&DAT_18000f5b0);
  _DAT_18000f520 = *(undefined8 *)(puVar3 + 0x38);
  _DAT_18000f648 = puVar3 + 0x40;
  _DAT_18000f630 = *(undefined8 *)(puVar3 + 0x40);
  _DAT_18000f510 = 0xc0000409;
  _DAT_18000f514 = 1;
  _DAT_18000f528 = 1;
  DAT_18000f530 = 2;
  *(undefined8 *)(puVar3 + 0x20) = DAT_18000f0e0;
  *(undefined8 *)(puVar3 + 0x28) = DAT_18000f0e8;
  *(undefined8 *)(puVar3 + -8) = 0x180006a84;
  DAT_18000f6a8 = _DAT_18000f520;
  __raise_securityfailure((_EXCEPTION_POINTERS *)&PTR_DAT_180008b38);
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
LAB_180006b2e:
    uVar3 = (ulonglong)pvVar2 & 0xffffffffffffff00;
  }
  else {
    do {
      LOCK();
      bVar1 = DAT_18000fa88 == 0;
      DAT_18000fa88 = DAT_18000fa88 ^ (ulonglong)bVar1 * (DAT_18000fa88 ^ (ulonglong)StackBase);
      pvVar2 = (void *)(!bVar1 * DAT_18000fa88);
      if (bVar1) goto LAB_180006b2e;
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
    uVar3 = CSharp_IBuildCallback_OnTileFailedSwigExplicitIBuildCallback();
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
  
  cVar1 = FUN_180007460();
  if (cVar1 != '\0') {
    cVar1 = FUN_180007460();
    if (cVar1 != '\0') {
      return 1;
    }
    FUN_180007460();
  }
  return 0;
}



// Library Function - Single Match
//  __scrt_dllmain_crt_thread_detach
// 
// Library: Visual Studio 2015 Release

undefined __scrt_dllmain_crt_thread_detach(void)

{
  FUN_180007460();
  FUN_180007460();
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
    _execute_onexit_table(&DAT_18000fa90);
    return;
  }
  uVar2 = CSharp_IBuildCallback_OnTileCompletedSwigExplicitIBuildCallback();
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
  FUN_180007460();
  FUN_180007460();
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
    DAT_18000fac0 = 1;
  }
  __isa_available_init();
  uVar1 = FUN_180007460();
  if ((char)uVar1 != '\0') {
    uVar1 = FUN_180007460();
    if ((char)uVar1 != '\0') {
      return uVar1 & 0xffffffffffffff00 | 1;
    }
    uVar1 = FUN_180007460();
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
      bVar2 = 0x40 - ((byte)DAT_18000f0e0 & 0x3f) & 0x3f;
      _DAT_18000faa0 = (0xffffffffffffffffU >> bVar2 | -1L << 0x40 - bVar2) ^ DAT_18000f0e0;
      local_28 = (undefined4)_DAT_18000faa0;
      uStack_24 = (undefined4)(_DAT_18000faa0 >> 0x20);
      _DAT_18000fa90 = local_28;
      uRam000000018000fa94 = uStack_24;
      uRam000000018000fa98 = local_28;
      uRam000000018000fa9c = uStack_24;
      _DAT_18000faa8 = local_28;
      uRam000000018000faac = uStack_24;
      uRam000000018000fab0 = local_28;
      uRam000000018000fab4 = uStack_24;
      _DAT_18000fab8 = _DAT_18000faa0;
    }
    else {
      uVar4 = _initialize_onexit_table(&DAT_18000fa90);
      if ((int)uVar4 == 0) {
        uVar4 = _initialize_onexit_table(&DAT_18000faa8);
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



// WARNING: Removing unreachable block (ram,0x000180006e16)
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
       param_1 - 0x180000000U < uVar1)) goto LAB_180006dff;
  }
  pIVar3 = (IMAGE_SECTION_HEADER *)0x0;
LAB_180006dff:
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
    DAT_18000fa88 = 0;
  }
  return;
}



// Library Function - Single Match
//  __scrt_uninitialize_crt
// 
// Library: Visual Studio 2015 Release

undefined __scrt_uninitialize_crt(undefined8 param_1,char param_2)

{
  if ((DAT_18000fac0 == '\0') || (param_2 == '\0')) {
    FUN_180007460();
    FUN_180007460();
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
  
  bVar2 = (byte)DAT_18000f0e0 & 0x3f;
  if (((DAT_18000f0e0 ^ _DAT_18000fa90) >> bVar2 | (DAT_18000f0e0 ^ _DAT_18000fa90) << 0x40 - bVar2)
      == 0xffffffffffffffff) {
    iVar1 = _crt_atexit();
  }
  else {
    iVar1 = _register_onexit_function(&DAT_18000fa90,_Func);
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
  if (DAT_18000f0e0 == 0x2b992ddfa232) {
    GetSystemTimeAsFileTime(&local_res10);
    local_res8 = local_res10;
    DVar1 = GetCurrentThreadId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    DVar1 = GetCurrentProcessId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    QueryPerformanceCounter((LARGE_INTEGER *)&local_res18);
    DAT_18000f0e0 =
         ((ulonglong)local_res18 << 0x20 ^ CONCAT44(uStackX_1c,local_res18) ^ (ulonglong)local_res8
         ^ (ulonglong)&local_res8) & 0xffffffffffff;
    if (DAT_18000f0e0 == 0x2b992ddfa232) {
      DAT_18000f0e0 = 0x2b992ddfa233;
    }
  }
  DAT_18000f0e8 = ~DAT_18000f0e0;
  return;
}



undefined8 FUN_180006f88(HMODULE param_1,int param_2)

{
  if (param_2 == 1) {
    DisableThreadLibraryCalls(param_1);
  }
  return 1;
}



void FUN_180006fac(void)

{
                    // WARNING: Could not recover jumptable at 0x000180006fb3. Too many branches
                    // WARNING: Treating indirect jump as call
  InitializeSListHead(&DAT_18000fad0);
  return;
}



undefined * FUN_180006fc8(void)

{
  return &DAT_18000fae0;
}



undefined * FUN_180006fd0(void)

{
  return &DAT_18000fae8;
}



// Library Function - Single Match
//  __scrt_initialize_default_local_stdio_options
// 
// Library: Visual Studio 2015 Release

void __scrt_initialize_default_local_stdio_options(void)

{
  ulonglong *puVar1;
  
  puVar1 = (ulonglong *)FUN_180006fc8();
  *puVar1 = *puVar1 | 4;
  puVar1 = (ulonglong *)FUN_180006fd0();
  *puVar1 = *puVar1 | 2;
  return;
}



undefined * FUN_180006ff4(void)

{
  return &DAT_18000faf8;
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
  _DAT_18000faf0 = 0;
  *(undefined8 *)(puVar4 + -8) = 0x18000703d;
  memset(local_4d8,0,0x4d0);
  *(undefined8 *)(puVar4 + -8) = 0x180007047;
  RtlCaptureContext(local_4d8);
  *(undefined8 *)(puVar4 + -8) = 0x180007061;
  FunctionEntry = RtlLookupFunctionEntry(local_3e0,&local_res10,(PUNWIND_HISTORY_TABLE)0x0);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0) {
    *(undefined8 *)(puVar4 + 0x38) = 0;
    *(undefined **)(puVar4 + 0x30) = local_res18;
    *(undefined **)(puVar4 + 0x28) = local_res20;
    *(undefined **)(puVar4 + 0x20) = local_4d8;
    *(undefined8 *)(puVar4 + -8) = 0x1800070a2;
    RtlVirtualUnwind(0,local_res10,local_3e0,FunctionEntry,*(PCONTEXT *)(puVar4 + 0x20),
                     *(PVOID **)(puVar4 + 0x28),*(PDWORD64 *)(puVar4 + 0x30),
                     *(PKNONVOLATILE_CONTEXT_POINTERS *)(puVar4 + 0x38));
  }
  local_440 = &stack0x00000008;
  *(undefined8 *)(puVar4 + -8) = 0x1800070d4;
  memset(puVar4 + 0x50,0,0x98);
  *(undefined8 *)(puVar4 + 0x60) = unaff_retaddr;
  *(undefined4 *)(puVar4 + 0x50) = 0x40000015;
  *(undefined4 *)(puVar4 + 0x54) = 1;
  *(undefined8 *)(puVar4 + -8) = 0x1800070f6;
  BVar2 = IsDebuggerPresent();
  *(undefined **)(puVar4 + 0x40) = puVar4 + 0x50;
  *(undefined **)(puVar4 + 0x48) = local_4d8;
  *(undefined8 *)(puVar4 + -8) = 0x180007117;
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  *(undefined8 *)(puVar4 + -8) = 0x180007122;
  LVar3 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)(puVar4 + 0x40));
  if (LVar3 == 0) {
    _DAT_18000faf0 = _DAT_18000faf0 & -(uint)(BVar2 == 1);
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
  
  for (ppcVar2 = (code **)&DAT_1800097c8; ppcVar2 < &DAT_1800097c8; ppcVar2 = ppcVar2 + 1) {
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



// WARNING: Removing unreachable block (ram,0x000180007301)
// WARNING: Removing unreachable block (ram,0x000180007266)
// WARNING: Removing unreachable block (ram,0x000180007208)
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
  DAT_18000f0fc = 2;
  piVar1 = (int *)cpuid_basic_info(0);
  _DAT_18000f0f8 = 1;
  puVar2 = (uint *)cpuid_Version_info(1);
  uVar4 = puVar2[3];
  uVar5 = DAT_18000faf4;
  if ((piVar1[2] ^ 0x49656e69U | piVar1[3] ^ 0x6c65746eU | piVar1[1] ^ 0x756e6547U) == 0) {
    _DAT_18000f100 = 0xffffffffffffffff;
    uVar6 = *puVar2 & 0xfff3ff0;
    if ((((uVar6 == 0x106c0) || (uVar6 == 0x20660)) || (uVar6 == 0x20670)) ||
       ((uVar5 = DAT_18000faf4 | 4, uVar6 - 0x30650 < 0x21 &&
        ((0x100010001U >> ((ulonglong)(uVar6 - 0x30650) & 0x3f) & 1) != 0)))) {
      uVar5 = DAT_18000faf4 | 5;
    }
  }
  DAT_18000faf4 = uVar5;
  if (((piVar1[1] ^ 0x68747541U | piVar1[2] ^ 0x69746e65U | piVar1[3] ^ 0x444d4163U) == 0) &&
     (0x600eff < (*puVar2 & 0xff00f00))) {
    DAT_18000faf4 = DAT_18000faf4 | 4;
  }
  if (6 < *piVar1) {
    lVar3 = cpuid_Extended_Feature_Enumeration_info(7);
    local_20 = *(uint *)(lVar3 + 4);
    if ((local_20 >> 9 & 1) != 0) {
      DAT_18000faf4 = DAT_18000faf4 | 2;
    }
  }
  if ((uVar4 >> 0x14 & 1) != 0) {
    _DAT_18000f0f8 = 2;
    DAT_18000f0fc = 6;
    if ((((uVar4 >> 0x1b & 1) != 0) && ((uVar4 >> 0x1c & 1) != 0)) && ((in_XCR0 & 6) == 6)) {
      DAT_18000f0fc = 0xe;
      _DAT_18000f0f8 = 3;
      if ((local_20 & 0x20) != 0) {
        _DAT_18000f0f8 = 5;
        DAT_18000f0fc = 0x2e;
      }
    }
  }
  return 0;
}



undefined8 CSharp_IBuildCallback_OnTileFailedSwigExplicitIBuildCallback(void)

{
                    // 0x73b0  6  CSharp_IBuildCallback_OnTileFailedSwigExplicitIBuildCallback
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __scrt_is_ucrt_dll_in_use
// 
// Library: Visual Studio 2015 Release

bool __scrt_is_ucrt_dll_in_use(void)

{
  return _DAT_18000f110 != 0;
}



void Unwind_1800073d0(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800073d0. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_terminate();
  return;
}



void __std_exception_copy(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800073d6. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_exception_copy();
  return;
}



void __std_exception_destroy(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800073dc. Too many branches
                    // WARNING: Treating indirect jump as call
  __std_exception_destroy();
  return;
}



void _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo)

{
                    // WARNING: Could not recover jumptable at 0x0001800073e2. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  _CxxThrowException(pExceptionObject,pThrowInfo);
  return;
}



void __CxxFrameHandler3(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800073e8. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler3();
  return;
}



void __RTDynamicCast(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800073ee. Too many branches
                    // WARNING: Treating indirect jump as call
  __RTDynamicCast();
  return;
}



void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001800073f4. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180007406. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



int __cdecl _callnewh(size_t _Size)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000740c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _callnewh(_Size);
  return iVar1;
}



void * __cdecl malloc(size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180007412. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = malloc(_Size);
  return pvVar1;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180007418. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000741e. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



void _initterm_e(void)

{
                    // WARNING: Could not recover jumptable at 0x000180007424. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm_e();
  return;
}



void _seh_filter_dll(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000742a. Too many branches
                    // WARNING: Treating indirect jump as call
  _seh_filter_dll();
  return;
}



void _configure_narrow_argv(void)

{
                    // WARNING: Could not recover jumptable at 0x000180007430. Too many branches
                    // WARNING: Treating indirect jump as call
  _configure_narrow_argv();
  return;
}



void _initialize_narrow_environment(void)

{
                    // WARNING: Could not recover jumptable at 0x000180007436. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_narrow_environment();
  return;
}



void _initialize_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000743c. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_onexit_table();
  return;
}



void _register_onexit_function(void)

{
                    // WARNING: Could not recover jumptable at 0x000180007442. Too many branches
                    // WARNING: Treating indirect jump as call
  _register_onexit_function();
  return;
}



void _execute_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x000180007448. Too many branches
                    // WARNING: Treating indirect jump as call
  _execute_onexit_table();
  return;
}



void _crt_atexit(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000744e. Too many branches
                    // WARNING: Treating indirect jump as call
  _crt_atexit();
  return;
}



void __cdecl _cexit(void)

{
                    // WARNING: Could not recover jumptable at 0x000180007454. Too many branches
                    // WARNING: Treating indirect jump as call
  _cexit();
  return;
}



BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000745a. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = IsProcessorFeaturePresent(ProcessorFeature);
  return BVar1;
}



undefined FUN_180007460(void)

{
  return 1;
}



// WARNING: This is an inlined function

void _guard_dispatch_icall(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
                    // WARNING: Could not recover jumptable at 0x000180007480. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void Catch_All_180007490(undefined8 param_1,longlong param_2)

{
  ulonglong **ppuVar1;
  
  ppuVar1 = *(ulonglong ***)(param_2 + 0x50);
  if (*ppuVar1 != (ulonglong *)0x0) {
    FUN_180001120(*ppuVar1,ppuVar1[1]);
    FUN_180003730(ppuVar1,*ppuVar1,(longlong)ppuVar1[2] - (longlong)*ppuVar1 >> 5);
    *ppuVar1 = (ulonglong *)0x0;
    ppuVar1[1] = (ulonglong *)0x0;
    ppuVar1[2] = (ulonglong *)0x0;
  }
                    // WARNING: Subroutine does not return
  _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
}



void Catch_All_180007500(undefined8 param_1,longlong param_2)

{
  FUN_180001120(*(ulonglong **)(param_2 + 0x38),*(ulonglong **)(param_2 + 0x30));
  FUN_180003730(*(undefined8 *)(param_2 + 0x80),*(void **)(param_2 + 0x38),
                *(ulonglong *)(param_2 + 0x40));
                    // WARNING: Subroutine does not return
  _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
}



void Unwind_180007550(void)

{
  _guard_check_icall();
  return;
}



void Catch_All_18000756c(undefined8 param_1,longlong param_2)

{
  FUN_180001120(*(ulonglong **)(param_2 + 0x58),*(ulonglong **)(param_2 + 0x50));
                    // WARNING: Subroutine does not return
  _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
}



void Unwind_1800075a0(void)

{
  _guard_check_icall();
  return;
}



void Catch_All_1800075bc(undefined8 param_1,longlong param_2)

{
  FUN_180001120(*(ulonglong **)(param_2 + 0x60),*(ulonglong **)(param_2 + 0x70));
                    // WARNING: Subroutine does not return
  _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
}



void Unwind_1800075f0(void)

{
  _guard_check_icall();
  return;
}



void Catch_All_18000760c(undefined8 param_1,longlong param_2)

{
  FUN_180001120(*(ulonglong **)(param_2 + 0x60),*(ulonglong **)(param_2 + 0x70));
                    // WARNING: Subroutine does not return
  _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
}



void Catch_All_180007640(undefined8 param_1,longlong param_2)

{
  FUN_180001120(*(ulonglong **)(param_2 + 0x50),*(ulonglong **)(param_2 + 0x60));
                    // WARNING: Subroutine does not return
  _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
}



void Catch_All_180007670(undefined8 param_1,longlong param_2)

{
  ulonglong **ppuVar1;
  
  ppuVar1 = *(ulonglong ***)(param_2 + 0x50);
  if (*ppuVar1 != (ulonglong *)0x0) {
    FUN_180001120(*ppuVar1,ppuVar1[1]);
    FUN_180003730(ppuVar1,*ppuVar1,(longlong)ppuVar1[2] - (longlong)*ppuVar1 >> 5);
    *ppuVar1 = (ulonglong *)0x0;
    ppuVar1[1] = (ulonglong *)0x0;
    ppuVar1[2] = (ulonglong *)0x0;
  }
                    // WARNING: Subroutine does not return
  _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
}



void Unwind_1800076e0(undefined8 param_1,longlong param_2)

{
  FUN_180001ce0((ulonglong **)(param_2 + 0x28));
  return;
}



void Unwind_1800076ec(undefined8 param_1,longlong param_2)

{
  FUN_180001ce0((ulonglong **)(param_2 + 0x48));
  return;
}



void Catch_All_180007700(undefined8 param_1,longlong param_2)

{
  ulonglong **ppuVar1;
  
  ppuVar1 = *(ulonglong ***)(param_2 + 0x60);
  if (*ppuVar1 != (ulonglong *)0x0) {
    FUN_180001120(*ppuVar1,ppuVar1[1]);
    FUN_180003730(ppuVar1,*ppuVar1,(longlong)ppuVar1[2] - (longlong)*ppuVar1 >> 5);
    *ppuVar1 = (ulonglong *)0x0;
    ppuVar1[1] = (ulonglong *)0x0;
    ppuVar1[2] = (ulonglong *)0x0;
  }
                    // WARNING: Subroutine does not return
  _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
}



undefined * Catch_All_180007770(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  void *pvVar2;
  
  lVar1 = *(longlong *)(param_2 + 0x68);
  *(longlong *)(param_2 + 0x68) = lVar1;
  pvVar2 = FUN_180002e60(*(undefined8 *)(param_2 + 0x60),lVar1 + 1);
  *(void **)(param_2 + 0x78) = pvVar2;
  return &DAT_18000264b;
}



// WARNING: Removing unreachable block (ram,0x0001800077cb)

void Catch_All_1800077a3(undefined8 param_1,longlong param_2)

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



undefined * Catch_All_180007850(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  void *pvVar2;
  
  lVar1 = *(longlong *)(param_2 + 0x68);
  *(longlong *)(param_2 + 0x68) = lVar1;
  pvVar2 = FUN_180002f50(*(undefined8 *)(param_2 + 0x60),lVar1 + 1);
  *(void **)(param_2 + 0x78) = pvVar2;
  return &DAT_1800027b4;
}



void Catch_All_180007883(undefined8 param_1,longlong param_2)

{
  void **ppvVar1;
  
  ppvVar1 = *(void ***)(param_2 + 0x60);
  if ((void *)0x7 < ppvVar1[3]) {
    FUN_1800037a0(ppvVar1,*ppvVar1,(longlong)ppvVar1[3] + 1);
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



void Catch_All_1800078e0(undefined8 param_1,longlong param_2)

{
  int iVar1;
  longlong lVar2;
  ulonglong *puVar3;
  undefined8 uVar4;
  
  iVar1 = *(int *)(param_2 + 0x34);
  lVar2 = *(longlong *)(param_2 + 0x48);
  puVar3 = *(ulonglong **)(param_2 + 0x40);
  uVar4 = *(undefined8 *)(param_2 + 0x38);
  if (1 < iVar1) {
    FUN_180001120(puVar3,puVar3 + lVar2 * 4);
  }
  if (0 < iVar1) {
    FUN_180001120(puVar3 + lVar2 * 4,puVar3 + (*(longlong *)(param_2 + 0x50) + lVar2) * 4);
  }
  FUN_180003730(uVar4,puVar3,*(ulonglong *)(param_2 + 0x68));
                    // WARNING: Subroutine does not return
  _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
}



void Catch_All_18000796f(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  
  lVar1 = *(longlong *)(param_2 + 0x50) * 0x20;
  FUN_180001120((ulonglong *)(lVar1 + *(longlong *)(param_2 + 0xf0)),
                (ulonglong *)(*(longlong *)(*(longlong *)(param_2 + 0x38) + 8) + lVar1));
                    // WARNING: Subroutine does not return
  _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
}



void Catch_All_1800079c0(undefined8 param_1,longlong param_2)

{
  FUN_180003730(*(undefined8 *)(param_2 + 0x60),*(void **)(param_2 + 0x70),
                *(ulonglong *)(param_2 + 0x68));
                    // WARNING: Subroutine does not return
  _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
}



void Unwind_1800079f0(void)

{
  _guard_check_icall();
  return;
}



void Unwind_180007a0c(void)

{
  _guard_check_icall();
  return;
}



void Unwind_180007a30(undefined8 param_1,longlong param_2)

{
  free(*(void **)(param_2 + 0x88));
  return;
}



void Unwind_180007a50(undefined8 param_1,longlong param_2)

{
  free(*(void **)(param_2 + 0x70));
  return;
}



undefined * Catch_180007a70(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(**(longlong **)(param_2 + 0x28) + 8))();
  (*DAT_18000f0d8)(0,uVar1);
  return &DAT_180005865;
}



undefined * Catch_180007aa1(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(**(longlong **)(param_2 + 0x30) + 8))();
  (*DAT_18000f0b8)(uVar1,&PTR_1800087f8);
  return &DAT_180005865;
}



void Unwind_180007ae0(undefined8 param_1,longlong param_2)

{
  FUN_180001d70((void **)(param_2 + 0x30));
  return;
}



undefined8 Catch_180007aec(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(**(longlong **)(param_2 + 0x28) + 8))();
  (*DAT_18000f0d8)(0,uVar1);
  return 0x1800058fe;
}



undefined8 Catch_180007b20(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(**(longlong **)(param_2 + 0x28) + 8))();
  (*DAT_18000f0d8)(0,uVar1);
  return 0x180005969;
}



undefined8 Catch_180007b60(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(**(longlong **)(param_2 + 0x28) + 8))();
  (*DAT_18000f0d8)(0,uVar1);
  return 0x180005983;
}



undefined8 Catch_180007ba0(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(**(longlong **)(param_2 + 0x28) + 8))();
  (*DAT_18000f0d8)(0,uVar1);
  return 0x1800059a3;
}



undefined8 Catch_180007bd1(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(**(longlong **)(param_2 + 0x30) + 8))();
  (*DAT_18000f0b8)(uVar1,&PTR_1800087f8);
  return 0x1800059a3;
}



void Unwind_180007c10(undefined8 param_1,longlong param_2)

{
  FUN_180001d70((void **)(param_2 + 0x30));
  return;
}



undefined * Catch_180007c1c(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(**(longlong **)(param_2 + 0x28) + 8))();
  (*DAT_18000f0d8)(0,uVar1);
  return &DAT_180005a5a;
}



undefined8 Catch_180007c50(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(**(longlong **)(param_2 + 0x28) + 8))();
  (*DAT_18000f0d8)(0,uVar1);
  return 0x180005ab3;
}



undefined8 Catch_180007c81(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(**(longlong **)(param_2 + 0x30) + 8))();
  (*DAT_18000f0b8)(uVar1,&PTR_1800087f8);
  return 0x180005ab3;
}



undefined8 Catch_180007cc0(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(**(longlong **)(param_2 + 0x28) + 8))();
  (*DAT_18000f0d8)(0,uVar1);
  return 0x180005ae9;
}



undefined * Catch_180007d00(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(**(longlong **)(param_2 + 0x28) + 8))();
  (*DAT_18000f0d8)(0,uVar1);
  return &DAT_180005b28;
}



void Unwind_180007d40(undefined8 param_1,longlong param_2)

{
  FUN_180001d70((void **)(param_2 + 0x30));
  return;
}



undefined * Catch_180007d4c(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(**(longlong **)(param_2 + 0x28) + 8))();
  (*DAT_18000f0d8)(0,uVar1);
  return &DAT_180005c2f;
}



void Unwind_180007d80(undefined8 param_1,longlong param_2)

{
  FUN_180001d70((void **)(param_2 + 0x30));
  return;
}



undefined8 Catch_180007d8c(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(**(longlong **)(param_2 + 0x28) + 8))();
  (*DAT_18000f0d8)(0,uVar1);
  return 0x180005d1e;
}



undefined * Catch_180007dc0(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(**(longlong **)(param_2 + 0x28) + 8))();
  (*DAT_18000f0d8)(0,uVar1);
  return &DAT_180006235;
}



void FUN_180007df1(undefined8 param_1,longlong param_2)

{
  __scrt_release_startup_lock(*(char *)(param_2 + 0x40));
  return;
}



void FUN_180007e08(undefined8 param_1,longlong param_2)

{
  __scrt_dllmain_uninitialize_critical();
  __scrt_release_startup_lock(*(char *)(param_2 + 0x38));
  return;
}



void FUN_180007e24(undefined8 *param_1,longlong param_2)

{
  __scrt_dllmain_exception_filter
            (*(undefined8 *)(param_2 + 0x60),*(int *)(param_2 + 0x68),
             *(undefined8 *)(param_2 + 0x70),dllmain_crt_dispatch,*(undefined4 *)*param_1,param_1);
  return;
}


