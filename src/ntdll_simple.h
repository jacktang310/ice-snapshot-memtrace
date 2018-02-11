/* **********************************************************
 * Copyright (c) 2011-2017 Google, Inc.  All rights reserved.
 * Copyright (c) 2003-2010 VMware, Inc.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Copyright (c) 2003-2007 Determina Corp. */

/*
 * ntdll.h
 * Routines for calling Windows system calls via the ntdll.dll wrappers.
 * We return a bool instead of NTSTATUS, for most cases.
 *
 * New routines however should return the raw NTSTATUS and leave to
 * the callers to report or act on some specific failure.  Should use
 * NT_SUCCESS to verify success, luckily here 0 indicates success, so
 * misuse as a bool will be caught easily.
 */

#ifndef _NTDLL_H_
#define _NTDLL_H_ 1

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stddef.h> /* for offsetof */

#include "ntdll_types.h"

#pragma warning(disable : 4214) /* allow short-sized bitfields for TEB */


/* a register value: could be of any type; size is what matters. */
#ifdef X64
typedef uint64 reg_t;
#else
typedef uint reg_t;
#endif
/* integer whose size is based on pointers: ptr diff, mask, etc. */
typedef reg_t ptr_uint_t;
#ifdef X64
typedef int64 ptr_int_t;
#else
typedef int ptr_int_t;
#endif

typedef uint uint32 ;

/* Current method is to statically link with ntdll.lib obtained from the DDK */
/* We cannot call get_module_handle at arbitrary points.
 * Some syscalls are at certain points in win32 API internal state
 * such that doing so causes problems.
 */
/* We used to dynamically get the proc address but that led to some untimely
 *  loader lock acquisitions by kernel32.GetProcAddress  (Bug 411).
 *  This should serve as an example why using kernel32 functions is not safe.
*/

/* A simple wrapper to define ntdll entry points used inside our functions.
   Since there is no official header file exporting these,
   we encapsulate signatures obtained from other sources.
 */
#define GET_NTDLL(NtFunction, signature)                             \
  NTSYSAPI NTSTATUS NTAPI NtFunction signature

/***************************************************************************
 * Structs and defines.
 * Mostly from either Windows NT/2000 Native API Reference's ntdll.h
 * or from the ddk's header files.
 * These were generated from such headers to make
 * information necessary for userspace to call into the Windows
 * kernel available to DynamoRIO.  They include only constants,
 * structures, and macros generated from the original headers, and
 * thus, contain no copyrightable information.
 */

#define NT_CURRENT_PROCESS ( (HANDLE) PTR_UINT_MINUS_1 )
#define NT_CURRENT_THREAD  ( (HANDLE) (ptr_uint_t)-2 )

/* This macro is defined in wincon.h, but requires _WIN32_WINNT be XP+. _WIN32_WINNT is
 * defined in globals.h to _WIN32_WINNT_NT4, thus the need for this re-definition.
 */
#ifndef ATTACH_PARENT_PROCESS
#  define ATTACH_PARENT_PROCESS ((DWORD)-1)
#endif

#ifndef X64
typedef struct ALIGN_VAR(8) _UNICODE_STRING_64 {
    /* Length field is size in bytes not counting final 0 */
    USHORT Length;
    USHORT MaximumLength;
    int padding;
    union {
        struct {
            PWSTR  Buffer32;
            uint   Buffer32_hi;
        } b32;
        uint64 Buffer64;
    } u;
} UNICODE_STRING_64;
#endif

/* from DDK2003SP1/3790.1830/inc/ddk/wnet/ntddk.h */
#define DIRECTORY_QUERY                 (0x0001)
#define DIRECTORY_TRAVERSE              (0x0002)
#define DIRECTORY_CREATE_OBJECT         (0x0004)
#define DIRECTORY_CREATE_SUBDIRECTORY   (0x0008)
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)

/* module information filled by the loader */
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_BALANCED_NODE {
    union {
        struct _RTL_BALANCED_NODE *Children[2];
        struct {
            struct _RTL_BALANCED_NODE *Left;
            struct _RTL_BALANCED_NODE *Right;
        };
    };
    union {
        UCHAR Red : 1;
        UCHAR Balance : 2;
        ULONG_PTR ParentValue;
    };
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

/* The ParentValue field should have the bottom 2 bits masked off */
#define RTL_BALANCED_NODE_PARENT_VALUE(rbn) \
    ((PRTL_BALANCED_NODE)((rbn)->ParentValue & (~3)))

typedef struct _RTL_RB_TREE {
    PRTL_BALANCED_NODE Root;
    PRTL_BALANCED_NODE Min;
} RTL_RB_TREE, *PRTL_RB_TREE;

/* Used for Windows 8 ntdll!_LDR_DATA_TABLE_ENTRY.LoadReason */
typedef enum _LDR_DLL_LOAD_REASON {
   LoadReasonStaticDependency = 0,
   LoadReasonStaticForwarderDependency = 1,
   LoadReasonDynamicForwarderDependency = 2,
   LoadReasonDelayloadDependency = 3,
   LoadReasonDynamicLoad = 4,
   LoadReasonAsImageLoad = 5,
   LoadReasonAsDataLoad = 6,
   LoadReasonUnknown = -1,
} LDR_DLL_LOAD_REASON;

/* Note that these lists are walked through corresponding LIST_ENTRY pointers
 * i.e., for InInit*Order*, Flink points 16 bytes into the LDR_MODULE structure.
 * The MS symbols refer to this data struct as ntdll!_LDR_DATA_TABLE_ENTRY
 */
typedef struct _LDR_MODULE {                         /* offset: 32bit / 64bit */
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID BaseAddress;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;                                             /* 0x034 / 0x068 */
    SHORT LoadCount;                                         /* 0x038 / 0x06c */
    SHORT TlsIndex;                                          /* 0x03a / 0x06e */
    union {
        struct {
            HANDLE SectionHandle;                            /* 0x03c / 0x070 */
            ULONG CheckSum;                                  /* 0x040 / 0x078 */
        };
        LIST_ENTRY HashLinks;                                /* 0x03c / 0x070 */
    };
    ULONG TimeDateStamp;                                     /* 0x044 / 0x080 */
    PVOID/*ACTIVATION_CONTEXT*/ EntryPointActivationContext; /* 0x048 / 0x088 */
    PVOID PatchInformation;                                  /* 0x04c / 0x090 */
    /* ----------------------------------------------------------------------
     * Below here is Win8-only.  Win7 has some different, incompatible
     * fields.  We only need to access things below here on Win8.
     */
    PVOID DdagNode;                                          /* 0x050 / 0x098 */
    LIST_ENTRY NodeModuleLink;                               /* 0x054 / 0x0a0 */
    PVOID SnapContext;                                       /* 0x05c / 0x0b0 */
    PVOID ParentDllBase;                                     /* 0x060 / 0x0b8 */
    PVOID SwitchBackContext;                                 /* 0x064 / 0x0c0 */
    RTL_BALANCED_NODE BaseAddressIndexNode;                  /* 0x068 / 0x0c8 */
    RTL_BALANCED_NODE MappingInfoIndexNode;                  /* 0x074 / 0x0e0 */
    ULONG_PTR OriginalBase;                                  /* 0x080 / 0x0f8 */
    LARGE_INTEGER LoadTime;                                  /* 0x088 / 0x100 */
    ULONG BaseNameHashValue;                                 /* 0x090 / 0x108 */
    LDR_DLL_LOAD_REASON LoadReason;                          /* 0x094 / 0x10c */
} LDR_MODULE, *PLDR_MODULE;

/* This macro is defined so that 32-bit dlls can be handled in 64-bit DR.
 * Not all IMAGE_OPTIONAL_HEADER fields are affected, only ImageBase,
 * LoaderFlags, NumberOfRvaAndSizes, SizeOf{Stack,Heap}{Commit,Reserve},
 * and DataDirectory, of which we use only ImageBase and DataDirectory.
 * All other fields happen to have the same offsets and sizes in both
 * IMAGE_OPTIONAL_HEADER32 and IMAGE_OPTIONAL_HEADER64.
 */
#ifdef X64
/* Don't need to use module_is_32bit() here as that is heavyweight.  Also, as
 * it is used directly in process_image() just when the module processing
 * begins, we don't have to do all the checks here.
 */
# define OPT_HDR(nt_hdr_p, field) OPT_HDR_BASE(nt_hdr_p, field, )
# define OPT_HDR_P(nt_hdr_p, field) OPT_HDR_BASE(nt_hdr_p, field, (app_pc)&)
# define OPT_HDR_BASE(nt_hdr_p, field, amp) \
    ((nt_hdr_p)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ?      \
        amp(((IMAGE_OPTIONAL_HEADER32 *)&((nt_hdr_p)->OptionalHeader))->field) : \
        amp(((IMAGE_OPTIONAL_HEADER64 *)&((nt_hdr_p)->OptionalHeader))->field))
#else
# define OPT_HDR(nt_hdr_p, field) ((nt_hdr_p)->OptionalHeader.field)
# define OPT_HDR_P(nt_hdr_p, field) (&((nt_hdr_p)->OptionalHeader.field))
#endif

/* For use by routines that walk the module lists. */
enum {MAX_MODULE_LIST_INFINITE_LOOP_THRESHOLD = 2048};

/* Originally from winternl.h from wine (thus not official),
 * these defines are (some of the) regular LDR_MODULE.Flags values.
 * Windows 8 has these as named bitfields so we now have official
 * confirmation.
 */
#define LDR_PROCESS_STATIC_IMPORT       0x00000020
#define LDR_IMAGE_IS_DLL                0x00000004
#define LDR_LOAD_IN_PROGRESS            0x00001000
#define LDR_UNLOAD_IN_PROGRESS          0x00002000
#define LDR_NO_DLL_CALLS                0x00040000
#define LDR_PROCESS_ATTACHED            0x00080000
#define LDR_MODULE_REBASED              0x00200000

typedef struct _PEBLOCKROUTINE *PPEBLOCKROUTINE;
typedef struct _PEB_FREE_BLOCK *PPEB_FREE_BLOCK;
typedef PVOID *PPVOID;

typedef struct _RTL_BITMAP {
    ULONG  SizeOfBitMap; /* Number of bits in the bitmap */
    LPBYTE BitMapBuffer; /* Bitmap data, assumed sized to a DWORD boundary */
} RTL_BITMAP, *PRTL_BITMAP;
typedef const RTL_BITMAP *PCRTL_BITMAP;

/* The layout here is from ntdll pdb on x64 xpsp2, though we
 * changed some PVOID types to more specific types.
 * Later updated to win8 pdb info.
 */
typedef struct _PEB {                                     /* offset: 32bit / 64bit */
    BOOLEAN                      InheritedAddressSpace;           /* 0x000 / 0x000 */
    BOOLEAN                      ReadImageFileExecOptions;        /* 0x001 / 0x001 */
    BOOLEAN                      BeingDebugged;                   /* 0x002 / 0x002 */
#if 0
    /* x64 xpsp2 lists this as a bitfield but compiler only accepts int bitfields: */
    BOOLEAN                      ImageUsesLargePages:1;           /* 0x003 / 0x003 */
    BOOLEAN                      SpareBits:7;                     /* 0x003 / 0x003 */
#else
    BOOLEAN                      ImageUsesLargePages;             /* 0x003 / 0x003 */
#endif
    HANDLE                       Mutant;                          /* 0x004 / 0x008 */
    PVOID                        ImageBaseAddress;                /* 0x008 / 0x010 */
    PPEB_LDR_DATA                LoaderData;                      /* 0x00c / 0x018 */
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;               /* 0x010 / 0x020 */
    PVOID                        SubSystemData;                   /* 0x014 / 0x028 */
    PVOID                        ProcessHeap;                     /* 0x018 / 0x030 */
    PRTL_CRITICAL_SECTION        FastPebLock;                     /* 0x01c / 0x038 */
#if 0
    /* x64 xpsp2 lists these fields as: */
    PVOID                        AtlThunkSListPtr;                /* 0x020 / 0x040 */
    PVOID                        SparePtr2;                       /* 0x024 / 0x048 */
#else
    /* xpsp2 and earlier */
    PPEBLOCKROUTINE              FastPebLockRoutine;              /* 0x020 / 0x040 */
    PPEBLOCKROUTINE              FastPebUnlockRoutine;            /* 0x024 / 0x048 */
#endif
    DWORD                        EnvironmentUpdateCount;          /* 0x028 / 0x050 */
    PVOID                        KernelCallbackTable;             /* 0x02c / 0x058 */
#if 0
    /* x64 xpsp2 lists these fields as: */
    DWORD                        SystemReserved[1];               /* 0x030 / 0x060 */
    DWORD                        SpareUlong;                      /* 0x034 / 0x064 */
#else
    /* xpsp2 and earlier */
    DWORD                        EvengLogSection;                 /* 0x030 / 0x060 */
    DWORD                        EventLog;                        /* 0x034 / 0x064 */
#endif
    PPEB_FREE_BLOCK              FreeList;                        /* 0x038 / 0x068 */
    DWORD                        TlsExpansionCounter;             /* 0x03c / 0x070 */
    PRTL_BITMAP                  TlsBitmap;                       /* 0x040 / 0x078 */
    DWORD                        TlsBitmapBits[2];                /* 0x044 / 0x080 */
    PVOID                        ReadOnlySharedMemoryBase;        /* 0x04c / 0x088 */
    PVOID                        ReadOnlySharedMemoryHeap;        /* 0x050 / 0x090 */
    PPVOID                       ReadOnlyStaticServerData;        /* 0x054 / 0x098 */
    PVOID                        AnsiCodePageData;                /* 0x058 / 0x0a0 */
    PVOID                        OemCodePageData;                 /* 0x05c / 0x0a8 */
    PVOID                        UnicodeCaseTableData;            /* 0x060 / 0x0b0 */
    DWORD                        NumberOfProcessors;              /* 0x064 / 0x0b8 */
    DWORD                        NtGlobalFlag;                    /* 0x068 / 0x0bc */
    LARGE_INTEGER                CriticalSectionTimeout;          /* 0x070 / 0x0c0 */
    ptr_uint_t                   HeapSegmentReserve;              /* 0x078 / 0x0c8 */
    ptr_uint_t                   HeapSegmentCommit;               /* 0x07c / 0x0d0 */
    ptr_uint_t                   HeapDeCommitTotalFreeThreshold;  /* 0x080 / 0x0d8 */
    ptr_uint_t                   HeapDeCommitFreeBlockThreshold;  /* 0x084 / 0x0e0 */
    DWORD                        NumberOfHeaps;                   /* 0x088 / 0x0e8 */
    DWORD                        MaximumNumberOfHeaps;            /* 0x08c / 0x0ec */
    PPVOID                       ProcessHeaps;                    /* 0x090 / 0x0f0 */
    PVOID                        GdiSharedHandleTable;            /* 0x094 / 0x0f8 */
    PVOID                        ProcessStarterHelper;            /* 0x098 / 0x100 */
    DWORD                        GdiDCAttributeList;              /* 0x09c / 0x108 */
    PRTL_CRITICAL_SECTION        LoaderLock;                      /* 0x0a0 / 0x110 */
    DWORD                        OSMajorVersion;                  /* 0x0a4 / 0x118 */
    DWORD                        OSMinorVersion;                  /* 0x0a8 / 0x11c */
    WORD                         OSBuildNumber;                   /* 0x0ac / 0x120 */
    WORD                         OSCSDVersion;                    /* 0x0ae / 0x122 */
    DWORD                        OSPlatformId;                    /* 0x0b0 / 0x124 */
    DWORD                        ImageSubsystem;                  /* 0x0b4 / 0x128 */
    DWORD                        ImageSubsystemMajorVersion;      /* 0x0b8 / 0x12c */
    DWORD                        ImageSubsystemMinorVersion;      /* 0x0bc / 0x130 */
    ptr_uint_t                   ImageProcessAffinityMask;        /* 0x0c0 / 0x138 */
#ifdef X64
    DWORD                        GdiHandleBuffer[60];             /* 0x0c4 / 0x140 */
#else
    DWORD                        GdiHandleBuffer[34];             /* 0x0c4 / 0x140 */
#endif
    PVOID                        PostProcessInitRoutine;          /* 0x14c / 0x230 */
    PVOID                        TlsExpansionBitmap;              /* 0x150 / 0x238 */
    DWORD                        TlsExpansionBitmapBits[32];      /* 0x154 / 0x240 */
    DWORD                        SessionId;                       /* 0x1d4 / 0x2c0 */
    ULARGE_INTEGER               AppCompatFlags;                  /* 0x1d8 / 0x2c8 */
    ULARGE_INTEGER               AppCompatFlagsUser;              /* 0x1e0 / 0x2d0 */
    PVOID                        pShimData;                       /* 0x1e8 / 0x2d8 */
    PVOID                        AppCompatInfo;                   /* 0x1ec / 0x2e0 */
    UNICODE_STRING               CSDVersion;                      /* 0x1f0 / 0x2e8 */
    PVOID                        ActivationContextData;           /* 0x1f8 / 0x2f8 */
    PVOID                        ProcessAssemblyStorageMap;       /* 0x1fc / 0x300 */
    PVOID                        SystemDefaultActivationContextData;/* 0x200 / 0x308 */
    PVOID                        SystemAssemblyStorageMap;        /* 0x204 / 0x310 */
    ptr_uint_t                   MinimumStackCommit;              /* 0x208 / 0x318 */
    PPVOID                       FlsCallback;                     /* 0x20c / 0x320 */
    LIST_ENTRY                   FlsListHead;                     /* 0x210 / 0x328 */
    PRTL_BITMAP                  FlsBitmap;                       /* 0x218 / 0x338 */
    DWORD                        FlsBitmapBits[4];                /* 0x21c / 0x340 */
    DWORD                        FlsHighIndex;                    /* 0x22c / 0x350 */
    PVOID                        WerRegistrationData;             /* 0x230 / 0x358 */
    PVOID                        WerShipAssertPtr;                /* 0x234 / 0x360 */
    PVOID                        pUnused;                         /* 0x238 / 0x368 */
    PVOID                        pImageHeaderHash;                /* 0x23c / 0x370 */
    union {
        ULONG                    TracingFlags;                    /* 0x240 / 0x378 */
        struct {
            ULONG                HeapTracingEnabled:1;            /* 0x240 / 0x378 */
            ULONG                CritSecTracingEnabled:1;         /* 0x240 / 0x378 */
            ULONG                LibLoaderTracingEnabled:1;       /* 0x240 / 0x378 */
            ULONG                SpareTracingBits:29;             /* 0x240 / 0x378 */
        };
    };
    ULONG64                      CsrServerReadOnlySharedMemoryBase;/*0x248 / 0x380 */
    /* The Wow64SyscallFlags is not present in the symbols from MS but
     * ntdll!Wow64SystemServiceCall tests bit 0x2 to decide whether to go into
     * the WOW64 layer.
     */
    DWORD                        Unknown;                          /*0x250 / 0x388 */
    DWORD                        Wow64SyscallFlags;                /*0x254 / 0x38c */
} PEB, *PPEB;

#ifndef _W64
# define _W64
#endif
#ifndef X64
typedef _W64 long LONG_PTR, *PLONG_PTR;
typedef _W64 unsigned long ULONG_PTR, *PULONG_PTR;
typedef ULONG KAFFINITY;
#endif
typedef LONG KPRIORITY;

typedef struct _KERNEL_USER_TIMES {
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
} KERNEL_USER_TIMES;

/* Process Information Structures */

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION *PPROCESS_BASIC_INFORMATION;

typedef struct _DESCRIPTOR_TABLE_ENTRY {
    ULONG Selector;
    LDT_ENTRY Descriptor;
} DESCRIPTOR_TABLE_ENTRY, *PDESCRIPTOR_TABLE_ENTRY;

/* format of data returned by QueryInformationProcess ProcessVmCounters */
typedef struct _VM_COUNTERS {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} VM_COUNTERS;

/* format of data returned by QueryInformationProcess ProcessDeviceMap */
typedef struct _PROCESS_DEVICEMAP_INFORMATION {
    union {
        struct {
            HANDLE DirectoryHandle;
        } Set;
        struct {
            ULONG DriveMap;
            UCHAR DriveType[32];
        } Query;
    };
#ifdef X64
    ULONG Flags;
#endif
} PROCESS_DEVICEMAP_INFORMATION, *PPROCESS_DEVICEMAP_INFORMATION;

#if defined(NOT_DYNAMORIO_CORE)
# ifndef bool
typedef char bool;
# endif /* bool */
typedef unsigned __int64 uint64;
#endif /* NOT_DYNAMORIO_CORE */

/* Case 7395: mmcgui build fails with redefinition of
 * _JOBOBJECT_EXTENDED_LIMIT_INFORMATION and _IO_COUNTERS
 */
#if !defined(NOT_DYNAMORIO_CORE) && !defined(NOT_DYNAMORIO_CORE_PROPER)

/* For NtQueryInformationProcess using ProcessQuotaLimits or
 * ProcessPooledQuotaLimits or for NtSetInformationProcess using
 * ProcessQuotaLimits */
/* QUOTA_LIMITS defined in VC98/Include/WINNT.H - from WinNT+ */

/* note for NtSetInformationProcess when setting can set either
 * working set or the other values: only when both
 * MinimumWorkingSetSize and MaximumWorkingSetSize are non-zero
 * working set is adjusted, and the other values are ignored.
 * (Nebbett p.141)
 *
 * Job and working set note from MSDN "Processes can still empty their
 * working sets using the SetProcessWorkingSetSize function, even when
 * JOB_OBJECT_LIMIT_WORKINGSET is used.  However, you cannot use
 * SetProcessWorkingSetSize to change the minimum or maximum working
 * set size."
 */

/* PageFaultHistory Information
 * NtQueryInformationProcess ProcessWorkingSetWatch
 */
typedef struct _PROCESS_WS_WATCH_INFORMATION {
    PVOID FaultingPc;
    PVOID FaultingVa;
} PROCESS_WS_WATCH_INFORMATION, *PPROCESS_WS_WATCH_INFORMATION;

/* NtQueryInformationProcess ProcessPooledUsageAndLimits */
typedef struct _POOLED_USAGE_AND_LIMITS {
    SIZE_T PeakPagedPoolUsage;
    SIZE_T PagedPoolUsage;
    SIZE_T PagedPoolLimit;
    SIZE_T PeakNonPagedPoolUsage;
    SIZE_T NonPagedPoolUsage;
    SIZE_T NonPagedPoolLimit;
    SIZE_T PeakPagefileUsage;
    SIZE_T PagefileUsage;
    SIZE_T PagefileLimit;
} POOLED_USAGE_AND_LIMITS;
typedef POOLED_USAGE_AND_LIMITS *PPOOLED_USAGE_AND_LIMITS;

/* Process Security Context Information
 *  NtSetInformationProcess ProcessAccessToken
 *  PROCESS_SET_ACCESS_TOKEN access needed to use
 */
typedef struct _PROCESS_ACCESS_TOKEN {
    //
    // Handle to Primary token to assign to the process.
    // TOKEN_ASSIGN_PRIMARY access to this token is needed.
    //
    HANDLE Token;

    //
    // Handle to the initial thread of the process.
    // A process's access token can only be changed if the process has
    // no threads or one thread.  If the process has no threads, this
    // field must be set to NULL.  Otherwise, it must contain a handle
    // open to the process's only thread.  THREAD_QUERY_INFORMATION access
    // is needed via this handle.
    HANDLE Thread;
} PROCESS_ACCESS_TOKEN, *PPROCESS_ACCESS_TOKEN;

/* End of Process Information Structures */

/* Basic Job Limit flags, specified in JOBOBJECT_BASIC_LIMIT_INFORMATION */
#define JOB_OBJECT_LIMIT_WORKINGSET                 0x00000001
#define JOB_OBJECT_LIMIT_PROCESS_TIME               0x00000002
#define JOB_OBJECT_LIMIT_JOB_TIME                   0x00000004
#define JOB_OBJECT_LIMIT_ACTIVE_PROCESS             0x00000008
#define JOB_OBJECT_LIMIT_AFFINITY                   0x00000010
#define JOB_OBJECT_LIMIT_PRIORITY_CLASS             0x00000020
#define JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME          0x00000040
#define JOB_OBJECT_LIMIT_SCHEDULING_CLASS           0x00000080

/* Extended Job Limit flags, specified in JOBOBJECT_EXTENDED_LIMIT_INFORMATION */
#define JOB_OBJECT_LIMIT_PROCESS_MEMORY             0x00000100
#define JOB_OBJECT_LIMIT_JOB_MEMORY                 0x00000200
#define JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION 0x00000400
#define JOB_OBJECT_LIMIT_BREAKAWAY_OK               0x00000800
#define JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK        0x00001000
#define JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE          0x00002000

/* End of Job Limits */
#endif /* !NOT_DYNAMORIO_CORE && !NOT_DYNAMORIO_CORE_PROPER */

/* OS dependent SEH frame supported by ntdll.dll
   referred to in WINNT.H as _EXCEPTION_REGISTRATION_RECORD */
typedef struct _EXCEPTION_REGISTRATION {
     struct _EXCEPTION_REGISTRATION* prev;
     PVOID                   handler;
} EXCEPTION_REGISTRATION, *PEXCEPTION_REGISTRATION;

typedef struct _GDI_TEB_BATCH
{
    ULONG  Offset;
    HANDLE HDC;
    ULONG  Buffer[0x136];
} GDI_TEB_BATCH;

/* The layout here is from ntdll pdb on x64 xpsp2,
 * later updated to win8 pdb info.
 */
typedef struct _TEB {                               /* offset: 32bit / 64bit */
    /* We lay out NT_TIB, which is declared in winnt.h */
    PEXCEPTION_REGISTRATION   ExceptionList;                /* 0x000 / 0x000 */
    PVOID                     StackBase;                    /* 0x004 / 0x008 */
    PVOID                     StackLimit;                   /* 0x008 / 0x010 */
    PVOID                     SubSystemTib;                 /* 0x00c / 0x018 */
    union {
        PVOID                 FiberData;                    /* 0x010 / 0x020 */
        DWORD                 Version;                      /* 0x010 / 0x020 */
    };
    PVOID                     ArbitraryUserPointer;         /* 0x014 / 0x028 */
    struct _TEB*              Self;                         /* 0x018 / 0x030 */
    PVOID                     EnvironmentPointer;           /* 0x01c / 0x038 */
    CLIENT_ID                 ClientId;                     /* 0x020 / 0x040 */
    PVOID                     ActiveRpcHandle;              /* 0x028 / 0x050 */
    PVOID                     ThreadLocalStoragePointer;    /* 0x02c / 0x058 */
    PEB*                      ProcessEnvironmentBlock;      /* 0x030 / 0x060 */
    DWORD                     LastErrorValue;               /* 0x034 / 0x068 */
    DWORD                     CountOfOwnedCriticalSections; /* 0x038 / 0x06c */
    PVOID                     CsrClientThread;              /* 0x03c / 0x070 */
    PVOID                     Win32ThreadInfo;              /* 0x040 / 0x078 */
    DWORD                     User32Reserved[26];           /* 0x044 / 0x080 */
    DWORD                     UserReserved[5];              /* 0x0ac / 0x0e8 */
    PVOID                     WOW32Reserved;                /* 0x0c0 / 0x100 */
    DWORD                     CurrentLocale;                /* 0x0c4 / 0x108 */
    DWORD                     FpSoftwareStatusRegister;     /* 0x0c8 / 0x10c */
    PVOID /* kernel32 data */ SystemReserved1[54];          /* 0x0cc / 0x110 */
    LONG                      ExceptionCode;                /* 0x1a4 / 0x2c0 */
    PVOID                     ActivationContextStackPointer;/* 0x1a8 / 0x2c8 */
    /* Pre-Vista has no TxFsContext with its 4 bytes in SpareBytes1[] */
#ifdef X64
    byte                      SpareBytes1[24];              /* 0x1ac / 0x2d0 */
#else
    byte                      SpareBytes1[36];              /* 0x1ac / 0x2d0 */
#endif
    DWORD                     TxFsContext;                  /* 0x1d0 / 0x2e8 */
    GDI_TEB_BATCH             GdiTebBatch;                  /* 0x1d4 / 0x2f0 */
    CLIENT_ID                 RealClientId;                 /* 0x6b4 / 0x7d8 */
    PVOID                     GdiCachedProcessHandle;       /* 0x6bc / 0x7e8 */
    DWORD                     GdiClientPID;                 /* 0x6c0 / 0x7f0 */
    DWORD                     GdiClientTID;                 /* 0x6c4 / 0x7f4 */
    PVOID                     GdiThreadLocalInfo;           /* 0x6c8 / 0x7f8 */
    ptr_uint_t                Win32ClientInfo[62];          /* 0x6cc / 0x800 */
    PVOID                     glDispatchTable[233];         /* 0x7c4 / 0x9f0 */
    ptr_uint_t                glReserved1[29];              /* 0xb68 / 0x1138 */
    PVOID                     glReserved2;                  /* 0xbdc / 0x1220 */
    PVOID                     glSectionInfo;                /* 0xbe0 / 0x1228 */
    PVOID                     glSection;                    /* 0xbe4 / 0x1230 */
    PVOID                     glTable;                      /* 0xbe8 / 0x1238 */
    PVOID                     glCurrentRC;                  /* 0xbec / 0x1240 */
    PVOID                     glContext;                    /* 0xbf0 / 0x1248 */
    DWORD                     LastStatusValue;              /* 0xbf4 / 0x1250 */
    UNICODE_STRING            StaticUnicodeString;          /* 0xbf8 / 0x1258 */
    WORD                      StaticUnicodeBuffer[261];     /* 0xc00 / 0x1268 */
    PVOID                     DeallocationStack;            /* 0xe0c / 0x1478 */
    PVOID                     TlsSlots[64];                 /* 0xe10 / 0x1480 */
    LIST_ENTRY                TlsLinks;                     /* 0xf10 / 0x1680 */
    PVOID                     Vdm;                          /* 0xf18 / 0x1690 */
    PVOID                     ReservedForNtRpc;             /* 0xf1c / 0x1698 */
    PVOID                     DbgSsReserved[2];             /* 0xf20 / 0x16a0 */
    DWORD                     HardErrorMode;                /* 0xf28 / 0x16b0 */
    PVOID                     Instrumentation[14];          /* 0xf2c / 0x16b8 */
    PVOID                     SubProcessTag;                /* 0xf64 / 0x1728 */
    PVOID                     EtwTraceData;                 /* 0xf68 / 0x1730 */
    PVOID                     WinSockData;                  /* 0xf6c / 0x1738 */
    DWORD                     GdiBatchCount;                /* 0xf70 / 0x1740 */
    byte                      InDbgPrint;                   /* 0xf74 / 0x1744 */
    byte                      FreeStackOnTermination;       /* 0xf75 / 0x1745 */
    byte                      HasFiberData;                 /* 0xf76 / 0x1746 */
    byte                      IdealProcessor;               /* 0xf77 / 0x1747 */
    DWORD                     GuaranteedStackBytes;         /* 0xf78 / 0x1748 */
    PVOID                     ReservedForPerf;              /* 0xf7c / 0x1750 */
    PVOID                     ReservedForOle;               /* 0xf80 / 0x1758 */
    DWORD                     WaitingOnLoaderLock;          /* 0xf84 / 0x1760 */
    ptr_uint_t                SparePointer1;                /* 0xf88 / 0x1768 */
    ptr_uint_t                SoftPatchPtr1;                /* 0xf8c / 0x1770 */
    ptr_uint_t                SoftPatchPtr2;                /* 0xf90 / 0x1778 */
    PPVOID                    TlsExpansionSlots;            /* 0xf94 / 0x1780 */
#ifdef X64
    PVOID                     DeallocationBStore;           /* ----- / 0x1788 */
    PVOID                     BStoreLimit;                  /* ----- / 0x1790 */
#endif
    DWORD                     ImpersonationLocale;          /* 0xf98 / 0x1798 */
    DWORD                     IsImpersonating;              /* 0xf9c / 0x179c */
    PVOID                     NlsCache;                     /* 0xfa0 / 0x17a0 */
    PVOID                     pShimData;                    /* 0xfa4 / 0x17a8 */
    DWORD                     HeapVirtualAffinity;          /* 0xfa8 / 0x17b0 */
    PVOID                     CurrentTransactionHandle;     /* 0xfac / 0x17b8 */
    PVOID                     ActiveFrame;                  /* 0xfb0 / 0x17c0 */
    PPVOID                    FlsData;                      /* 0xfb4 / 0x17c8 */
#ifndef PRE_VISTA_TEB /* pre-vs-post-Vista: we'll have to make a union if we care */
    PVOID                     PreferredLanguages;           /* 0xfb8 / 0x17d0 */
    PVOID                     UserPrefLanguages;            /* 0xfbc / 0x17d8 */
    PVOID                     MergedPrefLanguages;          /* 0xfc0 / 0x17e0 */
    ULONG                     MuiImpersonation;             /* 0xfc4 / 0x17e8 */
    union {
        USHORT                CrossTebFlags;                /* 0xfc8 / 0x17ec */
        USHORT                SpareCrossTebFlags:16;        /* 0xfc8 / 0x17ec */
    };
    union
    {
        USHORT                SameTebFlags;                 /* 0xfca / 0x17ee */
        struct {
            USHORT            SafeThunkCall:1;              /* 0xfca / 0x17ee */
            USHORT            InDebugPrint:1;               /* 0xfca / 0x17ee */
            USHORT            HasFiberData2:1;              /* 0xfca / 0x17ee */
            USHORT            SkipThreadAttach:1;           /* 0xfca / 0x17ee */
            USHORT            WerInShipAssertCode:1;        /* 0xfca / 0x17ee */
            USHORT            RanProcessInit:1;             /* 0xfca / 0x17ee */
            USHORT            ClonedThread:1;               /* 0xfca / 0x17ee */
            USHORT            SuppressDebugMsg:1;           /* 0xfca / 0x17ee */
            USHORT            DisableUserStackWalk:1;       /* 0xfca / 0x17ee */
            USHORT            RtlExceptionAttached:1;       /* 0xfca / 0x17ee */
            USHORT            InitialThread:1;              /* 0xfca / 0x17ee */
            USHORT            SessionAware:1;               /* 0xfca / 0x17ee */
            USHORT            SpareSameTebBits:4;           /* 0xfca / 0x17ee */
        };
    };
    PVOID                     TxnScopeEntercallback;        /* 0xfcc / 0x17f0 */
    PVOID                     TxnScopeExitCAllback;         /* 0xfd0 / 0x17f8 */
    PVOID                     TxnScopeContext;              /* 0xfd4 / 0x1800 */
    ULONG                     LockCount;                    /* 0xfd8 / 0x1808 */
    ULONG                     SpareUlong0;                  /* 0xfdc / 0x180c */
    PVOID                     ResourceRetValue;             /* 0xfe0 / 0x1810 */
    PVOID                     ReservedForWdf;               /* 0xfe4 / 0x1818 */
    /* Added in Win10 */
    PVOID                     ReservedForCrt;               /* 0xfe8 / 0x1820 */
    PVOID /* GUID */          EffectiveContainerId;         /* 0xff0 / 0x1828 */
#else /* pre-Vista: */
    byte                      SafeThunkCall;                /* 0xfb8 / 0x17d0 */
    byte                      BooleanSpare[3];              /* 0xfb9 / 0x17d1 */
#endif
} TEB;

typedef struct _THREAD_BASIC_INFORMATION { // Information Class 0
    NTSTATUS ExitStatus;
    PNT_TIB TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _SYSTEM_BASIC_INFORMATION {
    ULONG   Unknown;
    ULONG   MaximumIncrement;
    ULONG   PhysicalPageSize;
    ULONG   NumberOfPhysicalPages;
    ULONG   LowestPhysicalPage;
    ULONG   HighestPhysicalPage;
    ULONG   AllocationGranularity;
    PVOID   LowestUserAddress;
    PVOID   HighestUserAddress;
    ULONG_PTR ActiveProcessors;
    UCHAR   NumberProcessors;
#ifdef X64
    ULONG   Unknown2; /* set to 0: probably just padding to 8-byte max field align */
#endif
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_INFORMATION {
    USHORT  ProcessorArchitecture;
    USHORT  ProcessorLevel;
    USHORT  ProcessorRevision;
    USHORT  Unknown;
    ULONG   FeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

typedef struct _SYSTEM_PERFORMANCE_INFORMATION {
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    ULONG   ReadOperationCount;
    ULONG   WriteOperationCount;
    ULONG   OtherOperationCount;
    ULONG   AvailablePages;
    ULONG   TotalCommittedPages;
    ULONG   TotalCommitLimit;
    ULONG   PeakCommitment;
    ULONG   PageFaults;
    ULONG   WriteCopyFaults;
    ULONG   TranstitionFaults;
    ULONG   Reserved1;
    ULONG   DemandZeroFaults;
    ULONG   PagesRead;
    ULONG   PageReadIos;
    ULONG   Reserved2[2];
    ULONG   PageFilePagesWritten;
    ULONG   PageFilePagesWriteIos;
    ULONG   MappedFilePagesWritten;
    ULONG   PagedPoolUsage;
    ULONG   NonPagedPoolUsage;
    ULONG   PagedPoolAllocs;
    ULONG   PagedPoolFrees;
    ULONG   NonPagedPoolAllocs;
    ULONG   NonPagedPoolFrees;
    ULONG   TotalFreeSystemPtes;
    ULONG   SystemCodePage;
    ULONG   TotalSystemDriverPages;
    ULONG   TotalSystemCodePages;
    ULONG   SmallNonPagedLookasideListAllocateHits;
    ULONG   SmallPagedLookasieListAllocateHits;
    ULONG   Reserved3;
    ULONG   MmSystemCachePage;
    ULONG   PagedPoolPage;
    ULONG   SystemDriverPage;
    ULONG   FastReadNoWait;
    ULONG   FastReadWait;
    ULONG   FastReadResourceMiss;
    ULONG   FastReadNotPossible;
    ULONG   FastMdlReadNoWait;
    ULONG   FastMdlReadWait;
    ULONG   FastMdlReadResourceMiss;
    ULONG   FastMdlReadNotPossible;
    ULONG   MapDataNoWait;
    ULONG   MapDataWait;
    ULONG   MapDataNoWaitMiss;
    ULONG   MapDataWaitMiss;
    ULONG   PinMappedDataCount;
    ULONG   PinReadNoWait;
    ULONG   PinReadWait;
    ULONG   PinReadNoWaitMiss;
    ULONG   PinReadWaitMiss;
    ULONG   CopyReadNoWait;
    ULONG   CopyReadWait;
    ULONG   CopyReadNoWaitMiss;
    ULONG   CopyReadWaitMiss;
    ULONG   MdlReadNoWait;
    ULONG   MdlReadWait;
    ULONG   MdlReadNoWaitMiss;
    ULONG   MdlReadWaitMiss;
    ULONG   ReadAheadIos;
    ULONG   LazyWriteIos;
    ULONG   LazyWritePages;
    ULONG   DataFlushes;
    ULONG   DataPages;
    ULONG   ContextSwitches;
    ULONG   FirstLevelTbFills;
    ULONG   SecondLevelTbFills;
    ULONG   SystemCalls;
    /* Fields added in Windows 7 */
    ULONG   Unknown[4];
} SYSTEM_PERFORMANCE_INFORMATION, *PSYSTEM_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_TIME_OF_DAY_INFORMATION {
    LARGE_INTEGER BootTime;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeZoneBias;
    ULONG   CurrentTimeZoneId;
} SYSTEM_TIME_OF_DAY_INFORMATION, *PSYSTEM_TIME_OF_DAY_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_TIMES {
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    ULONG   InterruptCount;
} SYSTEM_PROCESSOR_TIMES, *PSYSTEM_PROCESSOR_TIMES;

typedef struct _IO_COUNTERSEX {
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} IO_COUNTERSEX, *PIO_COUNTERSEX;

typedef enum _THREAD_STATE {
    StateInitialized,
    StateReady,
    StateRunning,
    StateStandby,
    StateTerminated,
    StateWait,
    StateTransition,
    StateUnknown
} THREAD_STATE;

typedef enum _KWAIT_REASON {
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrVirtualMemory,
    WrPageOut,
    WrRendevous,
    WrSpare2,
    WrSpare3,
    WrSpare4,
    WrSpare5,
    WrSpare6,
    WrKernel
} KWAIT_REASON;

typedef struct _SYSTEM_THREADS {
    /* XXX: are Create and Kernel swapped? */
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    ULONG   WaitTime;
    PVOID   StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
    ULONG   ContextSwitchCount;
    THREAD_STATE ThreadState;
    KWAIT_REASON WaitReason;
    ULONG Padding;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES {
    ULONG NextEntryDelta;
    ULONG ThreadCount;
    LARGE_INTEGER WorkingSetPrivateSize; /* Vista+ */
    ULONG HardFaultCount;                /* Win7+ */
    ULONG NumberOfThreadsHighWatermark;  /* Win7+ */
    ULONGLONG CycleTime;                 /* Win7+ */
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ProcessName;
    KPRIORITY BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryFrame;
    VM_COUNTERS VmCounters;
    SIZE_T PrivatePageCount;   /* Windows 2000+: end of VM_COUNTERS_EX */
    IO_COUNTERSEX IoCounters;  /* Windows 2000+ only */
    SYSTEM_THREADS Threads[1]; /* Variable size */
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;


typedef struct _SYSTEM_GLOBAL_FLAG {
    ULONG   GlobalFlag;
} SYSTEM_GLOBAL_FLAG, *PSYSTEM_GLOBAL_FLAG;

typedef struct _MEMORY_SECTION_NAME {
    UNICODE_STRING SectionFileName;
} MEMORY_SECTION_NAME, *PMEMORY_SECTION_NAME;

#define SYMBOLIC_LINK_QUERY (0x1)
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYMBOLIC_LINK_QUERY)

/* Speculated arg 10 to NtCreateUserProcess.
 * Note the similarities to CreateThreadEx arg 11 below.  Struct starts with size then
 * after that looks kind of like an array of 16 byte (32 on 64-bit) elements corresponding
 * to the IN and OUT informational ptrs.  Each array elment consists of a ?flags? then
 * the sizeof of the IN/OUT ptr buffer then the ptr itself then 0.
 */

typedef enum { /* NOTE - these are speculative */
    THREAD_INFO_ELEMENT_BUFFER_IS_INOUT = 0x00000, /* buffer is ??IN/OUT?? */
    THREAD_INFO_ELEMENT_BUFFER_IS_OUT   = 0x10000, /* buffer is IN (?) */
    THREAD_INFO_ELEMENT_BUFFER_IS_IN    = 0x20000, /* buffer is OUT (?) */
} thread_info_elm_buf_access_t;

typedef enum { /* NOTE - these are speculative */
    THREAD_INFO_ELEMENT_CLIENT_ID       = 0x3, /* buffer is CLIENT_ID - OUT */
    THREAD_INFO_ELEMENT_TEB             = 0x4, /* buffer is TEB * - OUT */
    THREAD_INFO_ELEMENT_NT_PATH_TO_EXE  = 0x5, /* buffer is wchar * path to exe
                                                * [ i.e. L"\??\c:\foo.exe" ] - IN */
    THREAD_INFO_ELEMENT_EXE_STUFF       = 0x6, /* buffer is exe_stuff_t (see above)
                                                * - INOUT */
    THREAD_INFO_ELEMENT_UNKNOWN_1       = 0x9, /* Unknown - ptr_uint_t sized
                                                * [ observed 1 ] - IN */
} thread_info_elm_buf_type_t;

typedef struct _thread_info_element_t { /* NOTE - this is speculative */
    ptr_uint_t flags;   /* thread_info_elm_buf_access_t | thread_info_elm_buf_type_t */
    size_t buffer_size; /* sizeof of buffer, in bytes */
    void *buffer;       /* flags determine disposition, could be IN or OUT or both */
    ptr_uint_t unknown;  /* [ observed always 0 ] */
} thread_info_elm_t;

typedef struct _exe_stuff_t { /* NOTE - this is speculative */
    OUT void *exe_entrypoint_addr; /* Entry point to the exe being started. */
    // ratio of uint32 to ptr_uint_t assumes no larger changes between 32 and 64-bit
    ptr_uint_t unknown1[3]; // possibly intermixed with uint32s below IN? OUT?
    uint32 unknown2[8];     // possible intermixed with ptr_uint_ts above IN? OUT?
} exe_stuff_t;

typedef struct _create_proc_thread_info_t { /* NOTE - this is speculative */
    size_t struct_size; /* observed 0x34 or 0x44 (0x68 on 64-bit) = sizeof(this struct) */
    /* Observed - first thread_info_elm_t always
     * flags = 0x20005
     * buffer_size = varies (sizeof buffer string in bytes)
     * buffer = wchar * : nt path to executable i.e. "\??\c:\foo.exe" - IN */
    thread_info_elm_t nt_path_to_exe;
    /* Observed - second thread_info_elm_t always
     * flags = 0x10003
     * buffer_size = sizeof(CLIENT_ID)
     * buffer = PCLIENT_ID : OUT */
    thread_info_elm_t client_id;
    /* Observed - third thread_info_elm_t always
     * flags = 0x6
     * buffer_size = 0x30 (or 0x40 on 64-bit) == sizeof(exe_stuff_t)
     * buffer = exe_stuff_t * : IN/OUT */
    thread_info_elm_t exe_stuff;
    /* While the first three thread_info_elm_t have been present in every call I've seen
     * (and attempts to remove or re-arrange them caused the system call to fail,
     * assuming I managed to do it right), there's more variation in the later fields
     * (sometimes present, sometimes not) - most commonly there'll be nothing or just the
     * TEB * info field (flags = 0x10003) which I've seen here a lot on 32bit. */
#if 0 /* 0 sized array is non-standard extension */
    thread_info_elm_t info[];
#endif
}  create_proc_thread_info_t;

/* Speculated arg 11 to NtCreateThreadEx.  See the similar arg 10 of
 * NtCreateUserProcess above. */
typedef struct _create_thread_info_t { /* NOTE - this is speculative */
    size_t struct_size; /* observed 0x24 (0x48 on 64-bit) == sizeof(this struct) */
    /* Note kernel32!CreateThread hardcodes all the values in this structure and
     * I've never seen any variation elsewhere. Trying to swap the order caused the
     * system call to fail when I tried it (assuming I did it right). */
    /* Observed - always
     * flags = 0x10003
     * buffer_size = sizeof(CLIENT_ID)
     * buffer = PCLIENT_ID : OUT */
    thread_info_elm_t client_id;
    /* Observed - always
     * flags = 0x10004
     * buffer_size = sizeof(CLIENT_ID)
     * buffer = TEB ** : OUT */
    thread_info_elm_t teb;
} create_thread_info_t;

/* PEB.ReadOnlyStaticServerData has an array of pointers sized to match the
 * kernel (so 64-bit for WOW64).  The second pointer points at this structure.
 * However, be careful b/c the UNICODE_STRING structs are really UNICODE_STRING_64
 * for WOW64.
 */
typedef struct _BASE_STATIC_SERVER_DATA
{
    UNICODE_STRING WindowsDirectory;
    UNICODE_STRING WindowsSystemDirectory;
    UNICODE_STRING NamedObjectDirectory;
    USHORT WindowsMajorVersion;
    USHORT WindowsMinorVersion;
    USHORT BuildNumber;
    /* rest we don't care about */
} BASE_STATIC_SERVER_DATA, *PBASE_STATIC_SERVER_DATA;

#ifndef X64
typedef struct _BASE_STATIC_SERVER_DATA_64
{
    UNICODE_STRING_64 WindowsDirectory;
    UNICODE_STRING_64 WindowsSystemDirectory;
    UNICODE_STRING_64 NamedObjectDirectory;
    USHORT WindowsMajorVersion;
    USHORT WindowsMinorVersion;
    USHORT BuildNumber;
    /* rest we don't care about */
} BASE_STATIC_SERVER_DATA_64, *PBASE_STATIC_SERVER_DATA_64;
#endif

/* NtQueryDirectoryFile information, from ntifs.h */
typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

/* from ntdef.h */
typedef enum _NT_PRODUCT_TYPE {
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer
} NT_PRODUCT_TYPE, *PNT_PRODUCT_TYPE;

/* from ntdkk.h */
typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
    StandardDesign,                 // None == 0 == standard design
    NEC98x86,                       // NEC PC98xx series on X86
    EndAlternatives                 // past end of known alternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

#define PROCESSOR_FEATURE_MAX 64

typedef struct _KUSER_SHARED_DATA {

    //
    // Current low 32-bit of tick count and tick count multiplier.
    //
    // N.B. The tick count is updated each time the clock ticks.
    //

    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;

    //
    // Current 64-bit interrupt time in 100ns units.
    //

    volatile KSYSTEM_TIME InterruptTime;

    //
    // Current 64-bit system time in 100ns units.
    //

    volatile KSYSTEM_TIME SystemTime;

    //
    // Current 64-bit time zone bias.
    //

    volatile KSYSTEM_TIME TimeZoneBias;

    //
    // Support image magic number range for the host system.
    //
    // N.B. This is an inclusive range.
    //

    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;

    //
    // Copy of system root in Unicode
    //

    WCHAR NtSystemRoot[ 260 ];

    //
    // Maximum stack trace depth if tracing enabled.
    //

    ULONG MaxStackTraceDepth;

    //
    // Crypto Exponent
    //

    ULONG CryptoExponent;

    //
    // TimeZoneId
    //

    ULONG TimeZoneId;

    ULONG LargePageMinimum;
    ULONG Reserved2[ 7 ];

    //
    // product type
    //

    NT_PRODUCT_TYPE NtProductType;
    BOOLEAN ProductTypeIsValid;

    //
    // NT Version. Note that each process sees a version from its PEB, but
    // if the process is running with an altered view of the system version,
    // the following two fields are used to correctly identify the version
    //

    ULONG NtMajorVersion;
    ULONG NtMinorVersion;

    //
    // Processor Feature Bits
    //

    BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];

    //
    // Reserved fields - do not use
    //
    ULONG Reserved1;
    ULONG Reserved3;

    //
    // Time slippage while in debugger
    //

    volatile ULONG TimeSlip;

    //
    // Alternative system architecture.  Example: NEC PC98xx on x86
    //

    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;

    //
    // If the system is an evaluation unit, the following field contains the
    // date and time that the evaluation unit expires. A value of 0 indicates
    // that there is no expiration. A non-zero value is the UTC absolute time
    // that the system expires.
    //

    LARGE_INTEGER SystemExpirationDate;

    //
    // Suite Support
    //

    ULONG SuiteMask;

    //
    // TRUE if a kernel debugger is connected/enabled
    //

    BOOLEAN KdDebuggerEnabled;


    //
    // Current console session Id. Always zero on non-TS systems
    //
    volatile ULONG ActiveConsoleId;

    //
    // Force-dismounts cause handles to become invalid. Rather than
    // always probe handles, we maintain a serial number of
    // dismounts that clients can use to see if they need to probe
    // handles.
    //

    volatile ULONG DismountCount;

    //
    // This field indicates the status of the 64-bit COM+ package on the system.
    // It indicates whether the Itermediate Language (IL) COM+ images need to
    // use the 64-bit COM+ runtime or the 32-bit COM+ runtime.
    //

    ULONG ComPlusPackage;

    //
    // Time in tick count for system-wide last user input across all
    // terminal sessions. For MP performance, it is not updated all
    // the time (e.g. once a minute per session). It is used for idle
    // detection.
    //

    ULONG LastSystemRITEventTickCount;

    //
    // Number of physical pages in the system.  This can dynamically
    // change as physical memory can be added or removed from a running
    // system.
    //

    ULONG NumberOfPhysicalPages;

    //
    // True if the system was booted in safe boot mode.
    //

    BOOLEAN SafeBootMode;

    //
    // The following field is used for Heap  and  CritSec Tracing
    // The last bit is set for Critical Sec Collision tracing and
    // second Last bit is for Heap Tracing
    // Also the first 16 bits are used as counter.
    //

    ULONG TraceLogging;

    //
    // Depending on the processor, the code for fast system call
    // will differ, the following buffer is filled with the appropriate
    // code sequence and user mode code will branch through it.
    //
    // (32 bytes, using ULONGLONG for alignment).
    //
    // N.B. The following two fields are only used on 32-bit systems.
    //

    ULONGLONG   Fill0;          // alignment
    ULONGLONG   SystemCall[4];

    //
    // The 64-bit tick count.
    //

    union {
        volatile KSYSTEM_TIME TickCount;
        volatile ULONG64 TickCountQuad;
    };

    /* XXX: Vista+ have added more fields */
} KUSER_SHARED_DATA;

/* We only rely on this up through Windows XP */
#define KUSER_SHARED_DATA_ADDRESS ((ULONG_PTR)0x7ffe0000)

/***************************************************************************
 * convenience enums
 */
typedef enum {MEMORY_RESERVE_ONLY = MEM_RESERVE,
              MEMORY_COMMIT = MEM_RESERVE|MEM_COMMIT
} memory_commit_status_t;



#define HEAP_CLASS_PRIVATE 0x00001000

#endif /* _NTDLL_H_ */
