﻿using System;
using System.Runtime.InteropServices;

namespace DotNet
{
    public class Structs
    {
        public class Win32
        {
            public class Enums
            {
                [Flags]
                public enum ACCESS_MASK : uint
                {
                    DELETE = 0x00010000,
                    READ_CONTROL = 0x00020000,
                    WRITE_DAC = 0x00040000,
                    WRITE_OWNER = 0x00080000,
                    SYNCHRONIZE = 0x00100000,
                    STANDARD_RIGHTS_REQUIRED = 0x000F0000,
                    STANDARD_RIGHTS_READ = 0x00020000,
                    STANDARD_RIGHTS_WRITE = 0x00020000,
                    STANDARD_RIGHTS_EXECUTE = 0x00020000,
                    STANDARD_RIGHTS_ALL = 0x001F0000,
                    SPECIFIC_RIGHTS_ALL = 0x0000FFFF,
                    ACCESS_SYSTEM_SECURITY = 0x01000000,
                    MAXIMUM_ALLOWED = 0x02000000,
                    GENERIC_READ = 0x80000000,
                    GENERIC_WRITE = 0x40000000,
                    GENERIC_EXECUTE = 0x20000000,
                    GENERIC_ALL = 0x10000000,
                    DESKTOP_READOBJECTS = 0x00000001,
                    DESKTOP_CREATEWINDOW = 0x00000002,
                    DESKTOP_CREATEMENU = 0x00000004,
                    DESKTOP_HOOKCONTROL = 0x00000008,
                    DESKTOP_JOURNALRECORD = 0x00000010,
                    DESKTOP_JOURNALPLAYBACK = 0x00000020,
                    DESKTOP_ENUMERATE = 0x00000040,
                    DESKTOP_WRITEOBJECTS = 0x00000080,
                    DESKTOP_SWITCHDESKTOP = 0x00000100,
                    WINSTA_ENUMDESKTOPS = 0x00000001,
                    WINSTA_READATTRIBUTES = 0x00000002,
                    WINSTA_ACCESSCLIPBOARD = 0x00000004,
                    WINSTA_CREATEDESKTOP = 0x00000008,
                    WINSTA_WRITEATTRIBUTES = 0x00000010,
                    WINSTA_ACCESSGLOBALATOMS = 0x00000020,
                    WINSTA_EXITWINDOWS = 0x00000040,
                    WINSTA_ENUMERATE = 0x00000100,
                    WINSTA_READSCREEN = 0x00000200,
                    WINSTA_ALL_ACCESS = 0x0000037F
                }
                [Flags]
                public enum FileShareFlags : UInt32
                {
                    FILE_SHARE_NONE = 0x0,
                    FILE_SHARE_READ = 0x1,
                    FILE_SHARE_WRITE = 0x2,
                    FILE_SHARE_DELETE = 0x4
                }
                [Flags]
                public enum FileMapProtection : uint
                {
                    PageReadonly = 0x02,
                    PageReadWrite = 0x04,
                    PageWriteCopy = 0x08,
                    PageExecuteRead = 0x20,
                    PageExecuteReadWrite = 0x40,
                    SectionCommit = 0x8000000,
                    SectionImage = 0x1000000,
                    SectionNoCache = 0x10000000,
                    SectionReserve = 0x4000000,
                }
                [Flags]
                public enum FileAccessFlags : UInt32
                {
                    DELETE = 0x10000,
                    FILE_READ_DATA = 0x1,
                    FILE_READ_ATTRIBUTES = 0x80,
                    FILE_READ_EA = 0x8,
                    READ_CONTROL = 0x20000,
                    FILE_WRITE_DATA = 0x2,
                    FILE_WRITE_ATTRIBUTES = 0x100,
                    FILE_WRITE_EA = 0x10,
                    FILE_APPEND_DATA = 0x4,
                    WRITE_DAC = 0x40000,
                    WRITE_OWNER = 0x80000,
                    SYNCHRONIZE = 0x100000,
                    FILE_EXECUTE = 0x20
                }
                [Flags]
                public enum FileOpenFlags : UInt32
                {
                    FILE_DIRECTORY_FILE = 0x1,
                    FILE_WRITE_THROUGH = 0x2,
                    FILE_SEQUENTIAL_ONLY = 0x4,
                    FILE_NO_INTERMEDIATE_BUFFERING = 0x8,
                    FILE_SYNCHRONOUS_IO_ALERT = 0x10,
                    FILE_SYNCHRONOUS_IO_NONALERT = 0x20,
                    FILE_NON_DIRECTORY_FILE = 0x40,
                    FILE_CREATE_TREE_CONNECTION = 0x80,
                    FILE_COMPLETE_IF_OPLOCKED = 0x100,
                    FILE_NO_EA_KNOWLEDGE = 0x200,
                    FILE_OPEN_FOR_RECOVERY = 0x400,
                    FILE_RANDOM_ACCESS = 0x800,
                    FILE_DELETE_ON_CLOSE = 0x1000,
                    FILE_OPEN_BY_FILE_ID = 0x2000,
                    FILE_OPEN_FOR_BACKUP_INTENT = 0x4000,
                    FILE_NO_COMPRESSION = 0x8000
                }
                [Flags]
                public enum DllCharacteristics : UInt32
                {
                    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x20,
                    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x40,
                    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x80,
                    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x100,
                    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x200,
                    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x400,
                    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x800,
                    IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000,
                    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
                    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000,
                    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000,
                }
                public enum MEMORYINFOCLASS : int
                {
                    MemoryBasicInformation = 0,
                    MemoryWorkingSetList,
                    MemorySectionName,
                    MemoryBasicVlmInformation
                }
                public const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
                public const uint SECTION_QUERY = 0x0001;
                public const uint SECTION_MAP_WRITE = 0x0002;
                public const uint SECTION_MAP_READ = 0x0004;
                public const uint SECTION_MAP_EXECUTE = 0x0008;
                public const uint SECTION_EXTEND_SIZE = 0x0010;
                public const uint FILE_MAP_COPY = SECTION_QUERY;
                public const uint FILE_MAP_WRITE = SECTION_MAP_WRITE;
                public const uint FILE_MAP_READ = SECTION_MAP_READ;
                public const uint SECTION_ALL_ACCESS = (uint)ACCESS_MASK.STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE;
                public const uint FILE_MAP_ALL_ACCESS = SECTION_ALL_ACCESS;
                public const UInt32 PAGE_NOACCESS = 0x01;
                public const UInt32 PAGE_READONLY = 0x02;
                public const UInt32 PAGE_READWRITE = 0x04;
                public const UInt32 PAGE_WRITECOPY = 0x08;
                public const UInt32 PAGE_EXECUTE = 0x10;
                public const UInt32 PAGE_EXECUTE_READ = 0x20;
                public const UInt32 PAGE_EXECUTE_READWRITE = 0x40;
                public const UInt32 PAGE_EXECUTE_WRITECOPY = 0x80;
                public const UInt32 PAGE_GUARD = 0x100;
                public const UInt32 PAGE_NOCACHE = 0x200;
                public const UInt32 PAGE_WRITECOMBINE = 0x400;
                public const UInt32 PAGE_TARGETS_INVALID = 0x40000000;
                public const UInt32 PAGE_TARGETS_NO_UPDATE = 0x40000000;

                public const UInt32 SEC_COMMIT = 0x08000000;
                public const UInt32 SEC_IMAGE = 0x1000000;
                public const UInt32 SEC_IMAGE_NO_EXECUTE = 0x11000000;
                public const UInt32 SEC_LARGE_PAGES = 0x80000000;
                public const UInt32 SEC_NOCACHE = 0x10000000;
                public const UInt32 SEC_RESERVE = 0x4000000;
                public const UInt32 SEC_WRITECOMBINE = 0x40000000;

                public const UInt32 SE_PRIVILEGE_ENABLED = 0x2;
                public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1;
                public const UInt32 SE_PRIVILEGE_REMOVED = 0x4;
                public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x3;

                public const UInt64 SE_GROUP_ENABLED = 0x00000004L;
                public const UInt64 SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002L;
                public const UInt64 SE_GROUP_INTEGRITY = 0x00000020L;
                public const UInt32 SE_GROUP_INTEGRITY_32 = 0x00000020;
                public const UInt64 SE_GROUP_INTEGRITY_ENABLED = 0x00000040L;
                public const UInt64 SE_GROUP_LOGON_ID = 0xC0000000L;
                public const UInt64 SE_GROUP_MANDATORY = 0x00000001L;
                public const UInt64 SE_GROUP_OWNER = 0x00000008L;
                public const UInt64 SE_GROUP_RESOURCE = 0x20000000L;
                public const UInt64 SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010L;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct MODULEINFO
            {
                public IntPtr lpBaseOfDll;
                public uint SizeOfImage;
                public IntPtr EntryPoint;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DOS_HEADER
            {      // DOS .EXE header
                public UInt16 e_magic;              // Magic number
                public UInt16 e_cblp;               // Bytes on last page of file
                public UInt16 e_cp;                 // Pages in file
                public UInt16 e_crlc;               // Relocations
                public UInt16 e_cparhdr;            // Size of header in paragraphs
                public UInt16 e_minalloc;           // Minimum extra paragraphs needed
                public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
                public UInt16 e_ss;                 // Initial (relative) SS value
                public UInt16 e_sp;                 // Initial SP value
                public UInt16 e_csum;               // Checksum
                public UInt16 e_ip;                 // Initial IP value
                public UInt16 e_cs;                 // Initial (relative) CS value
                public UInt16 e_lfarlc;             // File address of relocation table
                public UInt16 e_ovno;               // Overlay number
                public UInt16 e_res_0;              // Reserved words
                public UInt16 e_res_1;              // Reserved words
                public UInt16 e_res_2;              // Reserved words
                public UInt16 e_res_3;              // Reserved words
                public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
                public UInt16 e_oeminfo;            // OEM information; e_oemid specific
                public UInt16 e_res2_0;             // Reserved words
                public UInt16 e_res2_1;             // Reserved words
                public UInt16 e_res2_2;             // Reserved words
                public UInt16 e_res2_3;             // Reserved words
                public UInt16 e_res2_4;             // Reserved words
                public UInt16 e_res2_5;             // Reserved words
                public UInt16 e_res2_6;             // Reserved words
                public UInt16 e_res2_7;             // Reserved words
                public UInt16 e_res2_8;             // Reserved words
                public UInt16 e_res2_9;             // Reserved words
                public UInt32 e_lfanew;             // File address of new exe header
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DATA_DIRECTORY
            {
                public UInt32 VirtualAddress;
                public UInt32 Size;
            }


            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_OPTIONAL_HEADER64
            {
                public UInt16 Magic;
                public Byte MajorLinkerVersion;
                public Byte MinorLinkerVersion;
                public UInt32 SizeOfCode;
                public UInt32 SizeOfInitializedData;
                public UInt32 SizeOfUninitializedData;
                public UInt32 AddressOfEntryPoint;
                public UInt32 BaseOfCode;
                public UInt64 ImageBase;
                public UInt32 SectionAlignment;
                public UInt32 FileAlignment;
                public UInt16 MajorOperatingSystemVersion;
                public UInt16 MinorOperatingSystemVersion;
                public UInt16 MajorImageVersion;
                public UInt16 MinorImageVersion;
                public UInt16 MajorSubsystemVersion;
                public UInt16 MinorSubsystemVersion;
                public UInt32 Win32VersionValue;
                public UInt32 SizeOfImage;
                public UInt32 SizeOfHeaders;
                public UInt32 CheckSum;
                public UInt16 Subsystem;
                public UInt16 DllCharacteristics;
                public UInt64 SizeOfStackReserve;
                public UInt64 SizeOfStackCommit;
                public UInt64 SizeOfHeapReserve;
                public UInt64 SizeOfHeapCommit;
                public UInt32 LoaderFlags;
                public UInt32 NumberOfRvaAndSizes;

                public IMAGE_DATA_DIRECTORY ExportTable;
                public IMAGE_DATA_DIRECTORY ImportTable;
                public IMAGE_DATA_DIRECTORY ResourceTable;
                public IMAGE_DATA_DIRECTORY ExceptionTable;
                public IMAGE_DATA_DIRECTORY CertificateTable;
                public IMAGE_DATA_DIRECTORY BaseRelocationTable;
                public IMAGE_DATA_DIRECTORY Debug;
                public IMAGE_DATA_DIRECTORY Architecture;
                public IMAGE_DATA_DIRECTORY GlobalPtr;
                public IMAGE_DATA_DIRECTORY TLSTable;
                public IMAGE_DATA_DIRECTORY LoadConfigTable;
                public IMAGE_DATA_DIRECTORY BoundImport;
                public IMAGE_DATA_DIRECTORY IAT;
                public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
                public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
                public IMAGE_DATA_DIRECTORY Reserved;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_FILE_HEADER
            {
                public UInt16 Machine;
                public UInt16 NumberOfSections;
                public UInt32 TimeDateStamp;
                public UInt32 PointerToSymbolTable;
                public UInt32 NumberOfSymbols;
                public UInt16 SizeOfOptionalHeader;
                public UInt16 Characteristics;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_NT_HEADERS
            {
                [FieldOffset(0)]
                public uint Signature;
                [FieldOffset(4)]
                public IMAGE_FILE_HEADER FileHeader;
                [FieldOffset(24)]
                public IMAGE_OPTIONAL_HEADER64 Optionalheader;
            }
            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_SECTION_HEADER
            {
                [FieldOffset(0)]
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
                public char[] Name;
                [FieldOffset(8)]
                public UInt32 VirtualSize;
                [FieldOffset(12)]
                public UInt32 VirtualAddress;
                [FieldOffset(16)]
                public UInt32 SizeOfRawData;
                [FieldOffset(20)]
                public UInt32 PointerToRawData;
                [FieldOffset(24)]
                public UInt32 PointerToRelocations;
                [FieldOffset(28)]
                public UInt32 PointerToLinenumbers;
                [FieldOffset(32)]
                public UInt16 NumberOfRelocations;
                [FieldOffset(34)]
                public UInt16 NumberOfLinenumbers;
                [FieldOffset(36)]
                public uint Characteristics;

                public string Section
                {
                    get { return new string(Name); }
                }
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_EXPORT_DIRECTORY
            {
                [FieldOffset(0)]
                public UInt32 Characteristics;
                [FieldOffset(4)]
                public UInt32 TimeDateStamp;
                [FieldOffset(8)]
                public UInt16 MajorVersion;
                [FieldOffset(10)]
                public UInt16 MinorVersion;
                [FieldOffset(12)]
                public UInt32 Name;
                [FieldOffset(16)]
                public UInt32 Base;
                [FieldOffset(20)]
                public UInt32 NumberOfFunctions;
                [FieldOffset(24)]
                public UInt32 NumberOfNames;
                [FieldOffset(28)]
                public UInt32 AddressOfFunctions;
                [FieldOffset(32)]
                public UInt32 AddressOfNames;
                [FieldOffset(36)]
                public UInt32 AddressOfOrdinals;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_BASE_RELOCATION
            {
                public uint VirtualAdress;
                public uint SizeOfBlock;
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct MEMORY_BASIC_INFORMATION64
            {
                public UInt64 BaseAddress;
                public UInt64 AllocationBase;
                public UInt32 AllocationProtect;
                public UInt32 __alignment1;
                public UInt64 RegionSize;
                public UInt32 State;
                public UInt32 Protect;
                public UInt32 Type;
                public UInt32 __alignment2;
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct CFG_CALL_TARGET_INFO
            {
                public IntPtr Offset;
                public IntPtr Flags;
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct VM_INFORMATION
            {
                public int dwNumberOfOffsets;
                public IntPtr pZero;
                public IntPtr plOutput;
                //public CFG_CALL_TARGET_INFO ptOffsets;
                public IntPtr ptOffsets;
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct MEMORY_RANGE_ENTRY
            {
                public IntPtr VirtualAddress;
                public IntPtr NumberOfBytes;
            }

        }
        public class Internals
        {
            [StructLayout(LayoutKind.Explicit)]
            public struct MethodTable
            {
                [FieldOffset(0)]
                public uint m_dwFlags;

                [FieldOffset(0x4)]
                public uint m_BaseSize;

                [FieldOffset(0x8)]
                public ushort m_wFlags2;

                [FieldOffset(0x0a)]
                public ushort m_wToken;

                [FieldOffset(0x0c)]
                public ushort m_wNumVirtuals;

                [FieldOffset(0x0e)]
                public ushort m_wNumInterfaces;

                [FieldOffset(0x10)]
                public IntPtr m_pParentMethodTable;

                [FieldOffset(0x18)]
                public IntPtr m_pLoaderModule;

                [FieldOffset(0x20)]
                public IntPtr m_pWriteableData;

                [FieldOffset(0x28)]
                public IntPtr m_pEEClass;

                [FieldOffset(0x30)]
                public IntPtr m_pPerInstInfo;

                [FieldOffset(0x38)]
                public IntPtr m_pInterfaceMap;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct EEClass
            {
                [FieldOffset(0)]
                public IntPtr m_pGuidInfo;

                [FieldOffset(0x8)]
                public IntPtr m_rpOptionalFields;

                [FieldOffset(0x10)]
                public IntPtr m_pMethodTable;

                [FieldOffset(0x18)]
                public IntPtr m_pFieldDescList;

                [FieldOffset(0x20)]
                public IntPtr m_pChunks;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct MethodDescChunk
            {
                [FieldOffset(0)]
                public IntPtr m_methodTable;

                [FieldOffset(8)]
                public IntPtr m_next;

                [FieldOffset(0x10)]
                public byte m_size;

                [FieldOffset(0x11)]
                public byte m_count;

                [FieldOffset(0x12)]
                public byte m_flagsAndTokenRange;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct MethodDesc
            {
                [FieldOffset(0)]
                public ushort m_wFlags3AndTokenRemainder;

                [FieldOffset(2)]
                public byte m_chunkIndex;

                [FieldOffset(0x3)]
                public byte m_bFlags2;

                [FieldOffset(0x4)]
                public ushort m_wSlotNumber;

                [FieldOffset(0x6)]
                public ushort m_wFlags;

                [FieldOffset(0x8)]
                public IntPtr TempEntry;
            }

            public const int mdcHasNonVtableSlot = 0x0008;

            [Flags]
            public enum AllocationType
            {
                Commit = 0x1000,
                Reserve = 0x2000,
                Decommit = 0x4000,
                Release = 0x8000,
                Reset = 0x80000,
                Physical = 0x400000,
                TopDown = 0x100000,
                WriteWatch = 0x200000,
                LargePages = 0x20000000
            }

            [Flags]
            public enum MemoryProtection
            {
                Execute = 0x10,
                ExecuteRead = 0x20,
                ExecuteReadWrite = 0x40,
                ExecuteWriteCopy = 0x80,
                NoAccess = 0x01,
                ReadOnly = 0x02,
                ReadWrite = 0x04,
                WriteCopy = 0x08,
                GuardModifierflag = 0x100,
                NoCacheModifierflag = 0x200,
                WriteCombineModifierflag = 0x400
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES
        {
            public Int32 Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName; // -> UNICODE_STRING
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct IO_STATUS_BLOCK
        {
            public IntPtr Status;
            public IntPtr Information;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }

        /// <summary>
        /// x64
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public uint ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }
    }
}
