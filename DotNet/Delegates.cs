using System;
using System.Runtime.InteropServices;
namespace DotNet
{
    class Delegates
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            UInt32 AllocationType,
            UInt32 Protect
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtProtectVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref IntPtr regionSize,
            uint newProtect,
            ref uint oldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void NtCreateThreadEx(
            ref IntPtr threadHandle,
            uint desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList);


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtWriteVirtualMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            IntPtr buffer,
            uint bufferLength,
            ref UInt32 NumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtWaitForSingleObject(
            IntPtr handle,
            Boolean Alertable,
            UInt64 Timeout);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlInitUnicodeString(
            ref Structs.UNICODE_STRING destinationString,
            [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtOpenFile(
            ref IntPtr FileHandle,
            Structs.Win32.Enums.FileAccessFlags DesiredAccess,
            ref Structs.OBJECT_ATTRIBUTES ObjAttr,
            ref Structs.IO_STATUS_BLOCK IoStatusBlock,
            Structs.Win32.Enums.FileShareFlags ShareAccess,
            Structs.Win32.Enums.FileOpenFlags OpenOptions);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            out IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            IntPtr SectionOffset,
            out ulong ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtCreateSection(
            ref IntPtr SectionHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            ref ulong MaximumSize,
            uint SectionPageProtection,
            uint AllocationAttributes,
            IntPtr FileHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtUnmapViewOfSection(
            IntPtr hProc,
            IntPtr baseAddr);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtFreeVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            UInt32 FreeType);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtQueryVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            int MemoryInformationClass,
            ref Structs.Win32.MEMORY_BASIC_INFORMATION64 MemoryInformation,
            UInt32 MemoryInformationLength,
            ref UInt32 ReturnLength);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtSetInformationVirtualMemory(
            IntPtr hProcess,
            uint VmInformationClass, // VmPrefetchInformation is 0x00 VmCfgCallTargetInformation is 0x02,
            UIntPtr NumberOfEntries,
            Structs.Win32.MEMORY_RANGE_ENTRY VirtualAddresses,
            Structs.Win32.VM_INFORMATION VmInformation
            );
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtGetContextThread(
            IntPtr Threadhandle,
            out Structs.CONTEXT64 Context);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtSetContextThread(
            IntPtr Threadhandle,
            Structs.CONTEXT64 Context);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtResumeThread(
            IntPtr Threadhandle,
            out ulong SuspendCount);
    }
}
