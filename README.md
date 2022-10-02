# HellsGate-with-no-gate-and-dinvoking-deez
title. a monstrosity that combines some dinvoke and some hellsgate cuz why not even if theyre similar

What it do?  
Find syscall IDs via reading ntdll in read memory and matching the order of the nt functions.  
Utilize these IDs for indirect syscalls
Write the syscall stubs into the method table entry (net framework 4+) OR code pointed at by the entry (net 5+).

Files  
* ntdll.cs => The core class to do all the syscall related stuff  
* Structs.cs => Data structures and flags meant for unmanaged activities  
* Utils.cs => Optional functions that implement syscalls; examples, basically  
* Delegates.cs => Delegates intended to be used to call the indirect syscallls  
  
Why?  
idk was bored and jumped into a rabit hole HAHAHAHAHAHAHAHAHAHA
