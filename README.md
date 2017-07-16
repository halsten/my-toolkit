# this is my toolkit
it has:

* Address [helper class for pointers, dereferences, add/sub/get/to/at/as]
* Stack [should really be called a 'StackFrame' but stack sounds better. You can grab locals/args/and traverse frames]
* VMT [lets you clonea virtual method table, or simply cache all the methods in it]
* hash [namespace built for doing constexpr compile time hasing (fnv1a used as an example)]
* IMAGE_DIR [just a small helper class for image directories like the IAT/EAT/others]
* Module [holds everything you would want to know about a module, including IAT/EAT]
* Pattern [search for arrays of bytes with IDA style signatures]
* PEB [holds every module and works by singleton]
* Syscalls [allows you to retrieve a syscall by its hashed name and invoke the corresponding ordinal]
* util [namespace with various helper functions]
