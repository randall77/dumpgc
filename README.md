# dumpgc

Usage:
```
    dumpgc <binary> [<function>]
```
Dumps garbage collection information about the functions
in the given binary, or the one specific function if given.
This tool must be built for the same architecture that
the binary was built.

Intended for use by compiler and runtime developers to check that the generated information is correct.
