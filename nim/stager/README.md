# Stager

Nim shellcode stager that executes shellcode in memory. The shellcode can either be loaded from a local file or requested from a remote web server. The shellcode injection was tested with a meterpreter reverse_tcp payload. 

## Compilation on Windows

```bash
nim c src/stager.nim
```

## Cross-compilation to Windows from UNIX

```bash
nim --os:windows --cpu:amd64 --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc -d:release c src/stager.nim
```

In addition to stager.nim, which injects the downloaded shellcode directly into memory of the current process, pinject_stager.nim requires the user to specify a target process name (e.g `notepad.exe`) and injects the shellcode into the memory of the target process.