# Nim DLL Injector

Not working atm.

## Usage

1. Create DLL
```
nim c --app:lib .\mkdll.nim
```

2. Run Injector
```
nim c -r .\dll_inject.nim <pid>
```