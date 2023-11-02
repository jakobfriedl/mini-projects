import winim

proc main(): void {.stdcall,exportc,dynlib.} = 
    MessageBox(0, "Hello from Nim", "Nim DLL", 0)

when isMainModule:
    main()