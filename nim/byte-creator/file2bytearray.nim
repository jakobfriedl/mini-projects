# Convert a file to a Nim byte array
# Author: Jakob Friedl

import os, streams, strformat, strutils

proc file2bytearray(path: string, width: int = 12): string = 
    
    if not os.fileExists(path): 
        return "File not found";

    var fileStream = streams.newFileStream(path, fmRead)
    var size = cast[int](os.getFileSize(path))

    # Nim format
    result = fmt"var bytes: array[{size}, byte] = [byte "
    result.add("\n")

    var counter: int = 0
    while not fileStream.atEnd():         
        var character = fileStream.readStr(1)
        result.add(fmt"0x{strutils.toHex(character).toLower()},")
        counter += 1

        if counter == width: 
            result.add("\n")
            counter = 0

    result = result[0..^1] # Remove last comma
    result.add("]")        

    fileStream.close()

when isMainModule: 
    import cligen; dispatch(file2bytearray, help = {"path": "Path to executable file", "width": "Maximum width of the output"})
