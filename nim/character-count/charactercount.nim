import strutils, sequtils, os, tables

if paramCount() != 1: 
    echo "Usage: nim c -r charactercount.nim <file>"
let file: string = paramStr(1)

var counts = initCountTable[char]()

for c in readFile(file).strip.toLowerAscii.splitLines.join("").replace(" ", "").toSeq:
    counts.inc(c)
    
counts.sort
for key, val in counts.mpairs:
    echo key, ": ", val