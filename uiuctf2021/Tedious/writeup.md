# Tedious

**Category:** Reverse

**Author:** Chief

**Description:**

> Enter the flag and the program will tell you if it is correct!



*Tedious* was a beginner-friendly reverse-engineering challenge with a very clear goal, finding the flag that gives the correct output from the program. Running the binary included and entering a wrong flag yields this output:

![output1](https://github.com/TheBlupper/ctf_writeups/blob/main/uiuctf2021/Tedious/output1.png?raw=true)

This solution will be using a binary analysis tool called [*angr*](https://angr.io/), which can simulate code paths in a binary to try and get to a desired result, using a combination of both static and dynamic symbolic analysis. These easier reverse challenges are usually solvable with tools like it, albeit a bit predictably at times. Installation instructions can be found on *angr*'s home page [here](https://angr.io/).

In order to use *angr* we first need to find what our goal is, i.e. which address in the binary we want to reach, and which address we want to avoid. I use [Ghidra](https://ghidra-sre.org/) because it's free but you can use any other reverse engineering tool, like [IDA](https://hex-rays.com/ida-home/).

Opening up the binary in Ghidra and analyzing it, the first thing we can note is the base address at the top of the file. Write it down, as *angr* will need it later.

![base_addr](https://github.com/TheBlupper/ctf_writeups/blob/main/uiuctf2021/Tedious/base_addr.png?raw=true)

Next we can head into the `main` function, from the symbol tree on the side. This is where the program starts execution, and all other functions branch off from there. Scrolling down we can recognize the prompt for the flag in `puts`  after which `fgets` is called and it starts waiting for input.

![puts_gets](https://github.com/TheBlupper/ctf_writeups/blob/main/uiuctf2021/Tedious/puts_gets.png?raw=true)

`fgets` is not dangerous in the way that `gets` is, so on my first time looking through I noted that it is probably not a buffer overflow we are looking at (which would be a common beginner reverse challenge).

After that comes this code-block, with loads of loops through the string, additions and xor operations, and so I realized I couldn't be bothered to go through this by hand, and instead decided to let *angr* do all the hard work.

![image-20210804115218253](https://github.com/TheBlupper/ctf_writeups/blob/main/uiuctf2021/Tedious/code_block.png?raw=true)

Scrolling further down we find the ending snippet which checks some condition and prints "*CORRECT!*" or "*WRONG!*" depending on what we provide as STDIN.

![end](https://github.com/TheBlupper/ctf_writeups/blob/main/uiuctf2021/Tedious/end.png?raw=true)

We want to note the addresses of these calls as well, so *angr* knows to avoid inputs leading to *WRONG* and try to find the input leading to *CORRECT*. Looking at the instructions on the left side, we can get everything we need.

![assmb](https://github.com/TheBlupper/ctf_writeups/blob/main/uiuctf2021/Tedious/assmb.png?raw=true)

So the addresses we have are

- Base address 	`0x00100000`
- Find address 	 `0x001019d1`
- Avoid address	`0x001019a9`

Now we are ready to give this to *angr*

Now, *angr* is a very versatile tool with a lot of ways to optimize the search. This could be for example setting a flag length, or limiting what letters can be used in STDIN, etc. We are not going to do that here, but only create a beginner friendly program which is easy to understand and that, of course, works.

First we import *angr* and define the addresses we've found

```python
import angr

base_addr = 0x00100000
find_addr = 0x001019d1
avoid_addr = 0x001019a9
```

Then we create a project from the binary and specify the base address

```python
proj = angr.Project('./challenge', main_opts= {'base_addr' : base_addr})
```

After that we create a simulation manager and tells it which address to find and which to avoid

```python
simgr = proj.factory.simulation_manager()
simgr.explore(find=find_addr, avoid=avoid_addr)
```

Lastly we check if it found any solutions and, if so, we display them

```python
STDIN_FD = 0 # 0 is the file descriptor of STDIN
if len(simgr.found) > 0:
    for found in simgr.found:
        print(f'Found flag: ' + found.posix.dumps(STDIN_FD).decode())
else:
    print('Could not find flag :(')
```

Running this works! Not so *tedious* with *angr*, eh?

![result](https://github.com/TheBlupper/ctf_writeups/blob/main/uiuctf2021/Tedious/result.png?raw=true)

Final code:

```python
import angr

base_addr = 0x00100000
find_addr = 0x001019d1
avoid_addr = 0x001019a9

proj = angr.Project('./challenge', main_opts= {'base_addr' : base_addr})

simgr = proj.factory.simulation_manager()
simgr.explore(find=find_addr, avoid=avoid_addr)

STDIN_FD = 0 # 0 is the file descriptor of STDIN
if len(simgr.found) > 0:
    for found in simgr.found:
        print(f'Found flag: ' + found.posix.dumps(STDIN_FD).decode())
else:
    print('Could not find flag :(')
```

