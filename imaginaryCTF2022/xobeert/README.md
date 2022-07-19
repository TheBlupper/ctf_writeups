# xobeert
**Category:** Reversing

**Author:** TheBadGod

**Description:**
> My friend played GoogleCTF. Afterwards they sent me this AST of their solution to one of the challenges. Apparently it also checks for a flag? Please help me find their hidden flag! Also it looks like you need python 3.9 or later!

**Attachments:** [boxast.txt](boxast.txt)

## The challenge
We are given a file containing the AST (abstract syntax tree) of a Python program. I think what a lot of people struggled with for this challenge was converting this into a more readable format, but I found a fairly easy way to go about it. First, we have to parse this syntax tree into a Python object, which can easily be done using `exec()`. For example:
```python
from ast import *
txt = open('boxast.txt').read().strip()
# Skip first and last letter since those are quotes and we want
# the actual thing not a string
exec('tree='+txt[1:-1])
```
Now we have the top-level `Module` object stored in tree. If you struggled to convert this to readable source code you might not like to hear that there is a function in the `ast` module since Python 3.9 called `ast.unparse`, which does exactly what it sounds like. It takes a AST and converts it to source code.

In this case, it will complain that some nodes are missing the `lineno` attribute, most likely because this AST was created dynamically in a running interpreter and not directly from a source file. This can however (after a bit of googling) easily be fixed using `ast.fix_missing_locations` (thanks [BTaskaya](https://bugs.python.org/msg399593)). We can now get the (ish) [original source code](src.py) using this
```python
src=unparse(fix_missing_locations(tree))
open('src.py','w').write(src)
```

## Inspiration
If you played the recent Google CTF you might, after looking at the source code, start to realize why it was mentioned in the description of the challenge. In that CTF there was a challenge named [treebox](https://capturetheflag.withgoogle.com/challenges/sandbox-treebox) (a pyjail) where we got to execute any Python code with the exception that it could not contain any of the AST nodes `Import`, `ImportFrom` and `Call`. This meant you had to find workarounds to call functions.

It seemed the most common approach was using decorators. Decorators in Python are merely syntactic sugar that allows you to modify functions or classes. The premise is that
```python
@d
def f():
    pass
```
is equivalent to
```python
def f():
    pass
f = d(f)
```
and as you can see this allows us to call `d` without explicitly writing `d(f)` anywhere.

What seemed like the most common solution for that challenge looked something like this
```python
@exec
@input
class a:
    pass
```
This lets us input any string we want and then execute it, though you might notice that the input prompt will look something like `<class '__main__.a'>` since it's calling `input(a)` and therefore getting the string representation of the class.

If we compare this to the source code we can see that there are *a lot* of decorators, and this program does in fact obey the rules set by treebox, only utilizing class definitions, decorators, assignments, and lambda functions. This, however, does a lot more than just give us RCE and is in fact a flag checker.

## The gist
Looking at the file you will quickly notice that the naming scheme is a bit... dense. For that reason, VS Code's renaming function came in very handy (I'm sure this is common in all modern ides/text editors). Whenever I knew what the purpose or value of a variable was I could rename all occurances of it to something more readable and telling.

Using this I was able to slowly make my way through the file, renaming stuff as I went. I think looking at the finished named file might be the most telling, but the gist of it is that TheBadGod built a stack machine using decorators. Let's go through the basics of how it works. First, some fundamentals are defined which will be used to build new values
```python
zero = lambda f: 0
one = lambda f: 1
emptylist = lambda f: []
add = lambda a: lambda b: a + b

@add
@one
class inc:
    pass
push = lambda item: lambda stack: [item] + stack
pop = lambda stack: stack[1:]
add = lambda stack: [stack[1] + stack[0]] + stack[2:]
sub = lambda stack: [stack[1] - stack[0]] + stack[2:]
pow = lambda stack: [stack[1] ** stack[0]] + stack[2:]
mul = lambda stack: [stack[1] * stack[0]] + stack[2:]
getbottom = lambda stack: stack[0]
```
Using these functions we can build a lot of stuff. `zero`, `one`, and `emptylist` don't care for what comes before them, they always return the same thing. Thus they are often applied first to the classes and built up upon after that. This is for example how 1, 2, and 3 are built (and all the numbers used after that).
```python
@push
@inc
@zero
class push1:
    pass

@push
@getbottom
@add
@push1
@push1
@emptylist
class push2:
    pass

@push
@getbottom
@add
@push2
@push1
@emptylist
class push3:
    pass
```

There's quite a bit of mental gymnastics you have to go through to verify that this does work, there are a lot of nested function calls.

I find it easier to simply not think about it and treat it like a normal stack machine, pushing and popping things and performing operations like adding stuff together. In that sense, it's very similar to CPython's interpreter, and I would be curious to see if anyone is brave enough to attempt to recreate that.

Once you get your head around things it's easy to go through each class and rename it appropriately. Naming all the push instructions for numbers did shine some light on my now very poor arithmetic skills and I pulled up the IPython interpreter<sup id="a1">[1](#f1)</sup> more times than I'm willing to admit.

I have provided the [file I did the reversing in](rev.py), but beware that there might be some mistakes. I know for a fact push116 has replaced push114, resulting in all `r`'s being replaced by `t`'s, leading to the program crashing trying to import "`tandom`".

All of this comes down to the final few classes where the actual flag checking algorithm can finally be performed
```python
@check_result
@xor_with_input
@random_randbytes
@wrapped_inputlen
@random_seed
@random_randbytes
@wrapped_inputlen
@random_seed
@bytes.decode
@bytes
@push100
@push101
@push98
@push100
@push98
@push101
@push101
@push102
@push95
@push111
@push116
@push95
@push115
@push116
@push104
@emptylist
class check_flag:
    pass
```
You will have to trust me with the naming of these classes or dive into the source file yourself. All of these numbers are turned into the string `'debdbeef_ot_sth'`, which is supposed to be `'debdbeef_or_sth'` but as I mentioned my reversing went south at some point. That string is then used as a seed for `random.seed()`, a new string is created using `random.randbytes(inplen)` which is once again fed into `random.seed()` afterwhich *another* string is made using `random.randbytes(inplen)` which is finally xor:ed with our input. The final check checks that this result is equal to some bytestring defined earlier, specifically
```python
b'{\xfa^_y\xc3\xf9FG;\x89;\x05CA\xe2\x11\xa0\xcdd\xfb\xa92v\xb8\xb1\x01\xaf\x85'
```
Now we can simply do this process ourselves but flip the xor:s
```python
import random
from pwn import xor
inplen = 29
a1 = b'{\xfa^_y\xc3\xf9FG;\x89;\x05CA\xe2\x11\xa0\xcdd\xfb\xa92v\xb8\xb1\x01\xaf\x85'
s = 'debdbeef_or_sth'
random.seed(s)
random.seed(random.randbytes(inplen))
print(xor(random.randbytes(inplen), a1))
```
And we get the flag!

**Footnotes:**

<b id="f1">1</b> IPython interpreter > any calculator, fight me [↩](#a1)