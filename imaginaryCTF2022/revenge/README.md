# One Liner: Revenge
**Category:** Reversing

**Author:** puzzler7

**Description:**
> The last time that I made a python one-liner challenge, I recieved two pieces of feedback. First, it's not a meaningful one-line challenge if the player can just ... add new lines. Second, "walrus operators are cringe". I've taken both of these criticisms to heart. Have fun!

**Attachments:** [revenge.py](revenge.py)

This is the sequel to [oneline.py](https://fdow.nl/MtYfF#oneline.py), a challenge from ImaginaryCTF's daily challenges (which is great; go check it out!)

## Overview
We are given a Python file which when run gives us a prompt. When we enter some input the program either crashes with a less-than-helpful error message or just says *no*, depending on the length of our input. We are therefore most likely dealing with a flag-checker that simply says if our input is the flag or not.
```
>>> abc123
Traceback (most recent call last):
[...]
IndexError: tuple index out of range
```
```
>>> aaaaaaaaaaaaaaaaaaaaaaaa
no
```
So without reversing anything it's reasonable to conclude that the shortest input that does not violently crash the program is the length of the correct flag, which in this case happens to be 24.

## Diving in
Opening up the [file](revenge.py) we are unsurprisingly greeted with a single line of 7566 characters. I first tried formatting the program a bit, separating list items into separate rows and such to get a better overview, but as hinted towards in the description, that is strictly forbidden. Running the program now does not even get us to the prompt and instead screams `('no', 'newlines!')`.

I duplicated the file and kept one unchanged for testing and formatted the other one to get a better idea of how it works. This would mean that debugging the program and testing stuff at runtime would be quite hard, so I hoped that static analysis of the code would do.

The program/line is as a whole a single, long, list with different actions in each entry. From here on out I will refer to these entries as "lines", even though they obviously aren't. Now for the breakdown.

```python
globals().__setitem__(chr(0x67),globals()),
```
This is the first *line*. `globals()` is used to assign a variable, a way to avoid using walrus (:=) operators because apparently that's cringe. `chr(0x67)` is just a harder-to-read way of writing `g`, so the variable assigned to is `g`, which is set to `globals()` itself. So `g` is now a shorthand for `globals()`.
```python
g.__setitem__(chr(0x74),lambda*a:bytes.fromhex('{:x}'.format(a[0])).decode()),
```
Here a new variable `t` (also `chr(0x74)`) is set to a lambda function. This function takes an integer as its first parameter and converts it into a string by first formatting it as a hex-string and then interpreting that hex-string as bytes and then decoding those bytes. This is an obfuscation technique that's used throughout the program.

## Strange custom class
```python
g.__setitem__(t(103), type('',(dict,),{
    t(6872320826472685407): lambda*a : {
            **{_:getattr(a[0],t(115298706365414908258770783))(*[(i%8if type(i)is(1).__class__ else i)for(i)in _[::-1]])for(_)in a[1:]},
            a.__reduce__:a[0]
        }.popitem()[len(a)%2*2-1],
    t(115298485004486023744151391) : lambda*a:dict.__getitem__(*[(i%8if type(i)is(4).__class__ else i)for(i)in a])
})())
```
Here is the third line, and things are already becoming very messy. We can see that `t` is now getting called with huge numbers as arguments, so we can immediately replace those with the strings they represent, something I will do without mentioning from now on.

```python
g.__setitem__('g', type('',(dict,),{
    '__call__': lambda*a : {
            **{_:getattr(a[0],'__setitem__')(*[
                (i%8 if type(i) is (1).__class__ else i)for(i)in _[::-1]
            ]) for _ in a[1:]},
            a.__reduce__:a[0]
        }.popitem()[len(a)%2*2-1],
    '__getitem__' : lambda*a:dict.__getitem__(*[(i%8 if type(i)is(4).__class__ else i)for(i)in a])
})())
```
This still isn't exactly easy to read, but let's try. It's using `g` as the shorthand for `globals()` and assigning something new to `g`. This something is a new class, created dynamically using the seldom used constructor for `type()`. It inherits from `dict` and has some custom methods defined, but I think it will be easiest explained by showing you the corresponding "normal" class definition so you can see what any of the areas you are uncertain about correspond to. This is how I would have written an identically-functioning class.
```python
class SpecialDict(dict):
    @staticmethod
    def transform(i):
        return i%8 if isinstance(i, int) else i

    def __call__(self, *args):
        for arg in args:
            '''
            The following is not strictly equivalent with the original code:
            self.__setitem__(*[
                    (i%8 if isinstance(i, int) else i) for i in arg[::-1]
                ])
            But this only makes sense if arg is a sequence of length 2 since
            __setitem__ only takes two arguments. Therefore this version should
            be functionally equivalent in basically all cases
            '''
            self[self.transform(arg[1])] = self.transform(arg[0])
        return self
    def __getitem__(self, key):
        '''
        Same thing as above applies here,
        the following is not strictly equivalent to the original function:
        lambda*a:dict.__getitem__(*[(i%8 if type(i)is(4).__class__ else i)for(i)in a])
        But if __getitem__ is supplied with any more than one argument it will crash
        so this will function the same
        '''
        return dict.__getitem__(self, self.transform(key))
```
Some steps you might get caught up on while reversing this:
 - At the end of the original definition of `__call__`, `popitem()` is used on a dictionary. Since Python 3.7 this will always return the last item defined even though dictionaries are technically unordered by nature.
 - The popped item will be the tuple `(a.__reduce__, a[0])`. `a[0]` is `self` since that's always the first argument to normal methods. This is then indexed by `len(a)%2*2-1`. This will always either be `1` or `-1` (feel free to verify that yourself), which in a 2-long tuple will always be the second element. Hence this `a.__reduce__` is thrown away and is just another obfuscation technique to hide the fact that it's still just `self` being returned.

So for a quick summary of what this dictionary does:
 - If it's indexed by an integer that integer will be taken mod 8 before being looked up
 - It can be called. Each argument must be a sequence (list, tuple, etc.) with only two elements. The former element will be the value and the latter will be the key when then setting an item in the dictionary. Both will be taken mod 8 if they are integers. For example:
   ```python
   g(('a', 1), ('b', 10))
   ```
   will be the same as doing
   ```python
   g[1]='a'
   g[2]='b'
   ```

It's good if you understand this because this will be how most values are looked up from now on. An important thing to recognize is that since all integer keys are taken mod 8, there can only be 8 different integer-indexed values stored in this dictionary.

Alright, let's move on.

## First tampering-check
```python
[
    g((lambda*a:(print(*a),exit()),7))((type('',([].__class__,),{
        '__hash__':lambda*a:1,
        '__call__':lambda*a:g(([a[0].insert(0,list.pop(a[0])),a[0]][1][a[-1]],5)),
        'append':lambda*a:[list.append(a[0],_)for(_)in a[1:]],
        'pop':lambda*a:(list.pop(a[0]),a[0].reverse())[0]
    })(),5))[5].append(*[g()[5],*[lambda*a:g[7]('no')]*15]),
    g((open('revenge.py').read(),2)),
    g()[7]
][
    any(any(_ in '#\n#\n#\n#\n' for _ in i)for i in open('revenge.py'))+1
](('no','newlines!')),
```
If you look in the original file you will see a lot bigger and crazier numbers than I have right here, and that is because I already took all the integers that index `g` mod 8 to make it easier to read. In the original `13463` and `11391` were both used to access the same value, because both are 7 mod 8.

Here we have a list of 3 elements, indexed by some expression and then called with `('no', 'newlines!')` as an argument. The first element saves some function at `g[7]` which when ran prints all its arguments and exits. It then does one of those dynamic class declarations which we definitely will need to examine. The second element opens `revenge.py` (the file being ran<sup id="a1">[1](#f1)</sup>) and saves its contents in `g[2]`, and the third element is just `g[7]` which we just defined.

So this list contains
 - Some result from declaring that custom class
 - `g`; what remains after storing the file contents of the current file in `g[2]`
 - `g[7]`; the print-and-exit function

This bigger list is then indexed by
```python
any(any(_ in '#\n#\n#\n#\n' for _ in i)for i in open('revenge.py'))+1
```
This iterates through every line and then every character of `revenge.py`. If any character is `#` or `\n` it will return `True`, otherwise `False`. Except there is `+1` at the end, so the boolean will be converted to an int (`True`->`1`, `False`->`0`) and then incremented. So if there is any `#` or `\n` the index will be `2`, otherwise it will be `1`. Looking at the list we see that that corresponds to either `g[7]` (print and exit) or `g`. The result of this lookup will be called with the argument `('no','newlines!')`.

It should be obvious by now that this is the anti-debugging technique that prevents us from adding newlines or comments to `revenge.py`, since if we do it would lookup the print-and-exit function and call that with `('no','newlines!')`, hence exiting the program. If it does not find any newlines or comments it will instead call this on `g`, which as we know will just store `'no'` to a variable called `newlines!` (`!` in a variable name; cursed, I know)

## Custom list
Now let's look closer at the dynamic class declaration in the first list item, which this time inherits from `list`. It is instantiated, stored at `g[5]`, and then some stuff is appended to it. This is my deobfuscated version of the class:
```python
class SpecialList(list):
    def __hash__(self): return 1

    def __call__(self, *args):
        self.insert(0, list.pop(self))
        g[5] = self[args[-1]]
        return g
    
    def append(self, *args):
        for arg in args:
            list.append(self, arg)

    def pop(self):
        self.reverse()
        return list.pop(self, 0)
```
Summary of what this does:
 - `__hash__` always returns `1`, which I suspect is to make it possible for this list to be used as a key in a dictionary. If you try to index a dictionary by a list you will find that Python complains about an "unhashable type", so this is a dirty workaround for that.
 - `__call__` will first rotate/shift the list by putting the last element first. Then it will set `g[5]`, which is where this custom list is stored, to *the item at the index stored in the last argument, within this list itself*. This will make slightly more sense later.
 - `append` just makes it possible to append several things in one call by passing several arguments
 - `pop` reverses the list before popping the first element off, which was the last element before it was reversed.

After it is defined, instantiated, and stored in `g[5]` it is accessed and `.append(*[g()[5],*[lambda*a:g[7]('no')]*15]),` is run on it. Remember that `g[5]` is this list itself and `g[7]` is a function that prints the arguments it is passed and then exits, in this case, printing `'no'`. That function is repeated 15 times resulting in our list containing 16 items, 15 of which are functions that exit the program and one of which is the list itself. This will be central to the final flag check, so keep that in mind.

## Final stretch
```python
[
    g(
        (g(
            (lambda*a:int(''.join(str(1*i)for i in a),2),6)
        )[5].__getattribute__('__class__')(), 3)
    )[3].append(*(
        lambda*a:(...,...,...,...),lambda*a:(...,...,...,...),
        lambda*a:(...,...,...,...),lambda*a:(...,...,...,...),
        lambda*a:(...,...,...,...),lambda*a:(...,...,...,...),
        lambda*a:(...,...,...,...),lambda*a:(...,...,...,...),
        lambda*a:(...,...,...,...),lambda*a:(...,...,...,...),
        lambda*a:(...,...,...,...),lambda*a:(...,...,...,...),
        lambda*a:(...,...,...,...),lambda*a:(...,...,...,...),
        lambda*a:(...,...,...,...),lambda*a:(...,...,...,...)
    )),
    g((input('>>> ').encode(),1)),
    g[7]
][
    ('f\n'[1]in g()[2])+1
](`('stop trying to debug me','fool!')`),
[g[5](
    g()[6](
        *g()[3].pop()(
            *g()[(3).__class__(g[2][138])]
        )
    )
) for i in iter(g()[3].__len__,0)],
g[7]('yes')
```
This final part does another tampering check before running the final algorithm to check the flag. The tampering check has a very similar structure to the previous one we just discussed, but it also does some extra stuff so let's walk through it regardless.

We first make a list containing 3 different items. The first one defines some stuff we will need later, the second one takes the input from the user to be checked and stores it at `g[1]`, and the final one is once again the print-and-exit function (`g[7]`). Before looking at what the first item does, we can look at what the list is being indexed by and we once again find a check with `+1` appended at the end. Specifically
```python
('f\n'[1]in g()[2])+1
```
`'f\n'[1]` will just be `'\n'`, and we found earlier that `g[2]` was the contents of the currently running file. So this just once again checks if there are any newlines in this file in which case the index will be that of the exit function and `('stop trying to debug me','fool!')` will be printed. Otherwise, it calls `g` with the same arguments and a harmless variable gets defined instead.

So now onto what the first element in the list means
```python
g(
    (g(
        (lambda*a:int(''.join(str(1*i)for i in a), 2), 6)
    )[5].__getattribute__('__class__')(), 3)
)[3].append(*(
    lambda*a:(...,...,...,...),lambda*a:(...,...,...,...),
    lambda*a:(...,...,...,...),lambda*a:(...,...,...,...),
    lambda*a:(...,...,...,...),lambda*a:(...,...,...,...),
    lambda*a:(...,...,...,...),lambda*a:(...,...,...,...),
    lambda*a:(...,...,...,...),lambda*a:(...,...,...,...),
    lambda*a:(...,...,...,...),lambda*a:(...,...,...,...),
    lambda*a:(...,...,...,...),lambda*a:(...,...,...,...),
    lambda*a:(...,...,...,...),lambda*a:(...,...,...,...)
))
```
The nested `g` calls first creates this function
```python
lambda*a:int(''.join(str(1*i)for i in a), 2)
```
and saves it at `g[6]`. This function iterates through the arguments, converts them to strings, joins those strings together, and then interprets the whole string as a binary number. If this is going to be a binary number the arguments must be either 1 or 0. But since every argument is multiplied by 1, booleans would also turn into integers, so passing booleans to this function would make perfect sense; keep that in mind.

Right after that `g[5]` is accessed, which is our weird custom list. The `__class__` attribute is then accessed and called, thereby creating a new instance of the class, which is then stored at `g[3]`. It is to this new instance of the weird list class that all the lambda expressions are appended. I've abbreviated this expression a lot, in actuality each `...` is a boolean expression looking something like
```python
51*a[10]+56*a[0]+12*a[14]+91*a[3]+9*a[14]==96*a[19]+96*a[9]+83*a[1]+91*a[1]+43*a[22]-11543
```
So each of these functions will return a tuple of 4 booleans based on the contents of the arguments passed. You might also notice that in none of these expressions does the index of `a` surpass `23` so it's reasonable to conclude that `a` is the flag-guess we input. All of these boolean expressions based on different letters of the flag should at this point ring some Z3-bells in every reverser's brain, and it is tempting to just chuck all of them into Z3 and let it do the work, but you would find the result very **unsat**isfying. We have some work left to do.

All of these functions are as mentioned appended to `g[3]` which is an instance of the custom list class. At this point, we have everything we need to tackle the last bit of code.
```python
[g[5](
    g()[6](
        *g()[3].pop()(
            *g()[(3).__class__(g[2][138])]
        )
    )
) for i in iter(g()[3].__len__,0)],
g[7]('yes')
```
To remind you, `g[1]` is the input we provide to the program. `g[5]` is an instance of our custom list class containing 15 functions saying `'no'` then exiting and a single entry containing itself, which sits at index 0. `g[6]` turns all the arguments it gets past into an integer based on the binary number they represent. `g[2]` is the text contents of the script and `g[3]` is an instance of our custom list class containing 16 functions which when given each character of a 24-length string as arguments returns a tuple of 4 booleans.

The main for-loop is a disguised while-loop<sup id="a2">[2](#f2)</sup> which runs as long as `g[3]` still has items in it. Let's now try to examine what's happening

`g[5]` is called causing its contents to "shift" by one, putting the reference to itself at index 1 within itself. The argument it was now called with will determine what `g[5]` is set to, so if we want to keep the reference to it the argument passed to it should be 1, and on the second go-round it should be 2 since it is shifted once again, and so on.

The argument passed to `g[5]` comes from `g[6]` (the list-of-booleans-to-int function) getting called on an an item popped from `g[3]` (the list of flag-checking functions) which is called with the following argument
```python
*g()[(3).__class__(g[2][138])
```
which is equivalent to 
```python
*g()[int(g[2][138])
```
And since `g[2]` is the source code of the program `g[2][138]` will be the 139th character in the program<sup id="a3">[3](#f3)</sup>, which happens to be `'1'`. Hence the looked-up value will be `g[1]`; our user input.

<sup><sub>bear with me here</sub></sup>

So a function popped from `g[3]` will be run on our input, yielding a tuple of 4 booleans ("bits"). This gets past to `g[6]` and turned into the number the booleans represent as bits. To keep our reference to `g[5]` we must always call it with the index of where `g[5]` is within itself which will increase by 1 each time we run the loop since `g[5]` shifts each time it gets called. The loop will stop when there is nothing to be popped from `g[3]`, which is after 16 iterations.

That's a lot to take in, let me try to explain what that entails.

Each function in `g[3]` has 4 equations. A true equation represents a 1 and a false equation represents a 0, hence each function call will yield a 4-bit number. These functions must, in the order that they are popped from `g[3]`, count from 1-16 (where 16 is `0b0000`) in order to always point to where `g[5]` is within itself.

So now we have a list of statements based on our user input and we know which ones need to be true and which ones need to be false for the check to pass. This is now something we can leave to Z3 to work out. Remember that popping things from `g[3]` is also using a custom implementation that reverses the list each call to `pop`, this will need to be taken into account. In the end, this is the [solve script I came up with](solve.py).
```python
from z3 import *

a = [Int(str(i)) for i in range(24)]
s = Solver()
fs = open('conditions.txt', 'r').readlines()
def popf():
    return (fs.pop(), fs.reverse())[0]

for i in range(1,17):
    bits = f'{i%16:04b}'
    f = popf()
    for b in bits:
        f = f.replace('==', 'EQ' if b=='1' else 'NE', 1)
    f = f.replace('EQ', '==').replace('NE', '!=')
    exec(f)

assert s.check() == sat
m = s.model()
flag = ''.join(chr(m[ch].as_long()) for ch in a)
print(flag)
```
Although I can't help but feel... uneasy. I solved the challenge, but at what cost? Searching for the truth I abandoned the values this challenge was built upon. I may have solved it, I may have made a solve script, but at the expense of so much waste, so many lines. I felt it was only right that this challenge was solved in the same spirit it was conceived, using unnecessary and contrived one-liners! Hence here is my [actual solution script](onelinesolve.py), all neatly contained in a single, unreadable, line; as all things should be.


**Footnotes:**

<b id="f1">1</b> It opens 'revenge.py', not the actual file being run. This means we can simply keep an unmodified version named revenge.py in the same directory as the file we are working on. I did however not see any great benefit from dynamic analysis in this case and so I didn't use it. [↩](#a1)

<b id="f2">2</b> Look into the second version of [iter](https://docs.python.org/3/library/functions.html#iter), it can be very useful at times [↩](#a2)

<b id="f3">3</b> Yet another anti-debugging technique  [↩](#a3)