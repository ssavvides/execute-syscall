execute-syscall
===============

A python program used to execute specific system calls directly. The purpose of
this program is not to execute system calls in order to carry out some specific
task. Instead, the program's purpose is to be used in combination with an
interposition utility such as strace (Linux), truss (Solaris), dtrace (BSD/Mac
OSX) in order to examine the interposition output format of specific system
calls.

Tested Under:
-------------
Ubuntu Linux



How to run
=============

The program requires a pickled package containing the available system calls in the system. This can be generated by running the program in this repository:

[parse-syscall-definitions](https://github.com/ssavvides/parse-syscall-definitions)

The latter will read the manual pages of the system to identify what system  calls are available and pack the information in a file called *syscall_definitions.pickle*

Once *syscall_definitions.pickle* is generated you can run *execute_syscall* using the following:

```
python execute_syscall.py syscall_definitions.pickle
```

To run and interpose system calls (Ubuntu):

```
strace -o TRACE python execute_syscall.py syscall_definitions.pickle
```

Consider changing the values of variable s*DEBUG* and *TRACE_PRINT* to see additional output.