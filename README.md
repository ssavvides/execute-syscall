execute-syscall
===============

A python program used to execute specific system calls directly. The purpose of
this program is not to execute system calls in order to carry out some specific
task. Instead, the program's purpose is to be used in combination with an
interposition utility such as strace (Linux), truss (Solaris), dtrace (BSD/Mac
OSX) in order to examine the interposition output format of specific system
calls.