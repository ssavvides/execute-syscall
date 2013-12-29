import os
import sys
import pickle
import socket

import ctypes
import ctypes.util

import SyscallDefinition

DEGUG = False

FILEPATH = "file.txt"

LIBC_NAME = ctypes.util.find_library('c')
LIBC = ctypes.CDLL(LIBC_NAME)


class sockaddr(ctypes.Structure):
  """
  struct sockaddr {
      unsigned short    sa_family;    // address family, AF_xxx
      char              sa_data[14];  // 14 bytes of protocol address
  };
  """
  _fields_ = (('family', ctypes.c_ushort), ('data', ctypes.c_byte * 14))



def get_parameter_arginfo(parameter):
  """
  http://docs.python.org/3.4/library/ctypes.html
    ctypes type     C type                                  Python type
    -------------------------------------------------------------------
    c_bool          _Bool                                   bool (1)
    
    c_char          char                                    1-character bytes object
    c_char_p        char * (NUL terminated)                 bytes object or None
    c_byte          char                                    int
    c_ubyte         unsigned char                           int
    
    c_wchar_p       wchar_t * (NUL terminated)              string or None
    c_wchar         wchar_t                                 1-character string

    c_short         short                                   int
    c_ushort        unsigned short                          int

    c_int           int                                     int
    c_uint          unsigned int                            int

    c_long          long                                    int
    c_ulong         unsigned long                           int
    c_longlong      __int64 or long long                    int
    c_ulonglong     unsigned __int64 or unsigned long long  int
    
    c_size_t        size_t                                  int
    c_ssize_t       ssize_t or Py_ssize_t                   int
    
    c_float         float                                   float
    
    c_double        double                                  float
    c_longdouble    long double                             float

    c_void_p        void *                                  int or None
  """

  argtype = None
  argvalue = None

  if(parameter.ellipsis):
    argtype = "ellipsis"

  if(parameter.type == "char"):
    if(parameter.pointer):
      # char *
      argtype = ctypes.c_char_p
      argvalue = ctypes.c_char_p(str.encode(FILEPATH))

    elif(parameter.unsigned):
      argtype = ctypes.c_ubyte

    elif(parameter.array):
      argtype = ctypes.c_char_p
      argvalue = None

    else:
      argtype = ctypes.c_char


  elif(parameter.type and 
          (parameter.type == "int" or parameter.type.endswith("_t"))):
    if(parameter.unsigned):
      argtype = ctypes.c_uint
      argvalue = ctypes.c_uint(0)
    
    else:
      argtype = ctypes.c_int
      argvalue = ctypes.c_int(0)
  
  elif(parameter.type == "sockaddr"):
    # sockddr should be a structure
    assert(parameter.struct)
    
    argtype = sockaddr
    
    t = ctypes.c_byte * 14
    argvalue = sockaddr(0, t())

  return argtype, argvalue


def get_syscall_arginfo(syscall_definition):
  syscall_argtypes = []
  syscall_argvalues = []

  parameters = syscall_definition.definition.parameters

  for parameter in parameters:
    argtype, argvalue = get_parameter_arginfo(parameter)

    if (argtype == "ellipsis"):
      continue

    if argtype == None:
      return None, None

    syscall_argtypes.append(argtype)
    syscall_argvalues.append(argvalue)

  assert(len(syscall_argtypes) == len(syscall_argvalues))

  return syscall_argtypes, syscall_argvalues



def execute_syscall(syscall_definition):
  
  """
  # *** remember that the system call name (syscall_definition.name) and the
  # definition name (syscall_definition.definition.name) are not always the
  # same.
  """

  if DEGUG:
    print("Trying:", syscall_definition)

  # get the syscall function to execute.
  syscall_func = getattr(LIBC, syscall_definition.name, None)

  if(syscall_func == None):
    if DEGUG:
      print("Syscall not found in LIBC:", syscall_definition.name)
      print()
    return

  # get the required argument types and argument values for this syscall
  # function.
  syscall_argtypes, syscall_argvalues = get_syscall_arginfo(syscall_definition)

  if syscall_argtypes == None:
    if DEGUG:
      print("Not Supported:", syscall_definition.name)
      print()
    return
  
  if DEGUG:
    print("Executing syscall funtion:", syscall_definition.name)
    print()

  # set the required argument types for the syscall function.
  syscall_func.argtypes = syscall_argtypes
  
  # call the syscall function with the derived arguments values unpacked
  syscall_func(*syscall_argvalues)



def init():
  # create a file if it does not already exist, to use as the path in syscalls.
  if not os.path.exists(FILEPATH):
    f = open(FILEPATH, 'w+')
    f.close()


def main():
  init()

  # to avoid generating long trace files, instead of generating the syscall
  # definitions we pickle them in.

  # need exactly one argument which is the pickle file from which to get the
  # syscall definitions.
  if len(sys.argv) != 2:
    raise Exception("Please give the name of the pickle file from which to " + 
                    "read syscall definitions.")

  # get the syscall definitions from the pickle file
  pickle_file = open(sys.argv[1], 'rb')
  syscall_definitions = pickle.load(pickle_file)
  
  # do not execute exit because it will cause the program to terminate.
  # do not execute pause because it pauses the program's execution.
  skip_syscalls = ["exit", "pause"]

  for sd in syscall_definitions:
    #if(sd.name == "open"):
    
    # check if we have a definition for this syscall first.
    if(sd.type == SyscallDefinition.SyscallDefinition.FOUND):
      if sd.name not in skip_syscalls:
        execute_syscall(sd)


      

if __name__ == '__main__':
  main()

