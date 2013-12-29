"""
<Started>
  June 2013

<Author>
  Savvas Savvides <savvas@purdue.edu>

<Purpose>
  Parse the definition of a system call into a SyscallDefinition object.

  Read the man page of a system call and extract its definition. If a definition
  with the exact system call name is not found then pick one with a similar name
  if such a definition exists. If there are multiple definitions for the same
  system call then choose the one with the most arguments.

  Examples demonstrating the above:

  man 2 chown32 gives the same page as man chown so for chown32 definition is:
    int chown(const char *path, uid_t owner, gid_t group)

  from open man page:
    int open(const char *pathname, int flags);
    int open(const char *pathname, int flags, mode_t mode); <-- pick this one.
  so we pick the second definition which has the most arguments.


  Manual pages (man) are read using the subprocess library.


  Example running this program:

  running:
    python3 SyscallDefinition.py open

  will return the definition of the open syscall which is:
    Syscall Name: open
    Definition:   int open(const char *pathname, int flags, mode_t mode)

"""

import re
import subprocess

# controls printing
DEBUG = False


class Parameter:
  """
  <Purpose>
    This object is used to describe a parameter of system call definitions.

  <Attributes>
    self.type:
      the data type of the argument, this can be for example int or char

    self.name:
      this is the name given to the parameter, for example pathname or domain

    self.ellipsis:
      ellipsis can appear in some syscalls indicating additional unspecified
      arguments may be required 
      e.g. int fcntl(int fd, int cmd, ...)

    self.enum:
      long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data)

    self.array:
      int execve(const char *filename, char *const argv[], char *const envp[])

    self.const:
      int execve(const char *filename, char *const argv[], char *const envp[])

    self.union:
      long nfsservctl(int cmd, struct nfsctl_arg *argp, union nfsctl_res *resp)

    self.struct:
      int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)

    self.pointer:
      int access(const char *pathname, int mode)

    self.unsigned:
      int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)

    self.function:
      int clone(int (*fn)(void *), void *child_stack, int flags, void *arg, ...)

    self.const_pointer:
      int execve(const char *filename, char *const argv[], char *const envp[])

  """

  def __init__(self, parameter_string):
    """
    <Purpose>
      Creates a Parameter object.

      The passed parameter_string is made up from the parameter type and a
      parameter name. We need both the type and the name along with some other
      derived information, to fully describe the parameter. 
      
      Example:
      Full definition: int open(const char *pathname, int flags);
      Example parameter string: const char *pathname
      
      In this example the name of the parameter is pathname and the type of the
      parameter is char. The type should be further described as const and
      pointer.

    <Arguments>
      parameter_string:
        The string part from a system call definition that describes a single 
        parameter.

    <Exceptions>
      An Exception will be raised if the format of the parameter string is not
      recognized.
    
    <Side Effects>
      None

    <Returns>
      None
    """

    # Let's first initialize all required fields.
    self.type = None
    self.name = None
    self.ellipsis = False
    
    # fields describing the type of the parameter.
    self.enum = False
    self.array = False
    self.const = False
    self.union = False
    self.struct = False
    self.pointer = False
    self.unsigned = False
    self.function = False
    self.const_pointer = False

    # a parameter could be the ellipsis ("...")
    if(parameter_string == "..."):
      # type and name of the parameter remain None
      self.ellipsis = True
      return

    # parameter can be a function pointer eg in clone: 
    # int clone(int (*fn)(void *), void *child_stack, int flags, void *arg, ...)
    # ==> int (*fn)(void *)
    if(parameter_string.endswith(")")):
      self.function = True
      # type will hold the return type of the function
      self.type = parameter_string[:parameter_string.find(" (*")].strip()
      # name will hold everything else.
      # TODO: could potentially be more fine-grained parsed.
      self.name = parameter_string[parameter_string.find(" (*"):].strip()
    
    else:
      # otherwise name is the right-most part and everything else is the type.
      self.type, self.name = parameter_string.rsplit(None, 1)
    
    # if the name starts with a "*" the parameter is a pointer.
    if(self.name.startswith("*")):
      self.pointer = True
      self.name = self.name[1:] # remove the asterisk.

    # if the name ends with a "[]" the parameter is an array.
    if(self.name.endswith("[]")):
      self.array = True
      self.name = self.name[:-2] # remove square brackets.

    # split and examine the parts of the type.
    while(len(self.type.split()) > 1):
      item, self.type = self.type.split(None, 1)

      if(item == "unsigned"):
        self.unsigned = True
      elif(item == "const"):
        self.const = True
      elif(item == "struct"):
        self.struct = True
      elif(item == "union"):
        self.union = True
      elif(item == "enum"):
        self.enum = True
      else:
        # it could be a constant pointer eg char *const argv[] in execve in
        # which case the item variable holds the correct type of the pointer and
        # self.type variable should hold the string "*const"
        if(self.type == "*const"):
          self.const_pointer = True
          self.type = item
        else:
          # if this is not the case then an unexpected format was encountered.
          raise Exception("Unexpected part in parameter: " + parameter_string)
  
  def __repr__(self):
    """
    This should match the original representation of the parameter as it appears
    in the man page it was originally parsed from.
    """

    if(self.ellipsis):
      return "..."

    representation = ""
    
    if(self.const):
      representation += "const "
    
    if(self.struct):
      representation += "struct "

    if(self.union):
      representation += "union "

    if(self.enum):
      representation += "enum "
    
    if(self.unsigned):
      representation += "unsigned "

    representation += self.type + " "
    
    # const pointer comes after the type.
    if(self.const_pointer):
      representation += "*const "

    if(self.pointer):
      representation += "*"
    
    representation += self.name

    # square brackets come right after the name.
    if(self.array):
      representation += "[]"

    return representation
      


class Definition:
  """
  <Purpose>
    A Definition object is made up of three parts: 
      - definition return type
      - definition name 
      - definition parameters
  
  <Attributes>
    self.ret_type:
      The return type of the syscall definition.

    self.name:
      The name of the definition. This is not always the same as the syscall 
      name.

    self.parameters:
      A list of Parameter objects each describing a parameter of the definition.

  """

  def __init__(self, definition_line):
    """
    <Purpose>
      Creates a Definition object.

      A Definition object has a return type variable, which is a string
      describing the return type of the definition, a name variable, which is
      the name of the definition and a list of Parameter objects describing all
      parameters of the definition.

    <Arguments>
      definition_line:
        A string with the definition in a single line as it appears in the 
        manual page of the corresponding system call, with any comments removed.

    <Exceptions>
      None
    
    <Side Effects>
      None

    <Returns>
      None
    """

    # get the beginning of the line before the first opening bracket. This part
    # holds the return type and the name of the definition. The remaining part
    # holds the parameters of the definition.
    def_beginning, parameters_string = definition_line.split("(", 1)
    
    # get the name and the return type of the definition. Name is a single word
    # at the end of def_beginning, and the rest is the return type.
    self.ret_type, self.name = def_beginning.rsplit(None, 1)

    # return type can be a pointer in which case the '*' character will be
    # included in the name of the definition instead of the return type. 
    if(self.name.startswith("*")):
      self.name = self.name[1:] # remove the asterisk from name
      self.ret_type += "*"      # and add it to the return type.

    # remove brackets and semi-colon from the end of the parameters and split
    # them into a list of type-name parameters.
    parameters_list = parameters_string.strip("();").split(", ")
    
    self.parameters = []
    
    # syscall definitions with no parameters are given as (void) in which case
    # the parameter_list will have its first (and only) item as "void". In this
    # case we leave the self.parameters as an empty list. Example void
    # definition: pid_t fork(void)
    if(parameters_list[0] == "void"):
      return

    for param_string in parameters_list:
      # replace whitespace with space
      param_string = " ".join(param_string.split())

      # if there is a "*" on its own, join it with the subsequent parameter. This
      # can happen eg: int sched_rr_get_interval(pid_t pid, struct timespec * tp);
      param_string = param_string.replace("* ", "*")

      # parse the parameter.
      parameter = Parameter(param_string)

      # test whether the parameter was parsed completely and correctly.
      assert(str(parameter) == param_string)

      self.parameters.append(parameter)
      

  def __repr__(self):
    """
    This should match the original representation of the definition as it
    appears in the man page it was originally parsed from.
    """

    # firstly generate the representation for the parameters.
    parameters_string = ''
    first = True
    for par in self.parameters:
      if(first):
        parameters_string += str(par)
        first = False
      else:
        parameters_string += ", " + str(par)

    return self.ret_type + " " + self.name + "(" + parameters_string + ")"




class SyscallDefinition:
  """
  <Purpose>
    A SyscallDefinition is made up of the system call name and its definition 
    parsed from its man page.

    The reason of having this object in addition to the Definition object is
    because the name of the system call and the definition name are not
    necessarily the same, but most of the times are. For example the name of the
    system call can be 'chown32' and the name of its definition 'chown'.

    Some intuition regarding the above taken from chown man page:
    The original Linux chown(), fchown(), and lchown()  system  calls  sup‐
    ported  only  16-bit user and group IDs.  Subsequently, Linux 2.4 added
    chown32(), fchown32(), and  lchown32(),  supporting  32-bit  IDs.   The
    glibc  chown(),  fchown(), and lchown() wrapper functions transparently
    deal with the variations across kernel versions.

  <Attributes>
    name:
      The name of the system call
    
    type:
      The type of the definition. Can be one of:
       - NO_MAN_ENTRY:
          no man entry was found for this syscall name

       - NOT_FOUND:
          man entry found but no definition found inside

       - UNIMPLEMENTED:
          syscall identified as unimplemented

       - FOUND:
          definition for this system call was found

    
    definition:
      Holds the definition object if the type is FOUND. Otherwise definition is 
      set to None.

  """

  # types of SyscallDefinitions.
  NO_MAN_ENTRY = 1 
  NOT_FOUND = 2    
  UNIMPLEMENTED = 3
  FOUND = 4        


  def __init__(self, syscall_name):
    """
    <Purpose>
      Creates a SyscallDefinition object.

      A SyscallDefinition object has a name, which is the name of the system
      call, a type, which is defined in terms of the for types given above and
      finally, a definition object.

    <Arguments>
      syscall_name:
        The name of the system call for which to create a SyscallDefinition 
        object.

    <Exceptions>
      None
    
    <Side Effects>
      None

    <Returns>
      None
    """
    self.name = syscall_name
    self.type, self.definition = self._parse_definition(self.name)


  def _parse_definition(self, syscall_name):
    """
    <Purpose>
      Reads the man entry of the system call whose name is given as a parameter
      and returns its definition as a Description object along with what kind of
      definition it is.

    <Arguments>
      syscall_name:
        The name of the system call for which to get the definition.

    <Exceptions>
      None
    
    <Side Effects>
      None

    <Returns>
      (self.NO_MAN_ENTRY, None):   if no manual entry was found.
      (self.NOT_FOUND, None):      if man entry found but definition not found.
      (self.UNIMPLEMENTED, None):  if the system call was identified as unimplemented.
      (self.FOUND, Definition()):  if the definition was found.
    """
    
    if DEBUG:
      print("Given name of syscall to parse: " + syscall_name)

    # read the man page of syscall_name into a byte string.
    #
    # TODO: reading entire man page: current implementation is not concerned 
    # with performance too much.
    try:
      man_page_bytestring = subprocess.check_output(['man', '2', syscall_name])
    except subprocess.CalledProcessError:
      # if a man entry does not exist no definitions exists.
      return self.NO_MAN_ENTRY, None

    # cast to string and split into a list of lines.
    man_page_lines = man_page_bytestring.decode("utf-8").split("\n")

    """
    Example of the open man page, upto the definitions part:

    <--start example-->
          OPEN(2)                  Linux Programmer's Manual           OPEN(2)

          NAME
                 open, creat - open and possibly create a file or device

          SYNOPSIS
                 #include <sys/types.h>
                 #include <sys/stat.h>
                 #include <fcntl.h>

                 int open(const char *pathname, int flags);
                 int open(const char *pathname, int flags, mode_t mode);

                 int creat(const char *pathname, mode_t mode);

          DESCRIPTION
    <--end example-->


    Note that, as shown in the example above, a man page can have multiple
    definitions for the same system call (2 definitions given for open) and it
    can also include definitions of similar but different system calls (creat).

    """

    # in some platforms attempts to access the man page of system calls ending
    # with 32 eg chown32 return the man page of the system call without the 32
    # eg chown. Same goes for syscalls ending with 64. Other platforms can
    # instead return an empty string which means the syscall definition will not
    # be discovered. If this happens check if there is a man page for the
    # syscall without the number at the end.
    if len(man_page_lines) == 1 and man_page_lines[0] == '':
      # read the man page of syscall_name into a byte string.
      if(syscall_name.endswith("32") or syscall_name.endswith("64")):
        try:
          man_page_bytestring = subprocess.check_output(['man', '2', syscall_name[:-2]])
        except subprocess.CalledProcessError:
          # if a man entry does not exist no definition exists.
          return self.NO_MAN_ENTRY, None

        # cast to string and split into a list of lines.
        man_page_lines = man_page_bytestring.decode("utf-8").split("\n")
      else:
        return self.NO_MAN_ENTRY, None


    # a regular expression used to sanitize the read lines. Specifically it
    # removes the backspace characters and the character they hide to allow
    # searching for substrings. e.g. the string "example\b" will be replaced
    # with the string "exampl".
    char_backspace = re.compile(".\b")

    # remove all lines until the "SYNOPSIS" line since the definitions of the
    # system calls are given right after this line. Refer to the example man
    # page given above for more information.
    while True:
      if len(man_page_lines) == 0:
        raise Exception("Reached end of man page while looking for SYNOPSIS " + 
                        "line")

      # read the first line
      line = man_page_lines[0]

      # and then remove the line
      man_page_lines.pop(0)

      # line could include backspaces \b which prevents from searching the line 
      # correctly. Remove backspaces.
      # e.g. __llllsseeeekk(2)                  1.2
      line = char_backspace.sub("", line)

      # if the line is the synopsis line we don't want to remove any more lines.
      if (line == "SYNOPSIS"):
        break
    
    # examine the lines until the 'DESCRIPTION' line is met, indicating the end
    # of the synopsis part. Examine each line in between for whether it is a
    # definition.
    all_definitions = []
    while True:
      if len(man_page_lines) == 0:
        raise Exception("Reached end of man page while looking for " + 
                        "DESCRIPTION line.")

      line = man_page_lines.pop(0).strip()
      
      # sanitize line
      line = char_backspace.sub("", line)

      # when we reach the description line then we can safely stop.
      if (line == "DESCRIPTION"):
        break

      # if the line includes the word "Unimplemented" then the system call is
      # unimplemented.
      if("Unimplemented" in line):
        return self.UNIMPLEMENTED, None

      # we can skip the type definition lines.
      if(line.startswith("typedef")):
        continue

      # remove comments if any. comments are wrapped in "/* */"
      if("/*" in line and "*/" in line):
        line = line[:line.find("/*")] + line[line.rfind("*/")+2:]
        line = line.strip()

      # a definition line must contain at least two parts (separated by
      # whitespace) and an opening bracket, otherwise it's not a definition. It
      # is possible that definition spans multiple lines hence we don't
      # expect it to have its closing bracket in the current line.
      if(not (len(line.split()) > 1 and "(" in line)):
        continue
      
      # a definition can sometimes span multiple lines. If a definition line
      # does not end with a semi-colon then the definition spans multiple lines.
      # For up to three times or until the line ends with a semi-colon, join the
      # line with the subsequent line.
      times = 0
      while(not line.endswith(";")):
        # join the line with the subsequent line, without removing it from the
        # man_page_lines, to avoid skipping a definition.
        line += " " + man_page_lines[times].strip()

        # remove comments from the newly created line.
        if("/*" in line and "*/" in line):
          line = line[:line.find("/*")] + line[line.rfind("*/")+2:]
          line = line.strip()
        
        # definitions cannot span more than 3 lines so don't join more than 3
        # lines.
        times += 1
        if(times == 3):
          break

      # at this point a complete definition must contain at least two
      # parts(separated by whitespace), an opening bracket, a closing bracket
      # and end with a semi-colon. if any of these requirements are missing,
      # then the line is not a definition and we skip it.
      if(not(len(line.split()) > 1 and "(" in line and line.endswith(");"))):
        continue

      if DEBUG:
        print(line)

      all_definitions.append(Definition(line))
    
    # We will consume some of these definitions but let's keep the
    # all_definitions variable intact which holds all the definitions parsed
    # from the man page. It might be useful in the future.
    definitions = all_definitions[:]

    # As shown in the example above, some manual pages include multiple
    # definitions. Remove definitions whose name does not start with the syscall
    # name given. At the same time note that a definition name can sometimes
    # have a "_" in front of it eg _exit instead of exit.
    def_index = 0
    while(def_index < len(definitions)):
      # remove the "_" if what's remaining is similar to the syscall_name.
      if(definitions[def_index].name.startswith("_") 
           and syscall_name.startswith(definitions[def_index].name[1:])):
        definitions[def_index].name = definitions[def_index].name[1:]

      # only keep the definitions whose name is the first part of the
      # syscall_name we care about. Remove all the other definitions. For
      # example if the syscall_name is "chown32" we want to keep the definition
      # with name "chown" but not the one with name "fchown".
      if(syscall_name.startswith(definitions[def_index].name)):
        def_index += 1 # increment index so we keep this item
      else:
        definitions.pop(def_index) # remove this item, don't incrementing index

    if(len(definitions) == 0):
      # if there are no definitions left, then we could not find a suitable
      # definition for this syscall_name
      return self.NOT_FOUND, None

    elif(len(definitions) == 1):
      # if there is exactly one definition left, then it must be the one we
      # need.
      return self.FOUND, definitions[0]

    else:
      # if there are more than one definitions left, choose and return the best
      # definition. Best definition is one whose name matches exactly the given
      # syscall name. If there is no such definition then there might be one
      # without the number at the end. eg eventfd2 definition is the same as
      # eventfd. If there are multiple such definitions then choose the one with
      # the most parameters, eg in the open system call example given above.

      # are there definitions with the exact same name as the given
      # syscall_name?
      same_name_definitions = []
      for definition in definitions:
        if(definition.name == syscall_name):
          same_name_definitions.append(definition)

      if(len(same_name_definitions) > 0):
        # return the definition with the most parameters.
        most_parameters_index = 0
        for sd_index in range(len(same_name_definitions)):
          if(len(same_name_definitions[sd_index].parameters)
               > len(same_name_definitions[most_parameters_index].parameters)):
            most_parameters_index = sd_index

        return self.FOUND, same_name_definitions[most_parameters_index]

      # if no same-name definitions were found, let's check if there are similar
      # definitions with the same name but without the number at the end.
      similar_definitions = []
      for definition in definitions:
        m = re.search(r'(*)\d+$', definition.name)
        if(m):
          if(m.group(1) == syscall_name):
            similar_definitions.append(definition)
      
      # from experience there is at most one such definition but let's assert to
      # be certain.
      assert len(similar_definitions) <= 1

      if(len(similar_definition) == 0):
        return self.NOT_FOUND, None
      return self.FOUND, similar_definitions[0]


  def __repr__(self):
    representation = "Syscall Name: " + self.name + "\nDefinition:   "

    if(self.type == self.NO_MAN_ENTRY):
      representation += "No man entry found for this system call name."
    elif(self.type == self.NOT_FOUND):
      representation += "Definition not found in man page."
    elif(self.type == self.UNIMPLEMENTED):
      representation += "System call is Unimplemented"
    else:
      representation += str(self.definition)

    return representation





def main():
  import sys

  if(len(sys.argv) != 2):
    print("Usage: python3 " + sys.argv[0] + " <syscall_name>")
    exit()

  syscall_definition = SyscallDefinition(sys.argv[1])
  print(syscall_definition)

if __name__ == "__main__":
  main()
