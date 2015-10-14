
class SyscallParameter:
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
          Creates a SyscallParameter object.
        
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
            self.name = self.name[1:]    # remove the asterisk.

        # if the name ends with a "[]" the parameter is an array.
        if(self.name.endswith("[]")):
            self.array = True
            self.name = self.name[:-2]    # remove square brackets.

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

    def __str__(self):
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
