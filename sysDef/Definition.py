from SyscallParameter import SyscallParameter

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
        A list of SyscallParameter objects each describing a parameter of the definition.
    
    """

    def __init__(self, definition_line):
        """
        <Purpose>
          Creates a Definition object.
        
          A Definition object has a return type variable, which is a string
          describing the return type of the definition, a name variable, which is
          the name of the definition and a list of SyscallParameter objects describing all
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
            self.name = self.name[1:]    # remove the asterisk from name
            self.ret_type += "*"    # and add it to the return type.

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
            parameter = SyscallParameter(param_string)

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
