import pydoc
import subprocess


class Check(object):

    '''
    Wrapper class used to perform checks
    All productive checks inherit from this class.

    Abstract methods check_interactive and check_mail may be implemented
    to create interactive checks (output in pager) or to be added to
    inventory mail (output in mail)

    Routinecheck configuration module is available by accessing
      self.routinecheck.config
    Example:
      packages = self.routinecheck.config.packages

    Routinecheck sysinfo dictionary is available by accessing
      self.routinecheck.sysinfo
    Example:
      distribution = self.routinecheck.sysinfo['linux_distro']

    Routinecheck utils module is available by accessing
      self.routinecheck.utils
    Example:
      logfile = self.routinecheck.utils.open_logfile('/...')
    '''

    def __init__(self, routinecheck):
        self.routinecheck = routinecheck
        self.sysinfo = routinecheck.sysinfo
        self.config = routinecheck.config
        self.utils = routinecheck.utils

    def execute_interactive(self):

        output = self.check_interactive()

        # if type(output) == type({}):
        if isinstance(output, dict):
            # if output.has_key('shell_programm'):
            if 'shell_programm' in output:
                subprocess.call(output['shell_programm'])
                return
            output = self.routinecheck.utils.prettify(output)
        pydoc.pager(output)

    def execute_mail(self):

        output = self.check_mail()

        # if type(output) == type({}):
        if isinstance(output, dict):
            output = self.routinecheck.utils.prettify(output)

        return output

    def execute_dryrun(self):

        output = self.check_interactive()

        # if type(output) == type({}):
        if isinstance(output, dict):
            # if output.has_key('shell_programm'):
            if 'shell_programm' in output:
                try:
                    proc = subprocess.Popen(output['shell_programm'])
                    proc.kill()
                except:
                    exit('{} has failed!'.format(self.__class__))

    # abstract methods to be implemented in subclass
    def check_interactive(self):
        pass

    def check_mail(self):
        pass
