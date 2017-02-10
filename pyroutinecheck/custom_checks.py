# BUILTIN
import os
import subprocess
import datetime

# PIP
import psutil

# CUSTOM
from check import Check
import generic

# TEMPLATE FOR SIMPLE CUSTOM CHECK


class Custom_Check(Check):

    def check_interactive(self):
        # return check result as string or dictionary
        # dictionaries will be prettified using prettytable!
        # utils module can be accessed using self.utils
        # config module can be accessed using self.config
        # sysinfo dictionary can be accessed using self.sysinfo
        return 'New custom check'

    def check_mail(self):
        # put check result to mail
        return self.check_interactive()

# TEMPLATE FOR CUSTOM CHECK CALLING SHELL PROGRAMM


class Custom_Check_Shell(Check):

    def check_interactive(self):
        # if you want to call a shell programm like top, use this!
        return {'shell_programm': ['top']}
