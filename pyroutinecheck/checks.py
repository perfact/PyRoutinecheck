# BUILTIN
import os
import subprocess
import datetime

# PIP
import psutil

# CUSTOM
from check import Check
import generic


class Check_Firewall(Check):

    def check_interactive(self):

        output = {}

        filter_rules = self.utils.get_firewall_chains(table_name='filter')
        for chain in filter_rules.keys():
            output[chain] = filter_rules[chain]

        mangle_rules = self.utils.get_firewall_chains(table_name='filter')
        for chain in mangle_rules.keys():
            output[chain] = mangle_rules[chain]

        nat_rules = self.utils.get_firewall_chains(table_name='nat')
        for chain in nat_rules.keys():
            output[chain] = nat_rules[chain]

        return output


class Check_Top(Check):

    def check_interactive(self):

        return {'shell_programm': ['top']}


class Check_Monit(Check):

    def check_interactive(self):

        return {'shell_programm': ['lynx', 'http://localhost:2812']}


class Check_Syslog(Check):

    def check_interactive(self):
        distro = self.sysinfo['linux_distro']

        if distro['name'] == 'Ubuntu':
            output = self.utils.filter_logfile(
                log_path='/var/log/syslog',
                keywords=['kernel', 'error']
            )
        else:
            output = self.utils.filter_logfile(
                log_path='/var/log/messages',
                keywords=['kernel', 'error']
            )

        return output


class Check_Authlog(Check):

    def check_interactive(self):
        distro = self.sysinfo['linux_distro']

        if distro['name'] == 'Ubuntu':
            output = self.utils.filter_logfile(
                log_path='/var/log/auth.log',
                keywords=['ssh', 'root']
            )
        else:
            output = self.utils.filter_logfile(
                log_path='/var/log/messages',
                keywords=['ssh', 'root']
            )

        return output


class Check_Varlog(Check):

    '''
    checks for files and directories in /var/log/ bigger than a given size [MB]
    '''

    def check_interactive(self):

        output = {}

        output['varlog_size'] = '{} MB'.format(
            self.utils.get_dir_size(start_path='/var/log/')
        )

        output['bigLogFiles'] = self.utils.get_bigfiles(
            size=1,
            start_path='/var/log/'
        )

        output['bigDirectories'] = self.utils.get_bigdirs(size=1)

        return output


class Check_Packages(Check):

    def check_interactive(self):

        distro = self.sysinfo['linux_distro']
        packages = self.config.listOfPackages

        packages.sort()

        output = {}

        if distro['name'] == 'Ubuntu':

            package_stati = self.utils.get_dpkg_package_info(packages)

            output['package_stati'] = package_stati
            return output

        else:
            # write distro-specific function in utils
            pass

        return output

    def check_mail(self):
        return self.check_interactive()


class Check_Cluster_Heartbeat(Check):

    def check_interactive(self):

        output = self.utils.nl('######## Cluster Status ########')

        # check for heartbeat-existance this way?!
        heartbeat = self.utils.file_exists('/etc/ha.d/ha.cf')

        if not heartbeat:
            output += self.utils.nl('Heartbeat not found!')
            return output

        output += self.utils.nl('Heartbeat found! Status :')
        rscstatus = self.utils.safe_syscall(['cl_status', 'rscstatus'])[1]
        output += self.utils.nl(
            'Heartbeat ressource status: {}'.format(rscstatus)
        )

        return output

    def check_mail(self):
        return self.check_interactive()


class Check_Drbd(Check):

    def check_interactive(self):

        output = self.utils.nl('######## drbd status ########')

        drbd = self.utils.file_exists('/proc/drbd')

        if not drbd:
            output += self.utils.nl('drbd not found!')
            return output

        with open('/proc/drbd', 'r') as f:
            drbd_status = f.readlines()
            # check drbd status here
            for line in drbd_status:
                output += line

        return output

    def check_mail(self):
        return self.check_interactive()


class Check_Raid(Check):

    def check_interactive(self):

        output = self.utils.nl('######## raid status ########')

        with open('/proc/mdstat', 'r') as f:
            mdstat_lines = f.readlines()

        raid_lines = [line for line in mdstat_lines if 'raid' in line.lower()]

        if not raid_lines:
            output += self.utils.nl('No raid found!')
            return output

        for line in mdstat_lines:
            output += line

        return output

    def check_mail(self):
        return self.check_interactive()


class Check_Zope(Check):

    def check_interactive(self):

        output = self.utils.nl('######## zope check ########')

        for proc in psutil.process_iter():
            if proc.name() == 'runzope':
                zope_pid = proc.pid
                zope_exe = proc.exe()
                zope_running = proc.create_time()
                zope_running = datetime.datetime.fromtimestamp(zope_running)
                zope_running = zope_running.strftime("%Y-%m-%d %H:%M:%S")
                output += self.utils.nl('Zope running!')
                output += self.utils.nl('PID: {}'.format(zope_pid))
                output += self.utils.nl('Path: {}'.format(zope_exe))
                output += self.utils.nl(
                    'Running since: {}'.format(zope_running)
                )
                return output

        output += self.utils.nl('Zope not running!')
        return output

    def check_mail(self):
        return self.check_interactive()


class Check_Sysinfo(Check):

    def check_interactive(self):

        output = self.sysinfo

        return output
