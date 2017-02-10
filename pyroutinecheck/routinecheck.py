# BUILTIN
import smtplib
from email.MIMEText import MIMEText
import imp
import sys
import os
import json

# CUSTOM
import utils


class Routinecheck(object):

    '''
    main class called by admin to perform routinecheck using run()
    '''

    format_map = {
        'tables': utils.prettify,
        'json': utils.prettify_json
    }

    def __init__(self, config_path):

        self.config_path = config_path

        self.utils = utils
        self.get_config()
        self.get_sysinfo()
        self.build_checks()

    def get_config(self):
        '''
        import config variables from python module
        crash if config can't be loaded
        '''

        config_module = imp.load_source(
            'config_module',
            self.config_path
        )
        self.config = config_module

    def build_checks(self):
        '''
        builds instances of checks given in self.config
        puts check instances to self.checks
        '''

        self.checks = []
        listOfChecks = self.config.listOfChecks
        for check_class in listOfChecks:
            check = check_class(self)
            self.checks.append(check)

    def get_sysinfo(self):
        '''
        call get_sysinfo from utils to acquire basic system information
        which may be useful in checks
        sysinfo will also be put to inventory mail
        '''

        self.sysinfo = utils.get_sysinfo()

    def run(self):
        '''
        main method started to perform routinecheck
        '''

        for check in self.checks:
            check.execute_interactive()

        if self.config.mail:
            if not self.config.cluster:
                self.write_mail()
            else:
                '''
                cluster-mailing: write temp_mail on first node,
                copy it to second node, add temp_mail to mail on second node
                '''
                if self.utils.file_exists('/tmp/temp_mail'):
                    with open('/tmp/temp_mail', 'r') as f:
                        first_mail = f.read()
                    mail = first_mail + '\n' + self.write_mail(debug=True)
                    self.send_mail(mail)
                else:
                    othernode = self.config.cluster_othernode
                    first_mail = self.write_mail(debug=True)
                    with open('/tmp/temp_mail', 'w') as f:
                        f.write(first_mail)
                    os.system('scp /tmp/temp_mail {}:/tmp/'.format(othernode))
                    print 'FIRST NODE, REMEMBER TO CHECK OTHER NODE!'
                os.system('rm /tmp/temp_mail')

    def dryrun(self):
        '''
        perform dryrun of complete routinecheck, primary testing method
        '''

        for check in self.checks:
            check.execute_dryrun()

        self.write_mail(debug=True)

        print 'OK'

    def write_mail(self, debug=False):
        '''
        mail body is built here by running checks in inventory mode
        '''

        mail_builder = self.format_map[self.config.mail_format]
        mail = mail_builder(self.sysinfo)

        mail += '\n######## CHECK RESULTS ########\n'

        for check in self.checks:
            result = check.execute_mail()
            if result:
                mail += result

        if debug:
            return mail
        else:
            self.send_mail(mail)

    def send_mail(self, text):
        '''
        sends prebuilt mail to configured address using configured
        '''

        mail_server = self.config.mail_server
        mail_host = mail_server['host']
        mail_port = mail_server['port']

        s = smtplib.SMTP()
        # uses host = localhost and port = 25 as default!
        s.connect(
            host=mail_host,
            port=mail_port
        )
        msg = MIMEText(text)
        msg['Subject'] = 'INFO;manid:{}'.format(self.sysinfo['pfsystemid'])
        msg['From'] = self.config.mail_from
        msg['To'] = self.config.mail_to
        s.sendmail(msg['from'], msg['to'], msg.as_string())
        s.close()

        print('Inventory mail sent to {}'.format(msg['to']))
