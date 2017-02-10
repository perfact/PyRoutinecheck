from pyroutinecheck import checks as checks
from pyroutinecheck import custom_checks as custom_checks

# detect DB-Utils version by calling url
pfinfourl = 'http://localhost:9081/PerFact/DB_Utils/VERSION'

# checks to perform
# add new to checks to list if needed
# read lib/checks.py and lib/custom_checks.py for cheks available
listOfChecks = [
    checks.Check_Sysinfo,
    checks.Check_Top,
    checks.Check_Monit,
    checks.Check_Firewall,
    checks.Check_Syslog,
    checks.Check_Authlog,
    checks.Check_Varlog,
    checks.Check_Packages,
    checks.Check_Cluster_Heartbeat,
    checks.Check_Drbd,
    checks.Check_Raid,
    checks.Check_Zope,
    # custom_checks.Custom_Check,
]

# packages routinecheck has to look for using package-manager
listOfPackages = [
    'rinetd', 'asterisk', 'apache', 'apache2', 'bind', 'bind9',
    'cups', 'dhcp-server', 'dhcp3-server', 'samba', 'squid',
    'ldap', 'spamassassin', 'openldap', 'openldap2', 'clamav',
    'amavis', 'postfix', 'openvpn', 'postgresql', 'swan',
    'amavisd-new', 'openswan', 'freeswan', 'zope', 'zope2.13',
    'monit', 'dovecot', 'dovecot2', 'dovecot20',
    'dovecot-common', 'python'
]

# Inventory-mail
# activate / deactivate sending mail when running
# mail can be sent manually by calling Routinecheck.write_mail()
# configure mail server
mail = True
mail_from = 'noreply@perfact.de'
mail_to = 'monitoring@perfact.de'
mail_server = {
    'host': 'localhost',
    'port': 25
}
# change format of inventory port in mail
# current possible values are : 'tables' and 'json'
mail_format = 'tables'

# Cluster
# activate / deactivate jumping to othernode after check
# configure hostname of othernode
cluster = False
cluster_othernode = None
