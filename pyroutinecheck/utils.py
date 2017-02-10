# BUILTINS
import os
import subprocess
import socket
import platform
import urllib  # use urllib to stay compatible to python 2.4
import time
import json
# removed apt because of missing dependencies during pip-installation
# import apt

# OTHER
import psutil  # use psutil 2.1.3 for python < 2.6
import prettytable
import iptc

# CUSTOM
import generic

'''
utils-module

This module is part of the PyRoutinecheck package and provides
useful functions to be used in checks.
This module utilizes several python-libraries acquire system-
informations nad is normally run from virtualenv python environment
'''

# mapping for human readable addresstypes
addresstype_map = {
    2: 'IPV4',
    10: 'IPV6',
    17: 'MAC'
}

safe_syscall = generic.safe_syscall


def get_dir_size(start_path='/var/log/'):
    '''
    returns size of given path in MB
    '''

    total_size = 0
    for dirpath, dirnames, filenames in os.walk(start_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)
    return round(total_size / (10.0 ** 6), 2)


def get_bigfiles(size=1, start_path='/var/log/'):
    '''
    returns list of dictionaries containg files bigger than given size in MB
    starts recursevily from given path
    '''

    listOfFiles = []
    for dirpath, dirnames, filenames in os.walk(start_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if not os.path.islink(fp):
                file_size = round(os.path.getsize(fp) / (10.0 ** 6), 2)
            else:
                file_size = 0
            if file_size > size:
                bigfile_d = {
                    'path': fp,
                    'size_mb': file_size
                }
                listOfFiles.append(bigfile_d)
    return listOfFiles


def get_bigdirs(size=1, start_path='/var/log/'):
    '''
    returns list of triples containg directories bigger than given size in MB
    starts from given path
    '''

    listOfDirs = []
    for dirpath, dirnames, filenames in os.walk(start_path):
        for d in dirnames:
            dp = os.path.join(dirpath, d)
            # if not os.path.islink(dp):
            dir_size = get_dir_size(start_path=dp)
            if dir_size > size or os.path.islink(dp):
                res_d = {
                    'path': dp,
                    'size_mb': dir_size,
                    'link': os.path.islink(dp)
                }
                listOfDirs.append(res_d)
    return listOfDirs


def file_exists(fp):
    '''
    return true if file exists at given path
    '''

    truth = os.path.exists(fp) and os.path.isfile(fp)
    return truth


def nl(line):
    '''
    Safely adds newline-character to given string
    use this instead of + '\n' !
    '''

    return '{}\n'.format(line)


def filter_logfile(log_path, keywords):
    '''
    returns filtered logfile at given path
    keywords must be provided as list!
    '''

    result = 'Filter logfile {0} Keywords: {1}\n'.format(log_path,
                                                         keywords)
    with open(log_path, 'r') as f:
        logfile = f.readlines()
        # BAM list comprehension ftw ;-)
        filtered = [
            line for line in logfile for word in keywords if word in line
        ]
    for fline in filtered:
        result += fline
    return result


def open_logfile(log_path):
    '''
    simply returns logfile at given path
    '''

    result = 'Logfile {}\n'.format(log_path)
    with open(log_path, 'r') as f:
        result += f.read()
    return result


def get_pid(processname):
    '''
    returns process id of give process by name
    returns none if no process is found
    '''

    pidlist = psutil.pids()
    for pid in pidlist:
        process = psutil.Process(pid)
        if process.name() == processname:
            return process.pid
    return None


def get_connections(processname):
    '''
    returns connections of given processname
    result is a list of connections as dictionaries
    '''

    pid = get_pid(processname)
    process = psutil.Process(pid)
    conns = process.connections()

    result = []
    for con in conns:
        con_d = {}
        con_d['family'] = addresstype_map[con.family]
        con_d['localaddr'] = con.laddr
        con_d['remoteaddr'] = con.raddr
        con_d['status'] = con.status
        result.append(con_d)

    return result


def get_listen_connections():
    '''
    returns list of dictionaries with processes having connections in LISTEN-status
    funtionality equals 'lsof -i -n -P | grep LISTEN', but result is delivered in more
    useful way
    '''

    result = []

    pidlist = psutil.pids()
    for pid in pidlist:
        process = psutil.Process(pid)
        conns = process.connections()
        fconns = [con for con in conns if con.status == 'LISTEN']
        for con in fconns:
            connection = {
                'pid': process.pid,
                'name': process.name(),
                'address': con.laddr[0],
                'port': con.laddr[1]
            }
            result.append(connection)
    return result


def get_url(url, params={}):
    '''
    Sends HTTP GET request to given url
    parameters may be applied as dictionary!
    '''

    if params:
        params = urllib.urlencode(params)
        openstring = '{0}?{1}'.format(url, params)
    else:
        openstring = url

    f = urllib.urlopen(openstring)
    output = {
        'html': f.read(),
        'code': f.getcode()
    }
    return output


def post_url(url, params={}):
    '''
    sends HTTP POST request to given url
    parameters must be applied as dictionary
    '''

    params = urllib.urlencode(params)

    f = urllib.urlopen(url, params)

    output = {
        'html': f.read(),
        'code': f.getcode()
    }

    return output


def test_socket(port, host='127.0.0.1'):
    '''
    test wether a given socket can be connected
    returns result as boolean
    '''

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        s.shutdown(2)
        return True
    except socket.error as e:
        return False


def get_linux_distro():
    '''
    utilizes platform module to acquire linux distribution infos
    returns result as dictionary
    '''

    res = {
        'name': platform.linux_distribution()[0],
        'version': platform.linux_distribution()[1],
        'codename': platform.linux_distribution()[2]
    }

    return res


def get_pfsystemid():
    '''
    reads and returns pfsystemid from file
    returns None if file not found, this would be a none-template-system!
    '''

    # pfsystemid
    # maybe path must be configured?!
    pfsystemid_path = '/etc/pfsystemid'
    try:
        with open(pfsystemid_path, 'r') as f:
            pfsystemid = f.read().rstrip('\n')
    except:
        # smells like non-template system
        pfsystemid = None

    return pfsystemid


def get_authorized_keys():
    '''
    reads authorized ssh keys for perfact user, returns list with names of
    users
    crashes if no keys file is found
    '''

    # authorized keys
    authorized_keys_path = '/home/perfact/.ssh/authorized_keys'

    with open(authorized_keys_path, 'r') as f:
        keys_raw = f.readlines()
        # patch: some authorized_keys files have more than one
        # newline-character at the end of file because we live in a godforsaken
        # world...
        for line in keys_raw:
            key_raw = line.split()
            if len(key_raw) < 3:
                continue
            yield key_raw[-1].rstrip('\n')


def get_cpu_info():
    '''
    reads cpu-info from /proc/cpuinfo
    returns list of cpus found
    '''

    with open('/proc/cpuinfo', 'r') as f:
        info_raw = f.readlines()
        model_names = [
            line.rstrip('\n') for line in info_raw if 'model name' in line
        ]

    return model_names


def get_if_addresses():
    '''
    returns list of dictionaries containing addresses of network-interfaces
    '''

    addresses_l = []
    addresses = psutil.net_if_addrs()
    for key in addresses:
        snic_list = addresses[key]
        for item in snic_list:
            addr_d = {
                'interface': key,
                'address': item.address,
                'netmask': item.netmask,
                'broadcast': item.broadcast,
                'type': addresstype_map.get(item.family)
            }
            addresses_l.append(addr_d)
    return addresses_l


def get_if_stats():
    '''
    returns list of dictionaries containing stati of network-interfaces
    '''

    ifstats_l = []
    ifstats = psutil.net_if_stats()
    for key in ifstats:
        iface_d = {}
        snicstats = ifstats[key]
        iface_d['interface'] = key
        iface_d['isup'] = snicstats.isup
        iface_d['duplex'] = snicstats.duplex
        iface_d['speed'] = snicstats.speed
        iface_d['mtu'] = snicstats.mtu
        ifstats_l.append(iface_d)
    return ifstats_l


def get_network_cards():
    '''
    returns list of network cards, one string for each card
    '''

    lspci_raw = safe_syscall(['lspci'])[1].split('\n')
    lspci = [line for line in lspci_raw if 'Ethernet' in line]

    return lspci


def get_routes():
    '''
    returns list of dictionaries containing routes on system
    '''

    # route -n parsed by hand
    routes_raw = safe_syscall(['route', '-n'])[1].split('\n')[2:]
    routes = []
    for line_raw in routes_raw:
        line = line_raw.split(' ')
        line = [char for char in line if char]
        if not line:
            continue
        route = {
            'Destination': line[0],
            'Gateway': line[1],
            'Genmask': line[2],
            'Interface': line[-1]
        }
        routes.append(route)
    return routes


def get_physical_volumes():
    '''
    returns list of dictionaries containing physical volumes on system
    '''

    volumes = []

    # pvs parsed by hand
    pvs_raw = safe_syscall(['pvs'])[1].split('\n')
    for line_raw in pvs_raw:
        line = line_raw.split(' ')
        line = [char for char in line if char]
        if not line:
            continue
        if line[0] == 'File':
            continue
        if line[0] == 'PV':
            continue
        volume = {
            'PV': line[0],
            'VG': line[1],
            'Fmt': line[2],
            'Attr': line[3],
            'PSize': line[4],
            'PFree': line[5]
        }
        volumes.append(volume)
    return volumes


def get_volume_groups():
    '''
    returns list of dictionaries containing volume groups on system
    '''

    groups = []
    vgs_raw = safe_syscall(['vgs'])[1].split('\n')
    for line_raw in vgs_raw:
        line = line_raw.split(' ')
        line = [char for char in line if char]
        if not line:
            continue
        if line[0] == 'File':
            continue
        if line[0] == 'VG':
            continue
        group = {
            'VG': line[0],
            'PV': line[1],
            'LG': line[2],
            'SN': line[3],
            'Attr': line[4],
            'VSize': line[5],
            'VFree': line[6]
        }
        groups.append(group)
    return groups


def get_filesystem_info():
    '''
    returns list of dictionaries containing filesystem disk space usage
    '''

    result = []

    filesystem_raw = safe_syscall(['df', '-h'])[1].split('\n')
    for line in filesystem_raw[1:]:
        items = line.split()
        if not items:
            continue
        filesystem_d = {
            'Filesystem': items[0],
            'Size': items[1],
            'Used': items[2],
            'Avail': items[3],
            'Use%': items[4],
            'Mounted_on': items[5]
        }
        result.append(filesystem_d)

    return result


def get_inodes_info():
    '''
    returns list of dictionaries containing inode usage information
    '''

    result = []

    filesystem_raw = safe_syscall(['df', '-i'])[1].split('\n')
    for line in filesystem_raw[1:]:
        items = line.split()
        if not items:
            continue
        filesystem_d = {
            'Filesystem': items[0],
            'Inodes': items[1],
            'IUsed': items[2],
            'IFree': items[3],
            'IUse%': items[4],
            'Mounted_on': items[5]
        }
        result.append(filesystem_d)

    return result


def get_sysinfo():
    '''
    inventory function

    calls lots of small functions to acquire system-data, wrapping them into
    one dictionary (to rule em' all)

    these infos are available in checks, call help(Check) for reference
    these infos will be also bee written to inventory-mail after prettyfing data into
    tables
    '''

    output = {}

    # fancy distro dict
    output['linux_distro'] = get_linux_distro()

    # hostname
    output['hostname'] = socket.gethostname()

    # kernel + distro - string
    output['system'] = platform.platform()

    # pfsystemid, neccessary for identification in ema
    output['pfsystemid'] = get_pfsystemid()

    # authorized ssh keys
    output['keys'] = list(get_authorized_keys())

    # memory of system in MB
    memory = psutil.virtual_memory()
    output['memtotal [MB]'] = memory.total / 1024

    # cpu info
    output['cpuinfo'] = get_cpu_info()

    # lsof -i -n -P | grep LISTEN
    output['listen_processes'] = get_listen_connections()

    # get addresses of network interfaces
    output['if_addresses'] = get_if_addresses()

    # get stati of network interfaces
    output['if_stats'] = get_if_stats()

    # routes
    output['routes'] = get_routes()

    # hardware - network card
    output['network_card'] = get_network_cards()

    # hardware - physical volumes
    output['volumes'] = get_physical_volumes()

    # volume groups
    output['volume_groups'] = get_volume_groups()

    output['time'] = time.ctime()

    # df -h
    output['filesystem_usage'] = get_filesystem_info()

    # df -i
    output['inodes_usage'] = get_inodes_info()

    return output


def dict_table(indict):
    '''
    creates pretty tables from result-dicts
    '''

    tables = {}
    for key, value in indict.items():

        head = key
        new_table = prettytable.PrettyTable()

        # one battle of ifs to rule all data-types possible

        if type(value) == type(''):
            new_table.add_column(key, [value])

        if type(value) == type([]):

            if not len(value):
                continue

            if type(value[0]) == type({}):
                for heading in value[0].keys():
                    heading_values = [item[heading] for item in value]
                    new_table.add_column(heading, heading_values)

            if type(value[0]) == type(''):
                new_table.add_column(key, value)

        if type(value) == type({}):
            for x, y in value.items():
                new_table.add_column(x, [y])

        if type(value) == type(1) or type(value) == type(1.0):
            new_table.add_column(key, [str(value)])

        tables[key.upper()] = new_table

    return tables


def prettify(indict):
    '''
    utilizes dict_table function to make prettytable-tables from dictionary
    returns string containing prettyfied data from dictionary
    '''

    sort_cols = ['name', 'use%', 'iuse%', 'interface', 'size_mb', 'installed']

    result = ''

    tables = dict_table(indict)

    for table_name, table in tables.items():

        columns = table.field_names

        for column in columns:
            if column.lower() in sort_cols:
                table.sortby = column

        result += nl(table_name)
        result += nl(table.get_string())

    return result


def prettify_json(indict):
    '''
    utilizes json library to generate json-formatted data
    from given string
    '''

    json_dict = json.dumps(
        indict,
        sort_keys=True,
        indent=2
    )

    return json_dict


def get_firewall_chains(table_name):
    '''
    returns dictionary containing rules of every chain by given table name
    '''

    output = {}

    table = iptc.Table(table_name)

    for chain in table.chains:
        chain_rules = []
        for rule in chain.rules:
            packets = rule.get_counters()[0]
            rbytes = rule.get_counters()[1]
            rule_d = {
                'prot': rule.protocol,
                'src': rule.src,
                'dst': rule.dst,
                'in': rule.in_interface,
                'out': rule.out_interface,
                'target': rule.target.name,
                'packets': packets,
                'bytes': rbytes
            }
            chain_rules.append(rule_d)
        output['_'.join([table_name, chain.name])] = chain_rules

    return output


def get_apt_package_info(package_list):
    # CODE NOT IN USE DUE TO BAD DEPENDENCY PROBLEMS WITH PYTHON-APT
    '''
    returns dictionary conatining package information
    IMPORTANT: THIS IS UBUNTU-SPECIFIC CODE!
    CALL THIS ONLY AFTER CHECKING DISTRIBUTION FOR BEING UBUNTU!
    '''

    cache = apt.Cache()

    result = []

    for package_name in package_list:

        package_known = cache.has_key(package_name)

        if not package_known:
            package_d = {
                'name': package_name,
                'in_cache': False,
                'installed': False,
                'version': None
            }
            result.append(package_d)
            continue

        package_d = {
            'in_cache': True,
            'name': package_name
        }

        package = cache[package_name]

        if package.is_installed:
            package_d['installed'] = True
            package_d['version'] = package.installed.version
        else:
            package_d['installed'] = False
            package_d['version'] = None

        result.append(package_d)

    # python-apt api seems to have changed for no reason
    # cache.close()

    return result


def get_dpkg_package_info(package_list):
    '''
    acquires package infos via dpkg-query
    '''
    result = []

    for package in package_list:
        call = [
            'dpkg-query', '-W', '-f=${Package} ${Version} ${Status}\n', package
        ]
        call_result = safe_syscall(call)
        ret_code = call_result[0]
        info_raw = call_result[1]

        infos = info_raw.split()

        if ret_code == 0:
            if infos[-1] == 'installed':
                package_d = {
                    'name': package,
                    'installed': True,
                    'version': infos[1]
                }
            elif infos[-1] == 'not-installed':
                package_d = {
                    'name': package,
                    'installed': False,
                    'version': None
                }
        else:
            package_d = {
                'name': package,
                'installed': False,
                'version': 'package unknown to dpkg'
            }

        result.append(package_d)

    return result
