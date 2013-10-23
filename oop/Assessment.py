import logging, platform, os, argparse, subprocess, shlex, getpass
from itertools import count

class Assessment():
    def make_dir(self, basedir, name):
        for attempt in count(1):
            dirname = os.path.join(basedir, name if attempt == 1 else '{}_{}'.format(name, attempt))
            if not os.path.exists(dirname):
                os.mkdir(dirname)
                return dirname
    
    def sys_info(self, dirname):    
        with open(os.path.join(self.make_dir(dirname, "system_info"), "system_info.txt"), 'w') as f:
            f.write("""
            *************************************
                    {uname}                     
            *************************************
            user: {login}
            system: {system}
            hostname: {node} 
            release: {release}
            kernel version: {version}
            processor: {machine}
            architecture: {architecture}
            """.format(uname=platform.uname(), login=getpass.getuser(), system=platform.system(), node=platform.node(),
            release=platform.release(), version=platform.version(), machine=platform.machine(),	architecture=platform.architecture()))
            
    def get_netinfo(self, dirname):
        with open(os.path.join(dirname, "system_info", "ip_configuration.txt"), 'wb') as f:
            f.write(subprocess.check_output(shlex.split('ifconfig -a')))
          
        with open(os.path.join(dirname, 'system_info', 'network_connections.txt'), 'w') as f:
            f.write("""
            *************************************
            +       NETSTAT -anbf               +
            *************************************
            {netstat_all}
            
            *************************************
            +       NETSTAT tcp                 +
            *************************************            
            {netstat_tcp}
            
            *************************************
            +       NETSTAT tcp                 +
            *************************************
            {netstat_udp}
            
            *************************************
            +        NETSTAT route              +
            *************************************
            {netstat_route}
            """.format(netstat_all=subprocess.check_output(shlex.split('netstat -an')), netstat_tcp=subprocess.check_output(shlex.split('netstat -anp "tcp"')), netstat_udp=subprocess.check_output(shlex.split('netstat -anp "udp"')), netstat_route=subprocess.check_output(shlex.split('netstat -r')) ))

    def get_environment(self, dirname):
		with open(os.path.join('{}/system_info'.format(dirname), "environment.txt"), 'wb') as f:
			f.write('\n'.join('{}: {}'.format(key, value) for key, value in os.environ.items()).encode('ascii'))
            
    def config_logger(self, dirname):
        logging.basicConfig(filename='{}/logger.log'.format(dirname),
            format='%(asctime)s %(levelname)s:  %(message)s \n',
            datefmt='%a, %d %b %Y %I:%M:%S%p',
            level='INFO')  

    def __init__(self):
        pass

class Windows(Assessment): #TODO: mbsa, support more AVs
    def sys_info(self, dirname): #obtain disk info, installed apps, installed hotfixes
        os.system('psinfo.exe -d -s -h /accepteula >> {}'.format(os.path.join(Assessment.make_dir(self, dirname, "system_info"), 'system_info.txt')))

    def get_avlogs(self, dirname): #copy McAfee Anti-Virus logs
        if os.environ.get("VSEDEFLOGDIR"):
            shutil.copytree(os.environ.get('VSEDEFLOGDIR'), os.path.join(Assessment.make_dir(self, dirname, "mcafee_logs"), 'logs'))
        logging.info('Assessment Finished.')
        print('[*] Retrieved anti-virus logs.')
    
    def get_fwlogs(self,dirname): #copy Firewall settings and logs
        with open (os.path.join(Assessment.make_dir(self, dirname, 'firewall_logs'), 'FWSetting.txt'), 'wb') as f:
            if platform.release() == '7':
                f.write(subprocess.check_output(shlex.split('netsh firewall show state verbose = enable')))
                f.write(subprocess.check_output(shlex.split('netsh advfirewall firewall show rule name=all')))
            else:
                f.write(subprocess.check_output(shlex.split('netsh firewall show state verbose = enable')))
        logging.info('Firewall settings saved.')
    
        for path in {'{}\\pfirewall.log'.format(os.environ.get('systemroot')), '{}\\system32\\LogFiles\\Firewall\\pfirewall.log'.format(os.environ.get('systemroot')), '{}\\system32\\LogFiles\\Firewall\\w7firewall.log'.format(os.environ.get('systemroot'))}:
            if os.path.exists(path):
                shutil.copytree(path, os.path.join(dirname,'firewall_logs'))
        logging.info('Firewall logs saved.')
        print('[*] Retrieved firewall settings and logs.')
        
    def get_eventlogs(self, dirname): #copy event logs
        evtdir = Assessment.make_dir(self, dirname, 'event_logs')
        for line in ['Application','System','Security']:
            with open (os.path.join(evtdir, '{}.txt'.format(line)), 'wb') as f:
                f.write(subprocess.check_output(shlex.split('psloglist.exe -s -t "\\t" -x /accepteula')))
        logging.info('Event logs saved.')
        print('[*] Retrieved event logs.')
    
    def get_gp(self, dirname): #get group policy
        try:
            subprocess.check_output(shlex.split('gpresult /H gpolicy.html'))
            shutil.move('gpolicy.html', os.path.join(dirname,'gpresult'))
            logging.info('Group policy saved.')
            print('[*] Retrieved group policy.')
        except Exception as e:
            logging.info('Group Policy Error: {}'.format(e))
            
    def get_netinfo(self, dirname):
        with open(os.path.join(dirname, "system_info", "ip_configuration.txt"), 'wb') as f:
            f.write(subprocess.check_output(shlex.split('ipconfig /all')))
          
        with open(os.path.join(dirname, 'system_info', 'network_connections.txt'), 'w') as f:
            f.write("""
            *************************************
            +       NETSTAT -anbf               +
            *************************************
            {netstat_all}
            
            *************************************
            +       NETSTAT tcp                 +
            *************************************            
            {netstat_tcp}
            
            *************************************
            +       NETSTAT tcp                 +
            *************************************
            {netstat_udp}
            
            *************************************
            +        NETSTAT route              +
            *************************************
            {netstat_route}
            """.format(netstat_all=subprocess.check_output(shlex.split('netstat -anbf')), netstat_tcp=subprocess.check_output(shlex.split('netstat -anp "tcp"')), netstat_udp=subprocess.check_output(shlex.split('netstat -anp "udp"')), netstat_route=subprocess.check_output(shlex.split('netstat -r')) ))

        subprocess.check_output(shlex.split('cports.exe /shtml {}'.format(os.path.join(dirname, 'system_info', 'cports.html'))))
    
    def __init__(self):    
        dirname = Assessment.make_dir(self, './', 'audit_{}'.format(platform.node()))
        Assessment.config_logger(self, dirname)
        self.sys_info(dirname)
        self.get_fwlogs(dirname)
        self.get_eventlogs(dirname)
        self.get_netinfo(dirname)
        
class Mac(Assessment):
    def __init__(self):
        print('hello world from Mac')
        
class Linux(Assessment): #TODO: check services and obtain configuration files for services

    def get_programs(self, dirname): #Purpose: retrieve OS installed programs and running processes
        #platform.version()
        with open(os.path.join('{}/system_info'.format(dirname), "installed_programs.txt"), 'wb') as f:
            if 'Debian' in platform.version():
                f.write(subprocess.check_output(shlex.split('dpkg --get-selections'))) #debian distros
            else:
                try:
                    f.write(subprocess.check_output(shlex.split('yum list installed'))) #RPM distros (e.g. RHEL, Fedora, Redhat)
                except subprocess.CalledProcessError:
                    f.write('[!] Implement program files for {}'.format(platform.version()))
                    
        #Retrieve list of all available updates 
        with open(os.path.join(make_dir(dirname, "programs"), "installed_programs.txt"), 'wb') as f:
            if 'Debian' in platform.version():
                f.write(subprocess.check_output(shlex.split('sudo apt-get update'))) 
            else:
                try: #RPM (e.g. RHEL, Fedora)
                    f.write(subprocess.check_output(shlex.split('yum list updates'))) 
                except subprocess.CalledProcessError:
                    f.write('[!] Implement update listing for {}'.format(platform.version()))
                    
    def get_services(self, dirname):
        with open(os.path.join('{}/system_info'.format(dirname), "services.txt"), 'wb') as f:
            f.write(subprocess.check_output(shlex.split('netstat -tulpn')))
            f.write(subprocess.check_output(shlex.split('service --status-all')))
            
        if 'running' in subprocess.check_output(shlex.split('service apache2 status')) or in subprocess.check_output(shlex.split('service httpd status')):
            shutil.copyfile('/etc/httpd', os.path.join('{}/system_info'.format(dirname), 'apache_httpd'))
            
        #e.g. if apache in running services -> copy server configuration onto dirname
    def __init__(self):
        dirname = Assessment.make_dir(self, './', 'audit_{}'.format(platform.node()))
        Assessment.config_logger(self, dirname)
        Assessment.sys_info(self, dirname)
    
    