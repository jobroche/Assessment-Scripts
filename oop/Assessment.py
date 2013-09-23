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
            
        
    def config_logger(self, dirname):
        logging.basicConfig(filename='{}/logger.log'.format(dirname),
            format='%(asctime)s %(levelname)s:  %(message)s \n',
            datefmt='%a, %d %b %Y %I:%M:%S%p',
            level='INFO')  

    def __init__(self):
        pass
    


class Windows(Assessment): #todo: mbsa, support more AVs

    def sys_info(self, dirname): #obtain disk info, installed apps, installed hotfixes
        os.system('psinfo.exe -d -s -h /accepteula >> {}'.format(os.path.join(Assessment.make_dir(self, dirname, "system_info"), 'system_info.txt')))

    def get_avlogs(self, dirname):
        #copy mcafee logs
        if os.environ.get("VSEDEFLOGDIR"):
            shutil.copytree(os.environ.get('VSEDEFLOGDIR'), os.path.join(Assessment.make_dir(self, dirname, "mcafee_logs"), 'logs'))
        logging.info('Assessment Finished.')
        print('[*] Retrieved anti-virus logs.')
    
    def get_fwlogs(self,dirname):
        #firewall settings
        with open (os.path.join(Assessment.make_dir(self, dirname, 'firewall_logs'), 'FWSetting.txt'), 'wb') as f:
            if platform.win32_ver()[0] == '7':
                f.write(subprocess.check_output(shlex.split('netsh firewall show state verbose = enable')))
                f.write(subprocess.check_output(shlex.split('netsh advfirewall firewall show rule name=all')))
            else:
                f.write(subprocess.check_output(shlex.split('netsh firewall show state verbose = enable')))
        logging.info('Firewall settings saved.')
    
        #copy firewall logs
        for path in {'{}\\pfirewall.log'.format(os.environ.get('systemroot')), '{}\\system32\\LogFiles\\Firewall\\pfirewall.log'.format(os.environ.get('systemroot')), '{}\\system32\\LogFiles\\Firewall\\w7firewall.log'.format(os.environ.get('systemroot'))}:
            if os.path.exists(path):
                shutil.copytree(path, os.path.join(dirname,'firewall_logs'))
        logging.info('Firewall logs saved.')
        print('[*] Retrieved firewall settings and logs.')
        
    def get_eventlogs(self, dirname): #Save the list of event log files
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

    def run_mbsa(self, dirname):
        pass
        #with open(os.path.join(dirname, 'system_info', 'mbsa.txt'), 'w') as f:
            #f.write(subprocess.check_output(shlex.split('mbsacli.exe')))

    def __init__(self):    
        dirname = Assessment.make_dir(self, './', 'audit_{}'.format(platform.node()))
        Assessment.config_logger(self, dirname)
        self.sys_info(dirname)
        self.run_mbsa(dirname)
        self.get_fwlogs(dirname)
        self.get_eventlogs(dirname)
        self.get_netinfo(dirname)
        
class Mac(Assessment):
    def __init__(self):
        print('hello world from Mac')
        
class Linux(Assessment):
    def __init__(self):
        print('hello world from Linux')
    
    