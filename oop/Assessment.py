import logging, platform, os, argparse
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
            f.write("""************************************************************************
            uname: {uname}
            ************************************************************************
            user: {login}
            system: {system}
            hostname: {node} 
            release: {release}
            kernel version: {version}
            processor: {machine}
            architecture: {architecture}""".format(uname=platform.uname(), login=os.getlogin(), system=platform.system(), node=platform.node(),
            release=platform.release(), version=platform.version(), machine=platform.machine(),	architecture=platform.architecture()))
            
        
    def config_logger(self, dirname):
        logging.basicConfig(filename='{}/logger.log'.format(dirname),
            format='%(asctime)s %(levelname)s:  %(message)s \n',
            datefmt='%a, %d %b %Y %I:%M:%S%p',
            level='INFO')  

    def __init__(self):
        pass
    


class Windows(Assessment):

    def get_logs():
        pass
        
    def __init__(self):    
        dirname = Assessment.make_dir(self, './', 'audit_{}'.format(platform.node()))
        Assessment.config_logger(self, dirname)
        Assessment.sys_info(self, dirname)