#version2 Linosx Assessment Script made for Linux Distros and Mac OSX http://www.sans.org/score/checklists/linuxchecklist.pdf
#!/usr/bin/python3

import os, platform, subprocess, logging
from itertools import count
from shlex import split


#TODO: CHECK for missing updates, ports, start up scripts, open ports, check for apache install (and security), 

def make_dir(basedir, name):
	for attempt in count(1):
		dirname = os.path.join(basedir, name if attempt == 1 else '{}_{}'.format(name, attempt))
		if not os.path.exists(dirname):
			os.mkdir(dirname)
			return dirname


def sys_info(dirname): #Purpose: reterieve system information 

	try:
	
		logging.info("created system_info directory")
		logging.info("start platform module calls")	

		with open(os.path.join(make_dir(dirname, "system_info"), "system_info.txt"), 'wb') as f:
			f.write("""
			************************************************************************
			uname: {uname}
			************************************************************************

			user: {login}
			system: {system}
			hostname: {node}
			release: {release}
			kernel version: {version}
			processor: {machine}
			architecture: {architecture}""".format(uname=platform.uname(), login=os.getlogin(), system=platform.system(), node=platform.node(),
			release=platform.release(), version=platform.version(), machine=platform.machine(),	architecture=platform.architecture()).encode('ascii'))

		logging.info("end platform calls")
		
		
		#ip configuration
		with open(os.path.join('{}/system_info'.format(dirname), "ip_info.txt"), 'wb') as f:
			f.write(subprocess.check_output(split('ifconfig -a')))
			
	
		logging.info("ip configuration logged")	

		#environment variables
		with open(os.path.join('{}/system_info'.format(dirname), "environment.txt"), 'wb') as f:
			f.write('\n'.join('{}: {}'.format(key, value) for key, value in os.environ.items()).encode('ascii'))
		
		logging.info("environment variables logged")	

	except Exception as e:	
		print("**** Error in sysinfo")	
		logging.exception('')
	


def program_list(dirname): #Purpose: retrieve OS installed programs and running processes

    #Retrieve list of all installed programs 
        with open(os.path.join('{}/system_info'.format(dirname), "installed_programs.txt"), 'wb') as f:

            try:
                f.write(subprocess.check_output(split('dpkg --get-selections'))) #debian distros
            except subprocess.CalledProcessError:
                pass
            try:
                f.write(subprocess.check_output(split('yum list installed'))) #RPM distros (e.g. RHEL, Fedora, Redhat)
            except subprocess.CalledProcessError:
                pass

        #Retrieve list of all available updates 
        with open(os.path.join(make_dir(dirname, "programs"), "installed_programs.txt"), 'wb') as f:

            try: #Debian (e.g. Ubuntu)
                f.write(subprocess.check_output(split('sudo apt-get update'))) 
            except subprocess.CalledProcessError: 
                pass
            try: #RPM (e.g. RHEL, Fedora)
                f.write(subprocess.check_output(split('yum list updates'))) 
            except subprocess.CalledProcessError:
                pass
    
 
        #programs compiled by user
        with open(os.path.join('{}/programs'.format(dirname), "user_compiled.txt"), 'wb') as f:
            f.write(subprocess.check_output(split('ls -la /usr/local/bin')))

	    #process tree
        with open(os.path.join('{}/programs'.format(dirname), "process_tree.txt"), 'wb') as f:
            f.write(subprocess.check_output('pstree'))


#****************** MAIN *********************

def main():

	try:
		#create directory w/ format audit_COMPUTERNAME
		dirname = make_dir('./', 'audit_{}'.format(platform.node()))

		#configure logging
		logging.basicConfig(filename='{}/logger.log'.format(dirname),
							format='%(asctime)s %(levelname)s:  %(message)s \n',
							datefmt='%a, %d %b %Y %I:%M:%S%p',
							level='INFO')

		logging.info("created main directory & log configuration")
		
		
		#run chkrootkit: checks binaries for rootkit modification
        with open('./{}/chkrootkit_results.log'.format(dirname), 'wb') as f:
			print('running binary check...')
			f.write(subprocess.check_output(['sudo','./chkrootkit/chkrootkit']))

		logging.info("finished chkrootkit")

	
		#begin assessment		
		sys_info(dirname)
		program_list(dirname)
	
	except Exception:		
		logging.exception('')
		print("*** Error in main.")


if __name__ == '__main__':
	main()






