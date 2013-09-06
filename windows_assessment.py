#Vulnerability Assessment Script for Win Machines
#Author: Jonathan Broche
#Purpose: Retrieve system information such as logs, ports and more in order to investigate possible compromised systems.
#Tested on: Windows 7, XP SP2/SP3

import urllib.request, platform, os, ctypes, sys, datetime, subprocess, logging, shlex, shutil, time
import xml.etree.ElementTree as ET

def check_definitions(): #download latest MBSA definitions and run assessment

    if os.path.exists("wsusscn2.cab"):
        if datetime.date.fromtimestamp(os.path.getmtime("wsusscn2.cab")) != datetime.date.today():
            try:
                print('[*] Updated MBSA CAB file.')
                with open ('wsusscn2.cab', 'wb') as f:
                    f.write(urllib.request.urlopen('http://go.microsoft.com/fwlink/?LinkId=76054').read())
                print('[*] MBSA CAB file successfully updated.')
            except Exception as e:
                print('Error: {}'.format(e))
        run_assessment('audit_{}'.format(platform.node()))
    else:
        print('[*] Downloading MBSA CAB file.')
        with open ('wsusscn2.cab', 'wb') as f:
            f.write(urllib.request.urlopen('http://go.microsoft.com/fwlink/?LinkId=76054').read())
        run_assessment('audit_{}'.format(platform.node()))
        
def parse_xml(dirname):

    try:
        tree = ET.parse(os.path.join(dirname,'mbsa.xml'))
        root = tree.getroot()
        
        with open(os.path.join(dirname,'mbsa_results.txt'),'w') as f:

            try:
                f.write('*************************************************************************\n')
                f.write('Developer Tools, Runtimes and Redistributables Security Updates - {}'.format(root[1][0].text)) #dev updates
                f.write('\n*************************************************************************\n\n')
                for child in root[1][1]:
                    if child.attrib['IsInstalled'].lower() == 'true': #update installed
                        pass
                    else:
                        for subchild in child: #update not installed - write to file
                            if subchild.tag.lower() in 'title':
                                f.write('Title: {}\n'.format(subchild.text))
                            for subsubchild in subchild:
                                if subsubchild.tag.lower() in {'bulletinurl', 'downloadurl'}:
                                    if subsubchild.tag.lower() in 'bulletinurl':
                                        f.write('BulletinURL: {}\n'.format(subsubchild.text))
                                    else:
                                        f.write('DownloadURL: {}\n\n--\n'.format(subsubchild.text))
            except IndexError:
                pass


            try:
                f.write('\n*************************************************************************\n')
                f.write('Office Security Updates - {}'.format(root[2][0].text))#Office Security Updates
                f.write('\n*************************************************************************\n\n')
                for child in root[2][1]:
                    if child.attrib['IsInstalled'].lower() == 'true': #update installed
                        pass
                    else:
                        for subchild in child: #update not installed - write to file
                            if subchild.tag.lower() in 'title':
                                f.write('Title: {}\n'.format(subchild.text))
                            for subsubchild in subchild:
                                if subsubchild.tag.lower() in {'bulletinurl', 'downloadurl'}:
                                    if subsubchild.tag.lower() in 'bulletinurl':
                                        f.write('BulletinURL: {}\n'.format(subsubchild.text))
                                    else:
                                        f.write('DownloadURL: {}\n\n--\n'.format(subsubchild.text))             
            except IndexError:
                pass
            

            try:
                f.write('\n*************************************************************************\n')
                f.write('SQL Server Security Updates - {}'.format(root[3][0].text)) #SQL
                f.write('\n*************************************************************************\n\n')
                for child in root[3][1]:
                    if child.attrib['IsInstalled'].lower() == 'true': #update installed
                        pass
                    else:
                        for subchild in child: #update not installed - write to file
                            if subchild.tag.lower() in 'title':
                                f.write('Title: {}\n'.format(subchild.text))
                            for subsubchild in subchild:
                                if subsubchild.tag.lower() in {'bulletinurl', 'downloadurl'}:
                                    if subsubchild.tag.lower() in 'bulletinurl':
                                        f.write('BulletinURL: {}\n'.format(subsubchild.text))
                                    else:
                                        f.write('DownloadURL: {}\n\n--\n'.format(subsubchild.text))   
            except IndexError:
                pass

            

            try:             
                f.write('\n*************************************************************************\n')
                f.write('Windows Security Updates - {}'.format(root[4][0].text)) #Windows Security Updates
                f.write('\n*************************************************************************\n\n')
                for child in root[4][1]:
                    if child.attrib['IsInstalled'].lower() == 'true': #update installed
                        pass
                    else:
                        for subchild in child: #update not installed - write to file
                            if subchild.tag.lower() in 'title':
                                f.write('Title: {}\n'.format(subchild.text))
                            for subsubchild in subchild:
                                if subsubchild.tag.lower() in {'bulletinurl', 'downloadurl'}:
                                    if subsubchild.tag.lower() in 'bulletinurl':
                                        f.write('BulletinURL: {}\n'.format(subsubchild.text))
                                    else:
                                        f.write('DownloadURL: {}\n\n--\n'.format(subsubchild.text)) 
            except IndexError:
                pass
             
            try:
                f.write('\n*************************************************************************\n')
                f.write('Incomplete Updates - {}'.format(root[5][0].text)) #Incomplete Updates
                f.write('\n*************************************************************************\n')
                for child in root[5][1]:
                    if child.attrib['IsInstalled'].lower() == 'true': #update installed
                        pass
                    else:
                        for subchild in child: #update not installed - write to file
                            if subchild.tag.lower() in 'title':
                                f.write('Title: {}\n'.format(subchild.text))
                            for subsubchild in subchild:
                                if subsubchild.tag.lower() in {'bulletinurl', 'downloadurl'}:
                                    if subsubchild.tag.lower() in 'bulletinurl':
                                        f.write('BulletinURL: {}\n'.format(subsubchild.text))
                                    else:
                                        f.write('DownloadURL: {}\n\n--\n'.format(subsubchild.text)) 
            except IndexError:
                pass
                
    except Exception as e:
        logging.info('Parse XML Error: {}'.format(e))


        
def run_assessment(dirname):     
    
    if os.path.exists(dirname): #create directory TODO: make a better naming scheme/format
        dirname = 'audit_{}_{}'.format(platform.node(), str(datetime.datetime.now()).replace(':','_')).replace(' ','_').replace('.','_')
        os.mkdir(dirname)
        print('[*] {} directory created.'.format(dirname))
    else:
        os.mkdir(dirname)
        print('[*] {} directory created.'.format(dirname))
        
    #create log file
    logging.basicConfig(filename='{}.log'.format(os.path.join(dirname,dirname)),
                        format='%(asctime)s %(levelname)s:  %(message)s \n',
                        datefmt='%a, %d %b %Y %I:%M:%S%p',
                        level='INFO')
                        
    logging.info('Starting Assessment')
    logging.info('OS: {} - Machine name: {} - Logged in user: {}'.format(platform.platform(), platform.node(), os.environ['USERNAME']))
    print('[*] Logger started.')
    
    try:
        print('[*] Starting assessment.')
        #create directories
        for dir in {'sys_info','event_logs','firewall_logs','gpresult','mcafee_logs'}:
            os.mkdir(os.path.join(dirname,dir))        
            logging.info('System information saved.')

        os.system('systeminfo | find /i "install" > {}\sys_info\system_info.txt'.format(dirname))
        os.system('psinfo.exe -d -s -h /accepteula >> {}\sys_info\system_info.txt'.format(dirname))
        print('[*] Retrieved systeminfo.')

        with open (os.path.join(dirname, 'sys_info', 'ip_config.txt'), 'wb') as f:        
            f.write(subprocess.check_output(shlex.split('ipconfig /all')))
        logging.info('IP configuration saved.')
        print('[*] Retrieved ip configuration.')
        

        with open (os.path.join(dirname, 'sys_info', 'set_info.txt'), 'w') as f:
            for variable in os.environ:
                f.write('{}: {}\n'.format(variable, os.environ[variable]))
        logging.info('Environment variables saved.')
        print('[*] Retrieved env variables.')
     
        try:
            print('[*] Starting MBSA.\n')
            with open (os.path.join(dirname, 'mbsa.xml'), 'wb') as f:
                f.write(subprocess.check_output(shlex.split('mbsacli.exe /catalog wsusscn2.cab /wi /nvc /nd /xmlout')))
            parse_xml(dirname)
        except Exception as e:
            print('[!] MBSA Error: {}'.format(e))
            logging.info('MBSA Error: {}'.format(e))
            print('[*] Status Report: 25% Completed') 
            
        #cports
        subprocess.check_output(shlex.split('cports.exe /shtml "{}"'.format(os.path.join(dirname,'sys_info','cports.html'))))    
        logging.info('Services and ports saved.')
        print('[*] Retrieved ports.')

        #processes
        with open (os.path.join(dirname,'sys_info','process_info.txt'), 'wb') as f:
            f.write(subprocess.check_output(shlex.split('pslist.exe /accepteula')))
        logging.info('Process information saved.')
        print('[*] Retrieved processes.')
        
        for line in ["users","policy","rights","shares","printers","services","groups"]:
            subprocess.check_output(shlex.split('dumpsec.exe /rpt="{}" /saveas=fixed /showtruelastlogon /outfile="{}.txt"'.format(line, os.path.join(dirname,'sys_info', line))))
        logging.info('Group policy information saved.')
        print('[*] Status Report: 50% Completed')
        
        #Save the list of event log files
        for line in ['Application','System','Security']:
            with open (os.path.join(dirname, 'event_logs', '{}.txt'.format(line)), 'wb') as f:
                f.write(subprocess.check_output(shlex.split('psloglist.exe -s -t "\\t" -x /accepteula')))
        logging.info('Event logs saved.')
        print('[*] Retrieved event logs.')

        #firewall settings
        with open (os.path.join(dirname, 'firewall_logs', 'FWSetting.txt'), 'wb') as f:
            if platform.win32_ver()[0] == '7':
                f.write(subprocess.check_output(shlex.split('netsh firewall show state verbose = enable')))
                f.write(subprocess.check_output(shlex.split('netsh advfirewall firewall show rule name=all')))
            else:
                f.write(subprocess.check_output(shlex.split('netsh firewall show state verbose = enable')))
        logging.info('Firewall settings saved.')
        print('[*] Retrieved firewall settings.')
        print('[*] Status Report: 75% Completed')
        
        #copy firewall logs
        for path in {'{}\\pfirewall.log'.format(os.environ.get('systemroot')), '{}\\system32\\LogFiles\\Firewall\\pfirewall.log'.format(os.environ.get('systemroot')), '{}\\system32\\LogFiles\\Firewall\\w7firewall.log'.format(os.environ.get('systemroot'))}:
            if os.path.exists(path):
                shutil.copytree(path, os.path.join(dirname,'firewall_logs'))
        logging.info('Firewall logs saved.')
        
        
        #group policy
        try:
            subprocess.check_output(shlex.split('gpresult /H gpolicy.html'))
            shutil.move('gpolicy.html', os.path.join(dirname,'gpresult'))
            logging.info('Group policy saved.')
            print('[*] Retrieved group policy.')
        except Exception as e:
            logging.info('Group Policy Error: {}'.format(e))

        #copy mcafee logs
        if os.environ.get("VSEDEFLOGDIR"):
            shutil.copytree(os.environ.get('VSEDEFLOGDIR'), os.path.join(dirname, 'mcafee_logs', 'logs'))
        logging.info('Assessment Finished.')
        print('[*] Retrieved anti-virus logs.')
        print('[*] Status Report: 100% Completed')
        time.sleep(2)

    except Exception as e:
       print(e)
       logging.info('Error: {}'.format(e))
        
def main(): #TODO: create functions that point to main
    if platform.system() == "Windows" and ctypes.windll.shell32.IsUserAnAdmin():
        check_definitions()
    else:
        print('[!] Run application as administrator.')
        time.sleep(20)
if __name__ == '__main__':
    main()