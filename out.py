from scapy.all import *
from subprocess import *
import configparser
def warn(a):
	global whitelist
	#print(a.summary())
	if a.haslayer(DNS):
		pass
	else:	
		#print(a[TCP].sport)
		#net=subprocess.check_output('netstat -nap | grep {}'.format(a[TCP].sport),shell=True).decode()
		#print('###'+net)
		if a.haslayer(TCP):
			try:
				net=subprocess.check_output('lsof -i | grep {}'.format(a[TCP].sport), shell=True).decode()
			except:
				#print("\033[1;31;1m"+'Error:'+"\033[0m"+' Fail to get app name on TCP port '+"\033[1;31;1m"+str(a[IP].sport)+"\033[0m")
				pass
			else:
				if net.split(' ')[0] not in whitelist:
					print('Warning: '+"\033[1;31;1m"+net.split(' ')[0]+"\033[0m"+' has sent a TCP message to '+"\033[1;31;1m"+str(a[IP].dst)+"\033[0m."+' on port '+"\033[1;31;1m"+str(a.sport)+"\033[0m.")
		else:
			try:
				net=subprocess.check_output('lsof -i | grep {}'.format(a[UDP].sport), shell=True).decode()
			except:
				#print("\033[1;31;1m"+'Error:'+"\033[0m"+' Fail to get app name on UDP port '+"\033[1;31;1m"+str(a[IP].sport)+"\033[0m")
				pass
			else:
				if net.split(' ')[0] not in whitelist:
					print('Warning: '+"\033[1;31;1m"+net.split(' ')[0]+"\033[0m"+' has sent a UDP message (not DNS) to '+"\033[1;31;1m"+str(a[IP].dst)+"\033[0m."+' on port '+"\033[1;31;1m"+str(a[IP].sport)+"\033[0m.")
	return  

conf= configparser.ConfigParser()
conf.read('config.conf')  # 文件路径
whitelist = conf.get("whitelist","applist").split(',')  # 获取指定section 的option值
#with open('config.conf','r') as f:
#	whitelist=f.readlines()[0].split()
print('White List: '+str(whitelist))
local='192.168.12.137'
sniff(filter='ip src {}'.format(local),prn=warn)
#sniff(filter='ip src {}'.format(local),prn=lambda x : x[IP])

