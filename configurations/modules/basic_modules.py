import os, subprocess as sp, threading, socket

def colors(color, text, s=0, e=0, tsign=""):
	color = color.lower()

	color_end = '\033[0m'
	red = '\033[91m'
	lgray = '\033[2m'
	gray = '\033[90m'
	strike = '\033[9m'
	underline = '\033[4m'
	blue = '\033[94m'
	green = '\033[92m'
	yellow = '\033[93m'

	if color == "error":
		a = ''
		if tsign == "": a = "-"
		else: a = tsign
		a = ' [%s] ' % a
		text = red + a + color_end + blue + text + color_end
	elif color == "information":
		b = ''
		if tsign == "": b = "!"
		else: b = tsign
		b = ' [%s] ' % b
		text = blue + b + color_end + green + text + color_end
	elif color == "info":
		b = ' [ INFO ] '
		text = blue + b + color_end + green + text + color_end
	elif color == "success":
		c = ''
		if tsign == "": c = "+"
		else: c = tsign
		c = ' [%s] ' % c
		text = green + c + color_end + blue + text + color_end
	elif color == "warning":
		d = ''
		if tsign == "": d = "-"
		else: d = tsign
		d = ' [%s] ' % d
		text = red + d + color_end + blue + text + color_end
	elif color == "r" or color == "red" or color == "input":
		text = red + text + color_end
	elif color == "lgray" or color == "lg":
		text = lgray + text + color_end
	elif color == "gray" or color == "gr":
		text = gray + text + color_end
	elif color == "strike" or color == "-":
		text = strike + text + color_end
	elif color == "underline" or color == "_":
		text = underline + text + color_end
	elif color == "b" or color == "blue":
		text = blue	+ text + color_end
	elif color == "g" or color == "green":
		text = green + text + color_end
	elif color == "y" or color == "yellow":
		text = yellow + text+ color_end
	
	return "%s%s%s" % ("\n"*s, text, "\n"*e)

def execute_command(command):
	sh = sp.Popen(command, shell=True, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE)
	out, err = sh.communicate()
	returncode = sh.returncode
	return out, err, returncode

def configure_environment(path, rep = 0):
	status = 1
	reason = ""

	if os.path.exists(path) == False and rep == 0:
		try:
			os.mkdir(path)
			status = 0
		except Exception as e:
			reason = str(e)
			pass
	elif os.path.exists(path) == False and rep == 1:
		try:
			f = open(path,'a')
			f.close()
			status = 0
		except Exception:
			reason = str(e)
			pass
	else:
		status = 0 # Path Exists

	return status, reason

def send_data(connection, data = ''):
	if len(data) > 0:
		try:
			connection.send(data)
		except socket.error as e:
			print colors("error","Connection from Remote Host Has Been Terminated. Unable To Control Host.",1,1)
			return "[XX]SESSION-END[XX]"

	result = connection.recv(4096)

	total_size = 0

	try:
		total_size = long(result[:16])
	except Exception:
		print colors("error","Connection from Remote Host Has Been Terminated. Unable To Control Host.",1,1)
		return "[XX]SESSION-END[XX]"

	result = result[16:]

	while total_size > len(result):
		data = connection.recv(4096)
		result += data

	return result.rstrip("\n")

def ZConsoleHelp(alias_object, search):
	help_list = {}

	for x in alias_object:
		help_list[x] = alias_object[x]

	help_list["help"] = "Print this help screen"
	help_list["interact"] = "Interact with connected addresses. Use 'sessions' to list connected addresses"
	help_list['close'] = "Kill connected address."
	help_list['sessions'] = "List all connected addresses"
	help_list['start_server'] = "Start server on a defined port"
	help_list['stop_server'] = "Stop server on a defined port"
	help_list['stop_servers'] = "Stop all running servers"
	help_list['servers'] = "List all server/listeners running"
	help_list['exit'] = "Exit the framework. Same function as 'bye' and 'quit'"
	help_list['kill_all'] = "Disconnect all connected address."

	results = ""

	if len(search) != 0 and help_list.has_key(search):
		results += " " + colors("lg", "="*80,0,1)
		results += " " + colors("green",search) + " - " + colors("blue",help_list[search],0,1)
		results += " " + colors("lg", "="*80,0)
	elif len(search) != 0 and help_list.has_key(search) == False:
		results += " " + colors("lg", "="*80,0,1)
		results += " " + colors("error", "Unknown help command - " + search,0,1)
		results += " " + colors("lg", "="*80,0)
	else:
		results += " " + colors("lg", "="*80,0,1)
		for x in sorted(help_list):
			results += " " + colors("green",x) + " - " + colors("blue",help_list[x],0,1)
		results += " " + colors("lg", "="*80,0)

	return results