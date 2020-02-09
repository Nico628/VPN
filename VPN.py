#Assn3UI.py
import socket
import sys
import random
#python -m pip install pysha3
import sha3
#pip3 install pygubu
import _thread 
import base64
#imports
try:
    import tkinter as tk  # for python 3
except:
    import Tkinter as tk  # for python 2
import pygubu

#https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256?fbclid=IwAR3Ifln641QwP2SVXD68GCHx4_p4mef1AymLDWYL9xyzkjbUqc_7RIh0DeM Used for encryption and decryption
#pip install pycryptodome
from Crypto.Cipher import AES
from Crypto import Random

class Application:

	#class Attributes( ie. variables)
	IP = "localhost"
	Port = 50
	SharedSecret = "secret"
	isClientString = "" #string either 'Client' or 'Server'
	isClient = 0        # 0=server, 1=client
	isDebugString = ""
	isDebug = 0
	cont_state = 0 #continue state: 0 = wait, 1 = continue
	s = socket.socket()
	c = None
	key = 0
	sending = 0
	receiving = 0
	message = ""
	iv = {}
	sharedKey = {}
	raw = {}
	cipher = {}
	hash_val = {}
	SharedSecret = {}
	DH_Client = {}
	R_Server = {}
	R_Client = {}
	a = {}
	setup = 0
	temp_msg = ""
	def __init__(self, master):

		self.bs = 16

		#1: Create a builder
		self.builder = builder = pygubu.Builder()

        #2: Load an ui file
		builder.add_from_file('UI.ui')

		#3: Create the widget using a master as parent
		self.mainwindow = builder.get_object('mainwindow', master)
		
		#connect messaging widgets
		self.messaging  = builder.get_object('messaging', self.mainwindow)
		self.messages   = builder.get_object('messages', self.messaging)
		self.m_entry    = builder.get_object('m_entry', self.messaging)
		
		#connection Input widgets
		self.connectioninputs = builder.get_object('Connection Inputs', self.mainwindow)
		self.ip_entry = builder.get_object('IP entry', self.connectioninputs)
		self.port_entry = builder.get_object('Port Entry', self.connectioninputs)
		self.ss_entry =  builder.get_object('Shared Secret entry', self.connectioninputs)
		self.server_check = builder.get_object('Server', self.connectioninputs)
		self.server_var = builder.get_variable('server') #checkbuttons have connected variable for state, gets variable for server settings
		
		#connect log widgets
		self.debug  = builder.get_object('Debug', self.mainwindow)
		self.log   = builder.get_object('Log', self.messaging)
		self.log.insert(tk.END, '\n')
		
		
		#connect Debug Settings Widgets
		self.debug_settings = builder.get_object('debug_settings',self.mainwindow)
		self.debug_check = builder.get_object('debug_check',self.debug_settings)
		self.debug_var = builder.get_variable('debug_var') #gets variable for debug_settings
		self.continue_button = builder.get_object('Continue',self.mainwindow)
		
		#configure Callbacks
		#callback names defined in *.ui file
		builder.connect_callbacks(self)
	
	
	#Logging function
	#
	# input string is recorded in the Log Field if Debug is on
	# and printed to the command line
	def Log(self, text):
		if(self.isDebug == 1):
			self.log.insert(tk.END, text)
			self.log.insert(tk.END, "\n")
		print(text + "\n")

	############################
	#define Callbacks
	############################
	
	#triggers when the "Send" button is pressed
	#
	#
	#
	def send_message(self):
		if(self.isDebug == 0):
			message = self.m_entry.get() + "\n" #gets the message in the field
			self.messages.insert(tk.END, "Sent: " + message) #puts the text in 'message' into the text field
			encr = self.encrypt(message)
			self.Log("{}   {} ".format("this", 9))
			#self.messages.insert(tk.END, "\n")
			if(self.isClient == 1):
				self.s.send(encr)
			else:
				self.c.send(encr)
			self.Log("message sent")
		else:
			self.Log("In debug mode, press continue to step through sending a message. \n")
			self.sending = 1
			self.receiving = 0
			self.cont_state = 0
			self.setup = 0

	def start_connection(self):
		IP = self.ip_entry.get()
		Port = int(self.port_entry.get())
		self.SharedSecret = self.ss_entry.get()
		self.isClientString = self.server_var.get()
		
		self.Log("Connection Information Confirmed:" )
		self.Log("IP address: " + IP)
		self.Log("Port number: " + str(Port))
		self.Log("Shared Secret entered")
		if(self.isClientString == "Server"):
			self.isClient = 0
			self.Log("Initialized as Server")
			#self.s = socket.socket()
			self.Log("Socket successfully created")
			try:
				self.s.bind(('', Port))
			except:
				self.s = socket.socket()
				self.s.bind(('', Port))
			self.Log("Socket binded to %s"%Port)
			self.s.listen(5)
			self.Log("Socket is listening")
			self.c, addr = self.s.accept()
			self.Log("Connection established\n\n")
		elif(self.isClientString == "Client"):
			self.isClient = 1
			self.Log("Initialized as Client")
			try:
				IP = socket.gethostbyname(IP)
			except socket.gaierror: 
				pass
			try:
				self.s.connect((IP, Port))
			except:
				self.s = socket.socket()
				self.s.connect((IP, Port))
			self.Log("Connection established")
			self.Log("Click continue to send Diffie-Hellman key part and Challenge\n\n")


	def sStep1(self):
		# STEP 1:
		# RECEIVE Client's DH AND Ra
		s1 =self.c.recv(2000).decode()
		self.Log("Diffie-Hellman key part and Challenge received.\n")

		# split the message into DH_Client and R_Client
		result = [x.strip() for x in s1.split(',')]
		DH_Client = int(result[0])
		self.DH_Client = DH_Client
		R_Client = result[1]
		self.Log("DH_Client = " + str(DH_Client))
		self.Log("R_Client = " + str(R_Client))
		data = R_Client + self.SharedSecret
		self.hash_val = sha3.sha3_224(data.encode('utf-8')).hexdigest()
		self.Log("Hash of R_Client and the shared secret = " + str(self.hash_val))
		self.Log("Click continue to send Challenge, Diffie-Hellman key part and Response-to-Challenge(the hash)\n\n" )

	def sStep2(self):
		# STEP 2:
		# SEND R_Server AND DH2 with g = 5, p = 23, b AND H(Ra, K_sss)
		b = random.randint(0,999999)
		self.Log("Diffie-Hellman g = 5, p = 77171, random b = " + str(b))
		R_Server = str(random.randint(0,sys.maxsize))
		self.R_Server = R_Server
		self.Log("Random challenge create = " + str(R_Server))
		self.c.send((R_Server + ',' + str(pow(5, b)%77171) + ',' + self.hash_val).encode())
		self.Log("Sending to client = " + str((R_Server + ',' + str(pow(5, b)%77171) + ',' + self.hash_val).encode()))
		self.key = pow(self.DH_Client, b)%77171
		self.Log("DH Key: %s\n\n"%str(self.key))

	def sStep3(self):
		# STEP 3:
		# RECEIVE H(R_Server, K_sss)
		s1 = self.c.recv(2000).decode()
		self.Log("Response-to-Challenge received.")
		self.Log("Hash_Client = " + str(s1))
		# Calculate hash and see if it matches with client's response
		data = self.R_Server + self.SharedSecret
		hash_val = sha3.sha3_224(data.encode('utf-8')).hexdigest()
		self.Log("Expected hash = " + hash_val)
		if(hash_val == s1):
			self.Log("Client Identity is Confirmed")
			self.Log("You Can Safely Talk to Client Now")
		else:
			self.Log("Client Identity is NOT Confirmed")
			self.c.close()





	def cStep1(self):
		# STEP 1:
		# SEND DH1 with g = 5, p = 23, a AND Ra
		a = random.randint(0,999999)
		self.a = a
		self.Log("Initiating Diffie-Hellman key part and Challenge.")
		self.Log("Diffie-Hellman g = 5, p = 77171, random a = " + str(a))
		R_Client = str(random.randint(0,sys.maxsize))
		self.Log("Random challenge create = " + R_Client)
		self.R_Client = R_Client
		self.Log("Sending Diffie-Hellman key part and Challenge = " + str((str(pow(5, a)%77171) + ',' + R_Client).encode()) + "\n\n")
		self.s.send((str(pow(5, a)%77171) + ',' + R_Client).encode())


	def cStep2(self):
		# STEP 2:
		# RECEIVE Rb, Server's DH, H(Ra, K_sss)
		s1 = self.s.recv(2000).decode()
		self.Log("Challenge, Diffie-Hellman key part and Response-to-Challenge received.")
		# split the message into R_Server, DH_Server, H_Server
		result = [x.strip() for x in s1.split(',')]
		DH_Server = int(result[1])
		R_Server = result[0]
		self.R_Server = R_Server
		H_server = result[2]
		self.Log("R_Server = " + str(R_Server))
		self.Log("DH_Server = " + str(DH_Server))
		self.Log("Hash_Server = " + str(H_server))
		self.key = pow(DH_Server, self.a)%77171
		self.Log("DH Key: %s"%str(self.key))

		# calculate hash and see if it matches with server's response
		data = self.R_Client + self.SharedSecret
		hash_val = sha3.sha3_224(data.encode('utf-8')).hexdigest()
		self.Log("Expected hash = " + str(hash_val))
		if(hash_val == H_server):
			self.Log("Server Identity is Confirmed")
			self.Log("Click continue to send Response-to-Challenge\n\n")
		else:
			self.Log("Server Identity is NOT Confirmed")
			self.s.close()

		


	def cStep3(self):
		# STEP 3:
			# SEND H(R_Server, K_sss)
			data = self.R_Server + self.SharedSecret
			hash_val = sha3.sha3_224(data.encode('utf-8')).hexdigest()
			self.Log("Sending Hash of R_Server and the shared secret = " + str(hash_val))
			self.s.send(hash_val.encode())

			self.Log("You Can Safely Talk to Server Now")

	#triggers when the "Confirm" button is pressed
	#
	#Grabs the values in the connection inputs fields
	#and stores them in corresponding class attributes(variables)
	def confirm_connection(self):
		self.start_connection()
		if(self.isDebug == 0):
			if(self.isClient == 0):			
				self.sStep1()
				self.sStep2()
				self.sStep3()

		
			elif(self.isClient == 1):
				self.cStep1()
				self.cStep2()
				self.cStep3()
		else:
			self.receiving = 0
			self.sending = 0
			self.cont_state = 0
			self. setup = 1
            
	
	#triggers when "Continue" button is pressed
	#
	#sets Continue State to allow protocol to continue
	def continue_button_pressed(self):


		if(self.sending == 1):
			if(self.cont_state == 0):
				self.message = self.m_entry.get() #gets the message in the field
				self.temp_msg = self.m_entry.get() + "\n"
				# ADD HASHING FOR INTEGRITY PROTECTION
				data = self.message + str(self.key)
				hash_val = sha3.sha3_224(data.encode('utf-8')).hexdigest()
				self.message = self.message + "###" + hash_val + "\n"

				self.Log("Message to be sent: \n" + self.message + "\n")
				self.Log("Press continue.\n")
				self.cont_state = 1
			elif(self.cont_state == 1):
				self.raw = self._pad(self.message)
				self.Log("Raw, Padded message with Hash(message, DHKey) added: \n" + self.raw + "\n")
				self.Log("Press continue.\n")
				self.cont_state = 2
			elif(self.cont_state == 2):
				self.iv = Random.new().read(AES.block_size)
				self.Log("Initialization Vector in base64: \n " + str(base64.b64encode(self.iv)) + "\n")
				self.Log("Press continue.\n")
				self.cont_state = 3
			elif(self.cont_state == 3):
				self.sharedKey = self.key*pow(10, (16 - len(str(self.key)))) 
				self.Log("Shared DH Key: \n" + str(self.key) + "\n")
				self.Log("Press continue.\n")
				self.cont_state = 5
			elif(self.cont_state == 5):
				self.cipher = AES.new(str(self.sharedKey).encode(), AES.MODE_CBC, self.iv)
				self.Log("Encrypted message in base64 using AES mode CBC: \n" + str(base64.b64encode(self.cipher.encrypt(self.raw.encode()))) + "\n")
				self.Log("Press continue.\n")
				self.cont_state = 6
			elif(self.cont_state == 6):
				cipher = AES.new(str(self.sharedKey).encode(), AES.MODE_CBC, self.iv)
				encr = base64.b64encode(self.iv + cipher.encrypt(self.raw.encode()))
				self.Log("Sending encrypted message with Hash(message, DHKey): \n" + str(encr) + "\n")
				self.Log("DONE\n")
				if(self.isClient == 1):
					self.s.send(encr)
				else:
					self.c.send(encr)
				self.cont_state = 0
				self.sending = 0
				self.messages.insert(tk.END, "Sent: " + self.temp_msg)


		elif(self.receiving == 1):
			if(self.cont_state == 0):
				if(self.isClient == 1):
					self.s.setblocking(0)
					try:
						self.message = self.s.recv(2000)
						self.Log("Message to be received: \n" + str(self.message) + "\n")
						self.Log("Press continue.\n")
						self.cont_state = 1
					except:
						self.Log("nothing to receive")
					self.s.setblocking(1)

				else:
					self.c.setblocking(0)
					try:
						self.message = self.c.recv(2000)
						self.Log("Message to be received: \n" + str(self.message) + "\n")
						self.Log("Press continue.\n")
						self.cont_state = 1
					except:
						self.Log("nothing to receive")
					self.c.setblocking(1)
			elif(self.cont_state == 1):	
				self.message = base64.b64decode(self.message)
				self.iv = self.message[:AES.block_size]
				self.Log("Initialized Vector in base64: \n " + str(base64.b64encode(self.iv)) + "\n")
				self.Log("Press continue.\n")
				self.cont_state = 2
			elif(self.cont_state == 2):
				self.sharedKey = self.key*pow(10, (16 - len(str(self.key))))
				self.Log("Shared DH Key: \n" + str(self.key) + "\n")
				self.Log("Press continue.\n")
				self.cont_state = 4
			elif(self.cont_state == 4):
				cipher = AES.new(str(self.sharedKey).encode(), AES.MODE_CBC, self.iv)
				msg = self._unpad(cipher.decrypt(self.message[AES.block_size:])).decode('utf-8')

				# CHECK FOR HASH CHANGE
				result = [x.strip() for x in str(msg).split("###")]
				data = result[0] + str(self.key)
				hash_val = sha3.sha3_224(data.encode('utf-8')).hexdigest()
				self.Log("Expected hash = " + hash_val)
				self.Log("Received hash = " + result[1])

				if(result[1] != hash_val):
					self.Log("Warning! Message has been modified by a third party!")
				
				self.Log("Decrypted message using AES mode CBC: \n" + result[0] + "\n")
				self.Log("DONE\n")
				self.cont_state = 0
				self.receiving = 0
				self.messages.insert(tk.END, "Received: " + result[0] + "\n")










		elif(self.setup == 1):
			if(self.isClient == 1):
				if(self.cont_state == 0):
					self.cStep1()
					self.cont_state = 1
				elif(self.cont_state == 1):
					self.cStep2()
					self.cont_state = 2
				elif(self.cont_state == 2):
					self.cStep3()
					self.cont_state = 0
					self.setup = 0

			else:
				if(self.cont_state == 0):
					self.sStep1()
					self.cont_state = 1
				elif(self.cont_state == 1):
					self.sStep2()
					self.cont_state = 2
				elif(self.cont_state == 2):
					self.sStep3()
					self.cont_state = 0
					self.setup = 0


		else:
			self.Log("Send or receive a message to start")
		return
	
	#triggers when the debug checkbox is pressed
	#
	#toggles the stored debug variable
	def debug_setting_change(self):
		self.isDebugString = self.debug_var.get()
		if(self.isDebugString == "Debug_Off"):           # Turn Debug off, set continue to 
			self.isDebug = 0
			self.cont_state = 1                  
		elif(self.isDebugString == "Debug_On"):          # Turn Debug On, Set continue state
			self.isDebug = 1
			self.cont_state = 0
		self.Log("Debug setting changed to: " + self.isDebugString)
		self.Log("Cont_state set to " + str(self.cont_state))
	
	###############################
	#
	###############################		
		
	def rec_message(self):
		if(self.isDebug == 0):
			message = "Received: "
			if(self.isClient == 1):
				self.s.setblocking(0)
				try:
					decr = self.s.recv(2000)
					message += self.decrypt(decr)
					self.messages.insert(tk.END, message) #puts the text in 'message' into the text field
					#self.messages.insert(tk.END, "\n")
				except:
					self.Log("nothing to receive")
				self.s.setblocking(1)
			else:
				self.c.setblocking(0)
				try:
					decr = self.c.recv(2000)
					message += self.decrypt(decr)
					self.messages.insert(tk.END, message) #puts the text in 'message' into the text field
					#self.messages.insert(tk.END, "\n")
				except:
					self.Log("nothing to receive")
				self.c.setblocking(1)
		else:
			self.Log("In debug mode, press continue to step through sending a receiving a message. \n")
			self.sending = 0
			self.receiving = 1
			self.cont_state = 0
			self.setup = 0
	
	def disconnect(self):
		try:
			self.s.close()
		except:
			self.Log("no socket to close")
		try:
			self.c.close()
		except:
			self.Log("no socket to close")

	def __del__(self):
		try:
			self.s.close()
		except:
			self.Log("no socket to close")
		try:
			self.c.close()
		except:
			self.Log("no socket to close")

	def encrypt(self, raw):
		raw = self._pad(raw)
		iv = Random.new().read(AES.block_size)
		#pad DHKey to 16 bytes
		Shared_K = self.key*pow(10, (16 - len(str(self.key))))
		if(Shared_K == 0):
			Shared_K = 1000000000000000

		cipher = AES.new(str(Shared_K).encode(), AES.MODE_CBC, iv)
		return base64.b64encode(iv + cipher.encrypt(raw.encode()))

	def decrypt(self, enc):
		enc = base64.b64decode(enc)
		iv = enc[:AES.block_size]
		#pad DHKey to 16 bytes
		Shared_K = self.key*pow(10, (16 - len(str(self.key))))
		if(Shared_K == 0):
			Shared_K = 1000000000000000

		cipher = AES.new(str(Shared_K).encode(), AES.MODE_CBC, iv)
		return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

	def _pad(self, s):
		return  s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

	def _unpad(self, s):
		return s[:-ord(s[len(s)-1:])]
#runs the application
if __name__ == '__main__':
    root = tk.Tk()
    app = Application(root)
    root.mainloop()