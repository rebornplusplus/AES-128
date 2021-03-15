#!/usr/bin/python3

"""
	CS 406 - Computer Security
	Offline 1 | AES-128
	@author: 1605109 | Rafid Bin Mostofa
	@date: March 13, 2021
"""

import io, sys, os, getopt, time
from BitVector import *

class FieldOp:
	"""
		GF(1<<8) ops
		AES_mod = x^8 + x^4 + x^3 + x + 1
	"""

	AES_mod = BitVector(bitstring='100011011')

	def mult(a, b):
		va = BitVector(intVal=a, size=8)
		vb = BitVector(intVal=b, size=8)
		vr = va.gf_multiply_modular(vb, FieldOp.AES_mod, 8)
		return vr.intValue()

class AES:
	"""
		Class for AES-128 encryption.
		https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
	"""

	rounds_by_key_length = { 4: 10, 6: 12, 8: 14 }

	"""
		https://en.wikipedia.org/wiki/Rijndael_S-box
		Rijndael's Substitution box and inverse substitution box
	"""
	s_box = (
		0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
		0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
		0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
		0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
		0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
		0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
		0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
		0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
		0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
		0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
		0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
		0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
		0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
		0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
	)
	inv_s_box = (
		0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
		0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
		0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
		0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
		0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
		0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
		0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
		0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
		0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
		0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
		0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
		0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
		0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
		0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
		0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
	)

	"""
		column mixer and inverse mixer
	"""
	mixer = [ 
		[ 0x02, 0x03, 0x01, 0x01 ],
		[ 0x01, 0x02, 0x03, 0x01 ],
		[ 0x01, 0x01, 0x02, 0x03 ],
		[ 0x03, 0x01, 0x01, 0x02 ]
	]
	inv_mixer = [
		[ 0x0e, 0x0b, 0x0d, 0x09 ],
		[ 0x09, 0x0e, 0x0b, 0x0d ],
		[ 0x0d, 0x09, 0x0e, 0x0b ],
		[ 0x0b, 0x0d, 0x09, 0x0e ]
	]

	def __init__(self, key):
		assert (len(key) // 4) in AES.rounds_by_key_length
		self.key = key
		self.Nk = len(self.key) // 4
		self.Nr = AES.rounds_by_key_length[self.Nk]
		self.Nb = 4
		self.expand_key()

	def expand_key(self):
		"""
			Key schedule
			rcon is the round constant
			https://en.wikipedia.org/wiki/AES_key_schedule
		"""

		start_time = time.time()

		self.words = arr_to_mat(self.key)
		rcon = 1
		for i in range(self.Nk, self.Nb * (self.Nr + 1), 1):
			temp = list(self.words[i - 1])
			if i % self.Nk == 0:
				self.rotword(temp)
				self.subword(temp)
				temp[0] ^= rcon
				rcon = (rcon << 1) ^ (0x11B & -(rcon >> 7))
			elif self.Nk > 6 and i % self.Nk == 4:
				self.subword(temp)
			self.words.append(self.xorword(self.words[i - self.Nk], temp))

		elapsed = time.time() - start_time
		print("Key Scheduling: {:.9f} seconds".format(elapsed))
	
	def encrypt(self, inp):
		"""
			encrypt 128 bits
			inp is a length 16 byte-array
			returns a 16 bytes of cipher text
		"""
		assert len(inp) == 16

		state = arr_to_mat(inp)

		self.add_round_key(state, self.get_round_key(0))
		for round in range(1, self.Nr, 1):
			self.sub_bytes(state)
			self.shift_rows(state)
			self.mix_columns(state)
			self.add_round_key(state, self.get_round_key(round))

		self.sub_bytes(state)
		self.shift_rows(state)
		self.add_round_key(state, self.get_round_key(self.Nr))
		
		return mat_to_arr(state)
	
	def decrypt(self, inp):
		"""
			decrypt 128 bits
			inp is a length ciphered 16 bytes array
			returns 16 bytes deciphered array
		"""
		assert len(inp) == 16

		state = arr_to_mat(inp)

		self.add_round_key(state, self.get_round_key(self.Nr))
		for round in range(self.Nr - 1, 0, -1):
			self.inv_shift_rows(state)
			self.inv_sub_bytes(state)
			self.add_round_key(state, self.get_round_key(round))
			self.inv_mix_columns(state)

		self.inv_shift_rows(state)
		self.inv_sub_bytes(state)
		self.add_round_key(state, self.get_round_key(0))

		return mat_to_arr(state)
	
	def subword(self, word):
		"""
			substitute word bytes, needed for key expansion
		"""
		for i in range(4):
			word[i] = self.s_box[word[i]]
		
	def rotword(self, word):
		"""
			1 cyclic left rotation
		"""
		word.append(word.pop(0))

	def xorword(self, w1, w2):
		"""
			xor two bytewords
		"""
		assert len(w1) == 4 and len(w2) == 4
		return [(w1[i] ^ w2[i]) for i in range(0, 4)]

	def get_round_key(self, iter):
		return [self.words[iter * 4 + k] for k in range(4)]
	
	def add_round_key(self, state, round_key):
		for i in range(4):
			for j in range(4):
				state[i][j] ^= round_key[i][j]
	
	def sub_bytes(self, state):
		for i in range(4):
			for j in range(4):
				state[i][j] = self.s_box[state[i][j]]
	
	def shift_rows(self, s):
		s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
		s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
		s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

	def mix_columns(self, s):
		for i in range(4):
			c = s[i]
			cp = [ 0, 0, 0, 0 ]
			for j in range(4):
				for k in range(4):
					cp[j] ^= FieldOp.mult(AES.mixer[j][k], c[k])
			s[i] = cp
	
	def inv_sub_bytes(self, state):
		for i in range(4):
			for j in range(4):
				state[i][j] = self.inv_s_box[state[i][j]]
	
	def inv_shift_rows(self, s):
		s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
		s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
		s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

	def inv_mix_columns(self, s):
		for i in range(4):
			c = s[i]
			cp = [ 0, 0, 0, 0 ]
			for j in range(4):
				for k in range(4):
					cp[j] ^= FieldOp.mult(AES.inv_mixer[j][k], c[k])
			s[i] = cp

def arr_to_mat(arr):
	"""
		return a (N/4) x 4 matrix from a N length array
	"""
	return [list(arr[i:i+4]) for i in range(0, len(arr), 4)]

def mat_to_arr(mat):
	"""
		return a row x col length array flattening the matrix
	"""
	arr = []
	for row in mat:
		for entry in row:
			arr.append(entry)
	return arr

def pad(arr):
	"""
		Pad the given byte array with PKCS#7 padding to a multiple of 16 bytes
		if arr size is already a multiple of 16, a whole new block will be added
	"""
	pad_len = 16 - (len(arr) % 16)
	padding = bytes([ pad_len ] * pad_len)
	return arr + padding

def unpad(arr):
	"""
		Remove PKCS#7 padding, return unpadded byte array and ensure padding correctness
	"""
	pad_len = arr[-1]
	assert pad_len > 0
	org, padding = arr[:-pad_len], arr[-pad_len:]
	assert all(p == pad_len for p in padding)
	return org

def read_file(fname):
	"""
		read bytes from a file and return
	"""
	try:
		file = open(fname, "rb")
	except FileNotFoundError:
		print("Err: File '{}' could not be opened.".format(fname))
		exit(0)
	
	ret = io.BytesIO()
	byte = file.read(1)
	while byte:
		ret.write(byte)
		byte = file.read(1)

	file.close()
	ret.seek(0)
	return bytearray(ret.getvalue())

def write_file(fname, arr):
	"""
		write bytes to a file
	"""
	try:
		file = open(fname, "wb")
	except FileNotFoundError:
		print("Err: File '{}' could not be written.".format(fname))
		exit(0)
	
	file.write(arr)
	file.close()

def print_progress_bar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', blank = '-', printEnd = "\r"):
	"""
		Call in a loop to create terminal progress bar
		@params:
			iteration   - Required  : current iteration (Int)
			total       - Required  : total iterations (Int)
			prefix      - Optional  : prefix string (Str)
			suffix      - Optional  : suffix string (Str)
			decimals    - Optional  : positive number of decimals in percent complete (Int)
			length      - Optional  : character length of bar (Int)
			fill        - Optional  : bar fill character (Str)
			printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
		Credit: https://stackoverflow.com/a/34325723
	"""
	percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
	filledLength = int(length * iteration // total)
	bar = fill * filledLength + blank * (length - filledLength)
	print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
	if iteration == total: 
		print()

if __name__ == "__main__":
	arglist = sys.argv[1:]
	options = "k:m:f:chu"
	long_options = [ "key-len=", "mode=", "file=", "console", "hex", "usage" ]

	KEY_LEN = 16
	OP = "encrypt"
	CONSOLE = True
	HEXIO = False
	FILENAME = ""

	key_bytes = None
	txt_bytes = None

	try:
		args, vals = getopt.getopt(arglist, options, long_options)
		for cur_arg, cur_val in args:
			if cur_arg in ("-k", "--key-len"):
				KEY_LEN = int(cur_val)
				if not (KEY_LEN == 16 or KEY_LEN == 24 or KEY_LEN == 32):
					print("Err: Key length 16/24/32 bytes.")
					exit(0)
			if cur_arg in ("-m", "--mode"):
				OP = str(cur_val)
				if not (OP == "encrypt" or OP == "decrypt"):
					print("Err: mode = encrypt / decrypt")
					exit(0)
			if cur_arg in ("-f", "--file"):
				CONSOLE = False
				FILENAME = str(cur_val)
				txt_bytes = read_file(FILENAME)
			if cur_arg in ("-c", "--console"):
				CONSOLE = True
			if cur_arg in ("-h", "--hex"):
				HEXIO = True
			if cur_arg in ("-u", "--usage"):
				print("AES-128 encryption | Usage:")
				print("\t-k, --key-len      mention the key length in bytes, possible options are 16, 24 or 32.")
				print("\t-m, --mode         mention the procedure, either 'encrypt' or 'decrypt' without quotes.")
				print("\t-f, --file         provide the filename with relative/absolute path to encrypt/decrypt it.")
				print("\t                   not to be used with: -h, --hex, -c, --console.")
				print("\t-c, --console      encrypt/decrypt ASCII plaintext through console.")
				print("\t                   not to be used with: -f, --file.")
				print("\t-h, --hex          when in console mode, output encrypted bytes and input to decrypt bytes in hexadecimal string.")
				print("\t                   to be used with: -c or --console.")
				print("\t                   not to be used with: -f, --file.")
				exit(0)
	except getopt.error as err:
		sys.stderr.write(err)
		sys.stderr.flush()

	key = input("Input {} bytes key: ".format(KEY_LEN))
	key_bytes = bytearray(key, "UTF-8")

	if len(key_bytes) > KEY_LEN:
		key_bytes = key_bytes[:KEY_LEN]
	else:
		while len(key_bytes) < KEY_LEN:
			key_bytes.append(0)
	
	# print("Input key in hex: " + str(' '.join(format(x, '02x') for x in key_bytes)))

	if CONSOLE:
		txt = sys.stdin.read()
		if OP == "decrypt" and HEXIO:
			txt = txt.replace(' ', '')
			txt = txt.replace('\n', '')
			txt_bytes = bytearray.fromhex(txt)
		else:
			txt_bytes = bytearray(txt, "UTF-8")

	if OP == "encrypt":
		txt_bytes = pad(txt_bytes)
	else:
		if len(txt_bytes) % 16 != 0:
			print("Err: Padding wasn't done in encryption")
			exit(0)

	# print("Text bytes in hex: " + str(' '.join(format(x, '02x') for x in txt_bytes)))

	txt_blocks = [ txt_bytes[i:i+16] for i in range(0, len(txt_bytes), 16) ]
	out_blocks = [ ]

	aes = AES(key_bytes)

	start_time = time.time()

	step = 0
	print_progress_bar(step, len(txt_blocks), prefix = 'Progress', suffix = 'Complete', length=50, fill = '#', blank = '.')
	for block in txt_blocks:
		if OP == "encrypt":
			out_blocks.append(aes.encrypt(block))
		else:
			out_blocks.append(aes.decrypt(block))
		step += 1
		# time.sleep(0.1)
		print_progress_bar(step, len(txt_blocks), prefix = 'Progress', suffix = 'Complete', length=50, fill = '#', blank = '.')

	elapsed = time.time() - start_time
	print(OP + " time: {:.2f} seconds".format(elapsed))
	
	out_bytes = mat_to_arr(out_blocks)
	out_bytes = bytearray(out_bytes)

	if OP == "decrypt":
		out_bytes = unpad(out_bytes)
	
	if CONSOLE:
		if OP == "encrypt" and HEXIO:
			print(str(''.join(format(x, '02x') for x in out_bytes)))
		else:
			sys.stdout.buffer.write(out_bytes)
	else:
		write_file(FILENAME, out_bytes)

