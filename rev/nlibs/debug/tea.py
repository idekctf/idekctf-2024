import struct

TEA_DELTA = 0x9E3779B9
TEA_N = 32

def tea_encrypt(block, key, endian="!"):
	"""Encrypt 32 bit data block using TEA block cypher
		* block = 64 bit/8 bytes (byte string)
		* key = 128 bit/16 bytes (byte string)
		* endian = byte order (default '!', commonly used '<' and '>'; see also 'struct' module documentation) (string)
	"""
	(pack, unpack) = (struct.pack, struct.unpack)
	
	(y, z) = unpack(endian+"2L", block)
	k = unpack(endian+"4L", key)
	
	global TEA_DELTA, TEA_N
	(sum, delta, n) = 0, TEA_DELTA, TEA_N
	
	for i in range(n):
		sum = (sum + delta) & 0xFFFFFFFF
		y += (((z<<4)+k[0]) ^ (z+sum) ^ ((z>>5)+k[1])) & 0xFFFFFFFF
		y &= 0xFFFFFFFF
		z += (((y<<4)+k[2]) ^ (y+sum) ^ ((y>>5)+k[3])) & 0xFFFFFFFF
		z &= 0xFFFFFFFF
	return pack(endian+"2L", y, z)

def tea_decrypt(block, key, endian="!"):
	"""Decrypt 32 bit data block using TEA block cypher
		* block = 64 bit/8 bytes (byte string)
		* key = 128 bit/16 bytes (byte string)
		* endian = byte order (default '!', commonly used '<' and '>'; see also 'struct' module documentation) (string)
	"""
	(pack, unpack) = (struct.pack, struct.unpack)
	
	(y, z) = unpack(endian+"2L", block)
	k = unpack(endian+"4L", key)
	
	global TEA_DELTA, TEA_N
	(sum, delta, n) = 0, TEA_DELTA, TEA_N

	sum = delta<<5
	for i in range(n):
		z = (z - (((y<<4)+k[2]) ^ (y+sum) ^ ((y>>5)+k[3]))) & 0xFFFFFFFF
		y = (y - (((z<<4)+k[0]) ^ (z+sum) ^ ((z>>5)+k[1]))) & 0xFFFFFFFF
		sum = (sum - delta) & 0xFFFFFFFF
	return pack(endian+"2L", y, z)

def tea_encrypt_all(data, key, endian="!"):
	"""Encrypt a entire string using TEA block cypher"""
	newdata = b''
	data_s = len(data)
	data_p = data_s%8
	if data_p:
		data_pl = 8-data_p
		data+=bytes(data_pl)
		data_s+=data_pl
	for i in range(data_s//8):
		block = data[i*8:(i*8)+8]
		newdata+=tea_encrypt(block, key, endian)
	return newdata

def tea_decrypt_all(data, key, endian="!"):
	"""Decrypt a entire string using TEA block cypher"""
	newdata = b''
	data_s = len(data)
	data_p = data_s%8
	if data_p:
		data_pl = 8-data_p
		data+=bytes(data_pl)
		data_s+=data_pl
	for i in range(data_s//8):
		block = data[i*8:(i*8)+8]
		newdata+=tea_decrypt(block, key, endian)
	return newdata

class TEA(object):
	"""TEA class implementation"""
	def __init__(self, key, endian="!"):
		self.key = key
		self.endian = endian

	def encrypt(self, block):
		global tea_encrypt
		return tea_encrypt(block, self.key, self.endian)

	def decrypt(self, block):
		global tea_decrypt
		return tea_decrypt(block, self.key, self.endian)

	def encrypt_all(self, data):
		global tea_encrypt_all
		return tea_encrypt_all(data, self.key, self.endian)

	def decrypt_all(self, data):
		global tea_decrypt_all
		return tea_decrypt_all(data, self.key, self.endian)