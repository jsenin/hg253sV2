#! /usr/bin/env python

# source code modified from hg658c.wordpress.com
# https://github.com/jsenin/hg253sV2
# decrypt and crypt config files for HG253sV2 firmware version V100R001C202B026


# alternative command line tool
# openssl enc -aes-128-cbc -K CB8C4A517D6FAD6C86DBC4795A492C0E -iv D4AC8D2D9BFB6DCF5D10ACB4AE20172B -d -in configfile.conf -out decrypted.conf;

import sys
import os
from binascii import hexlify, unhexlify 
from Crypto.Cipher import AES
import zlib

AES128CBC_KEY = "CB8C4A517D6FAD6C86DBC4795A492C0E"
AES128CBC_IV  = "D4AC8D2D9BFB6DCF5D10ACB4AE20172B"

XML_VERSION_STRING = b'<?xml version="1.0" ?>'

def decrypt_body(enc_config_body):
	iv = unhexlify(AES128CBC_IV)
	key= unhexlify(AES128CBC_KEY)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	decrypted_data = cipher.decrypt(enc_config_body)
	# Strip block padding
	decrypted_data=decrypted_data.rstrip(b'\0')
	return decrypted_data

def check_config(new_config_file):
	head = new_config_file[0:len(XML_VERSION_STRING)]
	if head != XML_VERSION_STRING:
		print("Not a valid config file...exiting")
		sys.exit(1)

def save_to_file(dest_file, data):
	wfile = open(dest_file,"wb")
	wfile.write(data)
	wfile.close()

def decrypt_config(input_file, output_file):
	enc_config=load_config(input_file)
	enc_config_body=enc_config

	print("Decrypting...")
	decrypted_data = decrypt_body(enc_config_body)
	check_config(decrypted_data)

	print("Saving decrypted config to " + output_file + "...")
	save_to_file(output_file, decrypted_data)


def print_usage():
	print("Usage : " + sys.argv[0] + " {encrypt | decrypt} input_file output_file")
	sys.exit(1)

def load_config(config_file):
	if os.path.isfile(config_file):
		cf = open(config_file, "rb")
		config = cf.read()
		cf.close()
	else:
		print("Config file not found..exiting")
		sys.exit(1) 
	return config

def main():

	if len(sys.argv) < 4:
		print_usage()

	input_file = sys.argv[2]
	output_file = sys.argv[3]
	command = sys.argv[1]

	if (command == "encrypt"):
		encrypt_config(input_file, output_file)
	elif (command == "decrypt"):
		decrypt_config(input_file, output_file)	
	else: 
		print_usage()

def encrypt_config(input_file, output_file):
	new_config_file=load_config(input_file)

	check_config(new_config_file)

	padding_amount = len(new_config_file) % 32
	print("" + str(padding_amount) + " bytes padding needed")
	print("Adding padding...")
	new_config_file=new_config_file + b'\0'*(32-padding_amount)

	print("Encrypting config...")
	iv = unhexlify(AES128CBC_IV)
	key= unhexlify(AES128CBC_KEY)
	aes = AES.new(key, AES.MODE_CBC, iv)
	enc_new_config = aes.encrypt(new_config_file)

	print("Saving encrypted config to " + output_file + "...")
	save_to_file(output_file, enc_new_config)

if __name__ == "__main__":
	main()
