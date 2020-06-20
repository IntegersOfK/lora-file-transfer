#!/usr/bin/env python

""" For splitting a file into 252 byte pieces and sending it via LoRa """


import pathlib
import argparse

bytes_per_message = 252 # this is the max number of bytes the adafruit_rfm9x library is able to send in a message over LoRa

if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--input', required=True, help='the path to the file you wish to send')
	args = parser.parse_args()

	all_bytes = pathlib.Path(args.input).read_bytes()
	packaged_data = [all_bytes[i:i+bytes_per_message] for i in range(0, len(all_bytes), bytes_per_message)]
	print(str(args.input) + ' is ' + str(len(all_bytes)/1024)  +' kilobytes and can be sent in ' + str(len(packaged_data)) + ' messages of ' + str(bytes_per_message) + ' bytes each')

