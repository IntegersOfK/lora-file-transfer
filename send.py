#!/usr/bin/env python

""" For splitting a file into 252 byte pieces and sending it via LoRa """


import pathlib
import argparse
import time
import progressbar

# TODO setup the adafruit_rfm9x library

bytes_per_message = 252 # this is the max number of bytes the adafruit_rfm9x library is able to send in a message over LoRa

if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--input', required=True, help='the path to the file you wish to send')
	args = parser.parse_args()

	all_bytes = pathlib.Path(args.input).read_bytes() # get the file as bytes
	packaged_data = [all_bytes[i:i+bytes_per_message] for i in range(0, len(all_bytes), bytes_per_message)]

	print(str(args.input) + ' is ' + str(len(all_bytes)/1024)  +' kilobytes and can be sent in ' + str(len(packaged_data)) + ' messages of ' + str(bytes_per_message) + ' bytes each')

	i = 0
	start_time = time.time()
	for p in progressbar.progressbar(packaged_data, redirect_stdout=True):
		i += 1
		#print('Sending message ' + str(i) + ' of ' + str(len(packaged_data))) # using progressbar instead
		time.sleep(1) # how long does a message take to send? Let's simulate it taking 1 second, even though it seems like that might be faster than reasonable
		# TODO replace that sleep with actual transmit like rfm9x.send_with_ack(p)
	print('Done! Transmit took ' + str(int(time.time()-start_time)) + ' seconds')

