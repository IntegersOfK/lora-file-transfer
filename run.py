
import os
import argparse
import pathlib
import textwrap
import time
import hashlib
import json
import progressbar
import setupbon # offload all the bonnet-specific settings


class Transceiver():
    #bytes_per_message = 252 # this is the max number of bytes the adafruit_rfm9x library is able to send in a message over LoRa
    bytes_per_message = 100
    send_or_rec = 'recieve'
    valid_modes = ['data destination node id', 'this node id', 'toggle send or recieve']
    selection_mode = valid_modes[0]
    min_transmit_interval = 0
    packaged_data = {} # where we store files ready to be sent
    collected = {}  # where we store recieved messages until we have all pieces

    def __init__(self, rfm9x, display, incoming, outgoing=None, fernet=None):
        self.rfm9x = rfm9x
        self.display = display
        self.incoming_directory = incoming
        self.outgoing_file_path = outgoing
        self.fernet = fernet

    def update_display(self, text):
        self.display.fill(0)
        self.display.text(textwrap.fill(text, 20), 0,0, 1)
        self.display.show()

    def cycle_selection_mode(self):
        """First button. Changes the selection mode"""
        self.selection_mode = self.valid_modes[(self.valid_modes.index(self.selection_mode)+1)%len(self.valid_modes)]
        self.update_display(self.selection_mode)

    def decrease(self):
        """Second button. Changes the destination or node number to down one"""
        if self.selection_mode == self.valid_modes[0]:
            if self.rfm9x.destination > 0:
                self.rfm9x.destination -= 1
            else:
                self.rfm9x.destination = 255
            self.update_display("Broadcast destination is node: {0}".format(self.rfm9x.destination))
        elif self.selection_mode == self.valid_modes[1]:
            if self.rfm9x.node > 0:
                self.rfm9x.node -= 1
            else:
                self.rfm9x.node = 255
            self.update_display("This node id is set to: {0}".format(self.rfm9x.node))
        elif self.selection_mode == self.valid_modes[2]:
            if self.send_or_rec == 'receive':
                self.send_or_rec = 'send'
            else:
                self.send_or_rec = 'receive'
            self.update_display("This node is configured to: {0} press button 3 to start".format(self.send_or_rec.upper()))

    def increase(self):
        """Third button. Changes the destination or node number to up one"""
        if self.selection_mode == self.valid_modes[0]:
            if self.rfm9x.destination < 255:
                self.rfm9x.destination += 1
            else:
                self.rfm9x.destination = 0
            self.update_display("Broadcast destination is node: {0}".format(self.rfm9x.destination))
        elif self.selection_mode == self.valid_modes[1]:
            if self.rfm9x.node < 255:
                self.rfm9x.node += 1
            else:
                self.rfm9x.node = 0
            self.update_display("This node id is set to: {0}".format(rfm9x.node))
        elif self.selection_mode == self.valid_modes[2]:
            if self.send_or_rec == 'receive':
                self.update_display("Receive mode listening for messages...")
            else:
                self.update_display("Send mode, sending requested file...")
                self.send()


    def request_file_metadata(self):
        """When somebody sends a message requesting a file"""
        all_bytes = pathlib.Path(self.outgoing_file_path).read_bytes() # get the file as bytes
        # we can reasonably assume the first 6 characters are good enough to know it's the right file. Sure, small chance of collision but it will be used in every message so it needs to be short!
        filehash = hashlib.sha256(all_bytes).hexdigest()[:6]
        if self.fernet:
            print("Encrypting bytes string, size before encryption " + str(len(all_bytes)))
            all_bytes = self.fernet.encrypt(all_bytes)
            print("Size after encryption " + str(len(all_bytes)))
        self.packaged_data[filehash] = [bytearray(all_bytes[i:i+self.bytes_per_message], 'utf-8') for i in range(0, len(all_bytes), self.bytes_per_message)] # turn it into the right number of messages

        print(str(self.outgoing_file_path) + ' is ' + str(len(all_bytes)/1024)  +' kilobytes and can be sent in ' + str(len(packaged_data)) + ' messages of ' + str(self.bytes_per_message) + ' bytes each')

        start_time = time.time()
        print('Sending metadata about the file we are about to send')
        metadata = [0, filehash, pathlib.Path(self.outgoing_file_path).name, len(packaged_data)] # status 0 to start, filehash, filename, number of messages to be sent
        encoded_metadata = bytearray(json.dumps(metadata), 'utf-8')
        print(encoded_metadata)
        self.rfm9x.send_with_ack(encoded_metadata)

    def send_pieces(self, filehash, part):
        """Sends piece(s) of the requested file"""
        if part == 0:
            # send all parts in sequence
            index = 0
            for p in self.packaged_data[filehash]['messages']:
                 #if self.min_transmit_interval: time.sleep(self.min_transmit_interval)
                self.rfm9x.send_with_ack(bytes(str(index).zfill(4)) + bytes(filehash, 'utf-8') + p) # hash is the delimiter between metadata and filedata.
        else:
            # send the specific part requested
            self.rfm9x.send_with_ack(bytes(str(index).zfill(4)) + bytes(filehash, 'utf-8') + self.packaged_data[filehash][part]) # hash is the delimiter
        
    def combine_pieces(self, filehash):
        """Puts together all the pieces in the list"""
        all_bytes = b''.join(self.collected[filehash])
        if self.fernet:
            all_bytes = f.decrypt(all_bytes)
            print("Decrypted data with provided password")
        this_filehash = hashlib.sha256(all_bytes).hexdigest()[:6]
        if this_filehash == filehash:
            print("File hash matches, file integrity confirmed!")
        else:
            print("File hash doesn't match, writing to file anyway...")
        with open(os.path.join(self.output_dir, self.collected[filehash]['filename']), "wb") as f:
            f.write(all_bytes)
        print("Done, got the file! " + os.path.join(self.output_dir, self.collected[filehash]['filename']))

    
    # These are the codes we use in the first 4 bytes to know what we want
    # CODES = {'-200'}, # request a list of file hashes
    #         '-201': {'h':None}}, # request a file's metadata
    #         '-202', {'h':None}} # request all parts of a file
    #         '-203', {'h':None, 'p':0}, # request specific part of a file
    #         '-301' # make and forward command functions (with pieces?)
    #         }                   
                                

    def process_message(self, packet):
        """Deals with requests for information OR the collection of packets to stick them pack together when we have them all"""
        # TODO Working HERE do the check for data
        # Check if there's metadata
        # We need to always know that it's a bytesarray... need to find away against no json differentiation
        # check if request for metafdaa

        # We use the first 10 bytes in the packet The first 4 are piece numbers, and the next 6 are hash
        pieceid = packet[:4] # This comes in as a byte array, so put them together as an int
        pid = int(pieceid[0])*1000
        pid += int(pieceid[1])*100
        pid += int(pieceid[2])*10
        pid += int(pieceid[3])
        filehash = packet[4:10] # next 6 are filehash
        data = packet[10:]
        print("pieceid:")
        print(pid)
        print("filehash")
        print(filehash)
        print('data')
        print(data)

        if pid == 0:
            print("Some sort of meta was requested, interpreting data as dict")
            print(json.loads(data.decode('utf-8')))

        #print(piece)
        # if not self.collected.get(filehash):
        #     print("A file we have not seen before! " + filehash)
        #     self.collected[filehash] = {'meta':{}, 'messages':{}}

        # if piece == b'-200':
        #     print("A specific piece of a file is being requested")
        #     self.collected[filehash]['filename']
        #     a = json.loads(data.decode('utf-8'))

        # elif piece == b'-101':
        #     print("Meta information is being requested about the file to send!")
        #     self.rfm9x.send_with_ack(bytes(str(index).zfill(4)) + bytes(filehash, 'utf-8') + self.packaged_data[filehash][part]) # hash is the delimiter

        # elif piece == b'-102':
        #     print("Meta information is arriving about the file we want!")
        #     self.collected[filehash]['filename'] = a[0]
        #     a = json.loads(data.decode('utf-8'))


        # elif piece.isdigit():
        #     print("A piece of a file is being requested")
        #     self.rfm9x.send_with_ack(bytes(str(index).zfill(4)) + bytes(filehash, 'utf-8') + self.packaged_data[filehash][part]) # hash is the delimiter
        #     self.collected[filehash]['messages'][int(piece)] = data

        
        # try:
        #     decoded = packet.decode('utf-8')
        #     print(decoded)
        #     a = json.loads(decoded)
        #     if len(a):
        #         status = int(a[0])
        #         if status == 0:
        #             self.filename = a[1]
        #             self.total_messages = a[2]
        #             self.filehash = a[3]
        #             print("Recieved metadata about a new file to receive.")
        #             self.b.update_display("File incoming... " + self.filename)
        #             self.message_count = 0
                    
        #         if status == 1:
        #             print("Recieved all messages to recreate the file")
        #             self.b.update_display("File done recieving! " + self.filename)
        #             self.combine_pieces()
        # except Exception as e: # for cases when it's not metadata...
        #     if not self.filehash:
        #         print("Packet was received but no metadata was received earlier, ignoring")
        #         self.b.update_display("Got packet, but no metadata")
        #         return
        #     self.message_count += 1
        #     self.collected.append(bytes(packet))
        #     print("Recieving packet " + str(self.message_count) + " of " +  str(self.total_messages))
        #     self.b.update_display("Recieving packet " + str(self.message_count) + " of " +  str(self.total_messages))

def main(b, btnA, btnB, btnC):
    last_press = time.time()
    button_debounce = 0.200 # time until another press can be registered
    while True:
        if b.send_or_rec == 'receive':
            # Look for a new packet: only accept if addresses to my_node
            packet = b.rfm9x.receive(keep_listening=True, with_header=False, with_ack=True, timeout=0.3)
            # If no packet was received during the timeout then None is returned.
            if packet is not None:
                # Received a packet!
                # Print out the raw bytes of the packet:
#                print("Received (raw header):", [hex(x) for x in packet[0:4]])
                print("Received (raw packet): {0}".format(packet))
                print("Received RSSI: {0}".format(rfm9x.last_rssi))
                b.update_display("Recieving packet! Time: " + str(time.time()))
                print("Receiving packet! Time: " + str(time.time()))
                b.process_message(packet)
                packet = None
        if last_press < time.time()-button_debounce:
            last_press = time.time()
            if not btnA.value:
                last_press = int(time.time())
                b.cycle_selection_mode()
            if not btnB.value:
                b.decrease()
            if not btnC.value:
                b.increase() # button 3 can trigger the sending, so they might need fernet to encrypt with the given password

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--incoming', help='the directory where incoming files should be written in receiving mode, defaults to current working directory', default=os.getcwd())
    parser.add_argument('-o', '--outgoing', help='the path to the file you want to send if in sending mode')
    parser.add_argument('-p', '--password', help='a string to encrypt the file contents - but metadata is not encrypted, which means the filename and number of messages to transfer can be known by anyone watching!')
    args = parser.parse_args()

    fernet = None
    if args.password:
        import base64
        from cryptography.fernet import Fernet
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        # we don't actually save the password anywhere so I don't see why we need a salt... let's just derrive one from the password
        salt = bytes('{:<16}'.format(args.password[:16]), "utf-8")
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                         length=32,
                         salt=salt,
                         iterations=100000,
                         backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(bytes(args.password, 'utf-8')))
        fernet = Fernet(key)
        print("Password encryption enabled")

    rfm9x, display, buttons = setupbon.setup_bonnet()
    # start main loop to check for messages and button presses
    main(Transceiver(rfm9x, display, args.incoming, args.outgoing, fernet), buttons[0], buttons[1], buttons[2])

    


