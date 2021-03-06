
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
    bytes_per_message = 70
    send_or_rec = 'receive'
    valid_modes = ['data destination node id', 'this node id', 'toggle send or receive', 'get filelist']
    selection_mode = valid_modes[0]
    min_transmit_interval = 0
    packaged_data = {} # where we store files ready to be sent
    collected = {}  # where we store receive messages until we have all pieces

    def __init__(self, rfm9x, display, incoming, outgoing=None, fernet=None):
        self.rfm9x = rfm9x
        self.display = display
        self.incoming_directory = incoming
        self.outgoing_directory = outgoing
        self.fernet = fernet
        self._parse_available_files() # piece the files so we're ready to send them

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
                print("Requesting remaining pieces for the file")
                self.request_pieces('4a5afe')
            else:
                self.update_display("Send mode, sending requested file...")
                print("Sending request for remaining pieces for file")
                missing_pieces = [r for r in range(1, self.collected['4a5afe']['length']+1) if not self.collected['4a5afe']['data'].get(str(r))]
                if len(missing_pieces) > 20:
                    print("There are more pieces missing that can be requested, asking for the first 20 missing...")
                self.request_pieces('4a5afe', missing_pieces[:20])

        elif self.selection_mode == self.valid_modes[3]:
            print("Doing a filelist availability update")
            self.update_display("Sending request to recieve a list of files...")
            rfm9x.send(bytearray([0,0,0,0]) + '000000'.encode('utf-8') + json.dumps({'a':'ls'}, separators=(',', ':'), indent=None).encode('utf-8'))

    def request_pieces(self, filehash=None, parts=[0]):
        print("Sending request for piece(s) " + str(parts))
        rfm9x.send(bytearray([0,0,0,0]) + filehash.encode('utf-8') + json.dumps({'a':'a', 'p':parts}).encode('utf-8'))
    
    last_message_time = time.time()
    def send_pieces(self, filehash, parts=[0]):
        """Sends piece(s) of the requested file"""
        time.sleep(1) # initial wait so the requestor can be back in listening mode

        if parts == [0]:
            parts = [r for r in range(1, len(self.packaged_data[filehash]['data'])+1)]
        for part in parts:
            if self.min_transmit_interval:
                while self.last_message_time > time.time() - self.min_transmit_interval:
                    time.sleep(self.min_transmit_interval)
            print("Sending " + filehash + " " + str(part) + " of " + str(len(self.packaged_data[filehash]['data'])))
            byte_string = bytearray([int(b) for b in str(part).zfill(4)]) + filehash.encode('utf-8') + self.packaged_data[filehash]['data'][int(part)-1]
            print(byte_string)
            self.last_message_time = time.time()
            self.rfm9x.send_with_ack(byte_string) # filehash is the delimiter between metadata and filedata.
    
    def _combine_pieces(self, filehash):
        """Puts together all the pieces in the list"""
        all_bytes = b''
        for r in range(1,len(self.collected[filehash]['data'])+1):
            all_bytes += self.collected[filehash]['data'][str(r)]
        if self.fernet:
            all_bytes = f.decrypt(all_bytes)
            print("Decrypted data with provided password")
        this_filehash = hashlib.sha256(all_bytes).hexdigest()[:6]
        if this_filehash == filehash:
            print("File hash matches, file integrity confirmed!")
        else:
            print("File hash doesn't match, writing to file anyway...")
        with open(os.path.join(self.incoming_directory, self.collected[filehash]['filename']), "wb") as f:
            f.write(all_bytes)
        print("Done, got the file! " + os.path.join(self.incoming_directory, self.collected[filehash]['filename']))
        self.update_display("Got full file! " + self.collected[filehash]['filename'])
       
    def _parse_available_files(self):
        """Chunk/parse any files we might be requested to send in preperation"""
        for f in os.listdir(self.outgoing_directory):
            fpath = pathlib.Path(os.path.join(self.outgoing_directory, f))
            if fpath.is_file():
                all_bytes = fpath.read_bytes() # get the file as bytes
                # we can reasonably assume the first 6 characters are good enough to know it's the right file. Sure, small chance of collision but it will be used in every message so it needs to be short!
                fullhash = hashlib.sha256(all_bytes).hexdigest()
                filehash = fullhash[:6]
                if self.fernet:
                    print("Encrypting bytes string, size before encryption " + str(len(all_bytes)))
                    all_bytes = self.fernet.encrypt(all_bytes)
                    print("Size after encryption " + str(len(all_bytes)))
                self.packaged_data[filehash] = {'h':filehash} # already have it as the key, but we can put it for ease here
                self.packaged_data[filehash] = {'fh':fullhash} # in case we want to do a full integrity check
                self.packaged_data[filehash]['data'] = [all_bytes[i:i+self.bytes_per_message] for i in range(0, len(all_bytes), self.bytes_per_message)] # turn it into the right number of messages
                self.packaged_data[filehash]['n'] = f
                print(f + ' with shorthash ' + filehash  + ' is ' + str(len(all_bytes)/1024)  +' kilobytes and can be sent in ' + str(len(self.packaged_data[filehash]['data'])) + ' messages of ' + str(self.bytes_per_message) + ' bytes each')
        

    def process_message(self, packet):
        """Deals with requests for information OR the collection of packets to stick them back together when we have them all"""
        
        got_all_pieces = False
        try:
            # We use the first 10 bytes in the message. The first 4 are piece numbers, and the next 6 are hash, rest is data or metadata
            pieceid = packet[0:4] # This comes in as a byte array, so put them together as an int
            print("here")
            print(pieceid)
            print(str(pieceid[0]) + str(pieceid[1]) + str(pieceid[2]) + str(pieceid[3]))
            pid = int(str(pieceid[0]) + str(pieceid[1]) + str(pieceid[2]) + str(pieceid[3]))
            filehash = packet[4:10].decode() # next 6 are filehash
            data = packet[10:] # finally, any raw data or metadata
            print("pieceid: " + str(pid))
            print("filehash " + filehash)
            print(data)

            if pid == 0:
                print("A pieceid of 0 was found, which means if it's from us, this is metadata and can be interpreted as json dict")
                d = json.loads(data.decode('utf-8'))
                # 'a' is a key for what to do
                
                if d.get('a') == 'ls':
                    print("A list of files available was requested...")
                    # TODO add pagination? Or at least some way to limit the number of files per message
                    # for now, return list of hashes and their filenames and assume there won't be too many for the message
                    filelist = json.dumps({'a':'fl', 'ls': [{'h':f, 'n':self.packaged_data[f]['n'], 'l':len(self.packaged_data[f]['data'])} for f in self.packaged_data]}, separators=(',', ':'), indent=None)
                    print(filelist)
                    self.rfm9x.send(bytearray([0,0,0,0]) + '123456'.encode() + filelist.encode('utf-8')) # we have to add that hash whitespace
                
                if d.get('a') == 'fl':
                    print("A list of files was recieved! The available files are:")
                    print(d.get('ls'))
                    for k in d.get('ls', []):
                        self.collected[k.get('h')[:6]] = {'filename':k.get('n'), 'length':k.get('l'), 'hash':k.get('h'), 'data':{}}
                    print(self.collected)

                if d.get('a') == 'a':
                    print("One or more pieces of a specific file were requested...")
                    self.send_pieces(filehash, d.get('p', [0])) # if there is a specific piece value of p, we will only send that
            else:
                if filehash in self.collected.keys():
                    #print("A filepiece was detected as part " + str(pid)  + " for file " +  filehash)
                    self.collected[filehash]['data'][str(pid)] = data
                    print( self.collected[filehash]['filename'] + " with filehash " + filehash + " is now " + str(len(self.collected[filehash]['data'].keys())) + " messages long")
                    self.update_display('Got ' + str(len(self.collected[filehash]['data'].keys())) + " of " + str(self.collected[filehash]['length']) + " " + self.collected[filehash]['filename'])
                    print(self.collected[filehash]['data'].keys())
                    if len(self.collected[filehash]['data']) == self.collected[filehash]['length']:
                        got_all_pieces = filehash
        except Exception as e:
            print(e)
            print("A message was detected but it doesn't appear to be for us (or is malformed). Skipping...")
        if got_all_pieces:
            print("Got all pieces! Combining " + got_all_pieces)
            self._combine_pieces(got_all_pieces)

def main(b, btnA, btnB, btnC):
    b.send_or_rec = 'receive'
    last_press = time.time()
    button_debounce = 0.300 # time until another press can be registered
    while True:
        if True: #b.send_or_rec == 'receive':
            # Look for a new packet: only accept if addresses to my_node
            packet = b.rfm9x.receive(keep_listening=True, with_header=False, with_ack=True, timeout=0.3)
            # If no packet was received during the timeout then None is returned.
            if packet is not None:
                # Received a packet!
                # Print out the raw bytes of the packet:
#                print("Received (raw header):", [hex(x) for x in packet[0:4]])
                print("Received (raw packet): {0}".format(packet))
                print("Received RSSI: {0}".format(rfm9x.last_rssi))
                #b.update_display("Recieving packet! Time: " + str(time.time()))
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
    parser.add_argument('-i', '--incoming', help='the directory where incoming files should be written in receiving mode, defaults to current working directory', default=os.path.join(os.getcwd(), 'incoming'))
    parser.add_argument('-o', '--outgoing', help='the path to the file you want to send if in sending mode', default=os.path.join(os.getcwd(), 'outgoing'))
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

    


