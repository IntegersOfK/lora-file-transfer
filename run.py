
import os
import board
import busio
import digitalio
import argparse
import pathlib
import textwrap
import time
import hashlib
import json
import  progressbar

# Import the SSD1306 module.
import adafruit_ssd1306
import adafruit_rfm9x

# Button A
btnA = digitalio.DigitalInOut(board.D5)
btnA.direction = digitalio.Direction.INPUT
btnA.pull = digitalio.Pull.UP

# Button B
btnB = digitalio.DigitalInOut(board.D6)
btnB.direction = digitalio.Direction.INPUT
btnB.pull = digitalio.Pull.UP

# Button C
btnC = digitalio.DigitalInOut(board.D12)
btnC.direction = digitalio.Direction.INPUT
btnC.pull = digitalio.Pull.UP

# Create the I2C interface.
i2c = busio.I2C(board.SCL, board.SDA)

# 128x32 OLED Display
reset_pin = digitalio.DigitalInOut(board.D4)
display = adafruit_ssd1306.SSD1306_I2C(128, 32, i2c, reset=reset_pin)
# Clear the display.
display.fill(0)
display.show()
width = display.width
height = display.height

# set the time interval (seconds) for sending packets
transmit_interval = 10

# Define radio parameters.
RADIO_FREQ_MHZ = 915.0  # Frequency of the radio in Mhz. Must match your
# module! Can be a value like 915.0, 433.0, etc.

# Define pins connected to the chip.
CS = digitalio.DigitalInOut(board.CE1)
RESET = digitalio.DigitalInOut(board.D25)

# Initialize SPI bus.
spi = busio.SPI(board.SCK, MOSI=board.MOSI, MISO=board.MISO)

# Initialze RFM radio

# Attempt to set up the rfm9x Module
try:
    rfm9x = adafruit_rfm9x.RFM9x(spi, CS, RESET, RADIO_FREQ_MHZ)
    display.text("rfm9x: Detected", 0, 0, 1)
except RuntimeError:
    # Thrown on version mismatch
    display.text("rfm9x: ERROR", 0, 0, 1)

display.show()

# enable CRC checking
rfm9x.enable_crc = True

#rfm9x.ack_wait(5.0) # increase the acknowledgement wait to 5 seconds from 0.5)
#rfm9x.receive_timeout(5.0) # increase the recieve timeout to 5 seconds.. might not be needed and could cause issues for button detection?

#incoming_dest = None
#outgoing_file = None

fernet = None # where we encrypt/decrypt the strings if a password was provided
class BonnetInteract():
    listen = False
    bytes_per_message = 252 # this is the max number of bytes the adafruit_rfm9x library is able to send in a message over LoRa
    fernet = None
    display = None
    send_or_rec = ['recieve', 'send']
    valid_modes = ['data destination node id', 'this node id', 'toggle send or recieve']
    selection_mode = valid_modes[0]
    rfm9x = None

    def __init(self, rfm9x, display, fernet=None):
        self.rfm9x = rfm9x
        self.display = display
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
            self.listen = False
            if self.send_or_rec == 'receive':
                self.send_or_rec = 'send'
            else:
                self.send_or_rec = 'receive'
                self.listen = True
            self.update_display("This node is configured to: {0} press button 3 to start".format(self.send_or_rec.upper()))

    def increase(self, fernet=None):
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
                self.listen = True
            else:
                self.update_display("Send mode, sending requested file...")
                self.listen = False
                self.send()
    
    def send(self):
        all_bytes = pathlib.Path(self.outgoing_file_path).read_bytes() # get the file as bytes
        filehash = hashlib.sha256(all_bytes).hexdigest()[:10] # we can reasonably assume the first 10 characters are good enough to know it's the right file
        if self.fernet:
            print("Encrypting bytes string, size before encryption " + str(len(all_bytes)))
            all_bytes = self.fernet.encrypt(all_bytes)
            print("Size after encryption " + str(len(all_bytes)))
        packaged_data = [all_bytes[i:i+self.bytes_per_message] for i in range(0, len(all_bytes), self.bytes_per_message)] # turn it into the right number of messages

        print(str(self.outgoing_file_path) + ' is ' + str(len(all_bytes)/1024)  +' kilobytes and can be sent in ' + str(len(packaged_data)) + ' messages of ' + str(self.bytes_per_message) + ' bytes each')

        start_time = time.time()
        print('Sending metadata about the file we are about to send')
        metadata = [0, pathlib.Path(self.outgoing_file_path).name, len(packaged_data), filehash] # status 0 to start, filename, number of messages to be sent, hash
        print(metadata)
        encoded_metadata = bytearray(json.dumps(metadata), 'utf-8')
        print(encoded_metadata)
        self.rfm9x.send_with_ack(encoded_metadata)

        for p in progressbar.progressbar(packaged_data, redirect_stdout=True):
            self.rfm9x.send_with_ack(bytearray(p, 'utf-8'))
        self.rfm9x.send_with_ack(bytearray(json.dumps([1, filehash]), 'utf-8')) # confirm all the pieces were sent, status 1 to end

        print('Done! Transmit took ' + str(int(time.time()-start_time)) + ' seconds')


class Receiver():

    message_count = None
    collected = []  # where we store the messages until we have all pieces
    filename = None
    total_size = None
    total_messages = None
    filehash = None
    output_dir = None
    fernet = None

    def __init__(self, output_dir):
        self.output_dir = output_dir

    def combine_pieces(self):
        """Puts together all the pieces in the list"""
        all_bytes = ''.join(self.collected)
        if self.fernet:
            all_bytes = f.decrypt(all_bytes)
            print("Decrypted data with provided password")
        filehash = hashlib.sha256(all_bytes).hexdigest()[:10]
        if filehash == self.filehash:
            print("File hash matches, file integrity confirmed!")
        else:
            print("File hash doesn't match, writing to file anyway...")
        with open(os.path.join(self.output_dir, filename), "wb") as f:
            f.write(all_bytes)

        # reset everything
        self.message_count = None
        self.collected = []
        self.filename = None
        self.total_messages = None
        self.filehash = None
    
    def process_message(self, packet):
        """Deals with the collection of packets and to stick them pack together"""
        # Check if there's metadata
        print(packet)
        decoded = packet.decode('utf-8')
        print(decoded)
        try:
            a = json.loads(decoded)
            print(a)
            if len(a):
                status = int(a[0])
                if status == 0:
                    self.filename = a[1]
                    self.total_messages = a[2]
                    self.filehash = a[3]
                    print("Recieved metadata about a new file to receive.")
                    update_display("File incoming... " + self.filename)
                    self.message_count = 0
                    collected = []
                if status == 1:
                    print("Recieved all messages to recreate the file")
                    update_display("File done recieving! " + self.filename)
                    self.combine_pieces()
        except Exception:
            if not self.filehash:
                print("Packet was received but no metadata was received")
                update_display("Got packet, but no metadata")
                return
            message_count += 1
            print("Recieving packet " + str(self.message_count) + " of " +  str(len(self.total_messages)))
            update_display("Recieving packet " + str(self.message_count) + " of " +  str(len(self.total_messages)))

def main(b):
    last_press = time.time()
    button_debounce = 0.200 # time until another press can be registered
    while True:
        if True:
            # Look for a new packet: only accept if addresses to my_node
            packet = rfm9x.receive(with_ack=True)
            # If no packet was received during the timeout then None is returned.
            if packet is not None:
                # Received a packet!
                # Print out the raw bytes of the packet:
                #print("Received (raw header):", [hex(x) for x in packet[0:4]])
                #print("Received (raw payload): {0}".format(packet[4:]))
                #print("Received RSSI: {0}".format(rfm9x.last_rssi))
                b.update_display("Recieving packet! Time: " + str(last_press))
                r.process_message(packet)
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

    r = Receiver(args.incoming)
    
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
        r.fernet = Fernet(key)
        print("Password encryption enabled")

    b = BonnetInteract(rfm9x, display, r.fernet)
    if args.outgoing:
        b.outgoing_file_path = args.outgoing

    # start main loop to check for messages and button presses
    main(b)


