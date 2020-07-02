

# Import the SSD1306 module.
import adafruit_ssd1306
import adafruit_rfm9x
import board
import busio
import digitalio

def setup_bonnet():

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

    # # set the min time interval (in seconds) to wait between sending packets
    # min_transmit_interval = 0

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
    return rfm9x, display, [btnA, btnB, btnC]

    #rfm9x.ack_wait(5.0) # increase the acknowledgement wait to 5 seconds from 0.5)
    #rfm9x.receive_timeout(5.0) # increase the recieve timeout to 5 seconds.. might not be needed and could cause issues for button detection?
