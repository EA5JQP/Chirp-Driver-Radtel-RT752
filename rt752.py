# Copyright 2025 Gonzalo EA5JQP <ea5jqp@proton.me>
# Copyright for laiyc_encdec class Pavel OK2MOP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.




import logging
import random
import struct
from datetime import datetime
from binascii import crc_hqx
import binascii

# noinspection PyUnresolvedReferences
from chirp import chirp_common, directory, bitwise, memmap, errors, util
# noinspection PyUnresolvedReferences
from chirp.settings import InvalidValueError, RadioSetting, RadioSettingGroup, \
    RadioSettingValueBoolean, RadioSettingValueList, \
    RadioSettingValueInteger, RadioSettingValueString, \
    RadioSettings, RadioSettingValueFloat

LOG = logging.getLogger(__name__)

MEM_FORMAT = """
#seekto 0x%X;
#printoffset "this_is_memory";

struct {
    lbcd rxfreq[4];             // byte[4]  - RX Frequency in 10Hz units 32 bit unsigned little endian
    lbcd txfreq[4];             // byte[4]  - TX Frequency in 10Hz units 32 bit unsigned little endian
    ul16 rxtone;                // byte[2]  - RX Sub Tone CTCSS: 0.1Hz units
    ul16 txtone;                // byte[2]  - TX Sub Tone (as rx sub tone)
    u8 unknown1:1,              // byte[1]  - Unknown
       spku_and:1,	            //          - Speaker Unmute is DQ/QDT by default, 1=Speaker Unmute DQ/QDT AND Signal
       spku_or:1,               //          - Speaker Unmute is DQ/QDT by default, 1=Speaker Unmute DQ/QDT OR Signal
       bcl_qt_dqt:1,	        //          - BCL is OFF by default. 1=QT/DQT
       bcl_carrier:1,           //          - BCL is OFF by default. 1=Carrier
       signaltype_2tone:1,	    //          - Signal Type is NONE by default 1=2-Tone
       signaltype_dtmf:1,	    //          - Signal Type is NONE by default 1=DTMF
       rev_freq:1;              //          - Unknown
    u8 vox:1,                   // byte[1]  - VOX activation 0=OFF 1=ACTIVE
       unknown3:1,              //          - Unknown	            
       txpower:1,               //          - TX Power 0=Low 1=High	
       bandwidth:1,             //          - Bandwidth 0=Wide 1=Narrow	       
       random:1,                //          - Random activation 0=OFF 1=ACTIVE
       dig:1,                   
       pttid:2;                 //          - PTT-ID 0=OFF 1=BOT 2=EOT 3=BOTH
    u8 unknown4:1,         
       unknown5:1,           	
       unknown6:1,          	
       hoppwd:1,
       enablescan:1,                   	
       compand:1,                   	
       scramble:1,                    	
       unknown7:1;                	
    u8 unknown8:1,
       unknown9:1,
       unknown10:1,
       deg:2,
       unknown11:1,
       unknown12:1, 
       unknown13:1;           
    u8 unknown14;
    u16 unknown15;           
    u8 unknown16;           

    char name[12];              // byte[12] - ASCII channel name, unused characters should be null (0)
} memory[251]; 

#printoffset "this_is_settings";
#seekto 16064;
struct{
    u8 jump_freq;                   
    u8 standby_light;                   
    u8 unknown17;                   
    u8 squelch;                     
    u8 voice;                       
    u8 unknown18;                   
    u8 vox_level;                   
    u8 unknown19;                    
    u8 backlight;                   
    u8 group_a_mode;                
    u8 group_b_mode;                
    
    #seekto 16077;                
    u8 ch_name_show;                
    u8 double_watch;                
    u8 tx_end_tone;                 
    u8 language;  

    #seekto 16085;
    u8 tone;                        

    #seekto 16087;
    u8 batt_save_ratio;              
    u8 radio_prio_tx;               
    u8 tot;                         
    u8 low_batt_alarm_int;          
    u8 low_batt_tone;               
    u8 low_batt_alarm;              
    u8 power_on_tone;               
    u8 an_power_on;                 
    u8 keylockmode;                     
    u8 keylocked;                     
    u8 unknown;                     
    u8 step;                        

    #seekto 16114;
    u8 power_on_pic;                
    
    #seekto 16128;
    u8 long_key_time;               
    
    #seekto 16132;
    u8 scan_tx_mode;                
    u8 sel_ch_group_a;              
    u8 sel_ch_group_b;              
    u8 prio_ch_group_a;             
    u8 prio_ch_group_b;             
    u8 talkback;                    
    u8 include_curr_fix_ch;         

    #seekto 16178;
    lbcd range_freq_a_start[4];     
    lbcd range_freq_a_end[4];       
    lbcd range_freq_b_start[4];     
    lbcd range_freq_b_end[4];       
    
    #seekto 16214;
    u8 vibration;                   
    u8 vibration_time;              
    u8 vibration_interval;          
    u8 low_batt_tx;                 
    u8 double_ptt;                  
    
    #seekto 16195;
    u8 record;                      

    #seekto 16175;
    u8 call_tone;

    #seekto 16239;
    u8 disable_menu;
    u8 denoise;

    #seekto 16262;
    u8 unknown:1,
       unknown:1,
       freq_sig_src:1,
       unknown:1,
       airband:1,
       unknown:1,
       unknown:1,
       freq_meas:1;
    u16 freq_hop_pwd;
    u8 freq_hop_ena; 

    #seekto 16270;
    u8 long_press_key2;
    u8 short_press_key2;
    u8 short_press_key1;
    u8 long_press_key1;

    #seekto 16294;
    u8 default_id;

    #seekto 16299;
    u8 vox_delay;

    #seekto 16352;
    char pon_msg1[16];
    char pon_msg2[16];
    char pon_msg3[16];

    #seekto 16416;
    char msg1[16];
    char msg2[16];


} settings;

"""



CMD_INIT_RADIO  = "5A335796ACBB"
CMD_WRITE_RADIO = "5A4588795296"
CMD_READ_RADIO  = "5A46998A6BA7"

BLOCK_CHANNEL_SIZE = 32 # 32 bytes per channel
BUFFER_SIZE = 1024 
BUFFER_SHORT_SIZE = 0x361
BUFFER_MAX_SIZE = 4118  

BLOCK_NUMBER_VFO = 251 # VFOs are stored as channels 

MAX_CHANNELS = 250

START_ADDR_CHANNELS = 0x48000
END_ADDR_CHANNELS = 0x4BC00
START_ADDR_SETTINGS = 0x44000
SHORT_ADDRS = [0x49C00, 0x4BC00]

NUMBER_INITS_FOR_DOWNLOAD = 25
NUMBER_INITS_FOR_UPLOAD = 18
NUMBER_INITS_FOR_STOP = 6

INIT_ADDR_CHANNELS = 0x48000
INIT_ADDR_SETTINGS = 0x1900

SPECIALS = {
        "VFO": BLOCK_NUMBER_VFO,
}

OFF_ON_LIST = ["Off", "On"]
BCL_LIST = ["Off", "Carrier", "QT/DQT"]
VOX_LIST = OFF_ON_LIST
RANDOM_LIST = OFF_ON_LIST
PTTID_LIST = ["Off","BOT","EOT","BOTH"]
COMPAND_LIST = OFF_ON_LIST
SCRAMBLE_LIST = OFF_ON_LIST
SIGNALTYPE_LIST = ["Off", "DTMF", "2-Tone&5-Tone"]
SPEAKERUNMUTE_LIST = ["QT/DQT", "QT/DQT AND Signal", "QT/DQT OR Signal"]
DIGSERVE_LIST = OFF_ON_LIST
DEGREE_LIST = ['Off', "120", "180", "240"]
HOPPWD_LIST = OFF_ON_LIST
SKIP_VALUES = ["S", ""]
SQUELCH_LIST = [f'{x}' for x in range(0, 10)]
BACKLIGHT_LIST = ["Off", "On", "Auto 5s", "Auto 10s", "Auto 20s", "Auto 30s", "Auto 60s"]
GROUPMODE_LIST = ["VFO Mode", "CH + VFO Mode", "CH Mode"]
REVFREQ_LIST = OFF_ON_LIST

TOT_LIST = ["Off", "15s", "30s", "45s", "60s", "75s", "90s", "105s", "120s", "135s", "150s", "165s", "180s", "195s", "210s", "225s", "240s", "255s", "270s"]
LANGUAGE_LIST = ["English", "Chinese"]

TONE_LIST = ["Off", "Tone 1", "Tone 2", "Tone 3", "Tone 4", "Tone 5", "Tone 6", "Tone 7", "Tone 8", "Tone 9", "Tone 10"]
BATTSAVE_LIST = ["None", "1:1", "1:2", "1:3", "1:4", "1:5"]
STEP_LIST = ["0.05kHz", "0.25kHz", "2.5kHz", "5kHz", "6.25kHz", "10kHz", "12.5kHz", "15kHz", "20kHz", "25kHz", "30kHz", "50kHz", "100kHz", "500kHz"]
VOICE_LIST = ["None", "Chinese", "English"]
LOWBATTTONE_LIST = ["Off", "Tone-1", "Tone-2"]
LOWBATTINTERVAL_LIST = ['None' if x == 0 else f'{x}s' for x in range(0, 502, 2)]
PONTONE_LIST = ["Off" if x == 0 else f'Tone-{x}' for x in range(0,8)]
PONPIC_LIST = ["Show Picture", "DC Voltage", "Show Message"]
VIBRATIONINT_LIST = [f'{x}min' for x in range(1,11)]
VIBRATIONTIME_LIST = [f'{x}s' for x in range(1,11)]
KEYLOCKMODE_LIST = ["Manual", "Auto-5s", "Auto-10s", "Auto-20s", "Auto-30s", "Auto+Save-5s", "Auto+Save-10s", "Auto+Save-20s", "Auto+Save-30s"]

SCANTXMODE_LIST = ["Selected Channel", "Final Active Channel", "Fixed Channel"]
GROUPSELECT_LIST = ["None" if x == 0 else f'{x}' for x in range(0,251)]

LONGPRESSTIME_LIST = [f'{x:.2f}' for x in [i * 0.05 for i in range(6, 201)]]
LONGKEYASSIGN_LIST = ["0: Off", 
                      "1: Scan", 
                      "2: Vox", 
                      "3: Squelch Off", 
                      "4: Squelch Off Momentary", 
                      "5: Adjust Power Level", 
                      "6: Emergency Alarm", 
                      "7: Annunciation CH No", 
                      "8: Roger", 
                      "9: Screen Display", 
                      "10: Battery Electric Power Display", 
                      "11: Scramble Switch", 
                      "12: Channel Group Switch", 
                      "13: Denoise Switch", 
                      "14: Recording Playback"]
SHORTKEYASSIGN_LIST = ["0: Off", 
                       "1: Scan", 
                       "2: Vox", 
                       "3: Squelch Off", 
                       "4: Adjust Power Level",
                       "5: Emergency Alarm", 
                       "6: Annunciation CH No", 
                       "7: Roger",
                       "8: Screen Display",
                       "9: Battery Electric Power Display", 
                       "10: Scramble Switch", 
                       "11: Channel Group Switch",
                       "12: Denoise Switch",
                       "13: Recording Playback"]

VOXLEVEL_LIST = ['Off' if x == 0 else f'{x}' for x in range(0, 11)]
VOXDELAY_LIST = ["0.3s", "0.5s", "1s", "1.5s", "2s", "3s"]


TUNING_STEPS = (0.05, 0.25, 2.5, 5.0, 6.25, 10.0, 12.5, 15.0, 20.0, 25.0, 30.0, 50.0, 100.0, 500 )

POWER_LEVELS        = [chirp_common.PowerLevel("Low", watts=0.50),
                        chirp_common.PowerLevel("High", watts=10.00)]
BANDWIDTH_LIST      = ["Wide", "Narrow"]

def generate_cmd(decoder, cmd, addr, data_len, data):
    checksum = decoder.calculate_checksum(bytes.fromhex(cmd + addr + data_len + data))
    return cmd + addr + data_len + data + checksum.hex().upper()

def _do_status(radio, block):
    status = chirp_common.Status()
    status.msg = "Cloning"
    status.cur = block
    status.max = 17 # There are 17 buffers to be read/written
    radio.status_fn(status)

def _enter_programming_mode(radio, number_inits):
    decoder = laiyc_encdec()
    decoder.debug = False
    decoder.verbose = False
    LOG.debug("Entering programming mode...")

    encrypted_cmd = decoder.encrypt_tx_buffer(bytes.fromhex(CMD_INIT_RADIO), seed=None)

    for _ in range(0, number_inits):
        radio.pipe.flushInput()
        radio.pipe.write(encrypted_cmd)
        encrypted_response = radio.pipe.read(6)
        if encrypted_response:
            decoded_rcv_buf = decoder.decrypt_rx_buffer(encrypted_response)
            LOG.debug("Received response: {}".format(decoded_rcv_buf))
        else:
            LOG.debug("No response received after sending INIT.")

def read_data(radio, addr, data_len):
    decoder = laiyc_encdec()
    decoder.debug = False
    decoder.verbose = False

    radio.pipe.baudrate = radio.BAUD_RATE
    radio.pipe.timeout = radio.TIME_OUT

    # Convert integers to hex strings (assuming addr and data are integers)
    addr_hex = hex(addr)[2:].zfill(8)  # Remove '0x' prefix and zero-pad to 6 digits
    data_len = hex(data_len)[2:].zfill(4)  # Zero-pad to 4 digits
    cmd = generate_cmd(decoder, CMD_READ_RADIO, addr_hex, data_len, '')
    LOG.info(cmd)

    cmd_bytes = bytes.fromhex(cmd)
    encrypted_cmd = decoder.encrypt_tx_buffer(cmd_bytes, seed=None)
    if encrypted_cmd:  
        radio.pipe.flushInput()
        radio.pipe.write(encrypted_cmd)
    else:
        LOG.debug("Error: Decoder returned no data when encrypting tx buffer.")

    encrypted_rx_buffer = radio.pipe.read(2070)

    if encrypted_rx_buffer:
        decrypted_rx_buffer = decoder.decrypt_rx_buffer(encrypted_rx_buffer)
        if decrypted_rx_buffer:
            # LOG.debug("Received response: {}".format(decrypted_rx_buffer))
            decrypted_rx_data = decoder.decrypt_rx_data(decrypted_rx_buffer)
            if decrypted_rx_data:
                return decrypted_rx_data
            else:
                LOG.debug("Error: Decoder returned no data when decoding rx data.")
                return None
        else:
            LOG.debug("Error: Decoder returned no data when decoding rx buffer.")
            return None
    else:
        LOG.debug("No response received.")
        return None     

def do_download(radio):
    _enter_programming_mode(radio, NUMBER_INITS_FOR_DOWNLOAD)

    blocks =b"" # Initialize data buffer     
    block_idx = 0 # Initialize block index

    for buf_idx, buf_addr in enumerate(range(START_ADDR_CHANNELS, END_ADDR_CHANNELS+BUFFER_SIZE, BUFFER_SIZE)):
        _do_status(radio, buf_idx)
        data_len = BUFFER_SHORT_SIZE if buf_addr in SHORT_ADDRS else BUFFER_SIZE
        data = read_data(radio, buf_addr, data_len)
        if not data:
            LOG.error("No data received")
        for i in range(0, len(data), BLOCK_CHANNEL_SIZE):
            LOG.debug("Extracting from {}".format(i))
            
            block = data[i:i+BLOCK_CHANNEL_SIZE]
            LOG.debug("Block size is: {}".format(len(block)))
            # Skip iteration if block size is less than expected
            if len(block) < BLOCK_CHANNEL_SIZE:
                LOG.debug("Error: Block size is less than expected.")
                continue
            else:
                LOG.info("Buffer: %i Block: %i",buf_idx, block_idx)
                LOG.info(util.hexprint(bytes(block)))
                blocks += bytes(block)
                block_idx += 1 

    # Setting data is 
    blocks += read_data(radio, START_ADDR_SETTINGS, BUFFER_SIZE)
    _enter_programming_mode(radio, NUMBER_INITS_FOR_STOP)
    LOG.info("Buffer: %i Block: %i",buf_idx, block_idx)
    LOG.info(util.hexprint(bytes(blocks)))

    return memmap.MemoryMapBytes(blocks)   

def write_data(radio, data, addr): 
    decoder = laiyc_encdec()
    decoder.debug = False
    decoder.verbose = False

    radio.pipe.baudrate = radio.BAUD_RATE
    radio.pipe.timeout = radio.TIME_OUT
    
    # Convert integers to hex strings (assuming addr and data are integers)
    addr_hex = hex(addr)[2:].zfill(8)  # Remove '0x' prefix and zero-pad to 6 digits
    LOG.debug("Address: {}".format(addr_hex))
    data_encrypted = decoder.encrypt_tx_data(data, seed=None)
    data_hex = binascii.hexlify(data_encrypted).decode('ascii').upper()
    data_len = hex(len(data))[2:].zfill(4)  # Zero-pad to 4 digits
    LOG.debug("Data length: {}".format(data_len))

    cmd = generate_cmd(decoder, CMD_WRITE_RADIO, addr_hex, data_len, data_hex)
    cmd_bytes = bytes.fromhex(cmd)  # Explicitly convert to bytes
    encoded_cmd = decoder.encrypt_tx_buffer(cmd_bytes, seed=None)

    # LOG.debug("Sending command: {}".format((cmd)))
    radio.pipe.write(encoded_cmd)
    encrypted_response = radio.pipe.read(550)
    if encrypted_response:
            decoded_rcv_buf = decoder.decrypt_rx_buffer(encrypted_response)
            LOG.debug("Received response: {}".format(decoded_rcv_buf))

def do_upload(radio):

    _enter_programming_mode(radio, NUMBER_INITS_FOR_UPLOAD)

    LOG.debug("Uploading...")

    mmap_pos = 0  # Track the current position in the memory map

    # First we have to form the buffer to send to the radio
    for buff_idx, buff_addr in enumerate(
        range(START_ADDR_CHANNELS, END_ADDR_CHANNELS + BUFFER_SIZE, BUFFER_SIZE)
    ):
        _do_status(radio, buff_idx)

        # Addresses 0x49C00 and 0x4BC00 contain only 26 channels and length is 361 bytes
        if buff_addr in SHORT_ADDRS:
            buffer_size = BUFFER_SHORT_SIZE-1
            LOG.debug("Buffer size is 0x361")
        else:
            buffer_size = BUFFER_SIZE

        # Slice the memory map using the current position and buffer size
        buffer = radio.get_mmap()[mmap_pos:mmap_pos + buffer_size]

        # Update the position in the memory map for the next iteration
        mmap_pos += buffer_size

        # LOG.debug("writemem channel data addr=0x%4.4x len=0x%4.4x:\n%s" %
        #     (buff_addr, len(buffer), util.hexprint(buffer)))
        write_data(radio, buffer, buff_addr)

    # Settings in a separate and non-consecutive address, thus cannot be handled in the loop
    total_blocks = 2 * MAX_CHANNELS + 2
    buffer_set = radio.get_mmap()[
         BLOCK_CHANNEL_SIZE * total_blocks: BLOCK_CHANNEL_SIZE * total_blocks + BUFFER_SIZE]    

    write_data(radio, buffer_set, START_ADDR_SETTINGS)
    LOG.debug("writemem settings data addr=0x%4.4x len=0x%4.4x:\n%s" %
            (START_ADDR_SETTINGS, len(buffer_set), util.hexprint(buffer_set)))
    
    _enter_programming_mode(radio, NUMBER_INITS_FOR_STOP)

def decode_tone(tone_word):
    """Decodes a tone word into CTCSS or DXXX[N/I] information.

    Args:
        tone_word: An integer representing the tone word.

    Returns:
        A tuple (tone_type, value, polarity) or (None, None, None) if invalid.
        tone_type: "Tone" for CTCSS, "DXXX" for DXXX[N/I], or None if invalid.
        value: The CTCSS frequency in Hz or the DXXX code.
        polarity: "N" for normal, "I" for inverted (DXXX only), or None if invalid.
    """

    if not isinstance(tone_word, int):
        return None, None, None

    # Check if tone_word is a valid CTCSS value
    if 1 <= tone_word <= 2541:
        return "Tone", tone_word / 10.0, None  # CTCSS (return frequency in Hz)

    # Check if tone_word is within the valid range for DXXX
    if 2541 < tone_word <= 43500:  # Decimal range for 
        # Convert tone_word to octal
        octal_value = oct(tone_word)[2:]  # Remove the "0o" prefix

        # Extract the three middle digits from the octal string
        if len(octal_value) >= 5:
            middle_three = octal_value[-3:]  # Extract the middle three digits
        else:
            return None, None, None  # Invalid if the octal representation is too short

        last_char = "R" if str(octal_value)[0] == '1' else "N"

        return "DTCS", int(middle_three), last_char
    return None, None, None  # Invalid tone word

def encode_tone(tone_type, value, polarity=None):
    """Encodes CTCSS or DTCS (formerly DXXX) information into a tone word.

    Args:
        tone_type: "Tone" for CTCSS, "DTCS" for DTCS.
        value: The CTCSS frequency in Hz or the DTCS code.
        polarity: "N" for normal, "R" for reversed (DTCS only). Defaults to None.

    Returns:
        An integer representing the tone word, or None if the input is invalid.
    """

    if tone_type == "Tone":
        if not isinstance(value, (int, float)):
            return None
        if not (67.0 <= value <= 254.1): #Corrected range based on decode function
            return None
        tone_word = int(value * 10)
        return tone_word

    elif tone_type == "DTCS":
        if not isinstance(value, int) or not (0 <= value <= 777): #Octal 777 is decimal 511. The middle 3 octal digits are not allowed to be above this.
            return None
        if polarity not in ("N", "R"):
            return None

        octal_value = str(value).zfill(3) #Pad with leading zeros to always have 3 digits
        print(octal_value)
        first_digit = "1" if polarity == "R" else "0"
        octal_string = first_digit + "24" + octal_value #Pad with leading zeros to at least 5 digits so the middle three are always there.
        try:
            tone_word = int(octal_string, 8)
        except ValueError:
            return None
        return tone_word

    return None

def pad_string(original_string, length):
    # Remove trailing spaces from the original string
    trimmed_string = original_string.rstrip()
    
    # Calculate the number of padding characters needed
    padding_length = length - len(trimmed_string)
    
    # If the trimmed string is already longer than the desired length, return it as is
    if padding_length <= 0:
        return trimmed_string
    
    # Pad the trimmed string with `FF` (ASCII 255) characters
    padded_string = trimmed_string + chr(255) * padding_length
    
    return padded_string


class laiyc_encdec(object):
	debug = False
	verbose = False
	line=None

	# Secret random byte array
	SecretRandom = [
		74, 197, 46, 33, 235, 180, 136, 68, 242, 176,
		65, 123, 230, 191, 249, 246, 60, 6, 0, 25,
		106, 66, 177, 214, 141, 57, 97, 92, 121, 122,
		69, 152, 229, 24, 190, 204, 139, 232, 168, 216,
		87, 49, 3, 58, 20, 226, 47, 81, 170, 48,
		244, 174, 96, 79, 107, 112, 219, 59, 193, 224,
		201, 252, 73, 223, 240, 50, 76, 169, 7, 253,
		86, 160, 212, 245, 39, 215, 140, 185, 210, 89,
		255, 211, 238, 239, 195, 99, 218, 42, 162, 108,
		243, 254, 158, 119, 217, 13, 126, 213, 70, 64,
		93, 144, 45, 28, 115, 179, 171, 11, 132, 34,
		157, 198, 189, 30, 250, 222, 35, 178, 113, 206,
		175, 128, 109, 67, 147, 84, 150, 116, 146, 129,
		88, 26, 29, 135, 165, 145, 16, 104, 225, 61,
		110, 208, 54, 102, 125, 94, 103, 205, 183, 71,
		237, 127, 40, 18, 44, 251, 143, 14, 220, 120,
		130, 91, 105, 36, 164, 228, 137, 149, 247, 200,
		78, 31, 156, 19, 155, 10, 77, 63, 118, 227,
		142, 98, 43, 184, 100, 38, 209, 32, 75, 172,
		196, 231, 95, 236, 173, 117, 2, 138, 241, 23,
		90, 234, 56, 148, 233, 5, 55, 188, 154, 186,
		167, 37, 192, 52, 62, 203, 187, 80, 207, 133,
		114, 194, 17, 131, 166, 161, 134, 221, 15, 22,
		159, 248, 182, 153, 82, 163, 111, 9, 27, 8,
		181, 12, 21, 199, 41, 202, 124, 51, 53, 151,
		4, 101, 72, 1, 83, 85
	]

	# Secret code data array
	SecretCodeData = [
		201, 33, 244, 0, 175, 145, 218, 31, 254, 38,
		247, 11, 161, 238, 195, 172, 187, 25, 43, 188,
		2, 28, 144, 57, 226, 208, 139, 196, 67, 245,
		118, 155, 86, 96, 98, 237, 189, 62, 164, 49,
		235, 147, 82, 242, 253, 79, 138, 248, 250, 255,
		246, 74, 22, 16, 41, 215, 122, 80, 225, 150,
		100, 71, 113, 107, 136, 83, 167, 159, 202, 40,
		210, 148, 185, 227, 177, 146, 63, 19, 124, 72,
		36, 46, 94, 102, 51, 209, 130, 112, 92, 123,
		99, 157, 73, 13, 132, 228, 6, 212, 87, 216,
		45, 64, 90, 23, 233, 121, 240, 169, 125, 197,
		55, 149, 192, 120, 252, 104, 85, 224, 231, 56,
		115, 126, 58, 171, 184, 30, 219, 135, 229, 134,
		52, 29, 15, 84, 78, 220, 108, 61, 47, 44,
		205, 178, 129, 27, 50, 165, 217, 204, 199, 59,
		101, 116, 183, 223, 213, 211, 8, 179, 81, 203,
		7, 97, 133, 156, 142, 221, 42, 4, 14, 251,
		174, 158, 32, 109, 75, 162, 193, 68, 106, 140,
		110, 243, 181, 190, 198, 93, 153, 131, 34, 60,
		141, 151, 170, 236, 152, 103, 143, 105, 168, 137,
		173, 95, 3, 5, 206, 222, 91, 24, 35, 37,
		26, 154, 166, 77, 182, 65, 114, 241, 20, 191,
		17, 54, 48, 88, 89, 207, 12, 111, 186, 239,
		180, 128, 18, 200, 119, 39, 9, 70, 214, 249,
		21, 69, 127, 163, 160, 176, 117, 53, 66, 76,
		232, 1, 194, 230, 10, 234
	]

	# Secret sequencing
	SecretSeqList =  [
		3, 251, 20, 202, 167, 203, 96, 160, 156, 236, 254,
		11, 226, 93, 168, 132, 53, 220, 232, 77, 218, 240,
		52, 103, 207, 17, 210, 143, 21, 131, 125, 7, 172,
		1, 188, 208, 80, 209, 9, 235, 69, 54, 166, 18, 139,
		100, 81, 138, 222, 39, 144, 84, 130, 247, 221, 110,
		119, 23, 122, 149, 189, 137, 37, 76, 101, 215, 248,
		28, 177, 241, 237, 61, 79, 92, 51, 174, 249, 213,
		134, 45, 57, 158, 42, 65, 133, 116, 32, 98, 223, 224,
		102, 206, 88, 185, 82, 201, 33, 161, 34, 90, 60, 150,
		83, 195, 115, 197, 178, 63, 136, 173, 180, 227, 87,
		62, 216, 120, 151, 246, 30, 234, 113, 105, 56, 89, 78,
		108, 121, 242, 231, 142, 86, 187, 94, 162, 129, 127,
		64, 199, 46, 26, 179, 190, 164, 196, 22, 5, 75, 41,
		71, 111, 59, 191, 194, 186, 211, 31, 163, 91, 171,
		67, 244, 12, 175, 243, 38, 145, 212, 66, 198, 107,
		192, 123, 15, 200, 170, 4, 245, 74, 141, 157, 230,
		182, 214, 152, 124, 72, 228, 16, 19, 36, 183, 219,
		112, 176, 252, 14, 27, 109, 184, 148, 233, 0, 68, 159,
		147, 140, 204, 225, 25, 85, 70, 155, 97, 154, 238, 55,
		99, 146, 6, 126, 135, 165, 205, 153, 117, 58, 24, 73,
		95, 128, 253, 118, 250, 104, 255, 40, 193, 35, 13, 229,
		106, 217, 43, 181, 2, 29, 50, 10, 47, 239, 48, 169, 114,
		44, 8, 49
	]

	def __init__(self):
		pass

	def encrypt_tx_buffer(self, tx_buffer, seed=None):
		random.seed(datetime.utcnow().timestamp())

		#Assume whole buffer will be sent
		tx_count=len(tx_buffer)
		if not seed is None:
			b = seed % 256
		else:
			b = random.randint(1, 255)

		# Replace the first byte of tx_buffer with this random seed
		b2 = tx_buffer[0]
		return_buffer = b"" + bytes([b])

		# Modify the rest of the buffer
		for i in range(tx_count):
			if i != tx_count -1:
				b3 = tx_buffer[i + 1]
			return_buffer += bytes([(self.SecretRandom[b] + b2) % 256])
			b2 = b3
			b = (b + 1) % 256
		#return modified buffer
		return return_buffer

	def decrypt_rx_buffer(self, rx_buffer, start=0, count=None):
		#If not specified, all bytes are processed
		if count is None:
			count = len(rx_buffer)
		num = start + count - 1

		# set initial secret to first byte of buffer
		if start == 0 or count is None:
			self.rx_random = rx_buffer[0]

		return_buffer = b""
		for i in range(start, num):
			#sys.stderr.write("Seed: %u\n" % self.rx_random)
			return_buffer += bytes([(rx_buffer[i+1] + 256 - self.SecretRandom[self.rx_random]) % 256])
			self.rx_random = (self.rx_random + 1) % 256
		if self.debug:
			sys.stderr.write("Buffer: " + str(binascii.hexlify(return_buffer), "utf-8") + '\n')
		if not self.verify_checksum(return_buffer):
			# Checksum does not match
			return None
		# Checksum is OK, return data buffer
		return return_buffer

	def get_rx_info(self, dec_rx_buffer):
		if dec_rx_buffer is None or len(dec_rx_buffer) < 0xc or dec_rx_buffer[0] != 0x5a:
			return None, None, len(dec_rx_buffer) #TBD RX/TX and command identification
		address, data_len = struct.unpack(">LH", dec_rx_buffer[6:0xc])
		if self.debug:
			sys.stderr.write("Address: 0x%04x, data len: 0x%04x" % (address, data_len))
		return address, data_len, len(dec_rx_buffer)

	def decrypt_rx_data(self, dec_rx_buffer):
		count = len(dec_rx_buffer)
		# Checksum is OK, decrypt data buffer

		address, data_len = struct.unpack(">LH", dec_rx_buffer[6:0xc])
		#sys.stderr.write("Address: 0x%08x, Data_length: 0x%04x\n" % (address, data_len))
		denc_data = dec_rx_buffer[0xc:data_len+0xc]
		if count > 16:
			return_buffer = b"" # dec_rx_buffer[:0xc]
			secret = self.SecretCodeData[dec_rx_buffer[data_len+0xc]]
			# Decrypt data portion
			for j in range(0, data_len):
				random_x = self.SecretRandom[j % 256];
				#sys.stderr.write("Seed: %02x, random_x: %02x\n" % (secret, random_x))
				return_buffer += bytes([self.SecretCodeData[(denc_data[j] - random_x + secret) % 256]])
			return return_buffer
		else:
			return None

	def encrypt_tx_data(self, data, seed=None):
		data_len = len(data)
		if not seed is None:
			seed = seed % 256
		else:
			seed = random.randint(1, 255)
		if data_len > 0:
			return_buffer = b""
			secret = self.SecretCodeData[seed]
			# Decrypt data portion
			for j in range(0, data_len):
				random_x = self.SecretRandom[j % 256];
				#sys.stderr.write("Seed: %02x, random_x: %02x\n" % (secret, random_x))
				return_buffer += bytes([(self.SecretSeqList[data[j]] + random_x - secret) % 256])
			return return_buffer + bytes([seed])
		else:
			return b""

	def calculate_checksum(self, data_buffer, start=6, end=None):
		if end is None:
			end = len(data_buffer)
		if start == end:
			return b""
		csum = 0x5aa5
		for i in range(start,end):
			csum += data_buffer[i]
		return struct.pack(">L", csum)

	def verify_checksum(self, rx_buffer, start=6, end=None):
		if end is None:
			end = len(rx_buffer)
		if start == end:
			#command without extras (6 bytes)
			return True
		elif end > 0x10:
			a, dlen, flen = self.get_rx_info(rx_buffer)
			if dlen is None:
				dlen=end
			end = min(dlen + 0xc + 1 + 4, end)
			if self.debug:
				sys.stderr.write("Start: %i, end: %i, data length: %i\n" % (start, end, dlen))
		buff = rx_buffer[start:end-4]
		cs1 = rx_buffer[end-4:end]
		cs2 = self.calculate_checksum(buff, 0, end-(start+4))
		if self.verbose and cs1 != cs2:
			sys.stderr.write("Checksums %s and %s do not match\n" % (binascii.hexlify(cs1), binascii.hexlify(cs2)))
		return cs1 == cs2

@directory.register
class rt752(chirp_common.CloneModeRadio):
    VENDOR = "RADTEL"       
    MODEL = "RT-752"        
    BAUD_RATE = 115200 
    TIME_OUT = 0.25

    VALID_BANDS = [(10000000, 136000000),  # RX only (Air Band)
                   (136000000, 174000000),  # TX/RX (VHF)
                   (174000000, 240000000),  # TX/RX
                   (240000000, 320000000),  # TX/RX
                   (320000000, 400000000),  # TX/RX
                   (400000000, 480000000),  # TX/RX (UHF)
                   (480000000, 1300000000)]  # TX/RX
    

    _upper = MAX_CHANNELS

    _memstart = 0x0000



    # Return information about this radio's features, including
    # how many memories it has, what bands it supports, etc
    def get_features(self):
        rf = chirp_common.RadioFeatures()
        rf.has_settings = True
        rf.has_bank = False
        rf.has_tuning_step = False
        rf.has_rx_dtcs = True
        rf.has_ctone = True
        rf.has_comment = False
        rf.has_mode = False


        rf.memory_bounds = (1, self._upper)
        rf.valid_tmodes = ["", "Tone", "TSQL", "DTCS", "Cross"]
        rf.valid_cross_modes = ["Tone->Tone", "Tone->DTCS", "DTCS->Tone",
                                "->Tone", "->DTCS", "DTCS->", "DTCS->DTCS"]
        rf.valid_characters = chirp_common.CHARSET_ASCII
        rf.valid_bands = self.VALID_BANDS
        rf.valid_duplexes = ["", "-", "+", "split", "off"]
        rf.valid_skips = ["", "S"]
        rf.valid_name_length = 12
        rf.valid_power_levels = POWER_LEVELS
        rf.valid_tuning_steps = TUNING_STEPS
        rf.valid_special_chans = list(SPECIALS.keys())
        rf.has_sub_devices = self.VARIANT == ""

        return rf
    
    def get_sub_devices(self):
        return [rt752GroupA(self._mmap), rt752GroupB(self._mmap)]
    
    # Do a download of the radio from the serial port
    def sync_in(self):
        try:
            self._mmap = do_download(self)
            self.process_mmap()

        except Exception as e:
            raise errors.RadioError("Failed to communicate with radio: %s" % e)
 
    # Do an upload of the radio to the serial port
    def sync_out(self):
        try:
            do_upload(self)
        except errors.RadioError:
            raise
        except Exception as e:
            raise errors.RadioError("Failed to communicate with radio: %s" % e)

    # Convert the raw byte array into a memory object structure
    def process_mmap(self):
        self._memobj = bitwise.parse(MEM_FORMAT % self._memstart, self._mmap)
        LOG.info("Memory object created {}".format(self._memstart))

    # Return a raw representation of the memory object, which
    # is very helpful for development
    def get_raw_memory(self, number):
        return repr(self._memobj.memory[number])

    def _get_mem(self, number):
        return self._memobj.memory[number]
    
    def get_memory(self, number):
    
        # Create a high-level memory object to return to the UI
        mem = chirp_common.Memory()

        if isinstance(number, str):
            mem.number = SPECIALS[number]
            mem.extd_number = number
        else:
            mem.number = number
        _mem = self._memobj.memory[mem.number - 1]


        
    
        # We'll consider any blank (i.e. 0 MHz frequency) to be empty
        if _mem.get_raw()[0] == 0xff:
            mem.empty = True
            # LOG.info("Channel %i is empty!",number)
            return mem
        
        # Negate scan to get skip
        mem.skip = SKIP_VALUES[_mem.enablescan]
   
        mem.freq = int(_mem.rxfreq) * 10
        txfreq = int(_mem.txfreq) * 10

        mem.power = POWER_LEVELS[int(_mem.txpower)]

        # Channel name
        for char in _mem.name:
            if "\x00" in str(char) or "\xFF" in str(char):
                char = ""
            mem.name += str(char)
        mem.name = mem.name.rstrip()

        chirp_common.split_tone_decode(mem, decode_tone(int(_mem.txtone)),
                                            decode_tone(int(_mem.rxtone)))

        # LOG.info(decode_tone(int(_mem.txtone)))
        # LOG.info(decode_tone(int(_mem.rxtone)))

        
        # Split
        if int(mem.freq) == txfreq: 
            mem.duplex = ""
            mem.offset = 0
        else:
            mem.duplex = int(mem.freq) > txfreq and "-" or "+"
            mem.offset = abs(int(mem.freq) - txfreq)

        # Extra 
        mem.extra = RadioSettingGroup("Extra", "extra")

        bandwidth = "Wide" if _mem.bandwidth  else "Narrow"
        rs = RadioSettingValueList(BANDWIDTH_LIST, bandwidth)
        rset = RadioSetting("bandwidth", "Bandwidth", rs)
        mem.extra.append(rset)

        # BCL
        if bool(_mem.bcl_carrier):
            bcl = 1
        elif bool(_mem.bcl_qt_dqt):
            bcl = 2
        else:
            bcl = 0
        rs = RadioSettingValueList(BCL_LIST, current_index = bcl)
        rset = RadioSetting("bcl", "BCL", rs)
        mem.extra.append(rset)

        # VOX
        vox = "On" if _mem.vox  else "Off"
        rs = RadioSettingValueList(VOX_LIST, vox)
        rset = RadioSetting("vox", "VOX", rs)
        mem.extra.append(rset)

        # SCRAMBLE
        scramble = "On" if _mem.scramble  else "Off"
        rs = RadioSettingValueList(SCRAMBLE_LIST, scramble)
        rset = RadioSetting("scramble", "Scramble", rs)
        mem.extra.append(rset)

        # COMPAND
        compand = "On" if _mem.compand  else "Off"
        rs = RadioSettingValueList(COMPAND_LIST, compand)
        rset = RadioSetting("compand", "Compand", rs)
        mem.extra.append(rset)

        # DEGREE
        rs = RadioSettingValueList(DEGREE_LIST, current_index = _mem.deg)
        rset = RadioSetting("deg", "Degree", rs)
        mem.extra.append(rset)

        # RANDOM
        random = "On" if _mem.random  else "Off"
        rs = RadioSettingValueList(RANDOM_LIST, random)
        rset = RadioSetting("random", "Random", rs)
        mem.extra.append(rset)

        # HOP PWD
        hoppwd = "On" if _mem.hoppwd  else "Off"
        rs = RadioSettingValueList(HOPPWD_LIST, hoppwd)
        rset = RadioSetting("hoppwd", "Hop PWD", rs)
        mem.extra.append(rset)

        # DIG SERVE
        dig = "On" if _mem.dig  else "Off"
        rs = RadioSettingValueList(DIGSERVE_LIST, dig)
        rset = RadioSetting("dig", "Dig Serve", rs)
        mem.extra.append(rset)  
        
        # SIGNALTYPE
        if bool(_mem.signaltype_dtmf):
            signaltype = 1
        elif bool(_mem.signaltype_2tone):
            signaltype = 2
        else:
            signaltype = 0
        rs = RadioSettingValueList(SIGNALTYPE_LIST, current_index = signaltype)
        rset = RadioSetting("signaltype", "Signal Type", rs)
        mem.extra.append(rset)
       
        # PTTID
        rs = RadioSettingValueList(PTTID_LIST, current_index = _mem.pttid)
        rset = RadioSetting("pttid", "PTT ID", rs)
        mem.extra.append(rset)

        # SPEAKERUNMUTE
        if bool(_mem.spku_or):
            spku = 1
        elif bool(_mem.spku_and):
            spku = 2
        else:
            spku = 0
        rs = RadioSettingValueList(SPEAKERUNMUTE_LIST, current_index = spku)
        rset = RadioSetting("spku", "Speaker Unmute", rs)
        mem.extra.append(rset)

        # REVERSE FREQUENCY
        rs = RadioSettingValueList(REVFREQ_LIST, current_index = _mem.rev_freq)
        rset = RadioSetting("rev_freq", "Rev Freq", rs)
        mem.extra.append(rset) 

        msgs = self.validate_memory(mem)

        if msgs != []:
            LOG.info("Following warnings were generating while validating channels:")
            LOG.info(msgs)

        return mem
    
    def set_memory(self, mem):
        # Get a low-level memory object mapped to the image
        _mem = self._get_mem(mem.number-1)
        

        LOG.info("Memory Map")
        LOG.info(self.process_mmap())

        if _mem.get_raw(asbytes=False)[0] == "\xff":
            _mem.set_raw("\xFF" * BLOCK_CHANNEL_SIZE)
            _mem.vox = 0
            _mem.bandwidth = 0
            _mem.bcl_qt_dqt = 0
            _mem.bcl_carrier = 0
            _mem.compand = 0
            _mem.deg = 0
            _mem.dig = 0
            _mem.hoppwd = 0
            _mem.pttid = 0
            _mem.random = 0
            _mem.scramble = 0
            _mem.spku_and = 0
            _mem.spku_or = 0
            _mem.vox = 0
            _mem.signaltype_2tone = 0
            _mem.signaltype_dtmf = 0
            _mem.rev_freq = 0
            _mem.unknown1
            _mem.unknown3=0
            _mem.unknown4=0
            _mem.unknown5=0
            _mem.unknown6=0
            _mem.unknown7=0
            _mem.unknown8=0
            _mem.unknown9=0
            _mem.unknown10=0
            _mem.unknown11=0
            _mem.unknown12=0
            _mem.unknown13=0
            _mem.unknown14=0
            _mem.unknown15=0
            _mem.unknown16=0

        # if empty memory
        if mem.empty:
            _mem.set_raw("\xFF" * BLOCK_CHANNEL_SIZE)
            return
            
        _mem.rxfreq = int(mem.freq) / 10 

        if mem.duplex == "split":
            _mem.txfreq = mem.offset / 10
        elif mem.duplex == "+":
            _mem.txfreq = (mem.freq + mem.offset) / 10
        elif mem.duplex == "-":
            _mem.txfreq = (mem.freq - mem.offset) / 10
        else:
            _mem.txfreq = mem.freq / 10

        _mem.enablescan = SKIP_VALUES.index(mem.skip)

        _mem.name = mem.name.rstrip('\xFF').ljust(12, '\x20')

        ((txmode, txtone, txpol),
         (rxmode, rxtone, rxpol)) = chirp_common.split_tone_encode(mem)

        if txtone != None:
            _mem.txtone = int(encode_tone(txmode, txtone, txpol))
        if rxtone != None:
            _mem.rxtone = int(encode_tone(rxmode, rxtone, rxpol))

        _mem.txpower = 0 if mem.power is None else POWER_LEVELS.index(mem.power)

        #extra
        for element in mem.extra:
            sname  = element.get_name()
            svalue = element.value.get_value()
            if sname == 'bandwidth':
                _mem.bandwidth = 1 if element.value=="Wide" else 0
            # BCL
            if sname == 'bcl':
                _mem.bcl_qt_dqt = 1 if element.value=="QT/DQT" else 0
                _mem.bcl_carrier = 1 if element.value=="Carrier" else 0
            # VOX
            if sname == 'vox':
                # _mem.vox = 1 if element.value=="On" else 0  
                _mem.vox = 0 if element.value is None else element.value
            # SCRAMBLE
            if sname == 'scramble':
                _mem.scramble = 1 if element.value=="On" else 0  
            # COMPAND
            if sname == 'compand':
                _mem.compand = 1 if element.value=="On" else 0
            # DEGREE
            if sname == 'deg':
                _mem.deg = DEGREE_LIST.index(svalue)
            # RANDOM
            if sname == 'random':
                _mem.random = 1 if element.value=="On" else 0
            # HOP PWD
            if sname == 'hoppwd':
                _mem.hoppwd = 1 if element.value=="On" else 0 
            # DIG SERVE
            if sname == 'dig':
                _mem.dig = 1 if element.value=="On" else 0             
            # SIGNALTYPE
            if sname == 'bcl':
                _mem.signaltype_dtmf = 1 if element.value=="DTMF" else 0
                _mem.signaltype_2tone = 1 if element.value=="2-Tone&5-Tone" else 0
            # PTTID
            if sname == "pttid":
                _mem.pttid = PTTID_LIST.index(svalue)
            # SPEAKERUNMUTE
            if sname == 'spku':
                _mem.spku_and = 1 if element.value=="QT/DQT AND Signal" else 0
                _mem.spku_or = 1 if element.value=="QT/DQT OR Signal" else 0 
            # REVERSE FREQUENCY 
            if sname == "rev_freq":
                _mem.rev_freq = 1 if element.value=="On" else 0



        return mem
    
    def get_settings(self):

        _mem = self._memobj
        LOG.info(((_mem.settings)))

        info = RadioSettingGroup("info", "Radio Info")
        basic = RadioSettingGroup("basic", "Basic Settings")
        scan = RadioSettingGroup("scan", "Scan Settings")
        key = RadioSettingGroup("key", "Key Assignment")

        group = RadioSettings(info, basic, scan, key)

        #################
        # Info Settings #
        #################

        freq_a_start = int(_mem.settings.range_freq_a_start) / 10
        rs = RadioSettingValueFloat(18, 580, freq_a_start, resolution= 0.00001, precision=1)
        rset = RadioSetting("range_freq_a_start", "Frequency Range Start Group A", rs)
        info.append(rset) 

        freq_a_end = int(_mem.settings.range_freq_a_end) / 10
        rs = RadioSettingValueFloat(18, 580, freq_a_end, resolution= 0.00001, precision=1)
        rset = RadioSetting("range_freq_a_end", "Frequency Range End Group A", rs)
        info.append(rset) 

        freq_b_start = int(_mem.settings.range_freq_b_start) / 10
        rs = RadioSettingValueFloat(18, 580, freq_b_start, resolution= 0.00001, precision=1)
        rset = RadioSetting("range_freq_b_start", "Frequency Range Start Group B", rs)
        info.append(rset) 
    
        freq_b_end = int(_mem.settings.range_freq_b_end) / 10
        rs = RadioSettingValueFloat(18, 580, freq_b_end, resolution= 0.00001, precision=1)
        rset = RadioSetting("range_freq_b_end", "Frequency Range End Group B", rs)
        info.append(rset) 

        def filter(s):
            s_ = ""
            for i in range(0, len(s)):
                c = str(s[i])
                s_ += (c if c in chirp_common.CHARSET_ASCII else "")
            return s_

        LOG.info(_mem.settings.pon_msg1)
        LOG.info(filter(_mem.settings.pon_msg1))        
        pon_msg1= ''.join(filter(_mem.settings.pon_msg1)).rstrip()
        LOG.info(pon_msg1)
        rs = RadioSettingValueString(0,16, pon_msg1, autopad= True)
        rset = RadioSetting("pon_msg1", "Power On Message 1", rs)
        info.append(rset)

        pon_msg2= ''.join(filter(_mem.settings.pon_msg2)).rstrip()
        rs = RadioSettingValueString(0,16, pon_msg2, autopad= True)
        rset = RadioSetting("pon_msg2", "Power On Message 2", rs)
        info.append(rset)

        pon_msg3= ''.join(filter(_mem.settings.pon_msg3)).rstrip()
        rs = RadioSettingValueString(0,16, pon_msg3, autopad= True)
        rset = RadioSetting("pon_msg3", "Power On Message 3", rs)
        info.append(rset)

        msg1= ''.join(filter(_mem.settings.msg1)).rstrip()
        rs = RadioSettingValueString(0,16, msg1, autopad= True)
        rset = RadioSetting("msg1", "Message 1", rs)
        info.append(rset)

        msg2= ''.join(filter(_mem.settings.msg2)).rstrip()
        rs = RadioSettingValueString(0,16, msg2, autopad= True)
        rset = RadioSetting("msg2", "Message 2", rs)
        info.append(rset)

        ##################
        # Basic Settings #
        ##################

        rs = RadioSettingValueList(SQUELCH_LIST, current_index = _mem.settings.squelch)
        rset = RadioSetting("squelch", "Squelch Level", rs)
        basic.append(rset)   

        rs = RadioSettingValueList(STEP_LIST, current_index = _mem.settings.step)
        rset = RadioSetting("step", "Step", rs)
        basic.append(rset)  

        rs = RadioSettingValueList(BACKLIGHT_LIST, current_index = _mem.settings.backlight)
        rset = RadioSetting("backlight", "Backlight", rs)
        basic.append(rset)  

        rs = RadioSettingValueList(GROUPMODE_LIST, current_index = _mem.settings.group_a_mode)
        rset = RadioSetting("group_a_mode", "Group A Mode", rs)
        basic.append(rset) 

        rs = RadioSettingValueList(GROUPMODE_LIST, current_index = _mem.settings.group_b_mode)
        rset = RadioSetting("group_b_mode", "Group B Mode", rs)
        basic.append(rset) 

        rs = RadioSettingValueList(TOT_LIST, current_index = _mem.settings.tot)
        rset = RadioSetting("tot", "TOT", rs)
        basic.append(rset) 

        rs = RadioSettingValueList(LANGUAGE_LIST, current_index = _mem.settings.language)
        rset = RadioSetting("language", "Language", rs)
        basic.append(rset)

        rs = RadioSettingValueList(VOICE_LIST, current_index = _mem.settings.voice)
        rset = RadioSetting("voice", "Voice", rs)
        basic.append(rset) 

        rs = RadioSettingValueList(BATTSAVE_LIST, current_index = _mem.settings.batt_save_ratio)
        rset = RadioSetting("batt_save_ratio", "Battery Save Ratio", rs)
        basic.append(rset) 

        rs = RadioSettingValueList(PONTONE_LIST, current_index = _mem.settings.power_on_tone)
        rset = RadioSetting("power_on_tone", "Power On Tone", rs)
        basic.append(rset) 

        rs = RadioSettingValueList(PONPIC_LIST, current_index = _mem.settings.power_on_pic)
        rset = RadioSetting("power_on_pic", "Power On Picture", rs)
        basic.append(rset) 

        rs = RadioSettingValueList(VOXLEVEL_LIST, current_index = _mem.settings.vox_level)
        rset = RadioSetting("vox_level", "VOX Level", rs)
        basic.append(rset) 

        rs = RadioSettingValueList(VOXDELAY_LIST, current_index = _mem.settings.vox_delay)
        rset = RadioSetting("vox_delay", "VOX Delay", rs)
        basic.append(rset) 

        rs = RadioSettingValueBoolean(bool(_mem.settings.tone))
        rset = RadioSetting("tone", "Tone", rs)
        basic.append(rset)  

        rs = RadioSettingValueBoolean(bool(_mem.settings.standby_light))
        rset = RadioSetting("standby_light", "Standby Light", rs)
        basic.append(rset)  

        rs = RadioSettingValueBoolean(bool(_mem.settings.jump_freq))
        rset = RadioSetting("jump_freq", "Jump Frequency Function", rs)
        basic.append(rset)        

        rs = RadioSettingValueBoolean(bool(_mem.settings.ch_name_show))
        rset = RadioSetting("ch_name_show", "Channel Name Show", rs)
        basic.append(rset)       

        rs = RadioSettingValueBoolean(bool(_mem.settings.double_watch))
        rset = RadioSetting("double_watch", "Double Watch", rs)
        basic.append(rset)     

        rs = RadioSettingValueBoolean(bool(_mem.settings.tx_end_tone))
        rset = RadioSetting("tx_end_tone", "Tx End Tone", rs)
        basic.append(rset)  

        rs = RadioSettingValueBoolean(bool(_mem.settings.low_batt_alarm))
        rset = RadioSetting("low_batt_alarm", "Low Battery Alarm Enabled", rs)
        basic.append(rset)  

        rs = RadioSettingValueList(LOWBATTTONE_LIST, current_index = _mem.settings.low_batt_tone)
        rset = RadioSetting("low_batt_tone", "Low Battery Tone", rs)
        basic.append(rset) 

        rs = RadioSettingValueList(LOWBATTINTERVAL_LIST, current_index = _mem.settings.low_batt_alarm_int)
        rset = RadioSetting("low_batt_alarm_int", "Low Battery Alarm Interval", rs)
        basic.append(rset) 

        rs = RadioSettingValueList(KEYLOCKMODE_LIST, current_index = _mem.settings.keylockmode)
        rset = RadioSetting("keylockmode", "Key Lock Mode", rs)
        basic.append(rset) 

        rs = RadioSettingValueBoolean(bool(_mem.settings.keylocked))
        rset = RadioSetting("keylocked", "Key Locked", rs)
        basic.append(rset) 

        rs = RadioSettingValueBoolean(bool(_mem.settings.an_power_on))
        rset = RadioSetting("an_power_on", "An Power On", rs)
        basic.append(rset)   

        rs = RadioSettingValueBoolean(bool(_mem.settings.vibration))
        rset = RadioSetting("vibration", "Vibration", rs)
        basic.append(rset)   

        rs = RadioSettingValueList(VIBRATIONINT_LIST, current_index = _mem.settings.vibration_interval)
        rset = RadioSetting("vibration_interval", "Vibration Interval", rs)
        basic.append(rset) 
        
        rs = RadioSettingValueList(VIBRATIONTIME_LIST, current_index = _mem.settings.vibration_time)
        rset = RadioSetting("vibration_time", "Vibration Time", rs)
        basic.append(rset) 

        rs = RadioSettingValueBoolean(bool(_mem.settings.double_ptt))
        rset = RadioSetting("double_ptt", "Double PTT", rs)
        basic.append(rset) 

        rs = RadioSettingValueBoolean(bool(_mem.settings.low_batt_tx))
        rset = RadioSetting("low_batt_tx", "TX Allowed when Battery Low", rs)
        basic.append(rset) 

        rs = RadioSettingValueBoolean(bool(_mem.settings.call_tone))
        rset = RadioSetting("call_tone", "Call Tone", rs)
        basic.append(rset)        

        rs = RadioSettingValueBoolean(bool(_mem.settings.denoise))
        rset = RadioSetting("denoise", "Noise Cancelling", rs)
        basic.append(rset)    

        rs = RadioSettingValueBoolean(bool(_mem.settings.disable_menu))
        rset = RadioSetting("disable_menu", "Disable Menu", rs)
        basic.append(rset)  

        rs = RadioSettingValueBoolean(bool(_mem.settings.airband))
        rset = RadioSetting("airband", "Enable AM in Airband", rs)
        basic.append(rset) 

        rs = RadioSettingValueBoolean(bool(_mem.settings.freq_hop_ena))
        rset = RadioSetting("freq_hop_ena", "Frequency Hop", rs)
        basic.append(rset)
 
        freq_hop_pwd = _mem.settings.freq_hop_pwd
        rs = RadioSettingValueInteger(1, 49999, freq_hop_pwd)
        rset = RadioSetting("freq_hop_pwd", "Frequency Hop Password", rs)
        basic.append(rset)

        rs = RadioSettingValueBoolean(bool(_mem.settings.freq_sig_src))
        rset = RadioSetting("freq_sig_src", "Enable Frequency Signal Source Function", rs)
        basic.append(rset)     

        
        rs = RadioSettingValueBoolean(bool(_mem.settings.freq_meas))
        rset = RadioSetting("freq_meas", "Frequency Measurement", rs)
        basic.append(rset) 

        #################
        # Scan Settings #
        #################

        rs = RadioSettingValueList(SCANTXMODE_LIST, current_index = _mem.settings.scan_tx_mode)
        rset = RadioSetting("scan_tx_mode", "Scan Tx Mode", rs)
        scan.append(rset) 

        rs = RadioSettingValueList(GROUPSELECT_LIST, current_index = _mem.settings.sel_ch_group_a)
        rset = RadioSetting("sel_ch_group_a", "A Group Selected Channel", rs)
        scan.append(rset) 

        rs = RadioSettingValueList(GROUPSELECT_LIST, current_index = _mem.settings.sel_ch_group_b)
        rset = RadioSetting("sel_ch_group_b", "B Group Selected Channel", rs)
        scan.append(rset) 

        rs = RadioSettingValueList(GROUPSELECT_LIST, current_index = _mem.settings.prio_ch_group_a)
        rset = RadioSetting("prio_ch_group_a", "A Group Priority Channel", rs)
        scan.append(rset) 

        rs = RadioSettingValueList(GROUPSELECT_LIST, current_index = _mem.settings.prio_ch_group_b)
        rset = RadioSetting("prio_ch_group_b", "B Group Priority Channel", rs)
        scan.append(rset) 

        rs = RadioSettingValueBoolean(bool(_mem.settings.talkback))
        rset = RadioSetting("talkback", "Talkback", rs)
        scan.append(rset) 

        rs = RadioSettingValueBoolean(bool(_mem.settings.include_curr_fix_ch))
        rset = RadioSetting("include_curr_fix_ch", "Include Current Fixed Channel", rs)
        scan.append(rset) 

        ##################
        # Key Assignment #
        ##################
        rs = RadioSettingValueList(LONGPRESSTIME_LIST, current_index = _mem.settings.long_key_time - 5)
        rset = RadioSetting("long_key_time", "Long Press Time", rs)
        key.append(rset) 

        rs = RadioSettingValueList(SHORTKEYASSIGN_LIST, current_index = _mem.settings.short_press_key1)
        rset = RadioSetting("short_press_key1", "Short Press Side Key 1", rs)
        key.append(rset)

        rs = RadioSettingValueList(LONGKEYASSIGN_LIST, current_index = _mem.settings.long_press_key1)
        rset = RadioSetting("long_press_key1", "Long Press Side Key 1", rs)
        key.append(rset)

        rs = RadioSettingValueList(SHORTKEYASSIGN_LIST, current_index = _mem.settings.short_press_key2)
        rset = RadioSetting("short_press_key2", "Short Press Side Key 2", rs)
        key.append(rset)

        rs = RadioSettingValueList(LONGKEYASSIGN_LIST, current_index = _mem.settings.long_press_key2)
        rset = RadioSetting("long_press_key2", "Long Press Side Key 2", rs)
        key.append(rset)

        
        return group
    
    def set_settings(self, settings):
        _mem = self._memobj
        _settings = _mem.settings


        for element in settings:
            if not isinstance(element, RadioSetting):
                self.set_settings(element)
                continue

        #################
        # Info Settings #
        #################
            if element.get_name() == "range_freq_a_start":
                _settings.range_freq_a_start = element.value * 10  
            if element.get_name() == "range_freq_a_end":
                _settings.range_freq_a_end = element.value * 10 
            if element.get_name() == "range_freq_b_start":
                _settings.range_freq_b_start = element.value * 10 
            if element.get_name() == "range_freq_b_end":
                _settings.range_freq_b_end = element.value * 10
            if element.get_name() == "pon_msg1":
                _settings.pon_msg1 = pad_string(str(element.value),16)
            if element.get_name() == "pon_msg2":
                _settings.pon_msg2 = pad_string(str(element.value),16)
            if element.get_name() == "pon_msg3":
                _settings.pon_msg3 = pad_string(str(element.value),16)
            if element.get_name() == "msg1":
                _settings.msg1 = pad_string(str(element.value),16)
            if element.get_name() == "msg2":
                _settings.msg2 = pad_string(str(element.value),16)


             
        ##################
        # Basic Settings #
        ##################        
            if element.get_name() == "squelch":
                _settings.squelch = SQUELCH_LIST.index(str(element.value))
            if element.get_name() == "step":
                _settings.step = STEP_LIST.index(str(element.value))
            if element.get_name() == "backlight":
                _settings.backlight = BACKLIGHT_LIST.index(str(element.value))
            if element.get_name() == "group_a_mode":
                _settings.group_a_mode = GROUPMODE_LIST.index(str(element.value))
            if element.get_name() == "group_b_mode":
                _settings.group_b_mode = GROUPMODE_LIST.index(str(element.value))
            if element.get_name() == "tot":
                _settings.tot = TOT_LIST.index(str(element.value))
            if element.get_name() == "language":
                _settings.language = LANGUAGE_LIST.index(str(element.value))
            if element.get_name() == "voice":
                _settings.voice = VOICE_LIST.index(str(element.value))
            if element.get_name() == "batt_save_ratio":
                _settings.batt_save_ratio = BATTSAVE_LIST.index(str(element.value))
            if element.get_name() == "power_on_tone":
                _settings.power_on_tone = PONTONE_LIST.index(str(element.value))
            if element.get_name() == "power_on_pic":
                _settings.power_on_pic = PONPIC_LIST.index(str(element.value))          
            if element.get_name() == "vox_level":
                _settings.vox_level = VOXLEVEL_LIST.index(str(element.value))  
            if element.get_name() == "vox_delay":
                _settings.vox_delay = VOXDELAY_LIST.index(str(element.value))           
            if element.get_name() == "tone":
                _settings.tone = element.value and 1 or 0          
            if element.get_name() == "standby_light":
                _settings.standby_light = element.value and 1 or 0            
            if element.get_name() == "jump_freq":
                _settings.jump_freq = element.value and 1 or 0 
            if element.get_name() == "ch_name_show":
                _settings.ch_name_show = element.value and 1 or 0    
            if element.get_name() == "double_watch":
                _settings.double_watch = element.value and 1 or 0    
            if element.get_name() == "tx_end_tone":
                _settings.tx_end_tone = element.value and 1 or 0    
            if element.get_name() == "low_batt_alarm":
                _settings.low_batt_alarm = element.value and 1 or 0    
            if element.get_name() == "low_batt_tone":
                _settings.low_batt_tone = LOWBATTTONE_LIST.index(str(element.value))
            if element.get_name() == "low_batt_alarm_int":
                _settings.low_batt_alarm_int = LOWBATTINTERVAL_LIST.index(str(element.value))
            if element.get_name() == "keylockmode":
                _settings.keylockmode = KEYLOCKMODE_LIST.index(str(element.value))
            if element.get_name() == "keylocked":
                _settings.keylocked = element.value and 1 or 0 
            if element.get_name() == "an_power_on":
                _settings.an_power_on = element.value and 1 or 0
            if element.get_name() == "vibration":
                _settings.vibration = element.value and 1 or 0
            if element.get_name() == "vibration_interval":
                _settings.vibration_interval = VIBRATIONINT_LIST.index(str(element.value))
            if element.get_name() == "vibration_time":
                _settings.vibration_time = VIBRATIONTIME_LIST.index(str(element.value))
            if element.get_name() == "double_ptt":
                _settings.double_ptt = element.value and 1 or 0
            if element.get_name() == "call_tone":
                _settings.call_tone = element.value and 1 or 0   
            if element.get_name() == "denoise":
                _settings.denoise = element.value and 1 or 0   
            if element.get_name() == "disable_menu":
                _settings.disable_menu = element.value and 1 or 0   
            if element.get_name() == "airband":
                _settings.airband = element.value and 1 or 0   
            if element.get_name() == "freq_hop_ena":
                _settings.freq_hop_ena = element.value and 1 or 0
            if element.get_name() == "freq_hop_pwd":
                _settings.freq_hop_pwd = element.value       
            if element.get_name() == "freq_sig_src":
                _settings.freq_sig_src = element.value and 1 or 0                                      
            if element.get_name() == "freq_meas":
                _settings.freq_meas = element.value and 1 or 0  

        #################
        # Scan Settings #
        #################
            if element.get_name() == "scan_tx_mode":
                _settings.scan_tx_mode = SCANTXMODE_LIST.index(str(element.value))
            if element.get_name() == "sel_ch_group_a":
                _settings.sel_ch_group_a = GROUPSELECT_LIST.index(str(element.value))
            if element.get_name() == "sel_ch_group_b":
                _settings.sel_ch_group_b = GROUPSELECT_LIST.index(str(element.value))
            if element.get_name() == "prio_ch_group_a":
                _settings.vibration_time = GROUPSELECT_LIST.index(str(element.value))
            if element.get_name() == "prio_ch_group_b":
                _settings.vibration_time = GROUPSELECT_LIST.index(str(element.value))
            if element.get_name() == "talkback":
                _settings.talkback = element.value and 1 or 0
            if element.get_name() == "include_curr_fix_ch":
                _settings.include_curr_fix_ch = element.value and 1 or 0

        #################
        # Scan Settings #
        #################
            if element.get_name() == "long_key_time":
                _settings.long_key_time = LONGPRESSTIME_LIST.index(str(element.value))
            if element.get_name() == "short_press_key1":
                _settings.short_press_key1 = SHORTKEYASSIGN_LIST.index(str(element.value))
            if element.get_name() == "long_press_key1":
                _settings.long_press_key1 = LONGKEYASSIGN_LIST.index(str(element.value))
            if element.get_name() == "short_press_key2":
                _settings.short_press_key2 = SHORTKEYASSIGN_LIST.index(str(element.value))
            if element.get_name() == "long_press_key2":
                _settings.long_press_key2 = LONGKEYASSIGN_LIST.index(str(element.value))

class rt752GroupA(rt752):
    """RT-752 Group A subdevice"""
    VARIANT = "A"
    _memstart = 0x0


class rt752GroupB(rt752):
    """RT-752 Group B subdevice"""
    VARIANT = "B"
    _memstart = 8032 #8032
