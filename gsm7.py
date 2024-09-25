import sys, math

"""
This script encodes a string to the GSM 7 bit format for usage in Cell Broadcast messages.
The structure printed to the console resembles that of TS 23.041, 9.4.2.2.5.
The message length is restricted to one page (maximum of 82 octets of GSM 7 bit encoded characters)
Based on the Javascript PDU Converter by Swen-Peter Ekkebu (https://www.solmu.org/pub/misc/flash_sms.html)
"""

# 82 octets per CBS-Message-Information-Page with GSM 7 encoded characters
# 82/7*8=~93 -> 82 Octets fit approximately 93 GSM 7 encoded characters
MAX_MESSAGE_LENGTH = 93
NUMBER_OF_PAGES = 1
GSM7_ALPHABET = ("@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
                 "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà")
EXTENDED_CHARS = {
    0x0A: '\f', 0x14: '^', 0x28: '{', 0x29: '}', 0x2F: '\\', 0x3C: '[',
    0x3D: '~', 0x3E: ']', 0x40: '|', 0x65: '€'
}


def _int_to_hex(num):
    return f"{num:02X}"


def _int_to_bin(num, length):
    return f"{num:0{length}b}"


def _bin_to_int(binary):
    return int(binary, 2)


def _get_seven_bit(char):
    return ord(char) & 0x7F


def encode_pdu_message(input_string):
    output = ""
    octet_second = ""

    for i in range(len(input_string) + 1):
        if i == len(input_string):
            if octet_second:
                output += _int_to_hex(_bin_to_int(octet_second))
            break

        current = _int_to_bin(_get_seven_bit(input_string[i]), 7)

        if i != 0 and i % 8 != 0:
            octet_first = current[7 - (i % 8):]
            current_octet = octet_first + octet_second
            output += _int_to_hex(_bin_to_int(current_octet))
            octet_second = current[:7 - (i % 8)]
        else:
            octet_second = current[:7 - (i % 8)]

    return output, len(output) // 2


def decode_pdu_message(_encoded_message):
    is_extended = False
    decoded = ""
    septets = ""

    # Convert hex to binary
    for byte in bytes.fromhex(_encoded_message):
        septets = f"{byte:08b}" + septets

    # Process 7-bit groups
    while len(septets) >= 7:
        septet = septets[-7:]
        septets = septets[:-7]

        char_code = int(septet, 2)
        if is_extended:
            decoded += EXTENDED_CHARS.get(char_code, chr(char_code))
            is_extended = False
        elif char_code == 0x1B:
            is_extended = True
        else:
            decoded += GSM7_ALPHABET[char_code]

    return decoded


def process_input(input_string):
    input_length = len(input_string)
    assert input_length <= MAX_MESSAGE_LENGTH, f"Input string is too long. Max: {MAX_MESSAGE_LENGTH}, was: {input_length}"

    # Pad the string with spaces to adhere to the defined length for CBS-Message-Information-Pages
    padded_string = input_string.ljust(MAX_MESSAGE_LENGTH)

    encoded, encoded_length = encode_pdu_message(padded_string)
    encoded_length = math.ceil(len(input_string)/8*7)  # Number of bytes that contain the actual message
    decoded = decode_pdu_message(encoded)

    return decoded, encoded, encoded_length


if __name__ == "__main__":
    assert len(sys.argv) == 2, f"Missing string to encode. Usage: {sys.argv[0]} <input_string>"
    _, encoded_message, encoded_message_length = process_input(sys.argv[1])
    print(f"{str(_int_to_hex(NUMBER_OF_PAGES))}{encoded_message}{str(_int_to_hex(encoded_message_length))}")
