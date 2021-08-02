from scipy.io import wavfile
import os
import numpy as np


SONG_DIR = './tracks/'
MARGIN = 2000

MINIMUM_HEIGHT = 10

def main():
    result = ''

    # Loop through all the files in the specified directory
    for file in os.listdir(SONG_DIR):
        # We only care about the sound files
        if not file.endswith('.wav'):
            continue

        filepath = os.path.join(SONG_DIR, file)

        samplerate, data = wavfile.read(filepath)

        # Unpack the data and separate the channels
        sample_num, channel_num = data.shape
        c1, c2, _ = data.T

        print(f'[*] Comparing channel 1 & 2 in {file}')

        # Find the difference between the first two channels
        sub = c1 - c2
        
        byte_num = 3
        while True:
            
            # Samples/bit
            bit_size = sample_num // (byte_num * 8)

            text = ''
            for by in range(byte_num): # For each byte in the song

                # bits will be string of 8 1s and 0s, which is later converted to a byte
                bits = ''

                for bi in range(8): # For each bit in the byte

                    i = by * 8 + bi # Compounded index of bit

                    arr = sub[i * bit_size + MARGIN : (i + 1) * bit_size - MARGIN]
                    m = np.amax(arr) # Find the highest point in the area
                    
                    # Check wheather the highest point is tall enough or not
                    bit = '1' if m > MINIMUM_HEIGHT else '0' 
                    bits += bit

                # Use string->int conversion with base 2, and make a character out of the bits
                text += chr(int(bits, 2))

            # Some (the last) files use 6 bytes instead of 3, so if the data
            # seems corrupted, we add 3 bytes and run extraction again
            if not text.isascii():
                byte_num += 3
                print(f'[!] {text} is not ASCII! Trying with {byte_num} bits')
                continue
            break
        result += text

        print(f'[*] Current string: "{result}"')

    print(f'\nFLAG: {result}\n')

if __name__ == '__main__':
    main()
