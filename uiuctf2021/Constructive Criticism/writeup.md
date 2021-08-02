# Constructive Criticism

**Category:** Misc

**Author:** Pranav Goel

**Description:**

> Checkout this playlist from a new soundcloud artist I found: https://soundcloud.com/nick-carraway-43926894/sets/lofi-beats-to-hack-with/s-83uzJdlwz3H
>
> He made a mix of some good songs to vibe with while you hack away. Download the songs if you want to listen offline!

**Hint:**

> Stereo is pretty cool if you look into it...



*Constructive Criticism* is based around a Soundcloud playlist with 20 different songs of some Lofi beats to jam to while you hack. The first thing you might notice when you listen to the tracks is that the sound seems awfully tilted towards one of your ears, and this would make sense given the hint that "Stereo is pretty cool", hinting at stereo channels in the audio.

The first thing I did was open up the first track in Python using the `scipy.io.wavfile` module and compare the first and second channel

```python
from scipy.io import wavfile

file = './tracks/a.wav'

samplerate, data = wavfile.read(file)

# Extract channels
c1, c2, _ = data.T

fig, axs = plt.subplots(2)
fig.tight_layout()
axs[0].set_title('Channel 1')
axs[0].plot(range(len(c1)), c1, linewidth=0.1)
axs[1].set_title('Channel 2')
axs[1].plot(range(len(c2)), c2, linewidth=0.1)
plt.show()
```

<img width="700" src="https://raw.githubusercontent.com/TheBlupper/ctf_writeups/main/uiuctf2021/Constructive%20Criticism/compare_channels.png">

As you can see, there is not any obvious difference between the two channels, so I tried seeing if there was any difference at all by subtracting channel #2 from channel #1

```python
sub = c1 - c2
plt.plot(range(len(sub)), sub, linewidth=.1)
plt.show()
```
<img width="700" src="https://github.com/TheBlupper/ctf_writeups/raw/main/uiuctf2021/Constructive%20Criticism/digital.png">

Bingo! A very clear digital pattern emerges!  At this point it becomes obvious why the challenge is named as it is. The two channels are *constructively* as well as *destructively* interfering with each other at regular periods, creating a digital pattern. With this I mean that in the parts where the above graph is 0, all the highs of the pressure curve of channel #1 are cancelled out by the lows in channel #2 resulting in a net pressure change of 0.

At this point in time I tried interpreting the digital signals by hand and write them down. The bits in this file would be

`01110101 01101001 01110101`

which corresponds to 

`75 69 75`

in hexadecimal. And wouldn't you know? That's the string "uiu", the first three letters of all flags (the flag format is uiuctf{*})! Now it was clear what I needed to do. I needed to make a script that loops through all songs in the album in order, calculates the difference of the first two channels and interprets them as bits that can be assembled into the flag.

I'll first show you the script I came up with, and then I'll explain the reasons behind the decisions I made.

```python
from scipy.io import wavfile
import os 
from matplotlib import pyplot as plt
import numpy as np
from bitstring import BitArray


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
```

The constants MARGIN and MINIMUM_HEIGHT are arbitrarily chosen after what I found worked. Setting a MARGIN is necessary to avoid interference from adjacent bits (the image below is greatly exaggerated). 
<img width="600" src="https://github.com/TheBlupper/ctf_writeups/raw/main/uiuctf2021/Constructive%20Criticism/margin_demonstration.png">

MINIMUM_HEIGHT is the highest any point in the measured bit can be before the bit becomes 1 instead of a 0. I also check whether the decoded text is in ASCII, which all flags are. The reason is that some (in this case only the last file) contains 6 bytes instead of 3, as the rest, so if the data looks corrupted I increase the byte count by 3 and run the extraction again.

`os.listdir` lists files in alphabetical order, so I renamed all the tracks to their number's corresponding letter, and put them all in the folder /tracks, and ran the script, yielding the following output.

```
[*] Comparing channel 1 & 2 in a.wav
[*] Current string: "uiu"
[*] Comparing channel 1 & 2 in b.wav
[*] Current string: "uiuctf"
[*] Comparing channel 1 & 2 in c.wav
[*] Current string: "uiuctf{lo"
[*] Comparing channel 1 & 2 in d.wav
[*] Current string: "uiuctf{lofi_"
[*] Comparing channel 1 & 2 in e.wav
[*] Current string: "uiuctf{lofi_bop"
[*] Comparing channel 1 & 2 in f.wav
[*] Current string: "uiuctf{lofi_bops_b"
[*] Comparing channel 1 & 2 in g.wav
[*] Current string: "uiuctf{lofi_bops_but_"
[*] Comparing channel 1 & 2 in h.wav
[*] Current string: "uiuctf{lofi_bops_but_enc"
[*] Comparing channel 1 & 2 in i.wav
[*] Current string: "uiuctf{lofi_bops_but_encryp"
[*] Comparing channel 1 & 2 in j.wav
[*] Current string: "uiuctf{lofi_bops_but_encryptin"
[*] Comparing channel 1 & 2 in k.wav
[*] Current string: "uiuctf{lofi_bops_but_encrypting_a"
[*] Comparing channel 1 & 2 in l.wav
[*] Current string: "uiuctf{lofi_bops_but_encrypting_audi"
[*] Comparing channel 1 & 2 in m.wav
[*] Current string: "uiuctf{lofi_bops_but_encrypting_audio_u"
[*] Comparing channel 1 & 2 in n.wav
[*] Current string: "uiuctf{lofi_bops_but_encrypting_audio_usin"
[*] Comparing channel 1 & 2 in o.wav
[*] Current string: "uiuctf{lofi_bops_but_encrypting_audio_using_i"
[*] Comparing channel 1 & 2 in p.wav
[*] Current string: "uiuctf{lofi_bops_but_encrypting_audio_using_inte"
[*] Comparing channel 1 & 2 in q.wav
[*] Current string: "uiuctf{lofi_bops_but_encrypting_audio_using_interfe"
[*] Comparing channel 1 & 2 in r.wav
[*] Current string: "uiuctf{lofi_bops_but_encrypting_audio_using_interferen"
[*] Comparing channel 1 & 2 in s.wav
[*] Current string: "uiuctf{lofi_bops_but_encrypting_audio_using_interference_"
[*] Comparing channel 1 & 2 in t.wav
[!] ÞÜß is not ASCII! Trying with 6 bits
[*] Current string: "uiuctf{lofi_bops_but_encrypting_audio_using_interference_slaps}"

FLAG: uiuctf{lofi_bops_but_encrypting_audio_using_interference_slaps}
```

And there's the flag!

