# Emoji Hunt 2: the Microwave

A challenge from Square CTF 2023

### Description

:he-brings-you-flag: isn't looking too hot :( maybe you can help the lil' guy out and figure out whats wrong with him?
slack wouldn't let me upload this as an emoji so you'll have to live with spamming the OG :he-brings-you-flag:

[Image](./hebringsyouflag.png)

### Solve

In the challenge description, the image file is the only thing they really give us. The first thing, therefore, that we did was analyze the metadata of the image. When we did, we found an entire script in a field of the metadata titled "microwave". That script is in [this file](./emoji.py), but we'll break it apart and analyze it here.

```python
import zlib, hashlib, pytesseract

flag = pytesseract.image_to_string("hebringsyouflag.png").strip().replace("\n", "").replace(" ", "")
flag_hash = hashlib.sha1(flag.encode()).digest()

def microwave_turtle(b_arr, flag_hash):
    ind = 0
    for b in flag_hash[:2]:
        orig = b_arr[ind]
        b_arr[ind] = orig ^ b
        ind += orig
    
    return b_arr
        
with open("hebringsyouflag.png", "rb") as f:
    img = bytearray(f.read())
idat_loc = img.index(b'IDAT') # gets the byte location of the IDAT section of the image where the actual data starts
idat_sz = int.from_bytes(img[idat_loc - 4:idat_loc], "big") # size comes BEFORE it says IDAT
crc_loc = idat_loc + 4 + idat_sz # crc comes AFTER image data

raw_image_data = img[idat_loc + 4 : crc_loc] # img data

block_offset = 0x420
img[idat_loc + 4 + block_offset:crc_loc] = microwave_turtle(raw_image_data[block_offset:], flag_hash)
img[crc_loc:crc_loc + 4] = zlib.crc32(img[idat_loc:crc_loc]).to_bytes(4, "big")

with open(__file__, "r") as f:
    the_microwave = f.read()

ztxt_data = bytearray(b'microwaver\x00\x00') + zlib.compress(the_microwave.encode("UTF-8"))
ztxt_chunk = bytearray(len(ztxt_data).to_bytes(4, "big") + b'zTXt' + ztxt_data + zlib.crc32(b'zTXt' + ztxt_data).to_bytes(4, "big"))
img[idat_loc - 4 : idat_loc - 4] = ztxt_chunk


with open("hebringsyouflag.png", "wb") as f:
    f.write(img)
```

Whoever wrote this challenge knows way too much about image byte data, to be completely honest with you. The script works in a couple parts, as separated by the new lines:

1. First, it uses pytesseract to extract the string of the flag from the data, and it prepares a hash of the flag to use later
1. Next, it defines a function called "microwave_turtle". This is an important one later, so we'll explain what it does now: this function takes the byte data of an image (b_arr) and the hash of the flag (flag_hash). It, using the hash of the flag xors the first byte of the image data (as a byte array) by the first byte of the flag hash digest. Then it jumps to the byte associated with the numberic value of the first xor'd byte and xors it with the second byte of the hash. Funnily enough, this is only called once and it corrupts the whole image
1. Then, it opens the original image and extracts some information: the location of the IDAT header in the image (this marks the start of the actual image data), the size of the image byte data (which is given right before the IDAT header), and the location of the crc (right after all the image data)
1. Next, it stores the actual image data in a variable
1. Now we'll start to see the actual editing of the image. They set an offset of 0x420 bytes and run the image data from the offset and on through microwave turtle. Then it updates the crc so the data doesn't show up as corrupted
1. Next, the script opens itself and saves itself to a string variable, which it then adds to the metadata of the image (there are a couple steps to this but it's just evidence that the author knows way too much lol)
1. Finally, it writes this updated image data back to the original image, returning the corrupted image with the script in the metadata

So in order to solve this challenge we would then need to fix the two bytes that have been messed up. Let's write a script to do so:

We can borrow a lot of the pieces of this original script to write our solve script. I tried to do this with tesseract and run it until it found an image with eligible text, but my WSL wouldn't work with Tesseract, so I resorted to the next best option: scrolling through thousands of deep fried pictures of turtles haha.

Here's a solve script that will brute force all the possibilities:

```python
import zlib

def microwave_turtle(b_arr, flag_hash):
    ind = 0
    for b in flag_hash:
        orig = b_arr[ind]
        b_arr[ind] = orig ^ b
        ind += b_arr[ind]
    
    return b_arr

for i in range(255):
    for j in range(128, 160):
            
    with open("hebringsyouflag.png", "rb") as f:
        img = bytearray(f.read())
    idat_loc = img.index(b'IDAT') # gets the byte location of the IDAT section of the image where the actual data starts
    idat_sz = int.from_bytes(img[idat_loc - 4:idat_loc], "big") # size comes BEFORE it says IDAT
    crc_loc = idat_loc + 4 + idat_sz # crc comes AFTER image data

    raw_image_data = img[idat_loc + 4 : crc_loc] # img data

    block_offset = 0x420


    img[idat_loc + 4 + block_offset:crc_loc] = microwave_turtle(raw_image_data[block_offset:], [68, 134])
    img[crc_loc:crc_loc + 4] = zlib.crc32(img[idat_loc:crc_loc]).to_bytes(4, "big")


with open("hebringflag/hebringsyouflag64-134.png", "wb") as f:
    f.write(img)
```

So a couple pieces of this function have been edited:

1. First, I changed the microwave turtle function to work with an array of two numbers, xor-ing by the first, then at the value generated by the first by the second. This will simulate the reverse of the original xor
2. I also removed the insertion of the script into the image.

In this for loop, it will brute force all possible combinations of two bytes at the start of the flag hash and generate the associated images. I did 8000-ish at a time because it was easier to work through by hand that way, but you could feasibly do more. I just ran it with various values until I came across the correct two bytes: 64 and 134

The original extracted image is [this one](./hebringsyouflag64-134.png) and the flag is flag{plsstopmicrowavingtheturtles}