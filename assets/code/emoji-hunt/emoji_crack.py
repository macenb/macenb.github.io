import zlib

def microwave_turtle(b_arr, flag_hash):
    ind = 0
    for b in flag_hash:
        orig = b_arr[ind]
        b_arr[ind] = orig ^ b
        ind += b_arr[ind]
    
    return b_arr

# for i in range(255):
#     for j in range(128, 160):
            
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