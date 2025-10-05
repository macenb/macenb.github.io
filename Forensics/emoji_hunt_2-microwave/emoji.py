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