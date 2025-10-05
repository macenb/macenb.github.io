# Electronical

A challenge from BuckeyeCTF 2023

### Description:
```
I do all my ciphering electronically

https://electronical.chall.pwnoh.io
```

When you visit the website in the challenge description, you can find a very basic implementation of a website on which you can submit a form request that will encrypt information you give it. 

![website](./electronical.png)

Upon further inspection you can see the source code for the page by following the link shown at the bottom.

Here is the code:

```python
from Crypto.Cipher import AES
from flask import Flask, request, abort, send_file
import math
import os

app = Flask(__name__)

key = os.urandom(32)
flag = os.environ.get('FLAG', 'bctf{fake_flag_fake_flag_fake_flag_fake_flag}')

cipher = AES.new(key, AES.MODE_ECB)

def encrypt(message: str) -> bytes:
    length = math.ceil(len(message) / 16) * 16
    padded = message.encode().ljust(length, b'\0')
    return cipher.encrypt(padded)

@app.get('/encrypt')
def handle_encrypt():
    param = request.args.get('message')

    if not param:
        return abort(400, "Bad")
    if not isinstance(param, str):
        return abort(400, "Bad")

    return encrypt(param + flag).hex()

@app.get('/source')
def handle_source():
    return send_file(__file__, "text/plain")

@app.get('/')
def handle_home():
    return """
        <style>
            form {
                display: flex;
                flex-direction: column;
                max-width: 20em;
                gap: .5em;
            }

            input {
                padding: .4em;
            }
        </style>
        <form action="/encrypt">
            <h2><i>ELECTRONICAL</i></h2>
            <label for="message">Message to encrypt:</label>
            <input id="message" name="message"></label>
            <input type="submit" value="Submit">
            <a href="/source">Source code</a>
        </form>
    """

if __name__ == "__main__":
    app.run()
```

The flask code for the website is fairly simple, and is intended to encode the text. Let's walk through each function together.

First, we have a random 32 byte key set, as well as a flag. Then, a cipher is set so that they can utilize the AES ECB in further code. The next function we see is an encrypt function, that will take an input, pad it with null bytes, and encode it. This is used in the handle_encrypt function that immediately follows. This takes your input to the site if it's valid, appends the flag, and encrypts it to be outputted in hex. Since they're appending the flag to your imput and they're encrypting with AES ECB, we can use a padding attack.

AES ECB works with a repeating key, so it is vulnerable to specialized brute force attacks. A padding attack is designed to get you one value at a time. Here's how it works:
- First, you create a padding that is 15 digits long, since 16 digits at a time are encrypted.
- Next, encrypt that padding and save the output. Then, if you add a value of your choice to that padding and encrypt that, if your value of choice is correct, the first block of encryption will be the same.
- Then you can shift what you have left, shortening the padding and adding the letter you discovered

This works solely because the flag is added to your message. So you have 15 known values and one unknown value encrypted with the same key every time. This means that when you are guessing the one unknown letter, it corresponds to a value of the flag. Let's script this.

First, I created a list of values that could correspond to real options for my bruteforce: `ascii_text_chars = list(range(97, 122)) + [32, 95, 123, 125] + list(range(48, 57)) + list(range(65, 90))`

Then we can build out a function, `bruteforce_letter(plaintext)` that will take a set of plaintext and run the bruteforce recursively until it outputs the whole flag.

Referencing the steps above, the first thing we need to do is create padding and send the request to the url to get the output. Importantly, when you submit a request to the website, it redirects to a different URL, so if I were to encrypt the word 'tacos' it would redirect me here: https://electronical.chall.pwnoh.io/encrypt?message=tacos

That means we can add the line `url = 'https://electronical.chall.pwnoh.io/encrypt?message='` and just append the plaintext we would like to encrypt.
Here is some code that accomplishes this first step, also pulling the correct length of value from the output:
```python
    padding = 'a' * (15 - (len(plaintext) % 16))
    if len(padding) == 0:
        padding = 'a' * 16
    
    temptext = padding + plaintext

    #send get request
    r = requests.get(url + padding)

    #cut the text to 
    if len(plaintext) < 15:
        match = r.text[0:32]
    elif len(plaintext) < 31:
        match = r.text[32:64]
    else:
        match = r.text[64:64+32]
```
(This code is designed to scale for keys larger than 16 characters, too)

Next we can, using this `match` value, bruteforce all possible letters until we can match the encrypted output.

```python
    for letter in ascii_text_chars:
        #add the new letter to the hex
        temp = temptext + chr(letter)

        #prep the new get request
        if len(plaintext) < 15:
            spoof = requests.get(url + temp).text[0:32]
        elif len(plaintext) < 31: 
            spoof = requests.get(url + temp).text[32:64]
        else: 
            spoof = requests.get(url + temp).text[64:64+32]

        #if it matches, recurse
        if spoof == match:
            if chr(letter) == "}":
                print(plaintext + chr(letter))
                break
            else:
                print(plaintext + chr(letter))
                if len(plaintext + chr(letter)) == 15:
                    print("15")
                bruteforce_letter(plaintext + chr(letter))
                break
```

This will add the recursive search with the new, correct letter. We can then call this function with `bctf{` as the plaintext to get the flag, letter by letter (it's kind of fun to watch actually)

Full code:

```py
import requests

ascii_text_chars = list(range(97, 122)) + [32, 95, 123, 125] + list(range(48, 57)) + list(range(65, 90))

url = 'https://electronical.chall.pwnoh.io/encrypt?message='

#length of string is 32

def bruteforce_letter(plaintext):

    #pad
    padding = 'a' * (15 - (len(plaintext) % 16))
    if len(padding) == 0:
        padding = 'a' * 16
    
    temptext = padding + plaintext

    #send get request
    r = requests.get(url + padding)

    #cut the text to 
    if len(plaintext) < 15:
        match = r.text[0:32]
    elif len(plaintext) < 31:
        match = r.text[32:64]
    else:
        match = r.text[64:64+32]

    #bruteforce through all the letters
    for letter in ascii_text_chars:
        #add the new letter to the hex
        temp = temptext + chr(letter)

        #prep the new get request
        if len(plaintext) < 15:
            spoof = requests.get(url + temp).text[0:32]
        elif len(plaintext) < 31: 
            spoof = requests.get(url + temp).text[32:64]
        else: 
            spoof = requests.get(url + temp).text[64:64+32]

        #if it matches, recurse
        if spoof == match:
            if chr(letter) == "}":
                print(plaintext + chr(letter))
                break
            else:
                print(plaintext + chr(letter))
                if len(plaintext + chr(letter)) == 15:
                    print("15")
                bruteforce_letter(plaintext + chr(letter))
                break

bruteforce_letter("bctf{")

```

The flag is: `bctf{1_c4n7_b3l13v3_u_f0und_my_c0d3b00k}`