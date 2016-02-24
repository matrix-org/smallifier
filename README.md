# smallifier
Smallifier is a small link shortener.

It responds to HTTP requests like so:
```
$ curl -d '{"long_url": "https://please.smallifiy.me"}' -v https://smallifier/_create
{"short_url":"https://smallifier/tj2TEXT7"}
```

And after this, navigating to ``https://smallifier/tj2TEXT7`` will 302 you to https://please.smallify.me
