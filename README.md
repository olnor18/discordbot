# discordbot

## Branches

### master
The original, which sets users nicknames to their full names and stores it.

### anonymous
Never version which does not set nicknames and just stores their discord ids, for easier reentering of the server.

## Install
Add a .env file in ./discordbot/discordbot/.env including the following env:
```
DISCORDPASS=<DISCORD-TOKEN>
```

You also need to change the env in the docker-compose file called AUTHLINK to the url the bot will be accessable on.

If you don't want HTTPS, change the proxy conf, otherwise add certs to the proxy/certs folder
