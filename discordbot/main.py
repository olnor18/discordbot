import discord
import os
import psycopg2
import asyncio
from threading import Thread
import requests
import xml.etree.ElementTree as ElementTree
from multiprocessing import Process
import logging
from flask import Flask, render_template, request
from discord.ext.tasks import loop
from discord.ext import commands

import base64

'''
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
'''

app = Flask(__name__)

intents = discord.Intents(messages=True, guilds=True, members=True)
client = discord.Client(intents=intents)
serverID = 795679940740907089 #786173237293875271
roleID = 795680059758477333 #Not valid!!!!
adminRoleIds = [796105678329479168]
adminRoles = []

ssolink = "https://sso.sdu.dk/login?service="
ssoverify = "https://sso.sdu.dk/serviceValidate"
authlink = os.environ['AUTHLINK']


connected = False
while not connected:
    try:
        conn = psycopg2.connect(
                host="db",
                database="postgres",
                user="postgres",
                password=os.environ['DBPASS'])
        connected = True
    except psycopg2.OperationalError:
        pass

'''
password_provided = os.environ['CRYPTPASS']
password = password_provided.encode()
salt = base64.b64decode(os.environ['CRYPTSALT'])
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)
'''
###########################
#########DISCORD###########
###########################
updateQueue = []

@loop(seconds=2)
async def updater():
    global updateQueue
    internalQueue = updateQueue
    for users in internalQueue:
        logging.info(users["user"]["username"] + " logged in on the discord user: " + users["discordId"])
        await addUser(users["user"]["username"], users["user"]["fullname"], users["discordId"])
        updateQueue.remove(users)

role = None

@client.event
async def on_ready():
    global role
    server = client.get_guild(serverID)
    role = server.get_role(roleID)
    for adminRoleId in adminRoleIds:
        adminRoles.append(server.get_role(adminRoleId))
    logging.info('Logged in as {0.user}'.format(client))
    

@client.event
async def on_message(message):
    if message.guild or message.author == client.user:
        return
    if message.channel.id == message.author.dm_channel.id and message.content.startswith('!username'):
        logging.info("Got a hit!")
        arg = message.content.split()[1]
        server = client.get_guild(serverID)
        member = server.get_member(message.author.id)
        logging.info("Done fetching")
        if member is not None:
            logging.info("Is a member")
            isAllowed = False
            for adminRole in adminRoles:
                if adminRole in member.roles:
                    isAllowed = True
            if isAllowed:
                logging.info("Is allowed")
                cur = conn.cursor()
                logging.info("Created cursor")
                cur.execute("SELECT username FROM users WHERE discordId = %s;", (arg,))
                logging.info("Executed")
                username = cur.fetchone()
                logging.info(username[0])
                cur.close()
                await message.channel.send(username[0])
            else:
                await message.channel.send("You are not allowed to use that command")
        else:
            await message.channel.send("You are not allowed to use that command")

@client.event
async def on_member_join(member):
    if (not member.guild.id == serverID):
        print("Huh")
        return
    #clear = str(member.id).encode()
    #encrypted = f.encrypt(clear)
    await member.send(str("For at få adgang til serveren skal du logge gennem følgende link: " + ssolink + authlink + base64.b64encode(str(member.id).encode('ascii')).decode("ascii")))

def truncate_middle(s, n):
    if len(s) <= n:
        return s
    split = s.split()
    if (len(split) > 2):
        i = 1
        while (len(' '.join(split)) > n):
            if (i <= len(split) - 2):
                split[i] = split[i][0]+'.'
                i += 1
            elif (i == len(split) - 1):
               split[0] = split[0][0]+'.'
               i += 1
            elif (i == len(split)):
               return ' '.join(split)[:n-3]+'...'
        return ' '.join(split)

    elif (len(split) == 2):
        temp = split[0][0]+'. '+split[1][:n-3]
        if len(temp) <= n:
            return s
        return temp[:n-3]+'...'
    else:
        return s[:n-3]+'...'

async def addUser(username, fullname, discordId):
    logging.info("Before anything")
    realname = truncate_middle(fullname, 32)
    logging.info("Before guild")
    server = client.get_guild(serverID)
    logging.info("Got Guild")
    logging.info("Before member with id: "+str(int(discordId)))
    member = server.get_member(int(str(discordId)))
    logging.info("All thing have been fetched and member")
    if (member is not None):
        if (role in member.roles):
            return "Du er allerede logget ind. Kontakt en TA eller Teacher for hjælp"
        roles = member.roles
        roles.append(role)
        try:
            logging.info("Before member.edit")
            await member.edit(nick=realname, roles=roles)
            logging.info("After member.edit")
            return True
        except discord.errors.Forbidden:
            print('Missing permissions! Check the if the role is higher than the bot role or if the user is admin')
    else:
        return "Du er ikke medlem af serveren"

###########################
##########FLASK############
###########################

@app.route('/<encryptedDiscordId>')
def validate(encryptedDiscordId):
    #discordId = f.decrypt(base64.b64decode(encryptedDiscordId)).decode('ascii')
    discordId = base64.b64decode(encryptedDiscordId).decode('ascii')
    ticket = request.args.get('ticket')
    user = getData(discordId, encryptedDiscordId, ticket)
    if user is None:
        return render_template("error.html", response="Authentication Failure")
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, fullname, discordId) VALUES (%s, %s, %s);", (user["username"], user["fullname"], discordId))
    except psycopg2.errors.UniqueViolation:
        return render_template("error.html", response="Du er allerede logget ind. Kontakt en TA eller Teacher for hjælp")
    finally:
        conn.commit()
    cur.close()
    global updateQueue
    updateQueue.append({"user": user, "discordId": discordId})
    return render_template("success.html")


def getData(discordId, encryptedDiscordId, ticket):
    response = requests.get(url = ssoverify, params = {'service':authlink+encryptedDiscordId, 'ticket': ticket})
    tree = ElementTree.fromstring(response.content)
    ns = {"cas": "http://www.yale.edu/tp/cas"}
    if tree.find("cas:authenticationFailure", namespaces=ns) is not None:
        return None
    elif tree.find("cas:authenticationSuccess", namespaces=ns) is not None:
        data = tree.find("cas:authenticationSuccess", namespaces=ns)
        username = data.find("cas:user", namespaces=ns)
        user = data.find("norEduPerson")
        fullname = user.find("cn")
        return {
            "username": username.text,
            "fullname": fullname.text
        }


###########################
########THREADING##########
###########################

def workerFlask():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(app.run(host="0.0.0.0", port=80, debug=False))
    return

logging.basicConfig(level=logging.INFO)
Thread(target=workerFlask).start()
updater.start()
client.run(os.environ['DISCORDPASS'])