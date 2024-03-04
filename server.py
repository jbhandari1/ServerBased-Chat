#! /usr/bin/env python3

import socket
from socket import *
import hashlib
import random
import base64
from cryptography.fernet import Fernet
import threading
from threading import Event
import sys

udpAddress = "127.0.0.1"
tcpAddress = "127.0.0.1"
udpPort = 12000
tcpPort = 5001 

name, keys = 4, 2
keyArr = [[0 for i in range(keys)] for j in range(name)]
keyArr[0][0] = "clientA"
keyArr[0][1] = "a3c52bc7fd3a125e"
keyArr[1][0] = "clientB"
keyArr[1][1] = "b0c2499ad74cf2a4"
keyArr[2][0] = "clientC"
keyArr[2][1] = "c341ad84cbf67fea" 
keyArr[3][0] = "clientD"
keyArr[3][1] = "d875acd920bfe21c"

connUser = []
threads = []
chatRoom1 = []
chatRoom1User = []
chatRoom2 = []
chatRoom2User = []

def column(arr, c):
    return [row[c] for row in arr]
#for name in keyArr:
#    print(name)
def findName(sock):
    sockIndex = threads.index(sock)
    print(connUser[sockIndex])
    return connUser[sockIndex]


def userChat1(name, req, sID, c1):
    #f = open("chatroom1.txt", "w")
     while True:
        msg = c1.recv(1024)
        print(msg.decode())
        #cmdSplit = msg.decode().split(': ')
        #cmd = cmdSplit[1]
        #print(cmd)
        if msg.decode() == "Log off":
            threads.remove(c1)               #Remove from thread array before closing connection
            c1.close()
            print(f"{clientAddress} disconnected")
            break
        elif msg.decode() == "End chat":
            for user in chatRoom1User:
                user.send("Ending session".encode())
            #del chatRoom1User[1]
            userIndex = chatRoom1User.index(c1)
            del chatRoom1User[userIndex]
            #del chatRoom1[1]
            del chatRoom1[userIndex]
            #print(threads)
            #print(chatRoom1User)
            print("Chat ended")
            break
        elif msg.decode() == "History":
            sender = findName(c1)
            f = open(name + "-" + req + ".txt", "r")
            c1.send(("CHAT HISTORY\n" + f.read()).encode())
            f.close()
        else:
            sender = findName(c1)
            f = open(name + "-" + req + ".txt", "a") #append to chat instead of overwriting
            f.write("session-" + str(sID) + " from " + msg.decode() + "\n")
            f.close()
            for user in chatRoom1User:
                if user != c1:
                    user.send(msg)

def userChat2(name, req, sID, c2):
    #f = open("chatroom1.txt", "w")
     while True:
        msg = c2.recv(1024)
        print(msg.decode())
       # cmdSplit = msg.decode().split(': ')
       # cmd = cmdSplit[1]
       # print(cmd)
        if msg.decode() == "Log off":
            threads.remove(c1)               #Remove from thread array before closing connection
            c1.close()
            print(f"{clientAddress} disconnected")
            break
        elif msg.decode() == "End chat":
            for user in chatRoom2User:
                user.send("Ending session".encode())
            #del chatRoom2User[1]
            del chatRoom2User[0]
            #del chatRoom2[1]
            del chatRoom2[0]
            #print(chatRoom1User)
            print("Chat ended")
            break
        elif msg.decode() == "History":
            sender = findName(c2)
            f = open(name + "-" + req + ".txt", "r")
            c2.send(("CHAT HISTORY\n" + f.read()).encode())
            f.close()
        else:
            sender = findName(c2)
            f = open(name + "-" + req + ".txt", "a") #append to chat instead of overwriting
            f.write("session-" + str(sID) + " from " + msg.decode() + "\n")
            f.close()
            for user in chatRoom2User:
                if user != c2:
                    user.send(msg)

        
def threadTCP(c):
    #print(threads)
    #print(threads[0])
    sessionID = 0
    while True:
        #print(str(c))
        data = c.recv(1024)
        print(data.decode())
        #print(data.decode()[:4])
        #print(data.decode()[-7:])
        #Logging off
        if data.decode() == "Log off":
            sockIndex = threads.index(c)
            threads.remove(c)               #Remove from thread array before closing connection
            del connUser[sockIndex]

            #print(threads)
            c.close()
            print(f"{clientAddress} disconnected")
            break
        elif data.decode()[:7] == "History":
            name = data.decode()[-7:]
            sender = findName(c)
            f = open(name + "-" + sender + ".txt", "r")
            c.send(("CHAT HISTORY\n" + f.read()).encode())
            f.close()
        elif data.decode()[:4] == "Chat":
            print(connUser)
            checkName = data.decode()[-7:]
            if checkName in connUser:
                userIndex = connUser.index(checkName)
                print(userIndex)
                toChat = threads[userIndex]
                #print("clientA: " + str(c))
                #print("clientB: " + str(toChat))
                #print(chatRoom1)
                #print(chatRoom2)

                #Checking if the requested user is already in another session
                if chatRoom1User:
                    inSession = False
                    for user in chatRoom1User:
                        if user == toChat:
                            c.send((data.decode()[-7:] + " is already in a session").encode())
                            inSession = True
                    #if inSession == True:
                        #break
                elif chatRoom2User:
                    inSession = False
                    for user in chatRoom2User:
                        if user == toChat:
                            c.send((data.decode()[-7:] + " is already in a session").encode())
                            inSession = True
                    #if inSession == True:
                        #break

                #Will add to chat room if it is empty
                elif not chatRoom1:
                    print("Starting chatroom 1")
                    sessionID += 1

                    #Users in chat room
                    chatRoom1User.append(c)
                    chatRoom1User.append(toChat)
                    requester = findName(c)
                    print(data.decode()[-7:])
                    username = data.decode()[-7:]
                    f = (username + "-" + requester + ".txt", "x")
                    #print(chatRoom1)
                    for user in chatRoom1User:
                        #print(user)
                        chatThread1 = threading.Thread(target=userChat1, args=(data.decode(), requester, sessionID,  user, ))
                        chatThread1.start()

                        #Thread array for chatroom
                        chatRoom1.append(chatThread1)

                    c.send(f"Connected to {data.decode()[-7:]}".encode())
                    toChat.send(f"Connected to {clientAddress}".encode())
                    #for c in chatRoom1:
                    chatThread1.join()
                
                    #print("Users connected")
                    #break
                
                elif not chatRoom2:
                    print("Starting chatroom 2")
                    chatRoom2User.append(c)
                    chatRoom2User.append(toChat)
                    requester = findName(c)
                    f = (data.decode()[-7:] + "-" + requester + ".txt", "x")
                    #print(chatRoom2)
                    for user in chatRoom2User:
                        #print(user)
                        chatThread2 = threading.Thread(target=userChat2, args=(data.decode(), requester, sessionID, user, ))
                        chatThread2.start()

                        chatRoom2.append(chatThread2)

                    c.send(f"Connected to {data.decode()}".encode())
                    toChat.send(f"Connected to {clientAddress}".encode())
                    #for c in chatRoom2:
                    chatThread2.join()

                    #print("Users connected")
                    #break
            else:
                c.send((checkName + " unreachable").encode())
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind((udpAddress, udpPort))

serverTCP = socket(AF_INET, SOCK_STREAM)
serverTCP.bind((tcpAddress, tcpPort))
serverTCP.listen(4)

print ("The server is ready to receive")
while True:
    clientID, clientAddress = serverSocket.recvfrom(1024)
    checkID = clientID.decode()
    #print(checkID)
    index = 0
    idColumn = column(keyArr, 0)
    keyColumn = column(keyArr, 1)
    for i in idColumn:
        #print("Checking name: " + str(i))
        if checkID == str(i):
            #print(index)
            #print(keyColumn[index])
            checkKey = keyColumn[index]
        index += 1
           #if checkID != j:
             #message = "Key does not match"
             #serverSocket.sendto(message.encode(), clientAddress)
             #serverSocket.close()
             #break

    print("Checking key: " + checkKey)
    rand = random.randint(1,10)
    h = hashlib.new('sha256')
    h2 = hashlib.new('md5')

    hashString = str(rand)+checkKey
    hashFunc = hashString.encode()
    h.update(hashFunc)
    xres = h.hexdigest()

    h2.update(hashFunc)
    ck_a = h2.hexdigest()
    #print("ck_a: " + ck_a)

    serverSocket.sendto(str(rand).encode(), clientAddress)

    chalAns, clientAddress = serverSocket.recvfrom(1024)
    res = chalAns.decode()

    #print(res)
    #print(xres)

    if res != xres: 
        msgFail = "Client not found. Aborting !!"
        serverSocket.sendto(msgFail.encode(), clientAddress)
        break

    print("Client authenticated !!")
    randCookie = random.randint(1,10)
    authSuccess = str(randCookie) + ',' + str(tcpPort)      #auth success message
    #print(authSuccess)
    connUser.append(clientID.decode())
    #print(connUser)

    #encrypt and send auth message
    b = base64.urlsafe_b64encode(bytes(ck_a, 'utf-8'))  #64-byte urlsafe 
    #print(b)
    cipher_suite = Fernet(b)                            #Fernet encryption
    print("Encrypting now !!")
    authEnc = cipher_suite.encrypt(authSuccess.encode())
    serverSocket.sendto(authEnc, clientAddress)

    #Allow client to connect to server
    connect, clientAddress = serverTCP.accept()
    print(f"Connected by {clientAddress}")

    connect.send(f"You are now connected to {tcpAddress}".encode())

    threads.append(connect)

    thread = threading.Thread(target=threadTCP, args=(connect,))
    thread.start()

serverSocket.close()
 
