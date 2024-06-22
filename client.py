import socket
import threading
from time import sleep
from datetime import datetime
from json import loads
from pystyle import Colors, Colorate, Write
from prompt_toolkit import prompt
from prompt_toolkit.patch_stdout import patch_stdout

def run_client(server_ip, server_port):
    print("Connecting to " + server_ip + ":" + str(server_port))
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((server_ip, server_port))
    except Exception as e:
        print(f"Could not connect to the server: {e}")
        return None

    response = loads(client.recv(1024).decode("utf-8"))
    if response.get("login"):
        print(response.get("login"))
    elif response.get("ban"):
        print(response.get("ban"))
        client.close()
        return None

    while True:
        username = input("Enter your username: ")
        client.send(username.encode("utf-8"))
        message = loads(client.recv(1024).decode("utf-8"))
        for key, value in message.items():
            if key == "userno":
                print(value + "\n")
            elif key == "con":
                print(value)
                return client
            elif key == "getpass":
                print(value)
                while True:
                    password = input("Type your password: ")
                    client.send(password.encode("utf-8"))
                    message = loads(client.recv(1024).decode("utf-8"))
                    for key, value in message.items():
                        if key == "wrongpass":
                            print(value)
                        elif key == "con":
                            print(value)
                            return client
            elif key == "createpass":
                print(value)
                while True:
                    password = input()
                    client.send(password.encode("utf-8"))
                    message = loads(client.recv(1024).decode("utf-8"))
                    for key, value in message.items():
                        if key == "wrongpass" or key == "passno":
                            print(value)
                        elif key == "con":
                            print(value)
                            return client

def send(client, stop_event):
    while not stop_event.is_set():
        try:
            with patch_stdout():
                msg = prompt(f"{datetime.now().strftime('%H:%M')} |: ")
                client.send(msg.encode("utf-8"))
                if msg.lower() == "exit":
                    stop_event.set()
                    return
        except ConnectionError:
            print("Connection error. Exiting...")
            stop_event.set()

def listen(client, stop_event):
    while not stop_event.is_set():
        try:
            response = loads(client.recv(1024).decode("utf-8"))
            if not response:
                print("Server closed...")
                stop_event.set()

            for key, value in response.items():
                if key in ["closed", "ban"]:
                    print(value)
                    stop_event.set()
                elif key == "msg":
                    print(f"{datetime.now().strftime('%H:%M')} | {value}")
        except ConnectionError:
            print("Connection error. Exiting...")
            stop_event.set()

def close(client, stop_event):
    stop_event.set()
    client.shutdown(socket.SHUT_RDWR)
    client.close()

print("Welcome to ChatFX! \n")
server_ip = "127.0.0.1"
server_port = 8000
client = run_client(server_ip, server_port)

if client:
    stop_event = threading.Event()

    thread1 = threading.Thread(target=listen, args=(client, stop_event))
    thread1.daemon = True
    thread1.start()

    thread2 = threading.Thread(target=send, args=(client, stop_event))
    thread2.daemon = True
    thread2.start()

    try:
        while not stop_event.is_set():
            sleep(0.1)
    except KeyboardInterrupt:
        close(client, stop_event)
    finally:
        close(client, stop_event)
