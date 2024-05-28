import socket
import threading
from time import sleep
from datetime import datetime
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

    response = client.recv(1024).decode("utf-8")
    if response == "logging_in":
        print(f"Connected to {server_ip}:{server_port}")
    elif response == "banned":
        print("You are banned by the host...")
        client.close()
        return None

    while True:
        username = input("Enter your username: ")
        client.send(username.encode("utf-8"))
        response = client.recv(1024).decode("utf-8")

        if response == "taken":
            print("The username is already taken...")
        elif response == "long":
            print("The username max letters are 16...")
        elif response == "forbidden":
            print("The username contains unallowed characters...")
        else:
            print(f"Registered as {username}!")
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
            response = client.recv(1024).decode("utf-8")

            if not response:
                print("Server closed...")
                stop_event.set()
                return

            if response.lower() == "closed":
                print("Connection to server closed")
                stop_event.set()
                return
            elif response.lower() == "banned":
                print("Got banned by server...")
                stop_event.set()
                return
            elif response.lower() == "received":
                pass
            else:
                time = datetime.now()
                response = f"{time.strftime('%H:%M')} | {response}"
                print(response)
        except ConnectionError:
            print("Connection error. Exiting...")
            stop_event.set()

def close(client, stop_event):
    stop_event.set()
    client.shutdown(socket.SHUT_RDWR)
    client.close()

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
        pass
    finally:
        close(client, stop_event)
