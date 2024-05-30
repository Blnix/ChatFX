import socket
import threading
import datetime
from time import sleep
from os import _exit
#from prompt_toolkit import prompt #for console
#from prompt_toolkit.patch_stdout import patch_stdout #for console

def is_valid_time(time_str):
    parts = time_str.split(':')
    try:
        hours = int(parts[0])
        minutes = int(parts[1])
        seconds = float(parts[2])
    except Exception:
        return False

    if len(parts) != 3 and hours < 0 or minutes < 0 or seconds < 0 or hours > 23 or minutes > 59 or seconds >= 60:
        return False
    return True

class Server:
    def __init__(self):
        self.server_ip = "127.0.0.1"
        self.server_port = 8000

        #Customizable items that will be saved.
        self.users = {}
        self.ip_banlist = []
        self.ranks = ["User","Admin","Helper","OG","Gymbro","fat"] #User, Admin, Helper, OG, Gymbro, Fat
        self.power_levels = [1,4,3,2,2,0]

        #Global server variables not changable by user
        self.server = None
        self.running = True
        self.UserDictionaryLock = threading.Lock()

        #Temporary variables, that delete its content after some time.
        self.announcelist = {}
        self.kick_list = []

    
    def run_server(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.bind((self.server_ip, self.server_port))
            self.server.listen()
            self.server.settimeout(1)

            print(f"Listening on {self.server_ip}:{self.server_port}")
            threading.Thread(target=self.checking_loop).start()
            threading.Thread(target=self.console).start()

            while self.running:
                try:
                    client_socket, addr = self.server.accept()
                    if addr[0] not in self.ip_banlist:
                        client_socket.send("logging_in".encode("utf-8"))
                        tmp = threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True)
                        tmp.start()
                    else:
                        client_socket.send("banned".encode("utf-8"))
                        client_socket.close()
                except socket.timeout:
                    continue
        except OSError as e:
            if e.errno == 10048:
                print("Port is already in use. Try using a different port.")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            if self.running:
                self.shutdown()
            print("Mainloop exit")


    def handle_client(self, client_socket, addr):
        print(f"Accepted connection from {addr[0]}:{addr[1]}")
        client_socket.settimeout(1)
        try:
            while self.running and client_socket.fileno() != -1:
                try:
                    username = client_socket.recv(1024).decode("utf-8")
                except socket.timeout:
                    continue

                if username in self.access_users():
                    client_socket.send("taken".encode("utf-8"))
                    print(f"{addr[0]}:{addr[1]} failed to register {username}. (Username already registered)")
                elif len(username) > 16 or len(username) < 3:
                    client_socket.send("long".encode("utf-8"))
                    print(f"{addr[0]}:{addr[1]} failed to register {username}. (Username too long)")
                else:
                    temp_forbidden = False
                    for char in " :@;'$£%^&*(+)=-,.[]}{~?!><|":
                        if char in username:
                            temp_forbidden = True

                    if temp_forbidden:
                        client_socket.send("forbidden".encode("utf-8"))
                        print(f"{addr[0]}:{addr[1]} failed to register {username}. (Contains unallowed characters)")
                    else:
                        client_socket.send("okay".encode("utf-8"))
                        self.update_users(username, [client_socket, addr, "User"], 0)

                        print(f"{addr[0]}:{addr[1]} registered with the name of {username}")
                        self.send_all_server(message=f"- {username} joined the server! -")
                        break

            while self.running and client_socket.fileno() != -1:
                try:
                    message = client_socket.recv(1024).decode("utf-8")
                except socket.timeout:
                    continue

                if addr[0] in self.ip_banlist:
                    client_socket.send("banned".encode("utf-8"))
                    client_socket.close()
                else:
                    if not message:
                        continue
                    if message.lower() == "exit":
                        client_socket.send("exit".encode("utf-8"))
                        break
                    elif message.lower() == "!help":
                        client_socket.send("help send.".encode("utf-8"))
                    elif message.lower() == "!list":
                        for name in self.access_users().keys():
                            client_socket.send(name.encode("utf-8"))
                    elif message.lower() == "!whisper" or message.lower() == "!msg" or message.lower() == "!tell":
                        message.split()
                        
                    elif message.startswith("!"):
                        level = self.power_levels[self.ranks.index(self.access_users()[username][2])]

                        for item in self.commands(message[1:], level):
                            client_socket.send(item.encode("utf-8"))
                    else:
                        self.send_all(message, client_socket, username)
                    print(f"Message from {username} ({addr[0]}:{addr[1]}): {message}")
        except Exception as e:
            if self.running:
                print(f"Error when handling client: {e}")
        finally:
            try:
                self.send_all_server(message=f"- {username} left the server! -")
                client_socket.close()
                print("CRASH DEL")
                self.update_users(username, None, 0)
            except Exception: print("Closed failed.")

            print(f"Connection to client ({addr[0]}:{addr[1]}) closed")
            print("Client exit")

    def send_all(self, message, client_socket, username):
        rank = self.access_users()[username][2]
        operator_username = f"[{rank}] {username}: {message}"
        for user_socket, ip, _rank in self.access_users().values():
            if user_socket != client_socket:
                try:
                    user_socket.send(operator_username.encode("utf-8"))
                except Exception as e:
                    print(f"Error sending message to {user_socket}: {e}")
    def send_all_server(self, message):
        operator_username = f"[Server] {message}"
        for user_socket, ip_address, rank in self.access_users().values():
            try:
                user_socket.send(operator_username.encode("utf-8"))
            except Exception as e:
                print(f"Error sending message to {user_socket}: {e}")

    def checking_loop(self):
        temp_delete = []
        while self.running:
            #Checking for announcement

            now = datetime.datetime.now()
            now_str = now.strftime("%H:%M:%S")
            for _ in self.announcelist:
                if _ == now_str:
                    self.send_all_server(message=self.announcelist.get(_))
                    print(f"Announced: {self.announcelist.get(_)}")
                    temp_delete.append(_)

            if len(temp_delete) > 0:
                for item in temp_delete:
                    self.announcelist.pop(item, None)
            sleep(0.1)
        print("Loop exit")

    def console(self):
        while self.running:
            command = input()
            self.commands(command, 4)
            #with patch_stdout():
            #    command = prompt()
            #    self.commands(command)


    def shutdown(self):
        print("Shutting down...")
        self.send_all_server("- Shutting down -")
        self.running = False
        try:
            for user in self.access_users():
                self.access_users()[user][0].shutdown(socket.SHUT_RDWR)
                self.access_users()[user][0].close()
            for thread in threading.enumerate():
                thread.join()
            self.server.close()
        except Exception:
            raise InterruptedError
        finally:
            print("console exit...")
            sleep(1)
            _exit(0)

    def update_users(self, key, value, index):
        with self.UserDictionaryLock:
            if value:
                if key in self.users:
                    self.users[key][index] = value
                else:
                    self.users[key] = value
            else:
                del self.users[key]

    def access_users(self):
        with self.UserDictionaryLock:
            return self.users.copy()

    def commands(self, command, level):
        returnText = []
        try:
            def stop(self, command):
                self.shutdown()
                return

            def banlist(self, command):
                if len(self.ip_banlist) != 0:
                    returnText.append("These users are banned:")
                    for user in self.ip_banlist:
                        returnText.append(user)

            def ban(self, command):
                self.ip_banlist.append(command[1])
                returnText.append(f"Banned : {command[1]}")

            def unban(self, command):
                self.ip_banlist.remove(command[1])
                returnText.append(f"Unbanned : {command[1]}")

            def kick(self, command):
                if command[1] in self.access_users().keys():
                    returnText.append("1")

            def list(self, command):
                returnText.append(self.access_users().keys())

            def rank(self, command):
                list_ranks = lambda: returnText.append("There are following ranks:\n" + " ".join(self.ranks))
                if len(command) > 1:
                    if command[1].lower() == "add":
                        for rank in self.ranks:
                            if rank.lower() == command[2].lower() and command[3] in self.access_users():
                                self.update_users(command[3], rank, 2)
                                self.access_users()[command[3]][0].send(f"You got the rank {rank}!".encode("utf-8"))
                                returnText.append(f"{command[3]} got the rank {rank}")
                                print(command[3] + " got the rank " + rank)
                                break
                        else:
                            list_ranks()
                    elif command[1].lower() == "create":
                        if len(command) == 4:
                            self.ranks.append(command[2])
                            self.power_levels.append(command[3])
                            returnText.append(f"Created {command[2]} rank.")
                            print("Created " + command[2] + " rank.")
                        else:
                            returnText.append("Wrong format: rank create NAME POWERLEVEL")
                    elif command.lower() == "delete":
                        self.power_levels.remove(self.ranks.index(command[2]))
                        self.ranks.remove(command[2])
                        for user in self.access_users():
                            if user[2] == command[2]:
                                user[2] = self.ranks()
                else:
                    returnText.append("")

            def shout(self, command):
                command.remove("shout")
                self.send_all_server(message=" ".join(command))

            def announce(self, command):
                if len(command) > 1 and is_valid_time(command[1]):
                    for item in command[2:]:
                        announceText = announceText + item
                    time_and_text = f" [Announcement] {command[2:]}"
                    announcement = {command[1]: time_and_text}
                    self.announcelist.update(announcement)
                    returnText.append(f"Announcing at {command[1]} ^{time_and_text}^")
                    print(f"Announcing at {command[1]} ^{time_and_text}^")
                else:
                    returnText.append("Wrong format. Command must be:announce 10:10:00 Hello World!")

            def help(self, command):
                print("Shutdown, Restart, Ban, Unban, banlist, kick, list, rank, shout, announce and help.")

            functions = {"stop": [stop, 4], "shutdown" : [stop, 4], "banlist": [banlist, 3], "ban": [ban, 3], "unban": [unban, 3], "kick": [kick, 3],
                         "list": [list, 1], "rank": [rank, 4], "shout": [shout, 3], "announce": [announce, 1], "help": [help, 1]}

            command = command.split()
            if command[0] in functions.keys():
                if functions[command[0]][1] <= level:
                    functions[command[0]][0](self, command)

            return returnText

        except Exception as e:
            print("Error trying to execute command: " + e)


if __name__ == "__main__":
    server = Server()
    server.run_server()
    print("Shutdown done!")
