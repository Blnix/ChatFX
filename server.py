#For logic and commands
import threading
from time import sleep, strftime, localtime
import toml

#For sending to client
from json import dumps
import socket

#For hashing user.db
import bcrypt
import sqlite3


from pystyle import Colors

def println(text, *type):
    """Useful when using a custom server."""

    timestamp = localtime()  # Get the current time
    timestamp = strftime("%H:%M:%S", timestamp)  # Format the time as HH:MM:SS

    for event in type:
        if event == "error":
            print(Colors.red + "[" + timestamp + "] " + text)
            break
        if event == "flag":
            print(Colors.yellow + "[" + timestamp + "] " + text)
            break
    else:
        print(Colors.light_gray + "[" + timestamp + "] " + text)

    """for logging purposes"""
    log.log("[" + timestamp + "] " + text + "\n")

def user_input(text, server):
    """Useful when using a custom server"""

    if server.betterInput:
        with patch_stdout():
            return prompt(text)

    return input(text)

def load_config():
    try:
        with open('config.toml', 'r') as file:
            data = toml.load(file)

        server_ip = data['server']['server_ip']
        server_port = data['server']['server_port']
        ip_banlist = data['server']['ip_banlist']
        ranks = data['server']['ranks']
        power_levels = data['server']['power_levels']
        betterInput = data['server']['betterInput']

        enable_logging = data['logging']['enable_logging']
        logging_file = data['logging']['logging_file']

        enable_accounts = data['user']['enable_accounts']
        password_requirement = data['user']['password_requirement']
        login_rules = data['user']['login_rules']
        user_db = data['user']['user_db']

        from prompt_toolkit import prompt
        from prompt_toolkit.patch_stdout import patch_stdout

        return (server_ip, server_port, ip_banlist, ranks, power_levels, betterInput, enable_logging, logging_file, enable_accounts, password_requirement, login_rules, user_db)
    except ValueError:
        print("There was a problem with your config. Please note that all bools have to be lowercase. Please reach out for help.")
        return None
    except Exception as e:
        print(e)
        return None

def is_valid_time(time_str):
    try:
        parts = time_str.split(':')
        hours = int(parts[0])
        minutes = int(parts[1])
        seconds = float(parts[2])
    except Exception:
        return False

    if len(parts) != 3 and hours < 0 or minutes < 0 or seconds < 0 or hours > 23 or minutes > 59 or seconds >= 60:
        return False
    return True

class Logging:
    def __init__(self, path, enable_logging):
        self.enable_logging = enable_logging
        path = path.split(".")

        index = 0
        while True:
            index += 1
            filename = path[0] + "-" + strftime("%d-%m-%Y") + "-" + str(index) + "." + path[1]

            try:
                with open(filename, 'r') as existsfile:
                    continue
            except FileNotFoundError:
                break

        self.path = filename

    def log(self, text):
        if self.enable_logging:
            with open(self.path, 'a') as logfile:
                logfile.write(text)

class Server:
    def __init__(self, server_ip, server_port, ip_banlist, ranks, power_levels, betterInput, enable_accounts, password_requirement, login_rules):
        self.server_ip = server_ip
        self.server_port = server_port

        self.ip_banlist = ip_banlist
        self.ranks = ranks
        self.power_levels = power_levels

        self.betterInput = betterInput
        if self.betterInput:
            from prompt_toolkit import prompt
            from prompt_toolkit.patch_stdout import patch_stdout

        self.enable_accounts = enable_accounts
        self.password_requirement = password_requirement
        self.login_rules = login_rules

        #Global server variables not changeable by user
        self.server = None
        self.running = True
        self.threads = [0, 1]
        self.users = {}
        self.UserDictionaryLock = threading.Lock()

        self.announcelist = {}
        self.kick_list = []

        self.run_server()


    def run_server(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.bind((self.server_ip, self.server_port))
            self.server.listen()
            self.server.settimeout(1)

            println(f"Listening on {self.server_ip}:{self.server_port}")
            threading.Thread(target=self.checking_loop).start()
            threading.Thread(target=self.console).start()

            while self.running:
                try:
                    client_socket, addr = self.server.accept()
                    if addr[0] not in self.ip_banlist:
                        client_socket.send(dumps({"login":f"Connected to {self.server_ip}:{self.server_port}. \n"}).encode("utf-8"))
                        tmp = threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True)
                        tmp.start()
                    else:
                        client_socket.send(dumps({"ban":"You got banned by an operator..."}).encode("utf-8"))
                        client_socket.close()
                except socket.timeout:
                    continue
        except OSError as e:
            if e.errno == 10048:
                println("Port is already in use. Try using a different port.", "error")
        except Exception as e:
            println(f"Error: {e}", "error")
        finally:
            if self.running:
                self.shutdown()


    def handle_client(self, client_socket, addr):
        self.threads[1] += 1
        println(f"Accepted connection from {addr[0]}:{addr[1]}")
        client_socket.settimeout(1)
        try:
            while self.running and client_socket.fileno() != -1:
                try:
                    username = client_socket.recv(1024).decode("utf-8")
                except socket.timeout:
                    if self.is_banned(addr[0], client_socket):
                        raise SystemExit
                    continue


                if username in self.access_users() and not self.enable_accounts:
                    client_socket.send(dumps({"userno": "The username is already in use."}).encode("utf-8"))
                    println(f"{addr[0]}:{addr[1]} failed to register {username}. (Username already registered)")
                elif username.lower() in self.access_users() and self.enable_accounts:
                    client_socket.send( dumps({"userno": f"A person with that account is already logged in..."}).encode("utf-8"))
                    println(f"{addr[0]}:{addr[1]} failed to connect {username}. (User already connected)")

                elif self.enable_accounts and usermanager.user_exists(username):
                    if self.client_login(username, client_socket, addr): break


                elif len(username) < 3:
                    client_socket.send(dumps({"userno": "The username is too short..."}).encode("utf-8"))
                    println(f"{addr[0]}:{addr[1]} failed to register {username}. (Username too short)")
                elif len(username) > 16:
                    client_socket.send(dumps({"userno": "The username is too long..."}).encode("utf-8"))
                    println(f"{addr[0]}:{addr[1]} failed to register {username}. (Username too long)")
                else:
                    temp_forbidden = False
                    for char in '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ':
                        if char in username:
                            temp_forbidden = True
                            break

                    if temp_forbidden:
                        client_socket.send(dumps({"chars": "The name uses forbidden characters"}).encode("utf-8"))
                        println(f"{addr[0]}:{addr[1]} failed to register {username}. (Contains forbidden characters)")
                    else:
                        if not self.enable_accounts:
                            client_socket.send(dumps({"con": f"Registered as {username}! \nYou can now chat with other people! \n"}).encode("utf-8"))
                            self.update_users(username, [client_socket, addr, "User"], 0)

                            println(f"{addr[0]}:{addr[1]} registered with the name of {username}")
                            self.send_all_server(message=f"- {username} joined the server! -")
                            break
                        else:
                            if self.client_registration(username, client_socket, addr):
                                break
                            else:
                                raise SystemExit

            if log.enable_logging: client_socket.send(dumps({"msg": "Note that everything you say will be logged and for the admin visible."}).encode("utf-8"))
            while self.running and client_socket.fileno() != -1:
                try:
                    message = client_socket.recv(1024).decode("utf-8")
                except socket.timeout:
                    if self.is_banned(addr[0], client_socket):
                        raise SystemExit
                    continue

                if self.is_banned(addr[0], client_socket):
                    break

                if not message:
                    continue
                if message.lower() == "exit":
                    break
                elif message.lower() == "!help":
                    client_socket.send(dumps({"msg":"help send"}).encode("utf-8"))

                elif message.lower().startswith("!tell"):
                    target = message.split()
                    tell_user = self.access_users()
                    temp_forbidden = False

                    for key in tell_user.keys():
                        if target[1].lower() == key.lower():
                            tell_user.get(key)[0].send(dumps({"msg":f"{username} whispered: {' '.join(target[2:])}"}).encode("utf-8"))
                            temp_forbidden = True
                    if not temp_forbidden:
                        client_socket.send(dumps({"msg":f"No user with the username of ^{target[1]}^"}).encode("utf-8"))

                elif message.startswith("!"):
                    level = self.power_levels[self.ranks.index(self.access_users()[username][2])]

                    for item in self.commands(message[1:], level):
                        client_socket.send(dumps({"msg":item}).encode("utf-8"))
                else:
                    self.send_all(message, client_socket, username)
                println(f"Message from {username} ({addr[0]}:{addr[1]}): {message}")
        except SystemExit:
            pass
        except Exception as e:
            if self.running:
                println(f"Error when handling client: {e}")
        finally:
            try:
                self.send_all_server(message=f"- {username} left the server! -")
                client_socket.close()
                println("CRASH DEL")
                self.update_users(username, None, 0)
            except Exception: println("Closed failed.")

            println(f"Connection to client ({addr[0]}:{addr[1]}) closed")
            self.threads[0] += 1
            if not self.running:
                println(f"User thread exit ({self.threads[0]}/{self.threads[1]})")

    def client_registration(self, username, client_socket, addr):
        client_socket.send(dumps({"createpass": f"Set username to {username}. \nYou will now have to select a password:"}).encode("utf-8"))
        while True:
            try:
                password = client_socket.recv(1024).decode("utf-8")
            except socket.timeout:
                if self.is_banned(addr[0], client_socket):
                    return False
                continue

            if self.password_requirement.get("uppercase"):
                uppercase = any(char.isupper() for char in password)
                if not uppercase:
                    client_socket.send(
                        dumps({"passno": "The password must contain at least one uppercase letter."}).encode("utf-8"))
                    println(f"{addr[0]}:{addr[1]} failed to set password. (No uppercase)")
                    continue

            if self.password_requirement.get("special_chars"):
                special_char = any(char in '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~' for char in password)
                if not special_char:
                    client_socket.send(dumps({"passno": "The password must contain at least one special character."}).encode("utf-8"))
                    println(f"{addr[0]}:{addr[1]} failed to set password. (No special character)")
                    continue

            if len(password) < self.password_requirement.get("length"):
                client_socket.send(dumps({"passno": f"The password must be at least {self.password_requirement.get('length')} characters long."}).encode("utf-8"))
                println(f"{addr[0]}:{addr[1]} failed to set password. (Too short)")
            else:
                client_socket.send(dumps({"con": f"Registered as {username}! \nYou can now chat with other people! \n"}).encode("utf-8"))
                usermanager.add_user(username, password, "User")
                self.update_users(username, [client_socket, addr, "User"], 0)

                println(f"{addr[0]}:{addr[1]} registered with the name of {username}")
                self.send_all_server(message=f"- {username} joined the server! -")
                return True
    def client_login(self, username, client_socket, addr):
        client_socket.send(dumps({"getpass": f"Please type in your password: "}).encode("utf-8"))

        banned = False
        tries = 0
        ban_tries = int(self.login_rules.get("ban_tries"))
        tries_until_warn = int(self.login_rules.get("tries_until_warn"))
        while True:
            try:
                password = client_socket.recv(1024).decode("utf-8")
            except socket.timeout:
                continue

            if not banned:
                tries += 1
                if usermanager.verify_password(username, password):
                    client_socket.send(
                        dumps({"con": f"Logged in as {username}! \nYou can now chat with other people! \n"}).encode(
                            "utf-8"))
                    self.update_users(username, [client_socket, addr, usermanager.get_rank_name(username)], 0)

                    println(f"{addr[0]}:{addr[1]} logged in as {username}")
                    self.send_all_server(message=f"- {username} joined the server! -")
                    return True

                else:
                    match tries:
                        case self.login_rules.get("tries_until_warn"):

                            client_socket.send(dumps({"wrongpass": f"The password is incorrect. You have {ban_tries - tries}"}).encode("utf-8"))
                            println(f"{addr[0]}:{addr[1]} failed to login as {username} at the {tries} try. (Password incorrect)")
                        case self.login_rules.get("ban_tries"):
                            client_socket.send(dumps({"wrongpass": "The password is incorrect... You are temporally banned!"}).encode("utf-8"))
                            println(f"{addr[0]}:{addr[1]} failed to login as {username} at the {tries} try. (Password incorrect)")
                        case _:
                            client_socket.send(dumps({"wrongpass": "The password is incorrect..."}).encode("utf-8"))
                            println(f"{addr[0]}:{addr[1]} failed to login as {username} at the {tries} try. (Password incorrect)")
            else:
                client_socket.send(dumps({"ban": "You are temporally banned!"}).encode("utf-8"))
                println(f"{addr[0]}:{addr[1]} failed to login as {username} at the {tries} try. (Password incorrect)")



    def send_all(self, message, client_socket, username):
        rank = self.access_users()[username][2]
        operator_username = f"[{rank}] {username}: {message}"
        for user_socket, ip, _rank in self.access_users().values():
            if user_socket != client_socket:
                try:
                    user_socket.send(dumps({"msg":operator_username}).encode("utf-8"))
                except Exception as e:
                    println(f"Error sending message to {user_socket}: {e}")
    def send_all_server(self, message):
        operator_username = f"[Server] {message}"
        for user_socket, ip_address, rank in self.access_users().values():
            try:
                user_socket.send(dumps({"msg":operator_username}).encode("utf-8"))
            except Exception as e:
                println(f"Error sending message to {user_socket}: {e}")

    def is_banned(self, ip, client_socket):
        if ip in self.ip_banlist:
            client_socket.send(dumps({"ban": "You got banned by an operator..."}).encode("utf-8"))
            return True
        return False

    def checking_loop(self):
        self.threads[1] += 1
        temp_delete = []
        while self.running:
            #Checking for announcement

            now = localtime()  # Get the current time
            now_str = strftime("%H:%M:%S", now)  # Format the time as HH:MM:SS
            for _ in self.announcelist:
                if _ == now_str:
                    self.send_all_server(message=self.announcelist.get(_))
                    println(f"Announced: {self.announcelist.get(_)}")
                    temp_delete.append(_)

            if len(temp_delete) > 0:
                for item in temp_delete:
                    self.announcelist.pop(item, None)
            #Tempban

            sleep(0.1)
        self.threads[0] += 1
        println(f"Checking thread exit ({self.threads[0]}/{self.threads[1]})")

    def console(self):
        self.threads[1] += 1
        while self.running:
            command = user_input("", self)
            print(self.commands(command, 4))

        self.threads[0] += 1
        println(f"Console thread exit ({self.threads[0]}/{self.threads[1]})")

    def shutdown(self):
        println("Shutting down...")
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
            return

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
                returnText.append(f"Added to banlist : {command[1]}")

            def unban(self, command):
                self.ip_banlist.remove(command[1])
                returnText.append(f"Unbanned : {command[1]}")

            def kick(self, command):
                if command[1] in self.access_users().keys():
                    returnText.append("1")

            def list(self, command):
                for item in self.access_users().keys():
                    returnText.append(item)
                if len(returnText) == 0:
                    returnText.append("There are no users online...")

            def rank(self, command):
                list_ranks = lambda: returnText.append("There are following ranks:\n" + " ".join(self.ranks))
                if len(command) > 1:
                    if command[1].lower() == "add":
                            for rank in self.ranks:
                                if rank.lower() == command[2].lower() and command[3] in self.access_users():
                                    if self.enable_accounts: usermanager.set_rank_name(command[3], rank)
                                    self.update_users(command[3], rank, 2)
                                    self.access_users()[command[3]][0].send(dumps({"msg":f"You got the rank {rank}!"}).encode("utf-8"))
                                    returnText.append(f"{command[3]} got the rank {rank}")
                                    println(command[3] + " got the rank " + rank)
                                    break
                            else:
                                list_ranks()
                    elif command[1].lower() == "create":
                        if len(command) == 4:
                            self.ranks.append(command[2])
                            self.power_levels.append(command[3])
                            returnText.append(f"Created {command[2]} rank.")
                            println("Created " + command[2] + " rank.")
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
                    announceText = ""
                    for item in command[2:]:
                        announceText = announceText + " " + item
                    self.announcelist.update({command[1]: f"[Announcement]{announceText}"})
                    returnText.append(f"Announcing at {command[1]} ^[Announcement]{announceText}^")
                    println(f"Announcing at {command[1]} ^[Announcement]{announceText}^")
                else:
                    returnText.append("Wrong format. Command must be:announce 10:10:00 Hello World!")

            def help(self, command):
                println("Shutdown, Restart, Ban, Unban, banlist, kick, list, rank, shout, announce and help.")

            functions = {"stop": [stop, 4], "shutdown" : [stop, 4], "banlist": [banlist, 3], "ban": [ban, 3], "unban": [unban, 3], "kick": [kick, 3],
                         "list": [list, 1], "rank": [rank, 4], "shout": [shout, 3], "announce": [announce, 1], "help": [help, 1]}

            command = command.split()
            if command[0] in functions.keys() and functions[command[0]][1] <= level:
                    functions[command[0]][0](self, command)
            else:
                returnText.append("Either you dont have permission run this command, or it doesnt exist.")

        except Exception as e:
            returnText.append(f"Exception while executing: {e}")
        finally:
            return returnText


class UserManager:
    def __init__(self, db_name):
        self.db_name = db_name
        self._create_users_table()

    def _create_users_table(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            rank_name TEXT DEFAULT 'user'
        )
        ''')
        conn.commit()
        conn.close()

    def hash_password(self, password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def verify_password(self, username, entered_password):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute('''
        SELECT password_hash FROM users WHERE username = ?
        ''', (username,))

        result = cursor.fetchone()
        conn.close()

        if result:
            stored_password_hash = result[0]
            return bcrypt.checkpw(entered_password.encode('utf-8'), stored_password_hash.encode('utf-8'))

        return False

    def user_exists(self, username):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute('''
        SELECT username FROM users WHERE LOWER(username) = LOWER(?)
        ''', (username,))

        result = cursor.fetchone()

        conn.close()

        return result is not None
    def add_user(self, username, password, rank_name='user'):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        password_hash = self.hash_password(password)

        try:
            cursor.execute('''
            INSERT INTO users (username, password_hash, rank_name) VALUES (?, ?, ?)
            ''', (username, password_hash, rank_name))

            conn.commit()
            println(f"User {username} added successfully.")
        except sqlite3.IntegrityError:
            println(f"User {username} already exists.")
        finally:
            conn.close()

    def remove_user(self, username):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        try:
            cursor.execute('''
            DELETE FROM users WHERE username = ?
            ''', (username,))

            if cursor.rowcount == 0:
                println(f"User {username} does not exist.")
            else:
                conn.commit()
                println(f"User {username} removed successfully.")
        finally:
            conn.close()

    def set_rank_name(self, username, rank_name):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        try:
            cursor.execute('''
            UPDATE users SET rank_name = ? WHERE username = ?
            ''', (rank_name, username))

            if cursor.rowcount == 0:
                println(f"User {username} not found.")
            else:
                conn.commit()
                println(f"Rank name updated for user {username}.")
        finally:
            conn.close()

    def get_rank_name(self, username):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute('''
        SELECT rank_name FROM users WHERE username = ?
        ''', (username,))

        result = cursor.fetchone()
        conn.close()

        if result:
            return result[0]
        else:
            return None


if __name__ == "__main__":
    config = load_config()
    if config != None:
        server_ip, server_port, ip_banlist, ranks, power_levels, betterInput, enable_logging, logging_file, enable_accounts, password_requirement, login_rules, user_db = config
        log = Logging(logging_file, enable_logging)
        usermanager = UserManager(user_db)

        server = Server(server_ip=server_ip, server_port=server_port, ranks=ranks, power_levels=power_levels, betterInput=betterInput, enable_accounts=enable_accounts, password_requirement=password_requirement, login_rules=login_rules, ip_banlist=ip_banlist)
        server.threads[0] += 1
        println(f"Main thread exit ({server.threads[0]}/{server.threads[1]})")
    else:
        println("The config is false. Please check for the correct toml file.", "error")
