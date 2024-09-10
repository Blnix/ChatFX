# ChatFX
A global chat platform in the command line interface using the socket library.
The tool offers multiple features, such as accounts, ranks, logs, announcements and so on.
It even supports hashing of the users passwords.

Also ChatFX is super customizable, you can easily change a lot, like adding commands or ranks.

## Commands
There are several commands:

stop - Stops the server (surprising)
banlist - List of all banned users
ban - bans someone of the server
unban - unbans someone from the server
list - list all users
rank - set, give and remove ranks from users
shout - Shoutting
announce - Setting up a message, that the server will send on a specific time

## Configuration

There are multiple ranks, that can me completely changed. For each rank you can have a powerlevel. Each rank has a powerlevel,
from 1-4. Moderators for example should have the power of 3, beeing able to ban people. Powerlevel 4 is the maximum, you are able to give each other roles, or shutdown the server. 1 Is the default User.

Logs will be standardly saved in logs/ but this can be changed.

There can be password requirements be set up, that the password needs to be a valid password.
While login, you can set the maximum tries.



## Bug fixing

- Crashing when cmd is closed
- Fix clients still in user list
- Fix user.db bugs
