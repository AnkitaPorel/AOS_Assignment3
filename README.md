Things done- 
client.cpp
Compile- g++ client.cpp -o client
Run- ./client <user_port> <user_ip> <tracker_port=5012>

tracker.cpp
Compilation-
g++ tracker.cpp -o tracker -lssl -lcrypto
Run- ./tracker tracker_info.txt <tracker_number>

# 1.Assumption- One user-id per peer: peerUserIds map stores the the user-id w.r.t a socket file descriptor, 
# i.e- since every connected peer has only one socket file descriptor, only one user-id can be created per peer.

