This project depends on these libraries:
CryptoPP, with PEM pack: https://github.com/weidai11/cryptopp, https://www.cryptopp.com/wiki/Pem_pack
CSPRNG: https://github.com/Duthomhas/CSPRNG
libbcrypt: https://github.com/trusch/libbcrypt
SQLite3: sudo apt-get install sqlite3 libsqlite3-dev
         https://www.sqlite.org/cintro.html
libuuid: should already be installed, if not sudo apt-get install e2fsprogs
         https://linux.die.net/man/3/libuuid

You can compile the individual CPP files with these commands:

g++ getToken.cpp csprng.cpp -I . --std=c++11 -lbcrypt -lsqlite3 -lcryptopp -o server/cgi-bin/getToken.cgi
g++ addUser.cpp csprng.cpp -I . --std=c++11 -lbcrypt -lsqlite3 -luuid -lcryptopp -o server/cgi-bin/addUser.cgi
g++ getMessage.cpp --std=c++11 -lsqlite3 -lcryptopp -o server/cgi-bin/getMessage.cgi
g++ sendMessage.cpp --std=c++11 -lsqlite3 -lcryptopp -o server/cgi-bin/sendMessage.cgi
g++ logoutUser.cpp --std=c++11 -lsqlite3 -lcryptopp -o server/cgi-bin/logoutUser.cgi
g++ getUserPub.cpp --std=c++11 -lsqlite3 -lcryptopp -o server/cgi-bin/getUserPub.cgi
g++ rsagen.cpp --std=c++11 -lcryptopp -o rsagen

Copy the html, css, and js files into the server's root folder, "server" in the paths above
The server needs to be setup to execute the cgi files in cgi-bin

Running rsagen will generate public and private keys for the server, 
the private key needs to go in the cgi-bin folder with the executables, 
and the public key should go in the server root folder with the html files

Navigate to the server's address in a browser, and you should see the login/signup page