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

------------------------------------------------------------------------------------------

There is also a command line version, test.cpp
g++ test.cpp csprng.cpp -I . --std=c++11 -Wall -Wextra -lbcrypt -lsqlite3 -luuid -lcrypto -lcryptopp -o test

Due to difficulty with handling PEM key formatting from the command line, keys are handled using hex encoding

------------------------------------------------------------------------------------------
Future Improvements/Known Issues
- A rewrite of the structure of a lot of the code would vastly improve readability & maintainability,
    I neglected to do this last step of my development workflow due to time constraints, and this not
    being a long-term project
- Use something other than bcrypt for password hashing so it can be done in the browser as well, this 
    would allow for more secure password authentication schemes
- A better system for session management than a random number token, or having to do user & pass auth
    for every database operation
- Communication back and forth between browser isn't ideal with the preset buffers
- There could be more form validation to prevent invalid/malicious inputs
- Better Apache security, I probably missed things in setting up Apache properly & securely
- Realistically, the best way to do this, would be to hook up the JS frontend to a firebase-style backend,
    and use their auth, session management, and database, while still using RSA in the browser to ensure
    messages can only be read by the user they were sent to