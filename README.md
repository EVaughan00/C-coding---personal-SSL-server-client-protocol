# C-coding---personal-SSL-server-client-protocol

The server will need to create a certificate for successful connection. to do so use 

openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout mycert.pem -out mycert.pem

start with running a make command to compile the code 
To start the server sudo ./server <port number>
To start Client sudo ./client <host> <port number>
  
  The SSL connection code between server and client was retrieved from 
  https://aticleworld.com/ssl-server-client-using-openssl-in-c/
  modifications were made to list files in directories and download said files
