<h1 align="center">Secure Half Duplex Messenger</h1>

The Kalyna block cipher was selected during Ukrainian National Public Cryptographic Competition (2007-2010) and its slight modification was approved as the new encryption standard of Ukraine in 2015. Main requirements for Kalyna were both high security level and high performance of software implementation on general-purpose 64-bit CPUs. The cipher has SPN-based (Rijndael-like) structure with increased MDS matrix size, a new set of four different S-boxes, pre- and postwhitening using modulo 2^{64} addition and a new construction of the key schedule. Kalyna supports block size and key length of 512 bits (key length can be either equal).
<br>

<div>
   Solution for a AES 512 bit computation was taken from  <a href="https://github.com/maxkrivich/kalyna-fork" target="_blank">kalyna-fork</a>.
</div>
<br>

## About The Project

<p>This is a C++ based project which I have created for learning purposes of sockets API and cybersecurity basics.
<br>
<br>The dependencies used are libsodium and gmp. 
<br>
<br>Each side needs to give confirmation for each message meaning client and server send message turn by turn.
<br>
</p>

## Built with

- C99
- sockets
- libsodium
- gmp

## How to built

- Need the following libraries gmp and libsodium. Works for windows but could be changed for linux by making some name changes

For Server

```
gcc -Wall -Wextra -std=c99 server.c -o server.exe -lws2_32 -lsodium -lgmp
```

For Client

```
gcc -Wall -Wextra -std=c99 client.c -o client.exe -lws2_32 -lsodium -lgmp
```
