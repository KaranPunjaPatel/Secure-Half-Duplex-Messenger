#include <assert.h>
#include <errno.h>
#include <memory.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")  // Link with Winsock library

#include <gmp.h>
#include <sodium.h>

#include "kalyna.h"
#include "transformations.h"

#define PORT "3490"  // the port users will be connecting to
#define BACKLOG 1   // how many pending connections queue will hold
#define MAXDATASIZE 65

//#define MESSAGE (const unsigned char *) "test"
//#define MESSAGE_LEN 4
#define CIPHERTEXT_LEN (crypto_box_MACBYTES + MAXDATASIZE)

#define KEY_LEN crypto_secretbox_KEYBYTES

void convert_char_to_uint64(const char* char_array, uint64_t arr[]) {
    for (int i = 0; i < 8; i++) {
        uint64_t value = 0;

        // Process 8 characters at a time
        for (int j = 0; j < 8; j++) {
            // Convert the char directly into its ASCII value and add it to the 64-bit value
            value = (value << 8) | (unsigned char)char_array[i * 8 + j];
        }

        // Store the resulting 64-bit value
        arr[i] = value;

        // Print the result for verification
        //printf("key_array[%d] = 0x%016llx\n", i, arr[i]);
    }
}

void convert_uint64_to_char(const uint64_t* key_array, char* char_array) {
    for (int i = 0; i < 8; i++) {
        uint64_t value = key_array[i];

        // Extract 8 bytes from the 64-bit value and store them in the char array
        for (int j = 7; j >= 0; j--) { // Start from the least significant byte
            char_array[i * 8 + j] = (char)(value & 0xFF); // Extract the lowest 8 bits
            value >>= 8;  // Shift to the next byte
        }
    }

    char_array[64] = '\0'; // Null-terminate the array
}


void init_winsock()
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        exit(1);
    }
}

void cleanup_winsock()
{
    WSACleanup();
}

void* get_in_addr(struct sockaddr* sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main() {
    // Ensure that the libsodium library is initialized
    if (sodium_init() < 0) {
        printf("libsodium couldn't be initialized.\n");
        return -1;
    }


    int sockfd, new_fd;
    struct addrinfo hints, * servinfo, * p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    char s[INET6_ADDRSTRLEN];
    int rv;
    int yes = 1;
    char message[MAXDATASIZE];
    char recv_buf[MAXDATASIZE];
    int numbytes;


    char modulo[129] = "fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17";
    char generator[129] = "678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca4";

    unsigned char client_key[crypto_box_PUBLICKEYBYTES];
    unsigned char shared_key[129];
    //crypto_box_keypair(client_publickey, client_secretkey);

    char ciphertext[MAXDATASIZE];

    char decryptedtext[MAXDATASIZE];

    randombytes_buf(client_key, sizeof(client_key));

    unsigned char key[129];
    unsigned char other_side_key[129];

    mpz_t a;
    mpz_t g;
    mpz_t mod;
    mpz_t res;

    /*for (int i = 0; i < crypto_box_PUBLICKEYBYTES; i++) {
        printf("%02x", client_key[i]);
    }
    printf("\n");*/

    // Convert the random bytes to a hexadecimal string
    char hex_string[65];  // 32 bytes * 2 characters per byte + null terminator
    for (int i = 0; i < 32; i++) {
        sprintf(&hex_string[i * 2], "%02x", client_key[i]);
    }

    mpz_init(res);
    mpz_init_set_str(a, hex_string, 16);
    mpz_init_set_str(mod, modulo, 16);
    mpz_init_set_str(g, generator, 16);

    mpz_powm_sec(res, g, a, mod);
    /*gmp_printf("a = %Zx\n", a);
    gmp_printf("g = %Zx\n", g);
    gmp_printf("mod = %Zx\n", mod);

    gmp_printf("g^a % mod = %Zx\n", res);*/


    size_t count;

    // Export the mpz_t value to the unsigned char array (big-endian format)
    mpz_export(key, &count, 1, 1, 1, 0, res);


    //mpz_import(a, count, 1, 1, 0, 0, key);
    //gmp_printf("a = %Zx\n", a);

    

    /*for (int i = 0; i < count; i++) {
        printf("%02x", key[i]);
    }*/
    
    init_winsock();

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo("127.0.0.1", PORT, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        cleanup_winsock();
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == INVALID_SOCKET)
        {
            fprintf(stderr, "server: socket: %d\n", WSAGetLastError());
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(int)) == SOCKET_ERROR)
        {
            fprintf(stderr, "setsockopt: %d\n", WSAGetLastError());
            cleanup_winsock();
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, (int)p->ai_addrlen) == SOCKET_ERROR)
        {
            closesocket(sockfd);
            fprintf(stderr, "server: bind: %d\n", WSAGetLastError());
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL)
    {
        fprintf(stderr, "server: failed to bind\n");
        cleanup_winsock();
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == SOCKET_ERROR)
    {
        fprintf(stderr, "listen: %d\n", WSAGetLastError());
        cleanup_winsock();
        exit(1);
    }

    printf("server: waiting for connections...\n");

    sin_size = sizeof their_addr;
    new_fd = accept(sockfd, (struct sockaddr*)&their_addr, &sin_size);
    if (new_fd == INVALID_SOCKET)
    {
        fprintf(stderr, "accept: %d\n", WSAGetLastError());
        cleanup_winsock();
        exit(1);
    }

    inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr*)&their_addr), s, sizeof s);
    printf("server: got connection from %s\n", s);


    if (send(new_fd, key, count, 0) == SOCKET_ERROR)
    {
        fprintf(stderr, "send: %d\n", WSAGetLastError());
    }
    // printf("%d\n", sizeof nonce - 1);

    numbytes = recv(new_fd, other_side_key, sizeof other_side_key-1, 0);
    /*if (numbytes > 0) {
        recv_buf[numbytes] = '\0';
        printf("Client: %s", recv_buf);
    }*/
    // printf("%d\n", numbytes);

    mpz_t b;
    mpz_t c;
    mpz_init(c);
    mpz_init(b);

    mpz_import(b, numbytes, 1, 1, 0, 0, other_side_key);

   /* gmp_printf("b = %Zx\n", b);
    gmp_printf("g = %Zx\n", res);
    gmp_printf("p = %Zx\n", mod);*/

    //mpz_powm(a, res, b, mod);
    //mpz_pow_ui(a, res, b);

    mpz_powm_sec(c, res, b, mod);
    //gmp_printf("Shared = %Zx\n", c);

    count = 0;

    mpz_export(shared_key, &count, 1, 1, 1, 0, c);

    /*for (int i = 0; i < count; i++) {
        printf("%02x", shared_key[i]);
    }*/
    mpz_clear(c);

    printf("\n");

    uint64_t known_shared_key[8];

    // Loop through the array in chunks of 8 bytes (64 bits = 16 hex digits)
    for (int i = 0; i < 8; i++) {
        uint64_t value = 0;

        // Combine 8 bytes into a single 64-bit value
        for (int j = 0; j < 8; j++) {
            value = (value << 8) | shared_key[i * 8 + j];
        }

        known_shared_key[i] = value; // Store the 64-bit value in the array

        // Print the converted value
        //printf("key_array[%d] = 0x%016llx\n", i, known_shared_key[i]);
    }



    while (1)
    {



        // Receiving data from the client
        numbytes = recv(new_fd, ciphertext, sizeof ciphertext-1, 0);

        printf("Size: %zu\n", numbytes);
        if (numbytes >= MAXDATASIZE) {
            ciphertext[MAXDATASIZE-1] = '\0';
        }

        uint64_t ciphertextInArr[8];
        convert_char_to_uint64(ciphertext, ciphertextInArr);

        // printf("%d\n", numbytes);
        uint64_t decrypttextInArr[8];
        memset(decrypttextInArr, 0, sizeof(uint64_t) * 8);

        kalyna_t* ctx88_d = KalynaInit(512, 512);
        KalynaKeyExpand(known_shared_key, ctx88_d);

        KalynaDecipher(ciphertextInArr, ctx88_d, decrypttextInArr);

        convert_uint64_to_char(decrypttextInArr, decryptedtext);


        printf("Client: %s", decryptedtext);

        // Server sending data
        printf("Server: ");
        fgets(message, MAXDATASIZE-1, stdin);

        kalyna_t* ctx88_e = KalynaInit(512, 512);

        uint64_t plaintext[8];
        memset(plaintext, 0, sizeof(uint64_t) * 8);

        convert_char_to_uint64(message, plaintext);

        KalynaKeyExpand(known_shared_key, ctx88_e);

        KalynaEncipher(plaintext, ctx88_e, ciphertextInArr);

        /*for (int i = 0; i < 8; i++) {
            printf("%llx\n", ciphertextInArr[i]);
        }
        printf("\n");*/

        convert_uint64_to_char(ciphertextInArr, ciphertext);


        if (send(new_fd, ciphertext, sizeof ciphertext-1, 0) == SOCKET_ERROR)
        {
            fprintf(stderr, "send: %d\n", WSAGetLastError());
        }
    }

    mpz_clear(res);
    mpz_clear(g);
    mpz_clear(mod);
    mpz_clear(a);
    mpz_clear(b);

    closesocket(new_fd);
    closesocket(sockfd);
    cleanup_winsock();

    return 0;
}
