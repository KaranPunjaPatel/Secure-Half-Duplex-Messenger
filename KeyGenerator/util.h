


#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")  // Link with Winsock library

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>



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

void init_winsock() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        exit(1);
    }
}

void cleanup_winsock() {
    WSACleanup();
}