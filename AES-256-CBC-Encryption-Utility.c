#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define EV EVP_CIPHER_CTX
#define EVN EVP_CIPHER_CTX_new
#define EVI EVP_EncryptInit_ex
#define EVU EVP_EncryptUpdate
#define EVF EVP_EncryptFinal_ex
#define EVDI EVP_DecryptInit_ex
#define EVDD EVP_DecryptUpdate
#define EVDF EVP_DecryptFinal_ex
#define EVFF EVP_CIPHER_CTX_free
#define EVPA EVP_aes_256_cbc()

// Color palette (dark theme)
#define CLR_TITLE    "\x1b[38;5;141m"  // Soft Purple
#define CLR_HEADER   "\x1b[38;5;37m"   // Muted Cyan
#define CLR_INFO     "\x1b[38;5;109m"  // Light Greenish
#define CLR_WARN     "\x1b[38;5;220m"  // Warm Yellow
#define CLR_ERROR    "\x1b[38;5;203m"  // Soft Red
#define CLR_RESET    "\x1b[0m"
#define CLR_BOLD     "\x1b[1m"

void err_exit(void) {
    ERR_print_errors_fp(stderr);
    exit(1);
}

int encrypt(unsigned char *in, int in_len, unsigned char *out, unsigned char *key, unsigned char *iv) {
    EV *ctx = EVN();
    int len, out_len;
    if (!ctx) err_exit();
    if (1 != EVI(ctx, EVPA, NULL, key, iv)) err_exit();
    if (1 != EVU(ctx, out, &len, in, in_len)) err_exit();
    out_len = len;
    if (1 != EVF(ctx, out + len, &len)) err_exit();
    out_len += len;
    EVFF(ctx);
    return out_len;
}

int decrypt(unsigned char *in, int in_len, unsigned char *out, unsigned char *key, unsigned char *iv) {
    EV *ctx = EVN();
    int len, out_len;
    if (!ctx) err_exit();
    if (1 != EVDI(ctx, EVPA, NULL, key, iv)) err_exit();
    if (1 != EVDD(ctx, out, &len, in, in_len)) err_exit();
    out_len = len;
    if (1 != EVDF(ctx, out + len, &len)) err_exit();
    out_len += len;
    EVFF(ctx);
    return out_len;
}

int parse_hex(const char *hex, unsigned char *buf, int buf_len) {
    int count = 0;
    unsigned int b;
    const char *p = hex;
    while (*p && count < buf_len) {
        while (*p == ' ') p++;
        if (!isxdigit(p[0]) || !isxdigit(p[1])) break;
        if (sscanf(p, "%2x", &b) != 1) return 0;
        buf[count++] = (unsigned char)b;
        p += 2;
    }
    return count == buf_len;
}

void print_hex(const unsigned char *data, int len) {
    for (int i = 0; i < len; i++)
        printf("%02x", data[i]);
}

void print_banner(void) {
    printf(CLR_TITLE CLR_BOLD);
    printf("===============================================\n");
    printf("           AES-256-CBC Encryption Utility      \n");
    printf("===============================================\n\n");
    printf(CLR_RESET);
}

void print_section(const char *title) {
    printf(CLR_HEADER CLR_BOLD);
    printf("---- %s -----------------------------------\n\n", title);
    printf(CLR_RESET);
}

int main() {
    unsigned char default_key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };

    unsigned char key[32], iv[16], input[256], output[256], decrypted[256];
    char key_hex[128] = {0}, iv_hex[64] = {0}, encrypted_hex[512] = {0};
    int output_len, decrypted_len;
    char choice;

#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif

    print_banner();

    printf(CLR_INFO "Choose mode:\n" CLR_RESET);
    printf("  1) Encrypt\n");
    printf("  2) Decrypt\n");
    printf("\nEnter choice (1 or 2): ");

    if (scanf(" %c", &choice) != 1 || (choice != '1' && choice != '2')) {
        fprintf(stderr, CLR_ERROR "Invalid choice. Exiting.\n" CLR_RESET);
        return 1;
    }
    getchar(); // consume newline

    if (choice == '1') {
        print_section("Encryption Mode");

        printf(CLR_INFO "Input text to encrypt (max 255 chars):\n" CLR_RESET);
        if (!fgets((char*)input, sizeof(input), stdin)) {
            fprintf(stderr, CLR_ERROR "Input error.\n" CLR_RESET);
            return 1;
        }
        input[strcspn((char*)input, "\n")] = 0;

        printf("\n%sEnter 64-char hex key (32 bytes), or press Enter to use default:%s\n", CLR_INFO, CLR_RESET);
        printf("Example key:\n603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4\n");
        if (!fgets(key_hex, sizeof(key_hex), stdin)) {
            fprintf(stderr, CLR_ERROR "Input error.\n" CLR_RESET);
            return 1;
        }
        key_hex[strcspn(key_hex, "\n")] = 0;

        if (strlen(key_hex) == 0) {
            memcpy(key, default_key, 32);
            printf(CLR_INFO "Using default key.\n\n" CLR_RESET);
        } else {
            for (int i = 0; key_hex[i]; i++) key_hex[i] = tolower(key_hex[i]);
            if (!parse_hex(key_hex, key, 32)) {
                fprintf(stderr, CLR_ERROR "Invalid key format.\n" CLR_RESET);
                return 1;
            }
        }

        if (1 != RAND_bytes(iv, sizeof(iv))) {
            fprintf(stderr, CLR_ERROR "IV generation failed.\n" CLR_RESET);
            return 1;
        }

        output_len = encrypt(input, (int)strlen((char*)input), output, key, iv);

        printf(CLR_INFO "Encrypted data (hex):\n" CLR_RESET);
        print_hex(output, output_len);
        printf("\n\n");

        printf(CLR_INFO "IV (hex):\n" CLR_RESET);
        print_hex(iv, 16);
        printf("\n\n");

        printf(CLR_INFO "Key used (hex):\n" CLR_RESET);
        print_hex(key, 32);
        printf("\n\n");

        printf(CLR_WARN CLR_BOLD "Important: Save the encrypted data, IV, and key securely to decrypt later!\n\n" CLR_RESET);

    } else {
        print_section("Decryption Mode");

        printf(CLR_INFO "Enter 64-char hex key used for encryption, or press Enter to use default:\n" CLR_RESET);
        if (!fgets(key_hex, sizeof(key_hex), stdin)) {
            fprintf(stderr, CLR_ERROR "Input error.\n" CLR_RESET);
            return 1;
        }
        key_hex[strcspn(key_hex, "\n")] = 0;

        if (strlen(key_hex) == 0) {
            memcpy(key, default_key, 32);
            printf(CLR_INFO "Using default key.\n\n" CLR_RESET);
        } else {
            for (int i = 0; key_hex[i]; i++) key_hex[i] = tolower(key_hex[i]);
            if (!parse_hex(key_hex, key, 32)) {
                fprintf(stderr, CLR_ERROR "Invalid key format.\n" CLR_RESET);
                return 1;
            }
        }

        printf(CLR_INFO "Enter the IV (32 hex chars):\n" CLR_RESET);
        if (!fgets(iv_hex, sizeof(iv_hex), stdin)) {
            fprintf(stderr, CLR_ERROR "Input error.\n" CLR_RESET);
            return 1;
        }
        iv_hex[strcspn(iv_hex, "\n")] = 0;
        for (int i = 0; iv_hex[i]; i++) iv_hex[i] = tolower(iv_hex[i]);
        if (!parse_hex(iv_hex, iv, 16)) {
            fprintf(stderr, CLR_ERROR "Invalid IV format.\n" CLR_RESET);
            return 1;
        }

        printf(CLR_INFO "Enter the encrypted data (hex):\n" CLR_RESET);
        if (!fgets(encrypted_hex, sizeof(encrypted_hex), stdin)) {
            fprintf(stderr, CLR_ERROR "Input error.\n" CLR_RESET);
            return 1;
        }
        encrypted_hex[strcspn(encrypted_hex, "\n")] = 0;

        unsigned char encrypted_bin[256];
        int enc_len = 0;
        char *p = encrypted_hex;
        unsigned int b;
        while (*p && enc_len < (int)sizeof(encrypted_bin)) {
            while (*p == ' ') p++;
            if (!isxdigit(p[0]) || !isxdigit(p[1])) break;
            if (sscanf(p, "%2x", &b) != 1) {
                fprintf(stderr, CLR_ERROR "Invalid encrypted data hex format.\n" CLR_RESET);
                return 1;
            }
            encrypted_bin[enc_len++] = (unsigned char)b;
            p += 2;
        }

        decrypted_len = decrypt(encrypted_bin, enc_len, decrypted, key, iv);
        decrypted[decrypted_len] = 0;

        printf(CLR_INFO "\nDecrypted text:\n" CLR_RESET);
        printf("%s\n\n", decrypted);
    }

    return 0;
}
