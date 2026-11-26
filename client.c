#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

#define PORT 43
#define BUFFER_SIZE 2048

void send_whois_request(const char *host, const char *query) {
    int sock;
    struct hostent *server;
    struct sockaddr_in server_addr;
    char request[BUFFER_SIZE];
    char response[BUFFER_SIZE];

    server = gethostbyname(host);
    if (server == NULL) {
        fprintf(stderr, "[-] Error: No such host '%s'\n", host);
        return;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("[-] Socket creation failed");
        return;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(PORT);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[-] Connection to WHOIS server failed");
        close(sock);
        return;
    }

    // RFC 3912 requires queries to end with CRLF (\r\n)
    snprintf(request, sizeof(request), "%s\r\n", query);
    send(sock, request, strlen(request), 0);

    printf("\n--- WHOIS Response from %s (Port %d) ---\n", host, PORT);
    int bytes_received;
    while ((bytes_received = recv(sock, response, BUFFER_SIZE - 1, 0)) > 0) {
        response[bytes_received] = '\0';
        printf("%s", response);
    }
    printf("--------------------------------------------\n");

    close(sock);
}

int main(int argc, char *argv[]) {
    char host[128] = "127.0.0.1";
    char input[256];

    if (argc >= 2) {
        strncpy(host, argv[1], sizeof(host) - 1);
    }

    printf("============================================\n");
    printf("  ITT440 WHOIS Client (Target: %s:%d)\n", host, PORT);
    printf("  Commands:\n");
    printf("   - <domain.com>  : Lookup domain record\n");
    printf("   - LIST          : Show all domains\n");
    printf("   - REGISTER <domain> <owner> <YYYY-MM-DD>\n");
    printf("   - exit          : Quit client\n");
    printf("============================================\n");

    while (1) {
        printf("\nwhois> ");
        if (fgets(input, sizeof(input), stdin) == NULL) break;
        input[strcspn(input, "\r\n")] = '\0';

        if (strlen(input) == 0) continue;
        if (strcasecmp(input, "exit") == 0) break;

        send_whois_request(host, input);
    }

    return 0;
}