#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define PORT 43
#define BUFFER_SIZE 2048
#define MAX_RECORDS 50

typedef struct {
    char domain[128];
    char registrar[128];
    char registrant[128];
    char status[64];
    char expiry[32];
} WhoisRecord;

WhoisRecord db[MAX_RECORDS] = {
    {"uitm.edu.my", "MYNIC Berhad", "Universiti Teknologi MARA (UiTM)", "ACTIVE (clientTransferProhibited)", "2028-12-31"},
    {"google.com", "MarkMonitor Inc.", "Google LLC", "ACTIVE (clientDeleteProhibited)", "2028-09-14"},
    {"jaring.my", "MYNIC Berhad", "JARING Communications Sdn Bhd", "ACTIVE", "2027-06-15"},
    {"github.com", "MarkMonitor Inc.", "GitHub, Inc.", "ACTIVE (clientUpdateProhibited)", "2027-10-09"}
};
int record_count = 4;

void trim_crlf(char *str) {
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == '\r' || str[len - 1] == '\n' || str[len - 1] == ' ')) {
        str[len - 1] = '\0';
        len--;
    }
}

void handle_query(const char *raw_query, char *response) {
    char query[BUFFER_SIZE];
    strncpy(query, raw_query, BUFFER_SIZE - 1);
    query[BUFFER_SIZE - 1] = '\0';
    trim_crlf(query);

    time_t now = time(NULL);
    char *timestamp = ctime(&now);
    trim_crlf(timestamp);

    // Extended Feature 1: LIST all registered domains in the database
    if (strcasecmp(query, "LIST") == 0) {
        snprintf(response, BUFFER_SIZE,
                 "%% ITT440 WHOIS Server - Registered Domains (%d)\r\n"
                 "%% Query Time: %s\r\n"
                 "--------------------------------------------------\r\n",
                 record_count, timestamp);
        for (int i = 0; i < record_count; i++) {
            char line[512];
            snprintf(line, sizeof(line), " - %-20s | Owner: %s\r\n", db[i].domain, db[i].registrant);
            strncat(response, line, BUFFER_SIZE - strlen(response) - 1);
        }
        return;
    }

    // Extended Feature 2: REGISTER <domain> <owner> <expiry>
    if (strncasecmp(query, "REGISTER ", 9) == 0) {
        char new_domain[128], new_owner[128], new_expiry[32];
        if (sscanf(query + 9, "%127s %127s %31s", new_domain, new_owner, new_expiry) == 3) {
            if (record_count >= MAX_RECORDS) {
                snprintf(response, BUFFER_SIZE, "ERROR: Database full.\r\n");
                return;
            }
            for (int i = 0; i < record_count; i++) {
                if (strcasecmp(db[i].domain, new_domain) == 0) {
                    snprintf(response, BUFFER_SIZE, "ERROR: Domain '%s' is already registered.\r\n", new_domain);
                    return;
                }
            }
            strcpy(db[record_count].domain, new_domain);
            strcpy(db[record_count].registrar, "ITT440 Custom Registrar");
            strcpy(db[record_count].registrant, new_owner);
            strcpy(db[record_count].status, "ACTIVE (Newly Registered)");
            strcpy(db[record_count].expiry, new_expiry);
            record_count++;

            snprintf(response, BUFFER_SIZE,
                     "SUCCESS: Registered '%s' to %s (Expires: %s)\r\n",
                     new_domain, new_owner, new_expiry);
        } else {
            snprintf(response, BUFFER_SIZE,
                     "INVALID FORMAT. Usage: REGISTER <domain> <owner_no_spaces> <YYYY-MM-DD>\r\n");
        }
        return;
    }
    
    // Extended Feature 3: DELETE <domain>
 	if (strncasecmp(query, "DELETE ", 7) == 0) {
     	char target[128];
     	if (sscanf(query + 7, "%127s", target) == 1) {
         	for (int i = 0; i < record_count; i++) {
             	if (strcasecmp(db[i].domain, target) == 0) {
                 	for (int j = i; j < record_count - 1; j++) {
                     	db[j] = db[j + 1];
                 	}
                 	record_count--;
                 	snprintf(response, BUFFER_SIZE,
                          "SUCCESS: Deleted '%s' from WHOIS database.\r\n", target);
                 	return;
             	}
         	}
         	snprintf(response, BUFFER_SIZE,
                  	"ERROR: Domain '%s' not found.\r\n", target);
     	} else {
         	snprintf(response, BUFFER_SIZE,
                  	"INVALID FORMAT. Usage: DELETE <domain>\r\n");
     	}
     	return;
 	}
    

    // Standard RFC 3912 Domain Lookup
    for (int i = 0; i < record_count; i++) {
        if (strcasecmp(db[i].domain, query) == 0) {
            snprintf(response, BUFFER_SIZE,
                     "%% ITT440 WHOIS Server v1.0 (RFC 3912)\r\n"
                     "%% Timestamp: %s\r\n\r\n"
                     "Domain Name:     %s\r\n"
                     "Registrar:       %s\r\n"
                     "Registrant Org:  %s\r\n"
                     "Domain Status:   %s\r\n"
                     "Expiry Date:     %s\r\n"
                     ">>> Last update of WHOIS database: %s <<<\r\n",
                     timestamp, db[i].domain, db[i].registrar,
                     db[i].registrant, db[i].status, db[i].expiry, timestamp);
            return;
        }
    }

    // Domain Not Found
    snprintf(response, BUFFER_SIZE,
             "%% ITT440 WHOIS Server v1.0 (RFC 3912)\r\n"
             "No match for domain \"%.255s\".\r\n"
             "Status: AVAILABLE FOR REGISTRATION\r\n",
             query);
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE];

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed (Did you run with sudo?)");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("[+] WHOIS Server listening on TCP Port %d...\n", PORT);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            perror("Accept failed");
            continue;
        }

        memset(buffer, 0, BUFFER_SIZE);
        int bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_read > 0) {
            printf("[*] Connection from %s:%d | Query: %s",
                   inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buffer);
            memset(response, 0, BUFFER_SIZE);
            handle_query(buffer, response);
            send(client_fd, response, strlen(response), 0);
        }

        close(client_fd);
    }

    close(server_fd);
    return 0;
}