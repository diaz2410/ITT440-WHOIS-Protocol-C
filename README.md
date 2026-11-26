# ITT440 Network Programming - WHOIS-Protocol (TCP Port 43) - in C language

A custom client-server implementation of the **WHOIS Protocol (RFC 3912)** written in **C** using POSIX sockets. 
Built for the **ITT440 (Network Programming)** Individual Assignment at Universiti Teknologi MARA (UiTM).

## Student Information
* **Name:** Muhammad Zaid Izzat Rahimuddin
* **Student ID:** 2024811362
* **Course:** ITT440 — Network Programming
* **Protocol Selected:** WHOIS (TCP Port 43 / RFC 3912)

---

## Project Overview & Architecture
This project demonstrates cross-platform client-server communication over **TCP Port 43**:
* **Server (`server.c`):** Runs inside an **Ubuntu Linux VM** (via Lima on Apple Silicon). Listens on well-known TCP Port 43, parses incoming CRLF-terminated (`\r\n`) queries, and returns formatted WHOIS domain registration records.
* **Client (`client.c`):** Runs natively on **macOS** (MacBook Pro M3). Connects locally to the server over TCP Port 43, sends RFC 3912-compliant queries, and displays the server's response.

### Features Implemented
1. **Standard RFC 3912 WHOIS Lookup:** Queries domain records (e.g., `uitm.edu.my`, `google.com`, `jaring.my`, `github.com`) and reports availability for unregistered domains.
2. **Extended Feature 1 : `LIST`:** Displays all currently registered domains stored in the server's database. (Note: Newly registered domains added via **`REGISTER`** are stored temporarily in RAM; restarting the server resets the database back to the original default records.)
3. **Extended Feature 2 : `REGISTER`:** Dynamically registers a new domain name, owner, and expiry date into the server's memory (`REGISTER <domain> <owner> <YYYY-MM-DD>`).
4. **Extended Feature 3 : DELETE <domain>** Allows clients to dynamically remove an existing domain record from the server's active in-memory database while the server is running **`(DELETE <domain>)`**. If the domain exists, the server removes it, shifts the remaining records, and returns a confirmation message; otherwise, it returns an error indicating the domain was not found.
5. **Live Internet & Native Tool Compatibility:** Capable of querying public WHOIS servers (e.g., `whois.iana.org`) and accepting connections from macOS's built-in `whois` CLI utility.

---

## Prerequisites
* **GCC Compiler** (`build-essential` on Ubuntu / CotEditor Command Line Tools on macOS)
* **Root / `sudo` privileges** on the server machine (required to bind to well-known TCP Port 43)

---

## How to Compile & Run

### 1. Start the WHOIS Server (Ubuntu VM)
```bash
gcc server.c -o server
sudo ./server
```

### 2. Start the WHOIS Client (macOS / Client Terminal)

Open a new terminal window on your MacBook, compile the client, and connect to the server's IP address (`127.0.0.1` via Lima port-forwarding):

```bash
gcc client.c -o client
./client 127.0.0.1
```

