#include "rcon.h"
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <unistd.h>

#define DATA_BUFFSIZE 4096
#define RCON_PID 0xBADC0DE

constexpr int SERVERDATA_AUTH = 3;
constexpr int SERVERDATA_AUTH_RESPONSE = 2;
constexpr int SERVERDATA_EXECCOMMAND = 2;
constexpr int SERVERDATA_RESPONSE_VALUE = 0;

RCONClient::RCONClient(const std::string& host, int port, const std::string& password)
    : host(host), port(port), password(password), socketFd(-1), requestId(1) {}

RCONClient::~RCONClient() {
    disconnect();
}

bool RCONClient::connect() {
    struct sockaddr_in serverAddr{};
    struct hostent* server;

    server = gethostbyname(host.c_str());
    if (server == nullptr) {
        std::cerr << "Error: no such host\n";
        return false;
    }

    socketFd = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFd < 0) {
        std::cerr << "Error opening socket\n";
        return false;
    }

    memset((char*)&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    memcpy((char*)&serverAddr.sin_addr.s_addr, (char*)server->h_addr, server->h_length);
    serverAddr.sin_port = htons(port);

    if (::connect(socketFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error connecting: " << strerror(errno) << "\n";
        return false;
    } else {
        printf("RCON Server connect successfully...\n");
    }

    return authenticate();
}

void RCONClient::disconnect() {
    if (socketFd >= 0) {
        close(socketFd);
        socketFd = -1;
    }
}

bool RCONClient::authenticate() {
    auto packet = createPacket(requestId, SERVERDATA_AUTH, password);
    std::cout << "Created packet with size: " << packet.size() << ", ID: " << requestId << ", type: " << SERVERDATA_AUTH << std::endl;
    std::cout << "Packet data: ";
    for (char c : packet) {
        std::cout << std::hex << static_cast<int>(c) << " ";
    }
    std::cout << std::dec << std::endl;
    std::cout << "Sending auth packet with ID: " << requestId << " and password: " << password << std::endl;

    if (send(socketFd, packet.data(), packet.size(), 0) < 0) {
        std::cerr << "Error sending auth packet\n";
        return false;
    }

    int id, type;
    std::string body;

    // Read the first response packet (auth response)
    if (!readPacket(id, type, body)) {
        std::cerr << "Failed to read the first response packet\n";
        return false;
    }
    std::cout << "First response packet received with ID: " << id << ", type: " << type << ", body: " << body << std::endl;

    if (type != SERVERDATA_AUTH_RESPONSE || id != requestId) {
        std::cerr << "Authentication failed\n";
        return false;
    }

    std::cout << "Authentication successful\n";
    return true;
}

std::string RCONClient::sendCommand(const std::string& command) {
    auto packet = createPacket(requestId++, SERVERDATA_EXECCOMMAND, command);
    if (send(socketFd, packet.data(), packet.size(), 0) < 0) {
        std::cerr << "Error sending command packet\n";
        return "";
    }

    int id, type;
    std::string body;
    if (!readPacket(id, type, body) || type != SERVERDATA_RESPONSE_VALUE) {
        std::cerr << "Error reading command response\n";
        return "";
    }

    return body;
}

std::vector<char> RCONClient::createPacket(int id, int type, const std::string& body) {
    uint32_t size = 10 + body.size();
    std::vector<char> packet(size + 4);
    std::memcpy(packet.data(), &size, 4);
    std::memcpy(packet.data() + 4, &id, 4);
    std::memcpy(packet.data() + 8, &type, 4);
    std::memcpy(packet.data() + 12, body.c_str(), body.size());
    packet[size + 2] = 0;
    packet[size + 3] = 0;
    return packet;
}

rc_packet *RCONClient::buildPacket(int id, int cmd, char *s1) {
    static rc_packet packet = {0, 0, 0, { 0x00 }};

    int len = strlen(s1);
    if (len >= DATA_BUFFSIZE) {
        fprintf(stderr, "Warning: Command string too long (%d). Maximum allowed: %d.\n", len, DATA_BUFFSIZE - 1);
        return NULL;
    }

    packet.size = sizeof(int) * 2 + len + 2;
    packet.id = id;
    packet.cmd = cmd;
    strncpy(packet.data, s1, DATA_BUFFSIZE - 1);

    return &packet;
}


int RCONClient::rconAuth(int sockfd, char *passwd) {
    int ret;

    rc_packet *packet = buildPacket(RCON_PID, SERVERDATA_AUTH, passwd);
    if (packet == NULL)
        return 0;

    int len;
    int total = 0;
    int bytesleft;
    
    bytesleft = len = packet->size + sizeof(int);

    while (total < len) {
        ret = send(sockfd, (char *) packet + total, bytesleft, 0);
        if(ret == -1) break;
        total += ret;
        bytesleft -= ret;
    }

}

bool RCONClient::readPacket(int& id, int& type, std::string& body) {
    uint32_t size;
    if (recv(socketFd, &size, 4, 0) != 4) {
        std::cerr << "Error reading size\n";
        return false;
    }
    std::cout << "Packet size: " << size << std::endl;

    if (recv(socketFd, &id, 4, 0) != 4) {
        std::cerr << "Error reading id\n";
        return false;
    }
    std::cout << "Packet ID: " << id << std::endl;

    if (recv(socketFd, &type, 4, 0) != 4) {
        std::cerr << "Error reading type\n";
        return false;
    }
    std::cout << "Packet type: " << type << std::endl;

    size -= 10;
    std::vector<char> buffer(size);
    if (recv(socketFd, buffer.data(), size, 0) != size) {
        std::cerr << "Error reading body\n";
        return false;
    }

    body.assign(buffer.data(), size);
    std::cout << "Received packet with ID: " << id << ", type: " << type << ", body: " << body << std::endl;
    return true;
}
