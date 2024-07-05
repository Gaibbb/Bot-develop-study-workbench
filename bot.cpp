#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <thread>
#include <error.h>
#include <unistd.h>
#include <vector>
#include <cstring>
#include "include/json.hpp"
#include <regex>
#include "rcon.h"

using json = nlohmann::json;


std::string parse_websocket_frame(const char* buf, size_t len) {
    if (len < 2) {
        throw std::runtime_error("Invalid frame: too short");
    }

    uint8_t second_byte = buf[1];
    uint64_t payload_length = second_byte & 0x7F;

    size_t pos = 2;

    if (payload_length == 126) {
        if (len < 4) {
            throw std::runtime_error("Invalid frame: too short for extended payload length");
        }
        payload_length = (buf[2] << 8) | buf[3];
        pos = 4;
    } else if (payload_length == 127) {
        if (len < 10) {
            throw std::runtime_error("Invalid frame: too short for extended payload length");
        }
        payload_length = 0;
        for (int i = 0; i < 8; ++i) {
            payload_length = (payload_length << 8) | buf[2 + i];
        }
        pos = 10;
    }

    bool masked = second_byte & 0x80;
    uint8_t masking_key[4] = {0};
    if (masked) {
        if (len < pos + 4) {
            throw std::runtime_error("Invalid frame: too short for masking key");
        }
        std::memcpy(masking_key, &buf[pos], 4);
        pos += 4;
    }

    if (len < pos + payload_length) {
        throw std::runtime_error("Invalid frame: too short for payload");
    }

    std::vector<uint8_t> payload(buf + pos, buf + pos + payload_length);

    if (masked) {
        for (size_t i = 0; i < payload.size(); ++i) {
            payload[i] ^= masking_key[i % 4];
        }
    }

    return std::string(payload.begin(), payload.end());
}

std::vector<uint8_t> create_websocke_frame(const std::string& message) {
    std::vector<uint8_t> frame;

    frame.push_back(0x81);
    size_t message_size = message.size();
    if (message_size < 126) {
        frame.push_back(static_cast<uint8_t>(0x80 | message_size));
    } else if (message_size <= 0xFFFF) {
        frame.push_back(static_cast<uint8_t>(0x80 | 126));
        frame.push_back((message_size >> 8) & 0xFF);
        frame.push_back(message_size & 0xFF);
    } else {
        frame.push_back(static_cast<uint8_t>(0x80 | 127));
        for (int i = 7; i >= 0; --i) {
            frame.push_back((message_size >> (i * 8)) & 0xFF);
        }
    }

    uint8_t masking_key[4];
    std::srand(std::time(0));
    for (int i = 0; i < 4; ++i) {
        masking_key[i] = std::rand() % 256;
    }
    frame.insert(frame.end(), masking_key, masking_key + 4);

    for (size_t i = 0; i < message_size; ++i) {
        frame.push_back(message[i] ^ masking_key[i % 4]);
    }

    return frame;
}

struct targetServer {
    int sockfd;
    sockaddr_in* addr;
    size_t addr_len;
    std::string serverAuth;
    std::string serverKey;
};

template<typename T>
int send_data(const T& msg, const targetServer* server) {
    return send_msg(msg, server);
};

int send_msg(const std::string& msg, const targetServer* server) {
    int ref;
    int msg_len = msg.length();
    ref = send(server->sockfd, msg.c_str(), msg_len, 0);
    if (ref <= 0) {
        printf("msg: %s, send failed...\n", msg.c_str());
        return 1;
    }

    return 0;
}

int send_msg(const uint8_t* msg, size_t msg_len, const targetServer* server) {
    int ref;

    ref = send(server->sockfd, msg, msg_len, 0);
    if (ref <= 0) {
        printf("msg: %u, send failed...\n", *msg);
        return 1;
    }

    return 0;
}


std::string httpRequestCreate(int& port, std::string& host, std::string& path, std::string& key, std::string& auth) {
    std::string http_request = "GET " + path + " HTTP/1.1\r\n" + 
        "Host: " + host + ":" + std::to_string(port) + "\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        "Authorization: Bearer " + auth + "\r\n" +
        "Sec-WebSocket-Key: " + key + "\r\n" +
        "Sec-WebSocket-Version: 13\r\n\r\n";
    
    return http_request;
}

targetServer* addrInit(int& port, std::string& host) {
    targetServer* target = new targetServer;
    target->sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (target->sockfd <= 0) {
        printf("Socket init failed...\n");
    }

    target->addr = new sockaddr_in;
    target->addr->sin_family = AF_INET;
    target->addr->sin_port = htons(port);
    target->addr->sin_addr.s_addr = inet_addr(host.c_str());

    target->addr_len = sizeof(*target->addr);

    return target;
}

void serverInit(const targetServer* server) {
    int ref;
    char buf[4092];
    int buf_len = sizeof(buf);
    memset(buf, 0, buf_len);
    ref = connect(server->sockfd, (sockaddr*)server->addr, server->addr_len);
    if (ref == -1) {
        printf("connect error... code: %d\n", ref);
    } else {
        printf("connect success...\n");
    }

    int port = ntohs(server->addr->sin_port);
    std::string host;
    char ipv4addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(server->addr->sin_addr), ipv4addr, sizeof(ipv4addr));
    std::string path = "/api";
    std::string http_request = httpRequestCreate(port, host, path, server->key, server->auth);
    ref = send_msg(http_request, server);
    if (ref == 0) {
        int ref_recv = recv(server->sockfd, buf, buf_len, 0);
        if (ref_recv <= 0) {
            printf("Upgrade to ws failed...\n");
        } else {
            printf("Upgrade to ws success...\n%s\n", buf);
        }
    }
}


int main() {
    std::string host_qqbot = "120.77.28.51";
    int port_qqbot = 11452;
    std::string auth = "1145141919810Doremifa";
    std::string key = "bXvlAwIJ+JqtxFGP2zue3w==";
    
    std::string host_rcon = "159.75.167.150";
    int port_rcon = 11451;
    targetServer* server = addrInit(port_rcon, host_rcon);
    server->serverAuth = auth;
    server->serverKey = key;

    // serverInit(server);

    RCONClient client("159.75.167.150", 11451, "1145141919810");

    if (!client.connect()) {
        std::cerr << "Failed to connect to the server\n";
        return 1;
    }

    std::string response = client.sendCommand("list");
    std::cout << "Server response: " << response << std::endl;

    client.disconnect();

    // json data;
    // data["action"] = "get_login_info";
    // std::string api_call = data.dump();
    // std::vector<uint8_t> frame = create_websocke_frame(api_call);

    // int ref = send_msg(frame.data(), frame.size(), server);
    // if (ref == 1) {
    //     printf("send failed...\n");
    // } else if (ref == 0) {
    //     printf("send success...\n");

    //     char buf[4096];
    //     int buf_len = sizeof(buf);
    //     memset(buf, 0, buf_len);
    //     recv(server->sockfd, buf, buf_len, 0);

    //     std::string json_str = parse_websocket_frame(buf, buf_len);
    //     json respone = json::parse(json_str);

    //     std::cout << respone["data"]["nickname"] << std::endl;
    // }





    return 0;
}