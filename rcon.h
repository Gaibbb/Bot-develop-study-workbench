#ifndef RCON_H
#define RCON_H

#include <string>
#include <vector>

typedef struct _rc_packet_ {
    int size;
    int id;
    int cmd;
    char data[4096];
} rc_packet;

class RCONClient {
    public:
        RCONClient(const std::string& host, int port, const std::string& password);
        ~RCONClient();

        bool connect();
        void disconnect();
        bool authenticate();
        std::string sendCommand(const std::string& command);

    private:
        std::string host;
        int port;
        std::string password;
        int socketFd;
        int requestId;

        std::vector<char> createPacket(int id, int type, const std::string& body);
        rc_packet *buildPacket(int id, int cmd, char *s1);
        bool readPacket(int& id, int& type, std::string& body);
        int rconAuth(int sock, char *passwd);
};

#endif // RCON_H
