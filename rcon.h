#ifndef RCON_H
#define RCON_H

#include <string>
#include <vector>

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
        bool readPacket(int& id, int& type, std::string& body);
};

#endif // RCON_H
