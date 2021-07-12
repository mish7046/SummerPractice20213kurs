#define _WIN32_WINNT 0x0600

#include <iostream>
#include <stdio.h>
#include <string>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

//#include <nlohmann/json.hpp>
//#pragma comment(lib, "Ws2_32.lib")

#define __ <<' '<<
#define _n <<'\n'
#define VALIDSOCK(s) ((s) != INVALID_SOCKET)

using namespace std;

const u_int VK_ADDRESSES_COUNT = 2;
string generateMethodHeader(string method, vector<pair<string, string>> params, string accessToken) // 100% works
{
    string query = "GET https://api.vk.com/method/" + method + "?";
    string header =
        "Host: api.vk.com\r\n"
        "Connection: close\r\n"
        "Accept: text/html\r\n";
    for(auto i: params)
    {
        query += i.first + "=" + i.second + "&";
    }
    query += "access_token=" + accessToken + "&v=5.103\r\n";
    return query + header;
}

int main()
{
    system("chcp 1251");
    WSADATA d; // init winsock dll
    OpenSSL_add_all_algorithms();
    SSL_library_init();
    SSL_load_error_strings();

    if(WSAStartup(MAKEWORD(2, 2), &d) )
        {
            cerr <<  "init failure: " __ WSAGetLastError() _n;
            WSACleanup();
            system("pause");
            return 1;
        }
    else
            cout << "wsa & ssl init success\n";

    string group_id = "182022767";
    string access_token = "c40ed8364b1fbd0bc1e4a753c25529c8f08258e1e8aad38627cded28a94560ec21c5b92be525af1af5a4f";
    char* vk_hostNames[VK_ADDRESSES_COUNT] = {"api.vk.com", "lp.vk.com"};
    struct addrinfo hints;
    struct addrinfo* results[VK_ADDRESSES_COUNT];
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    for(int i=0; i<VK_ADDRESSES_COUNT; i++)
    {
        if(getaddrinfo(vk_hostNames[i], "443", &hints, &results[i]) )
        {
            cerr <<  "getaddrinfo failed: " __ WSAGetLastError() _n;
            WSACleanup();
            system("pause");
            return 1;
        }
        else
            cout << WSAGetLastError() __ "address: " __ inet_ntoa(((struct sockaddr_in* )results[i]->ai_addr)->sin_addr) _n;
    }

    SOCKET vkApi_sock = socket(results[0]->ai_family, results[0]->ai_socktype, 0);
    if(!VALIDSOCK(vkApi_sock) )
    {
        cerr << "socket init failed:" __ WSAGetLastError() _n;
        WSACleanup();
        system("pause");
        return 1;
    }
    else cout<<"socket created successfully\n";

    if(connect(vkApi_sock, results[0]->ai_addr, results[0]->ai_addrlen) ) {
        cout << "connect failure: " __ WSAGetLastError() _n;
        WSACleanup();
        system("pause");
        return 1;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if(!ctx)
    {
        ERR_print_errors_fp(stderr);
        WSACleanup();
        system("pause");
        return 1;
    }
    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        cerr << "SSL_new() failed.\n";
        system("pause");
        return 1;
    }
    if(!SSL_set_tlsext_host_name(ssl, vk_hostNames[0]) || \
       !SSL_set_fd(ssl, vkApi_sock) || \
       SSL_connect(ssl)<0)
       {
        cout << "error during SSL_set_tlsext_host_name || SSL_set_fd || SSL_connect: " __ WSAGetLastError() _n;
        ERR_print_errors_fp(stdout);
        closesocket(vkApi_sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        ERR_free_strings();
        WSACleanup();
       }

    string query = generateMethodHeader("groups.getLongPollServer", {{"group_id", group_id}}, access_token);
    char* buf[4096];
    SSL_write(ssl, query.c_str(), query.length());
    cout << "sent:\n" __ query _n;
    while(1)
    {
        if(SSL_read(ssl, buf, sizeof(buf)) < 1) {
            cout << "read not successful OR conection closed\n";
            break; }
        else {
            printf("%s\n", buf);
            break; }
    }

    cout << "closing all\n";
    SSL_shutdown(ssl);
    closesocket(vkApi_sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_free_strings();
    WSACleanup();
    cout << "\n->all closed\n";
    system("pause");
    return 0;
}
// 1624465933131
