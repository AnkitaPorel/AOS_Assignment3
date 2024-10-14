#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>

using namespace std;

void logConnection(int port,const char* ip)
{
    const char* file="../tracker_info.txt";
    int fd=open(file,O_CREAT | O_WRONLY | O_APPEND,0666);
    if(fd<0)
    {
        printf("\ntracker_info.txt open error");
        return;
    }
    char buffer[1024];
    int length=snprintf(buffer,sizeof(buffer),"%s %d\n",ip,port);
    if(write(fd,buffer,length)<0)
        printf("\nwrite to tracker_info.txt failed");
    close(fd);
}

void* serverHandle(void* args)
{
    int sd=*(int*)args;
    char buff[1024];
    while(true)
    {
        int n=read(sd,buff,sizeof(buff)-1);
        if(n<=0)
        {
            cerr<<"\nSocket read failed";
            close(sd);
            return NULL;
        }
        buff[n]='\0';
        cout<<"\nReceived: "<<buff<<endl;
    }
    close(sd);
    return NULL;
}

void* clientHandle(void* args)
{
    int sd=*(int*)args;
    char buff[1024];
    ssize_t n;
    while(true)
    {
        cout<<"\nEnter filename or message to send: ";
        cin.getline(buff,sizeof(buff));
        if(strlen(buff)>0)
            write(sd,buff,strlen(buff));
        if(strlen(buff)==0)
            continue;
        if(access(buff,F_OK)==0)
        {
            int fd=open(buff,O_RDONLY);
            if(fd<0)
            {
                cerr<<"\nFailed to open file";
                continue;
            }
            while((n=read(fd,buff,sizeof(buff)))>0)
                write(sd,buff,n);
            close(fd);
            cout<<"\nFile sent successfully";
        }
        else
            write(sd,buff,strlen(buff));
    }

    close(sd);
    return NULL;
}

void* startServer(void* args)
{
    int port=*((int*)args);
    int server_fd,newSockfd;
    struct sockaddr_in serv_addr,cli_addr;
    socklen_t clilen=sizeof(cli_addr);

    server_fd=socket(AF_INET,SOCK_STREAM,0);
    if(server_fd < 0) {
        cerr << "\nSocket creation failed";
        pthread_exit(NULL);
    }
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family=AF_INET;
    serv_addr.sin_addr.s_addr=INADDR_ANY;  // Listen on any IP
    serv_addr.sin_port=htons(port);
    if(bind(server_fd,(sockaddr*)&serv_addr,sizeof(serv_addr))<0)
    {
        cerr<<"\nBinding failure";
        close(server_fd);
        pthread_exit(NULL);
    }
    listen(server_fd,5);
    while(true)
    {
        newSockfd=accept(server_fd,(struct sockaddr*)&cli_addr,&clilen);
        if(newSockfd<0)
        {
            printf("\nRequest not accepted");
            continue;
        }
        logConnection(ntohs(cli_addr.sin_port),inet_ntoa(cli_addr.sin_addr));
        pthread_t server_thread;
        pthread_create(&server_thread,NULL,serverHandle,&newSockfd);
    }
    close(server_fd);
    pthread_exit(NULL);
}

void startPeer(const char *ip,int port)
{
    int sockfd;
    struct sockaddr_in serv_addr;
    sockfd=socket(AF_INET,SOCK_STREAM,0);
    if(sockfd<0)
    {
        printf("\nSocket creation failed");
        exit(0);
    }
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family=AF_INET;
    serv_addr.sin_addr.s_addr=inet_addr(ip);
    serv_addr.sin_port=htons(port);
    if(connect(sockfd,(struct sockaddr*)&serv_addr,sizeof(serv_addr))<0)
    {
        printf("\nConnection failed");
        close(sockfd);
        exit(0);
    }
    logConnection(port,ip);
    pthread_t client_thread;
    pthread_create(&client_thread,NULL,clientHandle,&sockfd);
    cout<<"\nConnection established. You can start sending messages or files."<<endl;
}

int main(int argc,char **argv)
{
    if(argc != 4)
    {
        printf("\nUsage: ./program <your_port> <peer_ip> <peer_port>\n");
        exit(0);
    }
    int my_port=atoi(argv[1]);
    string peer_ip=argv[2];
    int peer_port=atoi(argv[3]);

    pthread_t server_thread;
    pthread_create(&server_thread,NULL,startServer,&my_port);

    // Start peer connection (client)
    sleep(15);  // Give server time to start
    startPeer(peer_ip.c_str(),peer_port);

    pthread_join(server_thread,NULL);
    return 0;
}