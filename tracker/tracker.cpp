#include <iostream>
#include <algorithm>
#include <iomanip>
#include <unordered_map>
#include <unordered_set>
#include <sys/types.h>
#include <vector>
#include <set>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
#include <fcntl.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/stat.h>
#include <thread>
#include <sstream>
#include <utility>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define MAX_CLIENT 20
#define BUFFER_SIZE 512*1024

using namespace std;

string local_ip="127.0.0.1";
int tracker_port=5012;

unsigned char key[16];

unordered_map<string,string> userAccounts;
unordered_map<int,string> peerUserIds;
unordered_map<string,set<string>> groups;
unordered_map<string,bool> loggedInUsers;
unordered_map<string,set<string>> pendingJoinRequests;
unordered_map<string,vector<string>> files;
unordered_map<string,unordered_map<string,char>> downloadStatus;
unordered_map<string,vector<pair<int,string>>> piecesPerUser;
unordered_map<string,string> encryptedPieces;

vector<pair<string,string>> trackerInfo[2];

bool running=true;

void encrypt(const string &plaintext,string &ciphertext,const unsigned char *key)
{
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;
    ciphertext.resize(plaintext.size()+EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    if(EVP_EncryptInit_ex(ctx,EVP_aes_128_cbc(),NULL,key,NULL)!=1)
    {
        cout<<"\nError initializing encryption";
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    if(EVP_EncryptUpdate(ctx,(unsigned char*)ciphertext.data(),&len,(const unsigned char*)plaintext.c_str(),plaintext.size())!=1)
    {
        cout<<"\nError during encryption update";
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len=len;
    if(EVP_EncryptFinal_ex(ctx,(unsigned char*)ciphertext.data()+len,&len)!=1)
    {
        cout<<"\nError during encryption finalization";
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len+=len;
    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
}

void decrypt(const string &ciphertext,string &plaintext,const unsigned char *key) {
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;
    plaintext.resize(ciphertext.size());
    if(EVP_DecryptInit_ex(ctx,EVP_aes_128_cbc(),NULL,key,NULL)!=1)
    {
        cout<<"\nError initializing decryption";
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    if(EVP_DecryptUpdate(ctx,(unsigned char*)plaintext.data(),&len,(const unsigned char*)ciphertext.c_str(),ciphertext.size())!=1)
    {
        cout<<"\nError during decryption update";
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    plaintext_len=len;
    if(EVP_DecryptFinal_ex(ctx,(unsigned char*)plaintext.data()+len,&len)!=1)
    {
        cout<<"\nError during decryption finalization";
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    plaintext_len+=len;
    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
}

void handleCreateUserCommand(const string &command,int sockfd)
{
    string cmd="create_user";
    string usrid,passwd;
    if(command.find(cmd)==0)
    {
        size_t fspace=command.find(' ',cmd.size());
        if(fspace==string::npos)
            return;
        size_t sspace=command.find(' ',fspace+1);
        usrid=command.substr(fspace+1,sspace-fspace-1);
        if(sspace==string::npos)
            return;
        passwd=command.substr(sspace+1);
        if(usrid.empty() || passwd.empty())
        {
            cout<<"\nUser id or password is invalid";
            return;
        }
        if(userAccounts.find(usrid)!=userAccounts.end())
        {
            cout<<"\nUser id already exists";
            return;
        }
        userAccounts[usrid]=passwd;
        cout<<"\nUser account created successfully";
        peerUserIds[sockfd]=usrid;
    }
}

void handleLogin(const string &command,int sockfd)
{
    string cmd="login";
    string usrid,passwd;
    if(command.find(cmd)==0)
    {
        size_t fspace=command.find(' ',cmd.size());
        if(fspace==string::npos)
            return;
        size_t sspace=command.find(' ',fspace+1);
        usrid=command.substr(fspace+1,sspace-fspace-1);
        if(sspace==string::npos)
            return;
        passwd=command.substr(sspace+1);
        string msg;
        if(usrid.empty() || passwd.empty())
        {
            cout<<"\nUser id or password is invalid";
            return;
        }
        if(userAccounts.find(usrid)==userAccounts.end())
        {
            cout<<"\nUser id is not in our repository";
            return;
        }
        if(userAccounts[usrid]!=passwd)
        {
            cout<<"\nWrong password";
            return;
        }
        if(loggedInUsers.find(usrid)!=loggedInUsers.end() && loggedInUsers[usrid]==true)
        {
            cout<<"\nYou are already logged in";
            return;
        }
        loggedInUsers[usrid]=true;
        cout<<"\nYou are logged in";
        peerUserIds[sockfd]=usrid;
    }
}

void handleGroupCreate(const string &command,int sockfd)
{
    string cmd="create_group";
    string grpid;
    if(command.find(cmd)==0)
    {
        size_t fspace=command.find(' ',cmd.size());
        if(fspace==string::npos)
            return;
        grpid=command.substr(fspace+1);
        if(grpid.empty())
        {
            cout<<"\nGroup ID is invalid";
            return;
        }
        if(groups.find(grpid)!=groups.end())
        {
            cout<<"\nGroup id already exists";
            return;
        }
        if(peerUserIds.find(sockfd)!=peerUserIds.end() && loggedInUsers.find(peerUserIds[sockfd])!=loggedInUsers.end() && loggedInUsers[peerUserIds[sockfd]]==true)
        {
            groups[grpid]=set<string>();
            groups[grpid].insert(peerUserIds[sockfd]);
        }
        else
        {
            cout<<"No user is logged in";
            return;
        }
        cout<<"\nGroup created";
    }
}

void handleGrpJoin(const string &command,int sockfd)
{
    string cmd="join_group";
    string grpid;
    if(command.find(cmd)==0)
    {
        size_t fspace=command.find(' ',cmd.size());
        if(fspace==string::npos)
            return;
        grpid=command.substr(fspace+1);
        if(grpid.empty())
        {
            cout<<"\nGroup ID is invalid";
            return;
        }
        string usrid=peerUserIds[sockfd];
        if(loggedInUsers.find(usrid)==loggedInUsers.end() || !loggedInUsers[usrid])
        {
            cout<<"\nYou are not logged in";
            return;
        }
        pendingJoinRequests[grpid].insert(usrid);
        cout<<"\nGroup join request submitted";
    }
}

void handleLeaveGrp(const string &command,int sockfd)
{
    string cmd="leave_group";
    string grpid,usrid;
    if(command.find(cmd)==0)
    {
        size_t fspace=command.find(' ',cmd.size());
        if(fspace==string::npos)
            return;
        grpid=command.substr(fspace+1);
        if(grpid.empty())
        {
            cout<<"\nGroup ID is invalid";
            return;
        }
        size_t sspace=command.find(' ',fspace+1);
        if(peerUserIds.find(sockfd)!=peerUserIds.end())
            usrid=peerUserIds[sockfd];
        else
        {
            cout<<"\nYou have not created any user id";
            return;
        }
        if(loggedInUsers.find(usrid)==loggedInUsers.end() || !loggedInUsers[usrid])
        {
            cout<<"\nYou are not logged in";
            return;
        }
        auto it=groups.find(grpid);
        if(it!=groups.end())
        {
            it->second.erase(usrid);
            cout<<"\nYou have left the group";
        }
        else
            cout<<"\nWrong group name";
    }
}

void handleListRequests(const string &command,int sockfd)
{
    string cmd="list_requests";
    string grpid;
    if(command.find(cmd)==0)
    {
        size_t fspace=command.find(' ',cmd.size());
        if(fspace==string::npos)
            return;
        grpid=command.substr(fspace+1);
        if(grpid.empty())
        {
            cout<<"\nGroup ID is invalid";
            return;
        }
        auto it=pendingJoinRequests.find(grpid);
        if(it!=pendingJoinRequests.end())
        {
            cout<<"\nPending requests for the group are-";
            for(const auto &request:it->second)
                cout<<"\n"<<request;
        }
        else
            cout<<"\nNo pending requests for the group";
    }
}

void handleAcceptRequest(const string &command,int sockfd)
{
    string cmd="accept_request";
    string msg;
    string grpid,usrid;
    if(command.find(cmd)==0)
    {
        size_t fspace=command.find(' ',cmd.size());
        if(fspace==string::npos)
            return;
        ssize_t sspace=command.find(' ',fspace+1);
        grpid=command.substr(fspace+1,sspace-fspace-1);
        if(sspace==string::npos)
            return;
        usrid=command.substr(sspace+1);
        if(grpid.empty() || usrid.empty())
        {
            cout<<"\nGroup id or user id is invalid";
            return;
        }
        auto it=pendingJoinRequests.find(grpid);
        if(it!=pendingJoinRequests.end() && it->second.find(usrid)!=it->second.end())
        {
            it->second.erase(usrid);
            groups[grpid].insert(usrid);
            cout<<"\nUser "+usrid+" has been added to the group "<<grpid;
        }
        else
            cout<<"\nNo pending request from user "+usrid+" to group "+grpid;
    }
}

void handleListGroups(int sockfd)
{
    if(groups.empty())
    {
        cout<<"\nNo groups in the network";
        return;
    }
    cout<<"\nThe groups in the network are-";
    for(const auto &group:groups)
        cout<<"\nGroup ID: "<<group.first;
}

void handleStopShare(const string &command,int sockfd)
{
    string cmd="stop_share";
    string grpid,filename;
    if(command.find(cmd)==0)
    {
        size_t fspace=command.find(' ',cmd.size());
        if(fspace==string::npos)
        {
            cout<<"\nNot enough arguments";
            return;
        }
        size_t sspace=command.find(' ',fspace+1);
        grpid=command.substr(fspace+1,sspace-fspace-1);
        filename=command.substr(sspace+1);
        if(grpid.empty() || filename.empty())
        {
            cout<<"\nInvalid group ID or file name";
            return;
        }
        if(groups.find(grpid)==groups.end())
        {
            cout<<"\nGroup ID does not exist";
            return;
        }
        auto &groupFiles=files[grpid];
        auto it=find(groupFiles.begin(),groupFiles.end(),filename);
        if(it==groupFiles.end())
        {
            cout<<"\nFile is not shared in the group";
            return;
        }
        groupFiles.erase(it);
        for(const auto &peerid:groups[grpid])
        {
            auto &pieces=piecesPerUser[peerid];
            for(auto pieceIt=pieces.begin(); pieceIt!=pieces.end();)
            {
                if(encryptedPieces.find(pieceIt->second)!=encryptedPieces.end())
                    pieceIt=pieces.erase(pieceIt);
                else
                    ++pieceIt;
            }
        }
        cout<<"\nFile successfully stopped sharing in the group";
    }
}

bool check(const string &peerid,const string &piece_hash)
{
    auto it=piecesPerUser.find(peerid);
    if(it==piecesPerUser.end())
        return false;
    const auto &pieces=it->second;
    for(const auto &piece_info:pieces)
    {
        if(piece_info.second==piece_hash)
            return true;
    }
    return false;
}

void handleLogOut(const string &command,int sockfd)
{
    string usrid;
    string cmd="logout";
    if(peerUserIds.find(sockfd)!=peerUserIds.end())
        usrid=peerUserIds[sockfd];
    else
    {
        cout<<"\nYou have not created any user id";
        return;
    }
    if(loggedInUsers.find(usrid)==loggedInUsers.end() || loggedInUsers[usrid]==false)
    {
        cout<<"\nYou are not logged in";
        return;
    }
    for(const auto &grpid:groups)
    {
        for(const auto &filename:files[grpid.first])
        {
            auto &pieces=piecesPerUser[usrid];
            for(const auto &piece_info:pieces)
            {
                string piece_hash=piece_info.second;
                int peerIndex=0;
                for(const auto &peerid:groups[grpid.first])
                {
                    if(peerid!=usrid && !check(peerid,piece_hash))
                    {
                        piecesPerUser[peerid].push_back(piece_info);
                        break;
                    }
                    peerIndex=(peerIndex+1)%groups[grpid.first].size();
                }
            }
            piecesPerUser[usrid].clear();
            string command="stop_share "+grpid.first+" "+filename;
            handleStopShare(command,sockfd);
        }
    }
    loggedInUsers[usrid]=false;
    auto it=peerUserIds.find(sockfd);
    if(it!=peerUserIds.end())
        peerUserIds.erase(it);
    cout<<"\nUser "<<usrid<<" has successfully logged out";
}

void handleListFiles(const string &command,int sockfd)
{
    string cmd="list_files";
    string grpid;
    if(command.find(cmd)==0)
    {
        size_t fspace=command.find(' ',cmd.size());
        if(fspace==string::npos)
            return;
        grpid=command.substr(fspace+1);
        if(grpid.empty())
        {
            cout<<"\nGroup ID is invalid";
            return;
        }
        if(peerUserIds.find(sockfd)!=peerUserIds.end())
        {
            if(loggedInUsers.find(peerUserIds[sockfd])==loggedInUsers.end() || loggedInUsers[peerUserIds[sockfd]]==false)
            {
                cout<<"\nNo logged in user";
                return;
            }
        }
        else
        {
            cout<<"\nNo logged in user";
            return;
        }
        auto it=groups.find(grpid);
        if(it!=groups.end())
        {
            if(files.find(grpid)!=files.end() && !files[grpid].empty())
            {
                cout<<"\nFiles in group "<<grpid<<" are-";
                for(const auto &file:files[grpid])
                    cout<<"\n"<<file;
            }
            else
                cout<<"\nNo files found in group"+grpid;
        }
        else
            cout<<"\nWrong group name";
    }
}

void handleUploadFile(const string &command,int sockfd)
{
    string cmd="upload_file";
    string file_path,grpid;
    if(command.find(cmd)==0)
    {
        size_t fspace=command.find(' ',cmd.size());
        if(fspace==string::npos)
        {
            cout<<"\nInvalid command format";
            return;
        }
        size_t sspace=command.find(' ',fspace+1);
        file_path=command.substr(fspace+1,sspace-fspace-1);
        grpid=command.substr(sspace+1);
        if(file_path.empty() || grpid.empty())
        {
            cout<<"\nInvalid file path/group id";
            return;
        }
        if(groups.find(grpid)==groups.end())
        {
            cout<<"\n"<<grpid;
            cout<<"\nGroup id does not exist";
            return;
        }
        if(access(file_path.c_str(),F_OK)!=0)
        {
            cout<<"\nFile not found";
            return;
        }
        
        int fd=open(file_path.c_str(),O_RDONLY);
        if(fd<0)
        {
            cout<<"\nFile open error";
            return;
        }
        string filename=file_path.substr(file_path.find_last_of("/\\")+1);
        files[grpid].push_back(filename);
        char buffer[BUFFER_SIZE];
        size_t bytes_read;
        int peerCount=groups[grpid].size();
        int peerIndex=0;
        while((bytes_read=read(fd,buffer,sizeof(buffer)))>0)
        {
            string piece(buffer,bytes_read);
            string encryptedPiece;
            encrypt(piece,encryptedPiece,key);
            string piece_hash;
            unsigned char sha_chunk_hash[SHA_DIGEST_LENGTH];
            SHA1((unsigned char*)encryptedPiece.data(),encryptedPiece.size(),sha_chunk_hash);
            piece_hash.assign((char*)sha_chunk_hash,SHA_DIGEST_LENGTH);
            encryptedPieces[piece_hash]=encryptedPiece;
            string usrid=*next(groups[grpid].begin(),peerIndex);
            piecesPerUser[usrid].push_back(make_pair(peerIndex,piece_hash));
            peerIndex=(peerIndex+1)%peerCount;
        }
        cout<<"\nFile succesfully uploaded to the group";
        close(fd);
    }
}

string retrievePiece(const string &peerid,const string &piece_hash)
{
    auto it=piecesPerUser.find(peerid);
    if(it==piecesPerUser.end())
    {
        cout<<"\nPeer ID not found in repository: "<<peerid;
        return "";
    }
    const auto &pieces=it->second;
    auto encryptedIt=encryptedPieces.find(piece_hash);
    if(encryptedIt!=encryptedPieces.end())
        return encryptedIt->second;
    cout<<"\nPiece hash not found for peer ID: "<<peerid;
    return "";
}

void handleDownload(const string &command,int sockfd)
{
    string cmd="download_file";
    string grpid,filename,dest;
    int destfd;
    if(command.find(cmd)==0)
    {
        size_t fspace=command.find(' ',cmd.size());
        if(fspace==string::npos)
        {
            cout<<"\nNot enough arguments";
            return;
        }
        size_t sspace=command.find(' ',fspace+1);
        grpid=command.substr(fspace+1,sspace-fspace-1);
        if(sspace==string::npos)
        {
            cout<<"\nNot enough arguments";
            return;
        }
        size_t tspace=command.find(' ',sspace+1);
        filename=command.substr(sspace+1,tspace-sspace-1);
        if(tspace==string::npos)
        {
            cout<<"\nNot enough arguments";
            return;
        }
        dest=command.substr(tspace+1);
        if(groups.find(grpid)==groups.end())
        {
            cout<<"\nGroup id is not in repository";
            return;
        }
        if(peerUserIds.find(sockfd)!=peerUserIds.end())
        {
            string usrid=peerUserIds[sockfd];
            if(loggedInUsers.find(usrid)==loggedInUsers.end() || loggedInUsers[usrid]==false)
            {
                cout<<"\nYou are not logged in";
                return;
            }
        }
        else
        {
            cout<<"\nYou have no logged in user to continue downloading";
            return;
        }
        if(find(files[grpid].begin(),files[grpid].end(),filename)==files[grpid].end())
        {
            cout<<"\nFile is not present in group";
            return;
        }
        downloadStatus[peerUserIds[sockfd]][filename]='D';
        unordered_set<string> requestPiece;
        struct stat sb;
        if(stat(dest.c_str(),&sb)==0 && S_ISDIR(sb.st_mode))
            dest+="/"+filename;
        destfd=open(dest.c_str(),O_WRONLY | O_CREAT | O_TRUNC,0666);
        if(destfd<0)
        {
            cout<<"\nError opening destination file";
            return;
        }
        vector<pair<int,string>> allPieces;
        for(auto &peerid:groups[grpid])
        {
            auto &pieces=piecesPerUser[peerid];
            for(auto &piece_info:pieces)
            {
                int pieceIndex=piece_info.first;
                string piece_hash=piece_info.second;
                if(requestPiece.find(piece_hash)==requestPiece.end())
                {
                    requestPiece.insert(piece_hash);
                    string pieceData=retrievePiece(peerid,piece_hash);
                    if(!pieceData.empty())
                    {
                        string decryptedData;
                        decrypt(pieceData,decryptedData,key);
                        if(!decryptedData.empty())
                            allPieces.emplace_back(pieceIndex,decryptedData);
                    }
                }
            }
        }
        sort(allPieces.begin(),allPieces.end());
        for(const auto &piece_info:allPieces)
        {
            const string &decryptedData=piece_info.second;
            size_t total_written=0;
            ssize_t bytes_written;
            while(total_written<decryptedData.size())
            {
                bytes_written=write(destfd,decryptedData.c_str()+total_written,decryptedData.size()-total_written);
                if(bytes_written<0)
                {
                    cout<<"\nError writing to file";
                    close(destfd);
                    return;
                }
                total_written+=bytes_written;
            }
        }
    }
    close(destfd);
    cout<<"\nDownload complete";
    downloadStatus[peerUserIds[sockfd]][filename]='C';
}

void splitString(char* str,char* ip,char* port)
{
    char* token=strtok((char*)str," ");
    strcpy(ip,token);
    token=strtok(NULL," ");
    strcpy(port,token);
}

void loadTrackerInfo()
{
    char buff[1024];
    int fd=open("../tracker_info.txt",O_RDONLY);
    string msg;
    if(fd<0)
    {
        cout<<"\nError opening tracker_info.txt file";
        exit(EXIT_FAILURE);
    }
    ssize_t bytes_read=read(fd,buff,sizeof(buff)-1);
    if(bytes_read<0)
    {
        cout<<"\nError reading tracker_info.txt file";
        close(fd);
        exit(EXIT_FAILURE);
    }
    buff[bytes_read]='\0';
    close(fd);
    char* line=strtok(buff,"\n");
    int index=0;
    while(line!=NULL)
    {
        char ip[64],port[16];
        splitString(line,ip,port);
        trackerInfo[index%2].emplace_back(string(ip),string(port));
        index++;
        line=strtok(NULL,"\n");
    }
    if(index<2)
        return;
}

void handleShowDownloads(int sockfd)
{
    string msg,usrid;
    if(peerUserIds.find(sockfd)!=peerUserIds.end())
        usrid=peerUserIds[sockfd];
    else
    {
        cout<<"\nYou have not created any user id";
        return;
    }
    if(downloadStatus.find(usrid)==downloadStatus.end() || downloadStatus[usrid].empty())
    {
        cout<<"\nNo downloads in progress or completed";
        return;
    }
    string result;
    for(auto &fileStatus:downloadStatus[usrid])
    {
        char status=fileStatus.second;
        string statusStr=(status=='D')?"[D]":"[C]";
        result+=statusStr+" "+fileStatus.first+"\n";
    }
    cout<<result;
}

void clientHandle(int sockfd)
{
    string command;
    char buff[1024];
    ssize_t n;
    string msg;
    while(running)
    {
        cout<<"\nTracker Output:\n";
        const char* prompt="$";
        write(sockfd,prompt,strlen(prompt));
        n=read(sockfd,buff,sizeof(buff)-1);
        if(n<=0)
        {
            if(n==0)
                printf("\nClient disconnected");
            else
                printf("\nRead error");
            break;
        }
        buff[n]='\0';
        command=string(buff);
        if(command=="quit")
        {
            running=false;
            break;
        }
        if(command.find("create_user")==0)
            handleCreateUserCommand(command,sockfd);
        else if(command.find("login")==0)
            handleLogin(command,sockfd);
        else if(command.find("create_group")==0)
            handleGroupCreate(command,sockfd);
        else if(command.find("join_group")==0)
        {
            if(!loggedInUsers.empty())
                 handleGrpJoin(command,sockfd);
            else
            {
                printf("\nYou are not logged in");
                return;
            }
        }
        else if(command.find("leave_group")==0)
            handleLeaveGrp(command,sockfd);
        else if(command.find("list_requests")==0)
            handleListRequests(command,sockfd);
        else if(command.find("accept_request")==0)
            handleAcceptRequest(command,sockfd);
        else if(command.find("list_groups")==0)
            handleListGroups(sockfd);
        else if(command.find("logout")==0)
            handleLogOut(command,sockfd);
        else if(command.find("list_files")==0)
            handleListFiles(command,sockfd);
        else if(command.find("upload_file")==0)
            handleUploadFile(command,sockfd);
        else if(command.find("download_file")==0)
            handleDownload(command,sockfd);
        else if(command.find("show_downloads")==0)
            handleShowDownloads(sockfd);
        else if(command.find("stop_share")==0)
            handleStopShare(command,sockfd);
        else
            cout<<"\nUnknown command";
    }
    close(sockfd);
}

void acceptClients(int server_fd,int trackerno)
{
    struct sockaddr_in cli_addr;
    socklen_t cli_len=sizeof(cli_addr);
    while(true)
    {
        if(!running)
            break;
        int newSockfd=accept(server_fd,(sockaddr*)&cli_addr,&cli_len);
        if(newSockfd<0)
        {
            if(errno==EWOULDBLOCK || errno==EAGAIN)
                continue;
            printf("\nConnection request not accepted");
            continue;
        }
        cout<<"\nConnection accepted from "<<inet_ntoa(cli_addr.sin_addr)<<": "<<ntohs(cli_addr.sin_port);
        thread clientThread(clientHandle,newSockfd);
        clientThread.detach();
    }
}

int main(int argc,char** argv)
{
    if(argc!=3)
    {
        printf("\nNo tracker info provided.");
        exit(0);
    }
    string file_name=argv[1];
    size_t found=file_name.find("tracker_info.txt");
    if(found==string::npos)
    {
        printf("\nWrong tracker file name given");
        exit(0);
    }
    int trackerno=atoi(argv[2]);
    if(trackerno>=3 ||trackerno<=0)
    {
        printf("\nInvalid tracker number");
        exit(0);
    }
    int server_fd=socket(AF_INET,SOCK_STREAM,0);
    if(server_fd<0)
    {
        printf("\nSocket creation failed");
        exit(0);
    }
    struct sockaddr_in serv_addr;
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family=AF_INET;
    serv_addr.sin_addr.s_addr=inet_addr(local_ip.c_str());
    serv_addr.sin_port=htons(tracker_port);

    if(bind(server_fd,(sockaddr*)&serv_addr,sizeof(serv_addr))<0)
    {
        printf("\nBinding failure");
        close(server_fd);
        exit(0);
    }
    if(listen(server_fd,50)<0)
    {
        printf("\nListening failure");
        close(server_fd);
        exit(0);
    }
    cout<<"\nServer listening on port "<<tracker_port;
    RAND_bytes(key,sizeof(key));
    loadTrackerInfo();
    acceptClients(server_fd,trackerno);
    close(server_fd);
    printf("\nServer shutdown");
    return 0;
}