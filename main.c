#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include <sys/types.h>
#include <unistd.h>
#ifdef _WIN32
#include <winsock.h>
#endif
#ifdef __unix
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#include "md5.h"
#include "config.h"

int sock;
char salt[4];
char nic_name[] = "";
char bind_ip[] = "0.0.0.0";

char log_file[] = "drcom_client.log";


void decode(unsigned char *data,int offset,int len)
{
    for(int i=0;i<len;i++)
        fprintf(stdout,"%02x",data[offset+i]);
    printf("\n");
}

void challenge(char srv[], int ran, char* recv_data)
{
    
    unsigned char send_data[20]={0};
    send_data[0]=0x01;
    send_data[1]=0x02;
    send_data[2]=(unsigned char)(ran % 0xFFFF);
    send_data[3]=(unsigned char)((ran % 0xFFFF) >> 8);
    send_data[4]=0x09;
    decode(send_data,0,20);
    struct sockaddr_in addr, address;
    int addr_len = sizeof(address);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(61440);
    addr.sin_addr.s_addr = inet_addr(srv);
    unsigned char data[1024];
    int ret;
    while(1)
    {
        if(sendto(sock,send_data,20,0,(struct sockaddr *)&addr,sizeof(addr))<20)
        {
            fprintf(stderr, "[challenge]: send challenge data failed.\n");
#ifdef __unix
            if(errno==EAGAIN)
#endif
#ifdef _WIN32
            if(WSAGetLastError()==WSAETIMEDOUT)
#endif
                fprintf(stdout,"[challenge]send timeout, retrying...");
            continue;
        }
        
        ret = recvfrom(sock,data,1024,0,(struct sockaddr *)&address,&addr_len);
        if(ret==-1)
        {
            fprintf(stderr, "[challenge]recive challenge data failed: %d.\n",errno);
            if(errno==EAGAIN)
                fprintf(stdout,"[challenge]recive timeout, retrying...\n");
            continue;
        }
        if(memcmp(((struct sockaddr *)&addr)->sa_data,((struct sockaddr *)&address)->sa_data,6)==0)
            break;
        else
            fprintf(stderr, "[challenge]address recived failed, retrying...\n");
    }
    fprintf(stdout,"[challenge]:\n");
    decode(data,0,ret);
    if(data[0]!=0x02)
    {
        fprintf(stderr, "[challenge]data recived failed\n");
        exit(1);
    }
    fprintf(stdout,"[challenge]challenge packet sent.\n");
    
    memcpy(recv_data,data+4,4);
}

void mkpkt(char salt[], char usr[], char pwd[], uint64_t mac, unsigned char *packet)
{
    unsigned char md5buff[1000],md5str[16];    
    size_t md5len;
    packet[0] = 0x03;
    packet[1] = 0x01;
    packet[2] = 0x00;
    packet[3] = (unsigned char)(strlen(usr) + 20);
    md5len = 6 + strlen(pwd);
    memset(md5buff, 0x00, md5len);
    md5buff[0]=0x03;
    md5buff[1]=0x01;
    memcpy(md5buff+2, salt, 4);
    memcpy(md5buff+6, pwd,strlen(pwd));
    MD5(md5buff, md5len, md5str);
    memcpy(packet + 4, md5str, 16);
    memcpy(packet + 20, usr, strlen(usr));
    packet[56]=CONTROLCHECKSTATUS;
    packet[57]=ADAPTERNUM;
    
    uint64_t sum = 0;
    for (int i = 0; i < 6; i++)
        sum = (int)md5str[i] + sum * 256;
    sum ^= mac;
    for (int i = 6; i > 0; i--) {
        packet[58 + i - 1] = (unsigned char)(sum % 256);
        sum /= 256;
    }
    
    md5len = 1 + strlen(pwd) + 8;
    memset(md5buff, 0x00, md5len);
    md5buff[0] = 0x01;
    memcpy(md5buff + 1, pwd, strlen(pwd));
    memcpy(md5buff + 1 + strlen(pwd), salt, 4);
    MD5(md5buff, md5len, md5str);
    memcpy(packet + 64, md5str, 16);
    packet[80] = 0x01;
    memcpy(packet+81,host_ip,4);
    
    md5len = 101;
    memset(md5buff, 0x00, md5len);
    memcpy(md5buff, packet, 97);
    md5buff[97]=0x14;
    md5buff[98]=0x00;
    md5buff[99]=0x07;
    md5buff[100]=0x0b;
    MD5(md5buff, md5len, md5str);
    memcpy(packet + 97, md5str, 8);
    
    packet[105]=ipdog;
    int len = strlen(host_name);
    len = len>32?32:len;
    memcpy(packet + 110,host_name, len);
    memcpy(packet+142,PRIMARY_DNS,4);
    memcpy(packet+146,dhcp_server,4);
    packet[162]=0x94;
    packet[166]=0x05;
    packet[170]=0x01;
    packet[174]=0x28;
    packet[175]=0x0A;
    packet[178]=0x02;
    len = strlen(host_os);
    len = len>32?32:len;
    memcpy(packet + 182,host_os, len);
    memcpy(packet + 310,AUTH_VERSION, 2);
    packet[312]=0x02;
    packet[313]=0x0c;
    
    packet[314]=0x01;
    packet[315]=0x26;
    packet[316]=0x07;
    packet[317]=0x11;
    
    for (int i = 0; i < 6; i++) {
        packet[320 + 5 - i] = (unsigned char)(mac % 256);
        mac /= 256;
    }
    sum = 1234;
    uint64_t check = 0;
    for (int i = 0; i < 326; i += 4) 
    {
        check = 0;
        for (int j = 3; j >=0; j--)
            check = check * 256 + (int)packet[i + j];
        sum ^= check;
    }
    sum = (1968 * sum) & 0xFFFFFFFF;
    for (int j = 0; j < 4; j++) 
        packet[314 + j] = (unsigned char)(sum >> (j * 8) & 0x000000FF);
    packet[328]=0xe9;
    packet[329]=0x13;
}


void create_socket()
{
#ifdef _WIN32
    WSADATA wsa={0};
    WSAStartup(MAKEWORD(2,2),&wsa);
#endif
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        fprintf(stderr, "[drcom]: create sock failed.\n");
        exit(1);
    }
#ifdef _WIN32
    int timeout=3000;
#endif
#ifdef __unix
    struct timeval timeout={3,0};
#endif
    setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,(const char*)&timeout,sizeof(timeout));
    setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(const char*)&timeout,sizeof(timeout));
}

void login(char usr[], char pwd[], char svr[], char recv_data[])
{
    unsigned char packet[330]={0};
    struct sockaddr_in addr, address;
    int addr_len = sizeof(address);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(61440);
    addr.sin_addr.s_addr = inet_addr(svr);
    unsigned char data[1024];
    int i=0,ret;
    while(1)
    {
        time_t rawtime;
        time (&rawtime);
        challenge(svr,(unsigned)time(0)+rand()%0xF0 + 0xF,salt);
        mkpkt(salt,username,password,mac,packet);
        fprintf(stdout,"[login] send ");
        decode(packet,0,330);
        if(sendto(sock,packet,330,0,(struct sockaddr *)&addr,sizeof(addr))<330)
        {
            fprintf(stderr, "[login]: send data failed.\n");
#ifdef __unix
            if(errno==EAGAIN)
#endif
#ifdef _WIN32
            if(WSAGetLastError()==WSAETIMEDOUT)
#endif
                fprintf(stdout,"[login]send timeout, retrying...");
            continue;
        }
        
        ret = recvfrom(sock,data,1024,0,(struct sockaddr *)&address,&addr_len);
        if(ret==-1)
        {
            fprintf(stderr, "[challenge]recive challenge data failed.\n");
#ifdef __unix
            if(errno==EAGAIN)
#endif
#ifdef _WIN32
            if(WSAGetLastError()==WSAETIMEDOUT)
#endif
                fprintf(stdout,"[challenge]recive timeout, retrying...\n");
            continue;
        }
        if(memcmp(((struct sockaddr *)&addr)->sa_data,((struct sockaddr *)&address)->sa_data,6)==0)
        {
            if(data[0]==0x04)
            {
                fprintf(stdout,"[login]loged in\n");
                break;
            }
            else
            {
                fprintf(stderr,"[login] login failed.\n");
                sleep(30);
                fprintf(stdout,"[login] retrying...\n");
                continue;
            }
        }
        else if(i>=0)
        {
            fprintf(stderr, "[login] exception occured.\n");
            exit(1);
        }
        else
        {
            fprintf(stderr,"[login] login failed.\n");
            sleep(30);
            fprintf(stdout,"[login] retrying...\n");
            continue;
        }
    }
    fprintf(stdout,"[login] login sent\n");
    memcpy(recv_data,data+23,16);
}

void keep_alive1(char salt[],char tail[],char pwd[],char svr[])
{
    unsigned char md5buff[1000],md5str[16],send_data[42]={0};    
    size_t md5len;
    md5len = 6 +strlen(pwd);
    md5buff[0]=0x03;
    md5buff[1]=0x01;
    memcpy(md5buff+2,salt,4);
    memcpy(md5buff+6,pwd,strlen(pwd));
    decode(md5buff,0,md5len);
    MD5(md5buff,md5len,md5str);
    send_data[0]=0xff;
    memcpy(send_data+1,md5str,16);
    memcpy(send_data+20,tail,16);
    int now = (int)time(0)%0xFFFF;
    send_data[36]=now/256;
    send_data[37]=now;
    fprintf(stdout,"[keep_alive1] send ");
    decode(send_data,0,42);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(61440);
    addr.sin_addr.s_addr = inet_addr(svr);
    unsigned char data[1024];
    int ret=42;
    while(1)
    {
        if(sendto(sock,send_data,42,0,(struct sockaddr *)&addr,sizeof(addr))<42)
        {
            fprintf(stderr, "[challenge]: send challenge data failed.\n");
#ifdef __unix
            if(errno==EAGAIN)
#endif
#ifdef _WIN32
            if(WSAGetLastError()==WSAETIMEDOUT)
#endif
                fprintf(stdout,"[challenge]send timeout, retrying...");
            continue;
        }
        
        ret = recvfrom(sock,data,1024,0,NULL,NULL);
        if(ret==-1)
        {
            fprintf(stderr, "[challenge]recive challenge data failed.\n");
#ifdef __unix
            if(errno==EAGAIN)
#endif
#ifdef _WIN32
            if(WSAGetLastError()==WSAETIMEDOUT)
#endif
                fprintf(stdout,"[challenge]recive timeout, retrying...\n");
            continue;
        }
        if(data[0]==0x07)
        {
            fprintf(stdout,"[keep-alive1] recv ");
            decode(data,0,ret);
            break;
        }
        else
            fprintf(stderr,"[keep-alive1]recv/not expected\n");
    }
    
}


void keep_alive_package_builder(int number, char tail[],unsigned char data[40], int type,int first)
{
    data[0]=0x07;
    data[1]=(unsigned char)number;
    data[2]=0x28;
    data[3]=0x00;
    data[4]=0x0b;
    data[5]=(unsigned char)type;
    if(first)
        data[6]=0x0f,data[7]=0x27;
    else
        memcpy(data+6,KEEP_ALIVE_VERSION,2);
    data[8]=0x2f;
    data[9]=0x12;
    memcpy(data+16,tail,4);
    if(type == 3)
        memcpy(data+28,host_ip,4);
}

void keep_alive2(char salt[],char _tail[],char pwd[],char svr[])
{
    unsigned char packet[40]={0};
    unsigned char tail[4]={0};
    unsigned char emptytail[4]={0};
    int svr_num = 0;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(61440);
    addr.sin_addr.s_addr = inet_addr(svr);
    unsigned char data[1024]={0};
    int ret=40;
    keep_alive_package_builder(svr_num,emptytail,packet,1,1);
    while(1)
    {
        fprintf(stdout,"[keep-alive2] send1 ");
        decode(packet,0,40);
        if(sendto(sock,packet,40,0,(struct sockaddr *)&addr,sizeof(addr))<40)
        {
            fprintf(stderr, "[keep-alive2] send1: send challenge data failed.\n");
#ifdef __unix
            if(errno==EAGAIN)
#endif
#ifdef _WIN32
            if(WSAGetLastError()==WSAETIMEDOUT)
#endif
                fprintf(stdout,"[keep-alive2] send1 timeout, retrying...");
            continue;
        }
        
        ret = recvfrom(sock,data,1024,0,NULL,NULL);
        if(ret==-1)
        {
            fprintf(stderr, "[keep-alive2] recv1 challenge data failed.\n");
#ifdef __unix
            if(errno==EAGAIN)
#endif
#ifdef _WIN32
            if(WSAGetLastError()==WSAETIMEDOUT)
#endif
                fprintf(stdout,"[keep-alive2] recv1 timeout, retrying...\n");
            continue;
        }
        fprintf(stdout,"[keep-alive2] recv1 ");
        decode(data,0,ret);
        if(*data ==0x07 && data[1]==0x00 && data[2] == 0x28 && data[3]==0x00)
            break;
        else if(*data == 0x07 && data[1]==(unsigned char)svr_num && data[2]==0x28 && data[3]==0x00)
            break;
        else if(*data ==0x07 && data[2] == 0x10)
        {
            fprintf(stdout,"[keep-alive2] recv1 file, resending..\n");
            svr_num = svr_num + 1;
            break;
        }
        else
            fprintf(stderr,"[keep-alive2] recv1/unexpected\n");
    }
    keep_alive_package_builder(svr_num,emptytail,packet,1,0);
    fprintf(stdout,"[keep-alive2] send2 ");
    decode(packet,0,40);
    while(1)
    {
        if(sendto(sock,packet,40,0,(struct sockaddr *)&addr,sizeof(addr))<40)
        {
            fprintf(stderr, "[keep-alive2] send2 data failed.\n");
#ifdef __unix
            if(errno==EAGAIN)
#endif
#ifdef _WIN32
            if(WSAGetLastError()==WSAETIMEDOUT)
#endif
                fprintf(stdout,"[keep-alive2] send2 timeout, retrying...");
            continue;
        }
        break;
    }
    while(1)
    {
        ret = recvfrom(sock,data,1024,0,NULL,NULL);
        if(ret==-1)
        {
            fprintf(stderr, "[keep-alive2]recv2 data failed.\n");
#ifdef __unix
            if(errno==EAGAIN)
#endif
#ifdef _WIN32
            if(WSAGetLastError()==WSAETIMEDOUT)
#endif
                fprintf(stdout,"[keep-alive2]recv2 timeout, retrying...\n");
            continue;
        }
        if(data[0]==0x07)
        {
            svr_num++;
            break;
        }
        else
        {
            fprintf(stderr,"[keep-alive2] recv2/unexpected\n");
            decode(data,0,ret);
        }
    }
    fprintf(stdout,"[keep-alive2] recv2 ");
    decode(data,0,ret);
    memcpy(tail,data+16,4);
    keep_alive_package_builder(svr_num,tail,packet,3,0);
    fprintf(stdout,"[keep-alive2] send3 ");
    decode(packet,0,40);
    while(1)
    {
        if(sendto(sock,packet,40,0,(struct sockaddr *)&addr,sizeof(addr))<40)
        {
            fprintf(stderr, "[keep-alive2] send3 data failed.\n");
#ifdef __unix
            if(errno==EAGAIN)
#endif
#ifdef _WIN32
            if(WSAGetLastError()==WSAETIMEDOUT)
#endif
                fprintf(stdout,"[keep-alive2] send3 timeout, retrying...");
            continue;
        }
        break;
    }
    
    while(1)
    {
        ret = recvfrom(sock,data,1024,0,NULL,NULL);
        if(ret==-1)
        {
            fprintf(stderr, "[keep-alive2]recv3 data failed.\n");
#ifdef __unix
            if(errno==EAGAIN)
#endif
#ifdef _WIN32
            if(WSAGetLastError()==WSAETIMEDOUT)
#endif
                fprintf(stdout,"[keep-alive2]recv3 timeout, retrying...\n");
            continue;
        }
        if(data[0]==0x07)
        {
            svr_num++;
            break;
        }
        else
        {
            fprintf(stderr,"[keep-alive2] recv3/unexpected\n");
            decode(data,0,ret);
        }
    }
    fprintf(stdout,"[keep-alive2] recv3 ");
    decode(data,0,ret);
    memcpy(tail,data+16,4);
    fprintf(stdout,"[keep-alive2] keep-alive2 loop was in daemon ");
    
    int i = svr_num;
    while(1)
    {
        sleep(20);
        keep_alive1(salt,_tail,pwd,svr);
        keep_alive_package_builder(i,tail,packet,1,0);
        sendto(sock,packet,40,0,(struct sockaddr *)&addr,sizeof(addr));
        fprintf(stdout,"[keep-alive2] send ");
        decode(packet,0,40);
        recvfrom(sock,data,1024,0,NULL,NULL);
        fprintf(stdout,"[keep-alive2] recv ");
        decode(data,0,ret);
        memcpy(tail,data+16,4);

        keep_alive_package_builder(i+1,tail,packet,3,0);
        sendto(sock,packet,40,0,(struct sockaddr *)&addr,sizeof(addr));
        fprintf(stdout,"[keep-alive2] send ");
        decode(packet,0,40);
        recvfrom(sock,data,1024,0,NULL,NULL);
        fprintf(stdout,"[keep-alive2] recv ");
        decode(data,0,ret);
        memcpy(tail,data+16,4);
        i=(i+2)%0xFF;
    }
}

int main()
{
    fprintf(stdout,"auth svr: %s\nusername: %s\n"
                    "password: %s\nmac:%x",
                    server,username,password,mac);
    unsigned char package_tail[16]={0};
    create_socket();
    while(1)
    {
        login(username,password,server,package_tail);
        keep_alive1(salt,package_tail,password,server);
        keep_alive2(salt,package_tail,password,server);
    }
    

}
