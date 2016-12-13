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
#include <stdarg.h>
#include "md5.h"
#include "config.h"

int sock;




FILE * logFile;

void LOG(FILE * stream,char format[],...)
{
    va_list ap;
    va_start(ap,format);
    vfprintf(stream,format,ap);
    vfprintf(logFile,format,ap);
    va_end(ap);
}

void decode(unsigned char *data,int offset,int len)
{
    for(int i=0;i<len;i++)
        LOG(stdout,"%02x",data[offset+i]);
    printf("\n");
}

int isTimeout()
{
#ifdef __unix
    if(errno==EAGAIN)
#endif
#ifdef _WIN32
    if(WSAGetLastError()==WSAETIMEDOUT)
#endif
        return 1;
    return 0;
}



int challenge(char srv[], int ran, char recv_data[])
{
    LOG(stdout,"[challenge]Ran:%d.\n",ran);
    unsigned char send_data[20]={0};
    send_data[0]=0x01;
    send_data[1]=0x02;
    send_data[2]=(unsigned char)(ran % 0xFFFF);
    send_data[3]=(unsigned char)((ran % 0xFFFF) >> 8);
    send_data[4]=0x09;
    struct sockaddr_in addr, address;
    int addr_len = sizeof(address);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(61440);
    addr.sin_addr.s_addr = inet_addr(srv);
    unsigned char data[1024];
    int ret,i=0;
    LOG(stdout,"[challenge]send:\n");
    decode(send_data,0,20);
    for(i=0;i<10;i++)
    {
        LOG(stdout,"[challenge]Trying to fetch challenge data for the %d time(s).\n",i+1);
        if(sendto(sock,send_data,20,0,(struct sockaddr *)&addr,sizeof(addr))<20)
        {
            LOG(stderr, "[challenge]send: Challenge data failed.\n");
            if(isTimeout())
                LOG(stderr,"[challenge]send: Timeout.\n");
            LOG(stdout,"[challenge]Retrying...\n");
            continue;
        }
        
        ret = recvfrom(sock,data,1024,0,(struct sockaddr *)&address,&addr_len);
        if(ret==-1)
        {
            LOG(stderr, "[challenge]recv: Challenge data failed.\n");
            if(isTimeout())
                LOG(stderr,"[challenge]recv: Timeout.\n");
            LOG(stdout,"[challenge]Retrying...\n");
            continue;
        }
        if(memcmp(((struct sockaddr *)&addr)->sa_data,((struct sockaddr *)&address)->sa_data,6)==0)
            break;
        else
        {
            LOG(stderr, "[challenge]recv: Address recived failed.\n");
            LOG(stdout,"[challenge]Retrying...\n");
        }
    }
    if(i==10)
    {
        LOG(stderr,"[challenge]Trying for 10 times. Terminate.\n");
        return 0;
    }
    LOG(stdout,"[challenge]Recv:\n");
    decode(data,0,ret);
    if(data[0]!=0x02)
    {
        LOG(stderr, "[challenge]Data recived failed.\n");
        sleep(30);
        LOG(stdout,"[challenge]Retrying...\n");
    }
    LOG(stdout,"[challenge]Challenge packet successfully sent.\n");
    
    memcpy(recv_data,data+4,4);
    return 1;
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
    int timeout=3000;
#endif
#ifdef __unix
    struct timeval timeout={3,0};
#endif
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        LOG(stderr, "[drcom]Fatal error: Create sock failed.\n");
        exit(1);
    }
    struct sockaddr_in local_addr;  
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = inet_addr(bind_ip);
    local_addr.sin_port = htons(61440);
    bind(sock,(struct sockaddr *)&(local_addr),sizeof(struct sockaddr_in));
    setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,(const char*)&timeout,sizeof(timeout));
    setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(const char*)&timeout,sizeof(timeout));
}

int login(char usr[], char pwd[], char svr[], char recv_data[], unsigned char salt[])
{
    unsigned char packet[330]={0};
    struct sockaddr_in addr, address;
    int addr_len = sizeof(address);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(61440);
    addr.sin_addr.s_addr = inet_addr(svr);
    unsigned char data[1024];
    int i=0,ret;
    LOG(stdout,"[login]Trying to login.\n");
    for(i=0;i<10;i++)
    {
        LOG(stdout,"[login]Trying to login for the %d time(s).\n",i+1);
        if(!challenge(svr,(unsigned)time(0)+rand()%0xF0 + 0xF,salt))
            continue;
        LOG(stdout,"[login]Making packet.\n");
        mkpkt(salt,username,password,mac,packet);
        LOG(stdout,"[login]send:\n");
        decode(packet,0,330);
        if(sendto(sock,packet,330,0,(struct sockaddr *)&addr,sizeof(addr))<330)
        {
            LOG(stderr, "[login]send: Data failed.\n");
            if(isTimeout())
                LOG(stderr,"[login]send: Timeout.\n");
            LOG(stdout,"[login]send: Retrying...\n");
            continue;
        }
        
        ret = recvfrom(sock,data,1024,0,(struct sockaddr *)&address,&addr_len);
        if(ret==-1)
        {
            LOG(stderr, "[login]recv: Recive data failed.\n");
            if(isTimeout())
                LOG(stderr,"[login]recv: Timeout.\n");
            LOG(stdout,"[login]recv: Retrying...\n");
            continue;
        }
        if(memcmp(((struct sockaddr *)&addr)->sa_data,((struct sockaddr *)&address)->sa_data,6)==0)
        {
            if(data[0]==0x04)
            {
                LOG(stdout,"[login]LOGed in successfully.\n");
                break;
            }
            else
            {
                LOG(stderr,"[login]login failed.\n");
                sleep(30);
                LOG(stdout,"[login]Retrying...\n");
                continue;
            }
        }
        else
        {
            LOG(stderr,"[login]login failed.\n");
            LOG(stdout,"[login]Retrying...\n");
            continue;
        }
    }
    if(i==10)
    {
        LOG(stderr,"[login]Trying for 10 times. Terminate.\n");
        return 0;
    }
    LOG(stdout,"[login]login data sent.\n");
    memcpy(recv_data,data+23,16);
    return 1;
}

int keep_alive1(char salt[],char tail[],char pwd[],char svr[])
{
    LOG(stdout,"[keep_alive1]Trying to Keep alive1.\n");
    unsigned char md5buff[1000],md5str[16],send_data[42]={0};
    size_t md5len;
    md5len = 6 +strlen(pwd);
    md5buff[0]=0x03;
    md5buff[1]=0x01;
    memcpy(md5buff+2,salt,4);
    memcpy(md5buff+6,pwd,strlen(pwd));
    MD5(md5buff,md5len,md5str);
    send_data[0]=0xff;
    memcpy(send_data+1,md5str,16);
    memcpy(send_data+20,tail,16);
    int now = (int)time(0)%0xFFFF;
    LOG(stdout,"[keep_alive1]Ran: %d.\n",now);
    send_data[36]=now/256;
    send_data[37]=now;
    LOG(stdout,"[keep_alive1]send:\n");
    decode(send_data,0,42);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(61440);
    addr.sin_addr.s_addr = inet_addr(svr);
    unsigned char data[1024];
    int ret,i=0;
    for(i=0;i<10;i++)
    {
        LOG(stdout,"[keep_alive1]Trying to send for the %i time(s).\n",i+1);
        if(sendto(sock,send_data,42,0,(struct sockaddr *)&addr,sizeof(addr))<42)
        {
            LOG(stderr, "[keep_alive1]send: Send data failed.\n");
            if(isTimeout())
                LOG(stderr,"[keep_alive1]send: Timeout.\n");
            LOG(stdout,"[keep_alive1]Retrying...\n");
            continue;
        }
        else
            break;
    }
    if(i>=10) return 0;
    for(i=0;i<10;i++)
    {
        LOG(stdout,"[keep_alive1]Trying to recive for the %i time(s).\n",i+1);
        ret = recvfrom(sock,data,1024,0,NULL,NULL);
        if(ret==-1)
        {
            LOG(stderr, "[keep_alive1]recv: Recive data failed.\n");
            if(isTimeout())
                LOG(stderr,"[keep_alive1]recv: Timeout.\n");
            LOG(stdout,"[keep_alive1]Retrying...\n");
            continue;
        }
        LOG(stdout,"[keep-alive1]recv:\n");
        decode(data,0,ret);
        if(data[0]==0x07)
        {
            LOG(stdout,"[keep_alive1]Success.\n");
            break;
        }
        else
        {
            LOG(stderr,"[keep-alive1]recv: Unexpected.\n");
            LOG(stdout,"[keep_alive1]Retrying...\n");
        }
    }
    return i!=10;
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
    int ret=40,i=0;
    LOG(stdout,"[keep-alive2]Making keep alive2 packet(%d,1,1).\n",svr_num);
    keep_alive_package_builder(svr_num,emptytail,packet,1,1);
    LOG(stdout,"[keep-alive2]send1:\n");
    decode(packet,0,40);
    for(i=0;i<10;i++)
    {
        LOG(stdout,"[keep-alive2]send1:Trying for the %i time(s).\n",i+1);
        if(sendto(sock,packet,40,0,(struct sockaddr *)&addr,sizeof(addr))<40)
        {
            LOG(stderr, "[keep-alive2]send1: Send data failed.\n");
            if(isTimeout())
                LOG(stderr,"[keep-alive2]send1: Timeout.\n");
            LOG(stdout,"[keep_alive2]send1: Retrying...\n");
            continue;
        }
        ret = recvfrom(sock,data,1024,0,NULL,NULL);
        if(ret==-1)
        {
            LOG(stderr, "[keep-alive2]recv1: Recive data failed.\n");
            if(isTimeout())
                LOG(stderr,"[keep-alive2]recv1: Timeout.\n");
            LOG(stdout,"[keep_alive2]recv1: Retrying...\n");
            continue;
        }
        LOG(stdout,"[keep-alive2]recv1:\n");
        decode(data,0,ret);
        if(*data ==0x07 && data[1]==0x00 && data[2] == 0x28 && data[3]==0x00)
        {
            LOG(stdout,"[keep-alive2]Success1.\n");
            break;
        }
        else if(*data == 0x07 && data[1]==(unsigned char)svr_num && data[2]==0x28 && data[3]==0x00)
        {
            LOG(stdout,"[keep-alive2]Success1.\n");
            break;
        }
        else if(*data ==0x07 && data[2] == 0x10)
        {
            LOG(stdout,"[keep-alive2]recv1: Recive file, skip.\n");
            svr_num ++;
            break;
        }
        else
        {
            LOG(stderr,"[keep-alive2]recv1: Unexpected.\n");
            LOG(stdout,"[keep_alive2]Retrying...\n");
        }
    }
    if(i==10) return;
    LOG(stdout,"[keep-alive2]Making keep alive2 packet(%d,1,0).\n",svr_num);
    keep_alive_package_builder(svr_num,emptytail,packet,1,0);
    LOG(stdout,"[keep-alive2]send3:\n");
    decode(packet,0,40);
    sendto(sock,packet,40,0,(struct sockaddr *)&addr,sizeof(addr));
    for(i=0;i<10;i++)
    {
        ret = recvfrom(sock,data,1024,0,NULL,NULL);
        if(ret==-1)
        {
            LOG(stderr, "[keep-alive2]recv2: Recive data failed.\n");
            if(isTimeout())
                LOG(stderr,"[keep-alive2]recv2: Timeout.\n");
            LOG(stdout,"[keep_alive2]recv2: Retrying...\n");
            continue;
        }
        LOG(stdout,"[keep-alive2]recv2:\n");
        decode(data,0,ret);
        if(data[0]==0x07)
        {
            LOG(stdout,"[keep-alive2]Success2.\n");
            svr_num++;
            break;
        }
        else
        {
            LOG(stderr,"[keep-alive2]recv2: Unexpected.\n");
            LOG(stdout,"[keep_alive2]recv2: Retrying...\n");
        }
    }
    if(i==10) return;
    memcpy(tail,data+16,4);
    LOG(stdout,"[keep-alive2]Making keep alive2 packet(%d,3,0).\n",svr_num);
    keep_alive_package_builder(svr_num,tail,packet,3,0);
    LOG(stdout,"[keep-alive2]send3:\n");
    decode(packet,0,40);
    sendto(sock,packet,40,0,(struct sockaddr *)&addr,sizeof(addr));
    for(i=0;i<10;i++)
    {
        ret = recvfrom(sock,data,1024,0,NULL,NULL);
        if(ret==-1)
        {
            LOG(stderr, "[keep-alive2]recv3: Recive data failed.\n");
            if(isTimeout())
                LOG(stderr,"[keep-alive2]recv3: Timeout.\n");
            LOG(stdout,"[keep_alive2]recv3: Retrying...\n");
            continue;
        }
        LOG(stdout,"[keep-alive2]recv3:\n");
        decode(data,0,ret);
        if(data[0]==0x07)
        {
            LOG(stdout,"[keep-alive2]Success3.\n");
            svr_num++;
            break;
        }
        else
        {
            LOG(stderr,"[keep-alive2]recv3: Unexpected.\n");
            LOG(stdout,"[keep_alive2]recv3: Retrying...\n");
        }
    }
    if(i==10) return;
    memcpy(tail,data+16,4);
    LOG(stdout,"[keep-alive2]keep alive2 loop was in daemon.\n");
    while(1)
    {
        sleep(20);
        LOG(stdout,"[keep-alive2]Trying to keep-alive.\n");
        if(!keep_alive1(salt,_tail,pwd,svr))
        {
            LOG(stderr,"[keep_alive1]Trying for 10 times. Terminate.\n");
            break;
        }
        LOG(stdout,"[keep-alive2]Making keep alive2 packet(%d,1,0).\n",svr_num);
        keep_alive_package_builder(svr_num,tail,packet,1,0);
        LOG(stdout,"[keep-alive2]send:\n");
        decode(packet,0,40);
        sendto(sock,packet,40,0,(struct sockaddr *)&addr,sizeof(addr));
        ret = recvfrom(sock,data,1024,0,NULL,NULL);
        if(ret==-1)
        {
            LOG(stderr, "[keep-alive2]recv: Recive data failed.\n");
            if(isTimeout())
                LOG(stderr,"[keep-alive2]recv: Timeout.\n");
            LOG(stdout,"[keep_alive2]recv2: Retrying...\n");
            continue;
        }
        LOG(stdout,"[keep-alive2]recv:\n");
        decode(data,0,ret);
        if(data[0]!=0x07)
        {
            LOG(stderr,"[keep-alive2]recv: Unexpected.\n");
            break;
        }
        memcpy(tail,data+16,4);
        
        LOG(stdout,"[keep-alive2]Making keep alive2 packet(%d,3,0).\n",svr_num+1);
        keep_alive_package_builder(svr_num+1,tail,packet,3,0);
        LOG(stdout,"[keep-alive2]send:\n");
        decode(packet,0,40);
        sendto(sock,packet,40,0,(struct sockaddr *)&addr,sizeof(addr));
        recvfrom(sock,data,1024,0,NULL,NULL);
        if(ret==-1)
        {
            LOG(stderr, "[keep-alive2]recv: Recive data failed.\n");
            if(isTimeout())
                LOG(stderr,"[keep-alive2]recv: Timeout.\n");
            LOG(stdout,"[keep_alive2]recv2: Retrying...\n");
            continue;
        }
        LOG(stdout,"[keep-alive2]recv:\n");
        decode(data,0,ret);
        if(data[0]!=0x07)
        {
            LOG(stderr,"[keep-alive2]recv: Unexpected.\n");
            break;
        }
        memcpy(tail,data+16,4);
        svr_num=(svr_num+2)%0xFF;
    }
}

void empty_socket_buffer()
{
    LOG(stdout,"[drcom]starting to empty socket buffer.\n");
    unsigned char data[1024];
    int ret;
    while(1)
    {
        ret = recvfrom(sock,data,1024,0,NULL,NULL);
        if(ret==-1)
        {
            LOG(stdout,"[drcom]exception in empty_socket_buffer.\n");
            break;
        }
        else
        {
            LOG(stdout,"[drcom]recived sth unexpected.\n");
            decode(data,0,ret);
        }
    }
    LOG(stdout,"[drcom]empty.\n");
}

int main()
{
    logFile = fopen(logPath,"w");
    setvbuf(stdout,(char * )NULL,_IOLBF,0);
    setvbuf(logFile,(char * )NULL,_IOLBF,0);
    unsigned char salt[4]={0};
    unsigned char package_tail[16]={0};
    LOG(stdout,"auth svr: %s\nusername: %s\n"
                    "password: %s\nmac:%llx\n",
                    server,username,password,mac);
    create_socket();
    while(1)
    {
        if(!login(username,password,server,package_tail,salt))
            continue;
        LOG(stdout,"[login]Recv tail:\n");
        decode(package_tail,0,16);
        LOG(stdout,"[login]Recv salt:\n");
        decode(salt,0,4);
        empty_socket_buffer();
        if(!keep_alive1(salt,package_tail,password,server))
        {
            LOG(stderr,"[keep_alive1]Trying for 10 times. Terminate.\n");
            sleep(30);
            LOG(stdout,"[drcom]Retrying...\n");
            continue;
        }
        
        keep_alive2(salt,package_tail,password,server);
        LOG(stderr,"[keep_alive2]Keep alive2 failed.\n");
        sleep(10);
        LOG(stdout,"[drcom]Retrying...\n");
        continue;
    }
    return 0;

}
