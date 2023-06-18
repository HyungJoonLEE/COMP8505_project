#include "common.h"
#include "cvc_server.h"



#define BUF_SIZE 100

void error_handling(char *buf);

int main(int argc, char *argv[]){

    int serv_sock, clnt_sock;
    struct sockaddr_in serv_adr, clnt_adr;
    struct timeval timeout;
    fd_set reads, cpy_reads;

    socklen_t adr_sz;
    int fd_max, str_len, fd_num, i;
    char buf[BUF_SIZE];


    serv_sock=socket(AF_INET,SOCK_STREAM,0);
    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family=AF_INET;
    serv_adr.sin_addr.s_addr=htonl(INADDR_ANY);
    serv_adr.sin_port=htons(CVC_PORT);

    if(bind(serv_sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr))==-1)
        error_handling("bind() error");

    if(listen(serv_sock,5)==-1)
        error_handling("listen() error");

    FD_ZERO(&reads);

    // 데이터의 수신여부를 관찰하는 관찰대상에 서버 소켓 포함시킴(서버소켓에 수신된 데이터 있으면 연결요청이 있었다는 뜻)
    FD_SET(serv_sock, &reads);

    fd_max=serv_sock;
    timeout.tv_sec=1;
    timeout.tv_usec=0;

    while(1){
        cpy_reads=reads;

        //select함수의 3번째, 4번째 인자가 0으로 채워져있는데, 이는 관찰의 목적에 맞게 reads만 사용한 것
        if((fd_num=select(fd_max+1,&cpy_reads,0,0,&timeout))==-1)
            break;
        if(fd_num==0)
            continue;

        //select 함수가 1 이상 반환했을 때 실행되는 반복문
        for(i=0; i<fd_max+1; i++){
            // 수신된 데이터가 있는 소켓의 파일 디스크립터 탐색
            if(FD_ISSET(i, &cpy_reads)){
                //서버 소켓에서 변화가 있었는지 확인
                //서버 소켓에서 변화가 있었을 시 연결요청에 대한 수락 과정 진행
                if(i==serv_sock){
                    adr_sz=sizeof(clnt_adr);
                    clnt_sock=accept(serv_sock,(struct sockaddr*)&clnt_adr, &adr_sz);
                    FD_SET(clnt_sock, &reads);
                    if(fd_max<clnt_sock)
                        fd_max=clnt_sock;
                    printf("connected client: %d\n",clnt_sock);
                }
                    //수신할 데이터가 있는 경우 실행
                else{
                    str_len=read(i,buf,BUF_SIZE);
                    //EOF일 시 연결종료
                    if(str_len==0){
                        FD_CLR(i, &reads);
                        close(i);
                        printf("closed client: %d\n", i);
                    }
                }
            }
        }
    }
    close(serv_sock);
    return 0;
}

void error_handling(char *buf){
    fputs(buf, stderr);
    fputc('\n',stderr);
    exit(1);
}