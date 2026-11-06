#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#define CHUNK 1024
static void die(const char *s) { fprintf(stderr,"%s\n",s); exit(1); }
/* All network reads/writes finish fully, or report failure. */
static int io(int fd,void *buf,size_t n,int send_it) {
    unsigned char *p=buf;
    while(n) {
        ssize_t k=send_it?send(fd,p,n,0):recv(fd,p,n,0);
        if(k<0 && errno==EINTR) continue;
        if(k<=0) return 0;
        p+=k; n-=(size_t)k;
    }
    return 1;
}
/* Plaintext framing: network-order length, then bytes. Zero means END. */
static int frame(int fd,unsigned char *b,uint32_t *n,int sending) {
    uint32_t w=htonl(*n);
    if(!io(fd,&w,4,sending)) return 0;
    if(!sending) *n=ntohl(w);
    return *n<=CHUNK && io(fd,b,*n,sending);
}
static int net(const char *ip,const char *port,int server) {
    char *end; errno=0; long p=strtol(port,&end,10);
    if(errno || !*port || *end || p<1 || p>65535) die("Invalid port");
    struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons((uint16_t)p);
    if(inet_pton(AF_INET,ip,&a.sin_addr)!=1) die("Invalid IPv4 address");
    int s=socket(AF_INET,SOCK_STREAM,0), r;
    if(s<0) die("socket failed");
    if(!server) {
        r=connect(s,(struct sockaddr*)&a,sizeof a);
        if(r<0 && errno==EINTR) {
            /* An interrupted connect may still be in progress. Wait for its
             * result instead of issuing another connect on the same socket. */
            struct pollfd wait={s,POLLOUT,0};
            do {r=poll(&wait,1,-1);} while(r<0 && errno==EINTR);
            if(r>0) {
                int error=0; socklen_t size=sizeof error;
                do {r=getsockopt(s,SOL_SOCKET,SO_ERROR,&error,&size);}
                while(r<0 && errno==EINTR);
                if(r==0 && error) {errno=error; r=-1;}
            }
        }
        if(r<0) die("connect failed; start downstream processes first");
        return s;
    }
    int yes=1;
    if(setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes)<0) die("setsockopt failed");
    if(bind(s,(struct sockaddr*)&a,sizeof a)<0 || listen(s,1)<0) die("bind/listen failed");
    fprintf(stderr,"Listening on %s:%s\n",ip,port);
    do {r=accept(s,NULL,NULL);} while(r<0 && errno==EINTR);
    close(s); if(r<0) die("accept failed"); return r;
}
static void load_key(const char *path,unsigned char key[32]) {
    FILE *f=fopen(path,"rb"); if(!f) die("Cannot open key");
    size_t n=fread(key,1,32,f); int c=fgetc(f), bad=ferror(f); fclose(f);
    if(n!=32 || c!=EOF || bad) die("Key must contain exactly 32 bytes");
}
/* Each frame uses nonce salt[8] || counter[4], with length as AAD. */
static int crypt_frame(int enc,unsigned char *key,unsigned char *salt,uint32_t counter,
                 uint32_t n,unsigned char *in,unsigned char *out,unsigned char *tag) {
    unsigned char nonce[12]; uint32_t c=htonl(counter), w=htonl(n);
    memcpy(nonce,salt,8); memcpy(nonce+8,&c,4);
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new(); int k=0,t=0,ok=0;
    if(!ctx) return 0;
    if(EVP_CipherInit_ex(ctx,EVP_aes_256_gcm(),NULL,NULL,NULL,enc)!=1 ||
       EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,12,NULL)!=1 ||
       EVP_CipherInit_ex(ctx,NULL,NULL,key,nonce,enc)!=1 ||
       EVP_CipherUpdate(ctx,NULL,&k,(unsigned char*)&w,4)!=1) goto done;
    /* AAD output length is separate from the payload length, including END. */
    k=0;
    if(n && EVP_CipherUpdate(ctx,out,&k,in,(int)n)!=1) goto done;
    if(!enc && EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,16,tag)!=1) goto done;
    if(EVP_CipherFinal_ex(ctx,out+k,&t)!=1) goto done;
    if(k+t!=(int)n) goto done;
    if(enc && EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,16,tag)!=1) goto done;
    ok=1;
done: EVP_CIPHER_CTX_free(ctx); return ok;
}
static void sender(char **v) {
    FILE *f=fopen(v[1],"rb");
    if(!f && errno==ENOENT) {
        f=fopen(v[1],"wbx"); if(!f) die("Cannot create sample");
        int bad=fputs("Sample file for the four-process transfer.\n",f)==EOF;
        if(fclose(f)!=0) bad=1;
        if(bad) die("Sample write failed");
        f=fopen(v[1],"rb");
    }
    if(!f) die("Cannot open input");
    int s=net(v[2],v[3],0); unsigned char b[CHUNK];
    for(;;) {
        uint32_t n=(uint32_t)fread(b,1,CHUNK,f);
        if(ferror(f) || !frame(s,b,&n,1)) die("Input read/send failed");
        if(!n) break;
    }
    fclose(f); close(s);
}
static void encoder(char **v) {
    unsigned char key[32],salt[8],b[CHUNK],out[CHUNK+16],tag[16];
    load_key(v[5],key); if(RAND_bytes(salt,8)!=1) die("Random generation failed");
    int in=net(v[1],v[2],1), dest=net(v[3],v[4],0);
    if(!io(dest,salt,8,1)) die("Salt send failed");
    uint32_t counter=0;
    for(;;) {
        uint32_t n=0;
        if(!frame(in,b,&n,0)) die("Interrupted/invalid plaintext transfer");
        /* Reserve UINT32_MAX for END; never wrap the counter. */
        if(n && counter==UINT32_MAX) die("Counter exhausted");
        if(!crypt_frame(1,key,salt,counter,n,b,out,tag)) die("Encryption failed");
        uint32_t w=htonl(n);
        if(!io(dest,&w,4,1) || !io(dest,out,n,1) || !io(dest,tag,16,1)) die("Encrypted send failed");
        if(!n) break;
        counter++;
    }
    OPENSSL_cleanse(key,32); close(in); close(dest);
}
static void decoder(char **v) {
    unsigned char key[32],salt[8],b[CHUNK],out[CHUNK+16],tag[16];
    load_key(v[5],key);
    /* tmpfile is private and removed automatically, including on exit. */
    FILE *spool=tmpfile(); if(!spool) die("Cannot create plaintext spool");
    int in=net(v[1],v[2],1); if(!io(in,salt,8,0)) die("Missing salt");
    uint32_t counter=0;
    for(;;) {
        uint32_t w; if(!io(in,&w,4,0)) die("Missing authenticated END");
        uint32_t n=ntohl(w);
        if(n>CHUNK || (n && counter==UINT32_MAX)) die("Invalid length/counter");
        if(!io(in,b,n,0) || !io(in,tag,16,0)) die("Interrupted encrypted frame");
        if(!crypt_frame(0,key,salt,counter,n,b,out,tag)) die("Authentication failed");
        if(!n) break;
        if(fwrite(out,1,n,spool)!=n) die("Spool write failed");
        counter++;
    }
    close(in); OPENSSL_cleanse(key,32);
    if(fflush(spool)!=0 || fseek(spool,0,SEEK_SET)!=0) die("Spool rewind failed");
    /* Only connect/forward after every frame and END authenticate. */
    int dest=net(v[3],v[4],0);
    for(;;) {
        uint32_t n=(uint32_t)fread(out,1,CHUNK,spool);
        if(ferror(spool) || !frame(dest,out,&n,1)) die("Forwarding failed");
        if(!n) break;
    }
    fclose(spool); close(dest);
}
static void listener(char **v) {
    int in=net(v[1],v[2],1);
    size_t size=strlen(v[3])+32; char *part=malloc(size);
    if(!part) die("Out of memory");
    snprintf(part,size,"%s.XXXXXX.part",v[3]);
    /* Linux mkstemps creates the final .part name exclusively, mode 0600.
     * There is no intermediate rename that could replace another temp file. */
    int fd=mkstemps(part,5); if(fd<0) die("Cannot create output temporary file");
    FILE *f=fdopen(fd,"wb"); int ok=f!=NULL;
    if(!f) close(fd);
    unsigned char b[CHUNK];
    while(ok) {
        uint32_t n=0; if(!frame(in,b,&n,0)) {ok=0; break;}
        if(!n) break;
        if(fwrite(b,1,n,f)!=n) ok=0;
    }
    if(f && fclose(f)!=0) ok=0;
    close(in);
    if(ok && rename(part,v[3])!=0) ok=0;
    if(!ok) {unlink(part); free(part); die("Listener failed; previous output preserved");}
    free(part);
}
int main(int argc,char **argv) {
    signal(SIGPIPE,SIG_IGN);
    const char *p=strrchr(argv[0],'/'); p=p?p+1:argv[0];
    if(!strcmp(p,"sender") && argc==4) sender(argv);
    else if(!strcmp(p,"listener") && argc==4) listener(argv);
    else if(!strcmp(p,"encoder") && argc==6) encoder(argv);
    else if(!strcmp(p,"decoder") && argc==6) decoder(argv);
    else die("Usage: sender INPUT DEST_IP PORT | listener BIND_IP PORT OUTPUT | encoder/decoder BIND_IP PORT DEST_IP PORT KEY");
    return 0;
}
