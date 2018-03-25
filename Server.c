#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <dirent.h> 
#include <stdio.h> 
#define FAIL    -1
void evftp(SSL* ssl);
// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{   
  int sd;
  int reuse = 1;

  struct sockaddr_in addr;

  sd = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;
  setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, (const char *)&reuse, sizeof(reuse)); // Overlap socket to avoid delay in using the socket in TIME_WAIT mode
  if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )			 // Bind my program to the socket 
    {
      perror("can't bind port");
      abort();
    }
  if ( listen(sd, 10) != 0 ) 							 // Listen to connection coming through the socket 
    {
      perror("Can't configure listening port");
      abort();
    }
  return sd;
}
int isRoot()
{
  if (getuid() != 0)
    {
      return 0;
    }
  else
    {
      return 1;
    }
}
SSL_CTX* InitServerCTX(void)
{   SSL_METHOD *method;
  SSL_CTX *ctx;
  OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
  SSL_load_error_strings();   /* load all error messages */

  method = (SSL_METHOD *)TLSv1_2_server_method();  /* create new server-method instance */
  ctx = SSL_CTX_new(method);   /* create new context from method */
  if ( ctx == NULL )
    {
      ERR_print_errors_fp(stderr);
      abort();
    }
  return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
  /* set the local certificate from CertFile */
  if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
      ERR_print_errors_fp(stderr);
      abort();
    }
  /* set the private key from KeyFile (may be the same as CertFile) */
  if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
      ERR_print_errors_fp(stderr);
      abort();
    }
  /* verify private key */
  if ( !SSL_CTX_check_private_key(ctx) )
    {
      fprintf(stderr, "Private key does not match the public certificate\n");
      abort();
    }
}
void ShowCerts(SSL* ssl)
{   X509 *cert;
  char *line;
  cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
  if ( cert != NULL )
    {
      printf("Server certificates:\n");
      line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
      printf("Subject: %s\n", line);
      free(line);
      line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
      printf("Issuer: %s\n", line);
      free(line);
      X509_free(cert);
    }
  else
    printf("No certificates.\n");
}
void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{   char buf[1024] = {0};
  int sd, bytes;

const char * ServerResponse="<Body><Name>aticleworld.com</Name><year>1.5</year><BlogType>Embedede and cc++<BlogType><Author>amlendra<Author></Body>";

const char *cpValidMessage = "<Body><UserName>Evan<UserName><Password>FTP<Password></Body>"; 
 if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
   ERR_print_errors_fp(stderr);
 else
   {
     ShowCerts(ssl);        /* get any certificates */
     bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
     buf[bytes] = '\0';
     printf("Client msg: \"%s\"\n", buf);
     if ( bytes > 0 )
       {
	 if(strcmp(cpValidMessage,buf) == 0)
	   {
	     SSL_write(ssl, ServerResponse, strlen(ServerResponse)); /* send reply */
	   }
	 else
	   {
	     SSL_write(ssl, "Invalid Message", strlen("Invalid Message")); /* send reply */
	   }
       }
     else
       {
	 ERR_print_errors_fp(stderr);
       }
   }
 evftp(ssl);
 sd = SSL_get_fd(ssl);       /* get socket connection */
  SSL_free(ssl);         /* release SSL state */
  close(sd);          /* close connection */
  printf("exiting servlet \n");
}
int main(int count, char *Argc[])
{   SSL_CTX *ctx;
  int server;
  char *portnum;
  //Only root user have the permsion to run the server
  if(!isRoot())
    {
      printf("This program must be run as root/sudo user!!");
      exit(0);
    }
  if ( count != 2 )
    {
      printf("Usage: %s <portnum>\n", Argc[0]);
      exit(0);
    }
  // Initialize the SSL library
  SSL_library_init();
  portnum = Argc[1];
  ctx = InitServerCTX();        /* initialize SSL */
  LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
  server = OpenListener(atoi(portnum));    /* create server socket */
  while (1)
    {   struct sockaddr_in addr;
      socklen_t len = sizeof(addr);
      SSL *ssl;
      int client = accept(server, (struct sockaddr*)&addr, &len);       /* accept connection as usual */
      printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
      ssl = SSL_new(ctx);              /* get new SSL state with context */
      SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
      Servlet(ssl);         /* service connection */
    }
  close(server);          /* close server socket */
  SSL_CTX_free(ctx);         /* release context */
}
void evftp(SSL* ssl) /* Serve the connection -- threadable */
{   char buf[1024] = {0};
  int bytes;
  char replyBuffer[1024];
 printf("Starting evftp \n");
 while(1){
 /*if ( SSL_accept(ssl) == FAIL ) */    /* do SSL-protocol accept */
 /*  ERR_print_errors_fp(stderr);
 else */
   {
     memset(buf, 0, sizeof(buf));              /* Cleans recieving buffer */
     bytes = SSL_read(ssl, buf, sizeof(buf));  /* get request */
     buf[bytes] = '\0';
     printf("FTP Client msg: \"%s\"\n", buf); 

     if ( bytes > 0 )
       {
	 if ( strstr(buf, "LIST") != NULL )
	{
		
		char path[1024];
		char *pp;
		DIR *d;
		//char yes[1024];
		struct dirent *dir = NULL;

		memset(path, 0, sizeof(path));
		pp = strstr(buf, " "); 
		
		if ( pp == NULL )
		{	
			sprintf(replyBuffer, "%s", "ERROR: Cannot find directory path");
			SSL_write(ssl, replyBuffer, strlen(replyBuffer));
			
		}
		else 
		{
			strcpy(path, pp+1);
		
  		
 		 d = opendir(path);
		 
 		 if (d != NULL)
		 {
		 
		 system("cd" d);
		 system("ls -F | grep /");
		
 		   while ((dir = readdir(d)) != NULL)
		   {
  		   // printf("%s\n", dir->d_name);
			
			if (strstr(dir->d_name, "." ) == 0){
			    sprintf(replyBuffer, "%s", dir->d_name) ;	//Assign replyBuffer string values of the directoryies/files
		 	   SSL_write(ssl, replyBuffer, strlen(replyBuffer));   //Send the buffer to the client
			}
 		   }
		   
 		   closedir(d);
 		 }
		SSL_write(ssl, "done", strlen("done"));			//Informs the client there are no more files
		}
	}
	else if ( strstr(buf, "QUIT") != NULL )
	{
		break;
	}
	else
	{
		sprintf(replyBuffer, "%s", "Un-supported Command");
		SSL_write(ssl, replyBuffer, strlen(replyBuffer));
	}

       }
     else
       {
	 ERR_print_errors_fp(stderr);
       }
   }
  }
     /* close connection */
}
