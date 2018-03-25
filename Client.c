#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define FAIL    -1
int OpenConnection(const char *hostname, int port)
{   
  int sd;
  struct hostent *host;
  struct sockaddr_in addr;
  if ( (host = gethostbyname(hostname)) == NULL )
    {
      perror(hostname);
      abort();
    }
  sd = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long*)(host->h_addr);
  if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
      close(sd);
      perror(hostname);
      abort();
    }
  return sd;
}
SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
  SSL_CTX *ctx;
  OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
  SSL_load_error_strings();   /* Bring in and register error messages */
  method = (SSL_METHOD *)TLSv1_2_client_method();  /* Create new client-method instance */
  ctx = SSL_CTX_new(method);   /* Create new context */
  if ( ctx == NULL )
    {
      ERR_print_errors_fp(stderr);
      abort();
    }
  return ctx;
}
void ShowCerts(SSL* ssl)
{   X509 *cert;
  char *line;
  cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
  if ( cert != NULL )
    {
      printf("Server certificates:\n");
      line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
      printf("Subject: %s\n", line);
      free(line);       /* free the malloc'ed string */
      line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
      printf("Issuer: %s\n", line);
      free(line);       /* free the malloc'ed string */
      X509_free(cert);     /* free the malloc'ed certificate copy */
    }
  else
    printf("Info: No client certificates configured.\n");
}
int main(int count, char *strings[])
{   SSL_CTX *ctx;
  int server;
  int option; 
  char requestBuffer[1024];
  SSL *ssl;
  char buf[1024];
  char acClientRequest[1024] ={0};
  int bytes;
  char *hostname, *portnum;
  char dirName[1024];
  if ( count != 3 )
    {
      printf("usage: %s <hostname> <portnum>\n", strings[0]);
      exit(0);
    }
  SSL_library_init();
  hostname=strings[1];
  portnum=strings[2];
  ctx = InitCTX();
  server = OpenConnection(hostname, atoi(portnum));
  ssl = SSL_new(ctx);      /* create new SSL connection state */
  SSL_set_fd(ssl, server);    /* attach the socket descriptor */
  if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
    ERR_print_errors_fp(stderr);
  else
    {  
        char acUsername[16] ={0};
        char acPassword[16] ={0};
	const char *cpRequestMessage = "<Body><UserName>%s<UserName><Password>%s<Password></Body>"; 

 	printf("Enter the User Name : ");
	scanf("%s",acUsername);

 	printf("\n\nEnter the Password : ");
 	scanf("%s",acPassword);

 	sprintf(acClientRequest, cpRequestMessage, acUsername,acPassword);   /* construct reply */
 	printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));

 	ShowCerts(ssl);        /* get any certs */

 	SSL_write(ssl,acClientRequest, strlen(acClientRequest));   /* encrypt & send message */
	bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
 	buf[bytes] = 0;

 	printf("Received: \"%s\"\n", buf);

 	while (1){
		printf("enter option: \n");
		printf("0-quit \n");
		printf("1-list files \n");
		printf("2-recieve file \n");
		scanf("%d", &option);

		switch(option)
		{

		case 0:
			printf("Close connection \n");
			sprintf(requestBuffer, "QUIT");
			count = SSL_write(ssl,requestBuffer, strlen(requestBuffer));
			printf("Sent %d bytes\n", count);
			break;			

		case 1: 
			printf("listing files \n");
			printf("Please enter directory name: ");
			scanf("%s", dirName);
			sprintf(requestBuffer, "LIST %s", dirName);
			count = SSL_write(ssl,requestBuffer, strlen(requestBuffer));
			//printf("Sent %d bytes\n", count);
			
			while (strstr(buf, "done") == 0){			 //Files will continue to be recieved until "done" is recieved.
				memset(buf, 0, sizeof(buf));                     /* Make sure that the recieve buffer is clean */
				bytes = SSL_read(ssl, buf, sizeof(buf));	 //reads the buffer sent from server
				printf("[%s] \n", buf);
			}
			memset(buf, 0, sizeof(buf));
			break;

		case 2:
			printf("Recieving files \n");
			sprintf(requestBuffer, "GETF test");
			count = SSL_write(ssl,requestBuffer, strlen(requestBuffer));
			printf("Sent %d bytes\n", count);		
			memset(buf, 0, sizeof(buf));                     /* Make sure that the recieve buffer is clean */
			bytes = SSL_read(ssl, buf, sizeof(buf));
			printf("Recieved %d bytes [%s] \n", bytes, buf);			
		break;

		default: 
		printf("Un-supported option \n");
		break; 	

		}
		if ( option == 0 )
		{
			break;
		}
 }
 SSL_free(ssl);        /* release connection state */
    }
  close(server);         /* close socket */
  SSL_CTX_free(ctx);        /* release context */
  return 0;
}
