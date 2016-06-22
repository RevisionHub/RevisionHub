#include <sys/stat.h>
#include <sys/file.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#define CERT_FOLDER "/home/harlan/website_ssl/"
#define MAX_PACKET_SIZE (1024*1024)
#ifdef VERBOSE_ALL
	#define VERBOSE_INFO
	#define VERBOSE_WARN
	#define VERBOSE_ERR
	#define VERBOSE_COMM
#endif
#ifdef VERBOSE_NOINFO
	#define VERBOSE_WARN
	#define VERBOSE_ERR
	#define VERBOSE_COMM
#endif
#ifdef VERBOSE_INFO
void info(char * s,...)
{
	printf("%-8c",'I');
	va_list args;
	va_start(args,s);
	vprintf(s,args);
	va_end(args);
	printf("\n");
}
#else
void info(char * s,...){}
#endif
#ifdef VERBOSE_WARN
void warn(char * s,...)
{
	printf("%-8c",'W');
	va_list args;
	va_start(args,s);
	vprintf(s,args);
	va_end(args);
	printf("\n");
}
#else
void warn(char * s,...){}
#endif
#ifdef VERBOSE_ERR
void err(char * s,...)
{
	printf("%-8c",'E');
	va_list args;
	va_start(args,s);
	vprintf(s,args);
	va_end(args);
	printf("\n");
}
#else
void err(char * s,...){}
#endif
void crit(int exitcode,char * s,...)
{
	printf("%-8c",'C');
	va_list args;
	va_start(args,s);
	vprintf(s,args);
	va_end(args);
	printf("\n");
	exit(exitcode);
}
#ifdef VERBOSE_COMM
void logsend(int s,unsigned short n)
{
	printf("> %-6i[%x]\n",n,s);
}
void logrec(int s,unsigned short n)
{
	printf("< %-6i[%x]\n",n,s);
}
#else
void logsend(int s,unsigned short n){}
void logrec(int s,unsigned short n){}
#endif
typedef enum Daemon_enum
{
	Meta,
	Backend,
	Disk,
	User,
	Page,
	Log,
	Cli,
	Pattern
} Daemon;
#define DAEMON_ENUM_LENGTH 8 
char* daemon_c(Daemon d, char * buffer)
{
	switch (d)
	{
		case Meta: strcpy(buffer,"Meta"); return buffer;
		case Backend: strcpy(buffer,"Backend"); return buffer;
		case Disk: strcpy(buffer,"Disk"); return buffer;
		case User: strcpy(buffer,"User");return buffer;
		case Page: strcpy(buffer,"Page"); return buffer;
		case Log: strcpy(buffer,"Log"); return buffer;
		case Cli: strcpy(buffer,"Cli"); return buffer;
		case Pattern: strcpy(buffer,"Pattern"); return buffer;
	}
}
typedef enum PayloadVerb_enum
{
	Get,
	GotPage,
	GotFile,
	Res404,
	Post,
	GotPost
}PayloadVerb;
typedef struct Packet_struct
{
	int payloadsize __attribute__((__packed__));
	PayloadVerb payloadverb __attribute__((__packed__));
	unsigned char payload[0];
} Packet;
#define PACKET_HEADER_SIZE sizeof(Packet)
char* daemon_file(Daemon d, char * buffer)
{
	char buffer2[16];
	sprintf(buffer,"/tmp/%s_Copelands_2016",daemon_c(d,buffer2));
	return buffer;
}
void write_packet(int fd, Packet * packet)
{
	flock(fd,LOCK_EX);
	int r = write(fd, packet, PACKET_HEADER_SIZE + packet->payloadsize);
	if(r == -1) err("Could not write to FIFO %x", fd); else logsend(fd,r);
	flock(fd,LOCK_UN);
}
void read_packet (int fd, Packet * buffer)
{
	int r = read(fd,buffer,PACKET_HEADER_SIZE);
	if (r == -1) return err("Could not read from FIFO [%x]", fd);
	int r2 = read(fd,buffer->payload,buffer->payloadsize);
	if (r2 == -1) return err("Could not read FIFO [%x] on second pass",fd);
	logrec(fd,r+r2);
}
void deletePipe(int fd,Daemon d)
{
	warn("Deleting FIFO [%x]",fd);
	char file[256];
	close(fd);
	if (remove(daemon_file(d,file))==-1) err("\tCould not delete FIFO");
}
int createPipe(Daemon d)
{
	char file[256];
	daemon_file(d,file);
	info("Creating FIFO %s", file);
	//ignore if it is already created, becuase we don't care
	if (mkfifo(file,0666)) warn("FIFO %s already created", file);
	//this we do care about, but if it doesn't work, there is nothing we can do
	int fd = open(file,0666);
	if (fd == -1) err("FIFO cannot be opened"); else info("Opening FIFO %s [%x]", file, fd); 
	return fd;
}