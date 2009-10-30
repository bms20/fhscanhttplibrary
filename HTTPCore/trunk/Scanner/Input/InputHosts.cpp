#include "../FHScan.h"
#include "InputHosts.h"
#include "../estructuras.h"
#ifdef XML_LIBRARY
#include "xmlParser.h"
#endif
//#pragma comment(lib, "xmlParser.lib")

PTARGETS targets = NULL;
unsigned int		ntargets = 0;
extern int          nports;
extern struct       _ports ports[MAX_PORTS];

/******************************************************************************/
int AddNewTarget(unsigned long ip, char *hostname, int port, int ssl)
{
	struct sockaddr_in iip;
	iip.sin_addr.s_addr = htonl((long)ip);
	//printf("Añadido: %s\n",inet_ntoa(iip.sin_addr));

	targets = (PTARGETS) realloc(targets,sizeof(TARGETS)*(ntargets+1));
	if (ip == 0) {
		targets[ntargets].hostname = strdup(hostname);
	} else {
		targets[ntargets].hostname = NULL;
		targets[ntargets].currentip = ip;
	}
	targets[ntargets].port=port;
	targets[ntargets].ssl=ssl;
	ntargets++;
	return(ntargets);
}

/******************************************************************************/
#ifdef XML_LIBRARY
int ParseNmapXMLFile(char *lpFilename)
{
	int status=1;
	XMLNode xMainNode=XMLNode::openFileHelper(lpFilename,NULL, &status);

	if (status == 0)
	{
		return(0);
	}

	XMLNode xNode=xMainNode.getChildNode("nmaprun");
	printf("[+] Datos. %s\n",xNode.getAttribute("args"));

	int nHosts = xNode.nChildNode("host");
	printf("[+] Se han encontrado %i hosts\n",nHosts);

	for (int i=0;i<nHosts; i++) 
	{
		int nports = xNode.getChildNode("host",i).getChildNode("ports").nChildNode("port");

		printf("Host: %s (%i opened ports)\n",
			xNode.getChildNode("host",i).getChildNode("address",0).getAttribute("addr"), nports);

		if (nports > 0) {
			for (int j = 0; j<nports; j++) {
				//verificar si es tcp
				if (strcmp(xNode.getChildNode("host",i).getChildNode("ports").getChildNode("port",j).getAttribute("protocol"),"tcp")==0)
				{
					//verificar si esta open
					if (strcmp(xNode.getChildNode("host",i).getChildNode("ports").getChildNode("port",j).getChildNode("state").getAttribute("state"),"open")==0)
					{						
						//verificar si existe la descripcion del tipo de protocolo
						if (xNode.getChildNode("host",i).getChildNode( "ports").getChildNode("port",j).getChildNode("service").isAttributeSet("name"))
						{						
							//verificar si es HTTP o HTTPS
							if ( (strcmp(xNode.getChildNode("host",i).getChildNode("ports").getChildNode("port",j).getChildNode("service").getAttribute("name"),"http")==0) ||
								(strcmp(xNode.getChildNode("host",i).getChildNode("ports").getChildNode("port",j).getChildNode("service").getAttribute("name"),"https")==0))
							{
								if (!targets) targets = (PTARGETS) malloc(sizeof(TARGETS));
								else targets = (PTARGETS) realloc(targets, (ntargets +1) *sizeof(TARGETS) );
								targets[ntargets].hostname = strdup(xNode.getChildNode("host",i).getChildNode("address",0).getAttribute("addr"));
								targets[ntargets].port=atoi(xNode.getChildNode("host",i).getChildNode("ports").getChildNode("port",j).getAttribute("portid"));
								targets[ntargets].ssl = (strcmp(xNode.getChildNode("host",i).getChildNode("ports").getChildNode("port",j).getChildNode("service").getAttribute("name"),"https")==0);
								ntargets++;

								printf("  Port %s - %s\n",xNode.getChildNode("host",i).getChildNode("ports").getChildNode("port",j).getChildNode("service").getAttribute("name"),xNode.getChildNode("host",i).getChildNode("ports").getChildNode("port",j).getAttribute("portid"));
							}
						}
					}
				}
			}
		}
	}


	for (unsigned int i=0;i<ntargets;i++)
	{
		printf("Host: %s\t%i - SSL: %i\n",targets[i].hostname,targets[i].port,targets[i].ssl);

	}
	return (ntargets);

}
#endif
/******************************************************************************/
int Parseipfile(FILE *ipfile)
{
	int total=0;
	char *p;
	char line[512];
	while (!feof(ipfile))
	{
		memset(line,'\0',sizeof(line));
		if ( ReadAndSanitizeInput(ipfile,line,sizeof(line)) )
		{
			p=strchr(line,':'); //search if the host has also an associated port
			if (!p) p=strchr(line,' ');
			if (!p) p=strchr(line,'\t');
			if (!p) p=strchr(line,0x09);

			if (p)
			{
				while ((*p==' ') || (*p==':') || (*p=='\t') || (*p==0x09) )
				{
					*p=0;
					p++;
				}
				AddNewTarget(0,line,atoi(p),0);
				total++;
			} else 
			{
				for(int k=0;k<nports;k++)
				{
					AddNewTarget(0,line,ports[k].port,ports[k].ssl);
					total++;
				}
			}
		}  else {
			fclose(ipfile);
			return(total);
		}		
	}
	return(total);
}
/******************************************************************************/
int ParseHosts( char *lphosts)
{
	char *p;
	int IP1[4];
	int IP2[4];
	int i;
	//	struct sockaddr_in ip1,ip2;
	unsigned long ipaddr=0;
	unsigned long endipaddr=0;
	int total = 0;


	char *chunk = strtok(lphosts,",");

	while (chunk!=NULL)
	{
		ipaddr = 0;
		endipaddr = 0;
		i = sscanf(chunk, "%d.%d.%d.%d", &IP1[0], &IP1[1], &IP1[2], &IP1[3]);
		if (i != 4) { //assume its a hostname
			for(int k=0;k<nports;k++)
			{
				AddNewTarget(0,chunk,ports[k].port,ports[k].ssl);
				total++;
			}
		} else 
		{
			for (i = 0; i < 4; i++) 
			{
				if (IP1[i] < 0 || IP1[i] > 255) {
					printf("Invalid IP Address");
					exit(1);
				}  
				ipaddr |= IP1[i] << 8*(3-i);
			} 
			if (p=strchr(chunk, '-'))
			{
				i = sscanf(p+1, "%d.%d.%d.%d", &IP2[0], &IP2[1], &IP2[2], &IP2[3]);
				switch (i)
				{
				case 0:
					exit(1);
				case 1:
					IP2[3]=IP2[0];
					IP2[2]=IP1[2];
					IP2[1]=IP1[1];
					IP2[0]=IP1[0];
					break;
				case 2:
					IP2[3]=IP2[1];
					IP2[2]=IP2[0];
					IP2[1]=IP1[1];
					IP2[0]=IP1[0];
					break;
				case 3:
					IP2[3]=IP2[2];
					IP2[2]=IP2[1];
					IP2[1]=IP2[0];
					IP2[0]=IP1[0];
					break;
				default:
					exit(1);
					for (i = 0; i < 4; i++)
					{
						if (IP2[i] < 0 || IP2[i] > 255) 
						{
							exit(1);
						}  
						endipaddr |= IP2[i] << 8*(3-i);
					}
					if (ipaddr > endipaddr)
					{
						exit(1);
					}

					do {
						for(int k=0;k<nports;k++)
						{
							AddNewTarget(ipaddr,NULL,ports[k].port,ports[k].ssl);
							total++;
						}
						ipaddr++;
					} while (ipaddr <= endipaddr);

				}
			} else 
			{
				for(int k=0;k<nports;k++)
				{
					AddNewTarget(ipaddr,NULL,ports[k].port,ports[k].ssl);
					total++;
				}
			}
		}
		chunk=strtok(NULL,",");
	}
	return(total);

}


/******************************************************************************/
int ReadAndSanitizeInput(FILE *file, char *buffer,int len) {
	//read a line from a file stream, and removes '\r' and '\n'
	//if the line is not a comment, true is returned
	fgets(buffer,len,file);
	buffer[len-1]='\0';
	unsigned int bufferSize = ( unsigned int ) strlen(buffer);
	if ( (bufferSize>3) && buffer[0]!='#'  && buffer[0]!=';'  ) {
		char *p=buffer+bufferSize-1;
		while ( (*p=='\r' ) || (*p=='\n') || (*p==' ') ) { p[0]='\0'; --p; }
		return(1);
	}
	return(0);
}
/******************************************************************************/


