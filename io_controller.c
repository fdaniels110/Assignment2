#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "io_controller.h"

int retreive_agent_address(char *agent_addr){
	int validIP = 0;
	int tries = 0;

	do{
	
		if(tries > 4){
			printf("Too many attempts. Could not resolve address. Check code, "
	 			"check hosts file, or check IP and reattempt.\n");
			return 0;
		}

		printf("Enter address of agent: \n");

		if(scanf("%s", agent_addr) < 0){
			printf("Could not accept input.\n");
			tries++;
		}else{
			validIP = validateIP(agent_addr);
		}
	 }while(validIP != 0 && tries < 4);

	 if(tries == 4){
	 	return 0;
	 }
	 return 1;
}

int retreive_agent_port(){
	char *end;
	char port_buff[5];
	int port_num = 0;
	int tries = 0;

	do{
		printf("Enter agent port (enter defaults 161):\n");

		if(scanf("%s", port_buff) > 0){
			if(port_buff[0] == '\n'){
				port_num = 161;
			}else{
				port_num = strtoul(port_buff, &end, 10);
				if (port_num == 0){
					printf("Port number %s is invalid. \n", port_buff);
				}else if(errno == ERANGE){
					printf("Port number %s is too big. \n", port_buff);
				}
			}
		}else{
			printf("Could not receive input.\n");
		}
		tries++;

	}while(port_num == 0 && tries < 4);

	if(tries == 4){
		printf("Defaulting to port 161.\n" );
		return 161;
	}

	return port_num;
}

int retrieve_agent_community(char *community){

	int tries = 0;
	do{
		printf("Enter community name: \n");
		if( scanf("%s", community) < 0){
			printf("Could not accept inputed string. Try again.\n");
		}else{
			return 1;
		}
		tries++;
	}while(tries < 4);

	return 0;
}