#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "ipcheck.h"

#undef SNMP_VERSION_3



int main(int argc, char **argv){
	
	

	char agent_addr[30];

	if(retreive_agent_address(&agent_addr) == 0){
		exit(1);
	}

	int port_num;

	port_num = retreive_agent_port();
	
	if(port_num < 1){
		printf("An error occured retrieving port number. \n");
		exit(1);
	}

	char community[100];
	
	retrieve_agent_community(&community);



	netsnmp_session session, *ss;
	netsnmp_pdu *pdu;
	netsnmp_pdu *response;

	oid anOID[MAX_OID_LEN];
	size_t anOID_len;

	netsnmp_variable_list *vars;
	int status;
	int count = 1;

	init_snmp("snmpapp");

	snmp_sess_init(&session);
	session.peername = agent_addr;
	session.remote_port = port_num;
	session.version = SNMP_VERSION_1;
	session.community = community;
	session.community_len = strlen(session.community);

	ss = snmp_open(&session);

	if(!ss){

	}

	pdu = snmp_pdu_create(SNMP_MSG_GET);
	anOID_len = MAX_OID_LEN;
	if(!get_node("ifNumber.0", anOID, &anOID_len)){
		snmp_perror("ifNumber.0");
		exit(3);
	}

	snmp_add_null_var(pdu, anOID, anOID_len);

	status = snmp_synch_response(ss, pdu, &response);

	if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){

		vars = response->variables;
		
		if(vars->type == ASN_INTEGER){
			long value = *(vars->val.integer);
			//char *str = (char *)malloc(1 + vars->val_len);
			//memcpy(str, vars->val.string, vars->val_len);
			//str[vars->val_len] = '\0';
			printf("You have %d interfaces.\n", value);
			//free(str);
		}else{
			printf("Accessed an incorrect MIB");
		}
		
		//print_variable(vars->name, vars->name_length, vars);

	}else{
		if(status == STAT_SUCCESS){
			fprintf(stderr, "Error in packet\nReason: %s", 
					snmp_errstring(response->errstat));
		}else if(status == STAT_TIMEOUT){
			fprintf(stderr, "Timeout: No response from %s", 
					session.peername);
		}else{
			snmp_sess_perror("assignment2", ss);
		}
	}

	if(response){
		snmp_free_pdu(response);
	}
	snmp_close(ss);
}


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
