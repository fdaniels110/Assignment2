#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "ipcheck.h"

#undef SNMP_VERSION_3

int main(int argc, char **argv){
	
	char agent_addr[20];
	int port_num;
	char community[100];


	do{
		printf("Enter address of agent:\n");

		scanf("%s", agent_addr);

	}while(validateIP(agent_addr) != 0);

	printf("Enter port agent listens on.(default 161)\n");

	if(scanf("%d", &port_num) < 0){
		port_num = 161;
	}

	printf("Enter community for agent.\n");

	scanf("%s", community);

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
		/*
		if(vars->type == ASN_INTEGER){
			//long value = *(vars->val.integer);
			char *str = (char *)malloc(1 + vars->val_len);
			memcpy(str, vars->val.string, vars->val_len);
			str[vars->val_len] = '\0';
			printf("You have %s interfaces.\n", str);
			free(str);
		}else{
			printf("Accessed an incorrect MIB");
		}
		*/
		print_variable(vars->name, vars->name_length, vars);

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