#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "ipcheck.h"
#include "io_controller.h"

#undef SNMP_VERSION_3

#define MAX_AGENT_LEN 30
#define MAX_COMMUNITY_LEN 100

struct session_info {
		char *agent;
		int port_num;
		char *community;
};

void get_user_data(struct session_info *);

int main(int argc, char **argv){
	
	struct session_info agent;

	get_user_data(&agent);

	netsnmp_session *ss;

	netsnmp_session session;

	init_snmp("snmpapp");

	snmp_sess_init(&session);
	session.peername = agent.agent;
	session.remote_port = agent.port_num;
	session.version = SNMP_VERSION_2c;
	session.community = agent.community;
	session.community_len = strlen(session.community);

	ss = snmp_open(&session);

	if(!ss){
		snmp_perror("ack");
		snmp_log(LOG_ERR, "Connection error");
		exit(2);
	}

	netsnmp_pdu *pdu;
	netsnmp_pdu *response;

	oid anOID[MAX_OID_LEN];
	size_t anOID_len;

	netsnmp_variable_list *vars;
	int status;

	pdu = snmp_pdu_create(SNMP_MSG_GET);
	anOID_len = MAX_OID_LEN;
	if(!get_node("ifNumber.0", anOID, &anOID_len)){
		snmp_perror("ifNumber.0");
		exit(3);
	}

	snmp_add_null_var(pdu, anOID, anOID_len);

	status = snmp_synch_response(ss, pdu, &response);

	long value;

	if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){

		vars = response->variables;
		
		if(vars->type == ASN_INTEGER){
			
			value = *(vars->val.integer);
			//char *str = (char *)malloc(1 + vars->val_len);
			//memcpy(str, vars->val.string, vars->val_len);
			//str[vars->val_len] = '\0';
			printf("You have %d interfaces:\n", value);
			printf("-----------------------\n");
			//free(str);
		}else{
			printf("Wrong datatype for MIB\n");
		}
		
		//print_variable(vars->name, vars->name_length, vars);

	}else{
		if(status == STAT_SUCCESS){
			fprintf(stderr, "Error in packet\nReason: %s", 
					snmp_errstring(response->errstat));
		}else if(status == STAT_TIMEOUT){
			fprintf(stderr, "Timeout: No response from %s", 
					agent.agent);
		}else{
			snmp_sess_perror("assignment2", ss);
		}
	}

	if(response){
		snmp_free_pdu(response);
	}

	pdu = snmp_pdu_create(SNMP_MSG_GETBULK);

	//oid ifIndex[MAX_OID_LEN], ifDescr[MAX_OID_LEN];
	size_t ifIndex_len, ifDescr_len;

	anOID_len = MAX_AGENT_LEN;
	
	pdu->non_repeaters = 0;
	pdu->max_repetitions = value;
	oid ifIndex[] = {1,3,6,1,2,1,2,2,1,1};
	
	oid ifDescr[] = {1,3,6,1,2,1,2,2,1,2};
		
	snmp_add_null_var(pdu, ifIndex, OID_LENGTH(ifIndex));
	snmp_add_null_var(pdu, ifDescr, OID_LENGTH(ifDescr));

	status = snmp_synch_response(ss, pdu, &response);

	if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){
		//char var1[30], var2[30];

		for(vars = response->variables; vars; vars = vars->next_variable){
			//print_variable(vars->name, vars->name_length, vars);
			if(vars->type == ASN_INTEGER){
					printf("Interface %d : is named ", *(vars->val.integer));
					//netsnmp_oid2str(var1, 30, vars->val.objid);
				}
			
			else if(vars->type == ASN_OCTET_STR){
					char *descr = (char *) malloc(1 + vars->val_len);
					memcpy(descr, vars->val.string, vars->val_len);
					descr[vars->val_len] = '\0';
					printf("%s.\n", descr);
					free(descr);
					//netsnmp_oid2str(var2, 30, vars->val.objid);
			}
						
		}
		
	}else{
		if(status == STAT_SUCCESS){
			fprintf(stderr, "Error in packet\nReason: %s\n",
				snmp_errstring(response->errstat));
		}else if(status == STAT_TIMEOUT){
			fprintf(stderr, "Timeout: No response from %s\n",
				session.peername );
		}else{
			snmp_sess_perror("assignment2", ss);
		}
	}

	if(response){
		snmp_free_pdu(response);
	}

	pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
	oid ipRouteDest[] = {1,3,6,1,2,1,4,21,1,1,0,0,0,0};
	size_t ipRouteDest_len = MAX_AGENT_LEN;

	snmp_add_null_var(pdu, ipRouteDest, OID_LENGTH(ipRouteDest));

	status = snmp_synch_response(ss, pdu, &response);

	if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){

		char ipRouteDestStr[30];

		vars = response->variables;
		printf("datatype String? %d\n", (vars->type == ASN_IPADDRESS));
		printf("length: %d\n", vars->val_len);
		unsigned long obj = *(vars->val.objid);
		printf("OID %d\n", obj);
		unsigned char *ipaddress = (unsigned char *) malloc(1 + vars->val_len);
		memcpy(ipaddress, vars->val.string, vars->val_len);
		int ip_array[4];
		int i;
		printf("Address: ");
		for(i = 0; i < 4; i++){
			ip_array[i] = ipaddress[i];
			printf("%d,",ip_array[i]);
		}
		printf("\n");
		//printf("Address: %d \n", ipaddress[0]);
		free(ipaddress);
	}else if(status == STAT_SUCCESS){
		fprintf(stderr, "Error in packet\nReason: %s\n",
				snmp_errstring(response->errstat));
	}else if (status == STAT_TIMEOUT){
		fprintf(stderr, "Timeout: No response from %s\n",
				session.peername);
	}else{
		snmp_sess_perror("assignment2", ss);
	}

	if(response){
		snmp_free_pdu(response);
	}

	snmp_close(ss);
}

void get_user_data(struct session_info *agent){

	char *agent_addr = (char *) malloc(MAX_AGENT_LEN);
	if(retreive_agent_address(agent_addr) == 0){
		exit(1);
	}

	agent->agent = agent_addr;

	int port_num;
	port_num = retreive_agent_port();	
	if(port_num < 1){
		printf("An error occured retrieving port number. \n");
		exit(1);
	}
	agent->port_num = port_num;

	char *community = (char *) malloc(MAX_COMMUNITY_LEN);	
	retrieve_agent_community(community);
	agent->community = community;
}