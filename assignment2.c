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
void generate_oid(char *, oid *);

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
	//retrieving number of interfaces
	if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){

		vars = response->variables;
		
		if(vars->type == ASN_INTEGER){
			
			value = *(vars->val.integer);
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

	//begin retrieving Interfaces and their ips
	pdu = snmp_pdu_create(SNMP_MSG_GETBULK);

	size_t ifIndex_len, ifDescr_len;

	anOID_len = MAX_AGENT_LEN;
	
	pdu->non_repeaters = 0;
	pdu->max_repetitions = value;
	oid ifIndex[] = {1,3,6,1,2,1,4,20,1,2};
	
	oid ip_addr[] = {1,3,6,1,2,1,4,20,1,1};
		
	snmp_add_null_var(pdu, ifIndex, OID_LENGTH(ifIndex));
	snmp_add_null_var(pdu, ip_addr, OID_LENGTH(ip_addr));

	status = snmp_synch_response(ss, pdu, &response);
	//sending ifIndex and ipAdEntAddr
	if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){
		//char var1[30], var2[30];

		for(vars = response->variables; vars; vars = vars->next_variable){
			//print_variable(vars->name, vars->name_length, vars);
			if(vars->type == ASN_INTEGER){
					printf("Interface %d : ", *(vars->val.integer));
					//netsnmp_oid2str(var1, 30, vars->val.objid);
				}
			
			else if(vars->type == ASN_IPADDRESS){
				unsigned char *ipaddress = (unsigned char *) malloc(1 + vars->val_len);
				memcpy(ipaddress, vars->val.string, vars->val_len);
				int ip_array[vars->val_len], i;
				for(i = 0; i < vars->val_len; i++){
					ip_array[i] = ipaddress[i];
					if(i < vars->val_len - 1)
						printf("%d.",ip_array[i]);
					else
						printf("%d\n", ip_array[i]);
				}
			}
						
		}

		printf("-----------------------\n");
		
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

	//beginning getting first ipRouteDest
	pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
	oid ipRouteDest[] = {1,3,6,1,2,1,4,21,1,1};
	oid ipRouteIfIndex[] = {1,3,6,1,2,1,4,21,1,2};
	size_t ipRouteDest_len = MAX_AGENT_LEN;

	snmp_add_null_var(pdu, ipRouteDest, OID_LENGTH(ipRouteDest));
	snmp_add_null_var(pdu, ipRouteIfIndex, OID_LENGTH(ipRouteIfIndex));

	status = snmp_synch_response(ss, pdu, &response);

	int entry_num = 0;
	char buff[SPRINT_MAX_LEN];
	size_t next_oid_len;
	size_t ipRouteDest_oid_len = 21;

	//sending getnext ipRouteDest
	printf("IP Neighbors\n");
	if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){
		char ipRouteDestStr[30];
		vars = response->variables;
		if(vars->type == ASN_IPADDRESS){
			entry_num++;
			
			netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID,
								NETSNMP_DS_LIB_OID_OUTPUT_FORMAT,
								NETSNMP_OID_OUTPUT_NUMERIC);
			snprint_objid(buff, sizeof(buff), vars->name, vars->name_length);
			next_oid_len = vars->name_length;
			unsigned char *ipaddress = (unsigned char *) malloc(1 + vars->val_len);
			memcpy(ipaddress, vars->val.string, vars->val_len);
			int ip_array[vars->val_len];
			int i;
			printf("Address: ");
			for(i = 0; i < 4; i++){
				if(ipaddress[i] < 10){
					ipRouteDest_oid_len += 2;
				}else if(ipaddress[i] < 100){
					ipRouteDest_oid_len += 3;
				}else if(ipaddress[i] < 1000){
					ipRouteDest_oid_len += 4;
				}else if(ipaddress[i] < 10000){
					ipRouteDest_oid_len += 5;
				}
				ip_array[i] = ipaddress[i];
				if(i < 3)
						printf("%d.",ip_array[i]);
					else
						printf("%d ", ip_array[i]);
			}
			//printf("%d\n", ipRouteDest_oid_len);
			free(ipaddress);
		}
		vars = vars->next_variable;
		if(vars->type == ASN_INTEGER){
			printf("is on interface %d\n", *(vars->val.integer));
		}
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

	int mib_bool = 0;
	//getting rest of neighboring ips
	do{
		pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);

		char new_oid[ipRouteDest_oid_len];
		memcpy(new_oid, buff, ipRouteDest_oid_len);
		//printf("%s\n", new_oid);

		oid next_oid[next_oid_len];

		generate_oid(new_oid, next_oid);

		snmp_add_null_var(pdu, next_oid, OID_LENGTH(next_oid));

		status = snmp_synch_response(ss, pdu, &response);


		if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){


			char ipRouteDestStr[100];
			vars = response->variables;
			if(vars->type == ASN_IPADDRESS){
				mib_bool = 1;
				entry_num++;
			
				netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID,
								NETSNMP_DS_LIB_OID_OUTPUT_FORMAT,
								NETSNMP_OID_OUTPUT_NUMERIC);
				snprint_objid(buff, sizeof(buff), vars->name, vars->name_length);
				//printf("OID %s\n", buff);
				unsigned char *ipaddress = (unsigned char *) malloc(1 + vars->val_len);
				memcpy(ipaddress, vars->val.string, vars->val_len);
				int ip_array[vars->val_len];
				int i;
				printf("Address: ");
				ipRouteDest_oid_len = 21;
				for(i = 0; i < 4; i++){
					if(ipaddress[i] < 10){
						ipRouteDest_oid_len += 2;
					}else if(ipaddress[i] < 100){
						ipRouteDest_oid_len += 3;
					}else if(ipaddress[i] < 1000){
						ipRouteDest_oid_len += 4;
					}else if(ipaddress[i] < 10000){
						ipRouteDest_oid_len += 5;
					}
					ip_array[i] = ipaddress[i];
					if(i < 3)
						printf("%d.",ip_array[i]);
					else
						printf("%d\n", ip_array[i]);
				}
				//printf("%d\n", ipRouteDest_oid_len);
				//printf("Address: %d \n", ipaddress[0]);
				free(ipaddress);
			}else{
				//printf("did not get right type\n");
				netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID,
								NETSNMP_DS_LIB_OID_OUTPUT_FORMAT,
								NETSNMP_OID_OUTPUT_NUMERIC);
				snprint_objid(buff, sizeof(buff), vars->name, vars->name_length);
				printf("OID %s\n", buff);
				mib_bool = 0;
			}
		}else if(status == STAT_SUCCESS){
			fprintf(stderr, "Error in packet\nReason: %s\n",
					snmp_errstring(response->errstat));
		}else if (status == STAT_TIMEOUT){
			fprintf(stderr, "Timeout: No response from %s\n",
					session.peername);
		}else{
			printf("did not go to mib\n");
			snmp_sess_perror("assignment2", ss);
		}		

	}while (mib_bool == 1);

	if(response){
		snmp_free_pdu(response);
	}

	pdu = snmp_pdu_create(SNMP_MSG_GET);

	oid inMib[] = {1,3,6,1,2,1,2,2,1,10,1};
	oid outMIB[] = {1,3,6,1,2,1,2,2,1,16,1};

	snmp_add_null_var(pdu, inMib, OID_LENGTH(inMib));
	snmp_add_null_var(pdu, outMIB, OID_LENGTH(outMIB));

	status = snmp_synch_response(ss, pdu, &response);	
	long long stats[2];

	if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){
		int get_num = 0;
		
		struct counter64 *stats = (struct counter64 *) malloc(sizeof(struct counter64));
		for(vars = response->variables; vars; vars = vars->next_variable){
			//printf("Type: %d\n", vars->type);
			//memcpy(stats, vars->val.counter64, sizeof(struct counter64));
			//printf("counter: %lu", stats->low);
			if(vars->type == ASN_COUNTER){
				memcpy(stats, vars->val.counter64, sizeof(struct counter64));
				printf("counter: %lu", vars->val.counter64->high );
			}else{
				printf("did not get right type\n");
				netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID,
								NETSNMP_DS_LIB_OID_OUTPUT_FORMAT,
								NETSNMP_OID_OUTPUT_NUMERIC);
				snprint_objid(buff, sizeof(buff), vars->name, vars->name_length);
				printf("OID %s\n", buff);
			}
		}

	}else if(status == STAT_SUCCESS){
			fprintf(stderr, "Error in packet\nReason: %s\n",
					snmp_errstring(response->errstat));
	}else if (status == STAT_TIMEOUT){
		fprintf(stderr, "Timeout: No response from %s\n",
				session.peername);
	}else{
		printf("did not go to mib\n");
		snmp_sess_perror("assignment2", ss);
	}

	//long long counter1 = (long long) stats[0]->high << 32 | stats[0]->low;
	//printf("num %llu\n", counter1);

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

void generate_oid(char *new_oid, oid *next_oid){
	int string_index;
	int oid_num = 0;
	int oid_index = 0;
	for(string_index = 1; string_index < sizeof(new_oid); string_index++){
		if(new_oid[string_index] < ':' && new_oid[string_index] > '/'){
			oid_num = (oid_num * 10) + (new_oid[string_index] - '0');
		}else{
			next_oid[oid_index] = oid_num;
			oid_num = 0;
			oid_index++;
		}
	}
}