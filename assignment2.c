/**
	Author: Frank Daniels
	Purpose: Act as an Management System that can only view information and make poll requests.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "ipcheck.h"
#include "io_controller.h"

#undef SNMP_VERSION_3

#define MAX_AGENT_LEN 30
#define MAX_COMMUNITY_LEN 100

//Used to pass information from get_user_info method to main method
struct session_info {
	char *agent;
	int port_num;
	char *community;
};

struct poll_input {
	int num_of_polls;
	int sec_per_poll;
};

void get_user_data(struct session_info *);
void generate_oid(char *, oid *, size_t);
void get_polling_data(struct poll_input *);
int resolve_ip_string(unsigned char *);

unsigned long packet_diff(unsigned long, unsigned long);

int main(int argc, char **argv){
	
	struct session_info agent;

	get_user_data(&agent);

	netsnmp_session *ss, session;

	//Initiate Session
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

	//Begin Getting Number of Interfaces
	netsnmp_pdu *pdu, *response;

	oid number_of_interfaces_oid[MAX_OID_LEN];
	size_t number_of_interfaces_oid_len;

	netsnmp_variable_list *vars;
	int status;

	pdu = snmp_pdu_create(SNMP_MSG_GET);
	number_of_interfaces_oid_len = MAX_OID_LEN;

	if(!get_node("ifNumber.0", number_of_interfaces_oid, &number_of_interfaces_oid_len)){
		snmp_perror("ifNumber.0");
		exit(3);
	}

	snmp_add_null_var(pdu, number_of_interfaces_oid, number_of_interfaces_oid_len);

	status = snmp_synch_response(ss, pdu, &response);
	//stores number of interfaces
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

	//begin retrieving Interfaces and their IPs
	pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
	pdu->non_repeaters = 0;
	pdu->max_repetitions = value;

	oid ifIndex[] = {1,3,6,1,2,1,4,20,1,2};		
	oid ip_addr[] = {1,3,6,1,2,1,4,20,1,1};
		
	snmp_add_null_var(pdu, ifIndex, OID_LENGTH(ifIndex));
	snmp_add_null_var(pdu, ip_addr, OID_LENGTH(ip_addr));

	status = snmp_synch_response(ss, pdu, &response);
	//sending ifIndex and ipAdEntAddr
	if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){
		

		for(vars = response->variables; vars; vars = vars->next_variable){
			
			if(vars->type == ASN_INTEGER){
					printf("Interface %d : ", *(vars->val.integer));
				}
			
			else if(vars->type == ASN_IPADDRESS){
				unsigned char *ipaddress = (unsigned char *) malloc(1 + vars->val_len);
				memcpy(ipaddress, vars->val.string, vars->val_len);
				resolve_ip_string(ipaddress);
				printf("\n");
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

	//Getting first ipRouteDest

	int mib_bool = 0;
	int first_run = 0;

	oid ipRouteDest[] = {1,3,6,1,2,1,4,21,1,1};
	oid ipRouteIfIndex[] = {1,3,6,1,2,1,4,21,1,2};

	oid next_ipRouteDest[MAX_OID_LEN];
	oid next_ipRouteIfIndex[MAX_OID_LEN];

	char buffipRouteDest[SPRINT_MAX_LEN];
	char buffipRouteIfIndex[SPRINT_MAX_LEN];

	size_t ipRouteDest_oid_len;

	printf("IP Neighbors\n");

	//loop for getting all neighbors
	do{
		pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);

		//Only assigns next OIDs if first run is completed since values won't be correct until after first loop.
		if(first_run == 0){
			snmp_add_null_var(pdu, ipRouteDest, OID_LENGTH(ipRouteDest));
			snmp_add_null_var(pdu, ipRouteIfIndex, OID_LENGTH(ipRouteIfIndex));
		}else{
			//generates new OIDs using previous loops string values
			generate_oid(buffipRouteDest, next_ipRouteDest, ipRouteDest_oid_len);
			generate_oid(buffipRouteIfIndex, next_ipRouteIfIndex, ipRouteDest_oid_len);
			snmp_add_null_var(pdu, next_ipRouteDest, OID_LENGTH(next_ipRouteDest));
			snmp_add_null_var(pdu, next_ipRouteIfIndex,OID_LENGTH(next_ipRouteIfIndex));
		}

		status = snmp_synch_response(ss, pdu, &response);

		//length of OID before INDEX
		ipRouteDest_oid_len = 21;

		//Condition for loop. Checks if beginning to pass intended values;
		if(strcmp(buffipRouteIfIndex, ".1.3.6.1.2.1.4.21.1.3")){
			mib_bool = 0;
		}

		//sending getnext ipRouteDest
		
		if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){

			char ipRouteDestStr[100];
			vars = response->variables;
			if(vars->type == ASN_IPADDRESS){
				mib_bool = 1;
				first_run = 1;

				//resolves OID to full string to be paresd by resolve_ip_string and for generating next OID lengths
				netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID,
								NETSNMP_DS_LIB_OID_OUTPUT_FORMAT,
								NETSNMP_OID_OUTPUT_NUMERIC);
				snprint_objid(buffipRouteDest, sizeof(buffipRouteDest), vars->name, vars->name_length);
				unsigned char *ipaddress = (unsigned char *) malloc(1 + vars->val_len);
				memcpy(ipaddress, vars->val.string, vars->val_len);
				ipRouteDest_oid_len += resolve_ip_string(ipaddress);
				free(ipaddress);
			}
			vars = vars->next_variable;
			if(vars->type == ASN_INTEGER && mib_bool == 1){
				printf(" is on interface %d\n", *(vars->val.integer));

				//resolves to string for next loop
				netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID,
									NETSNMP_DS_LIB_OID_OUTPUT_FORMAT,
									NETSNMP_OID_OUTPUT_NUMERIC);
				snprint_objid(buffipRouteIfIndex, sizeof(buffipRouteIfIndex), vars->name, vars->name_length);
			}
		}else if(status == STAT_SUCCESS){
			fprintf(stderr, "Error in packet\nReason: %s\n",
					snmp_errstring(response->errstat));
		}else if (status == STAT_TIMEOUT){
			fprintf(stderr, "Timeout: No response from %s\n",
					session.peername);
		}else{
			printf("Can't reach session.\n");
			snmp_sess_perror("assignment2", ss);
		}

		if(response){
			snmp_free_pdu(response);
		}

	}while(mib_bool == 1);

	printf("-----------------------\n");

	oid inMib[] = {1,3,6,1,2,1,2,2,1,10};
	oid outMIB[] = {1,3,6,1,2,1,2,2,1,16};
	oid ifDescr[] = {1,3,6,1,2,1,2,2,1,2};
	oid ififIndex[] = {1,3,6,1,2,1,2,2,1,1};
	
	time_t previous;
	time_t next;

	struct poll_input data_rate = {0,0};

	//calls io_controller for inputs for polling
	get_polling_data(&data_rate);

	//used for determining if first round 
	int runs = 0;

	unsigned long in_prev[value]; 
	unsigned long in_next[value];
	unsigned long out_prev[value];
	unsigned long out_next[value];

	//Begin polling loop
	do{

		pdu = snmp_pdu_create(SNMP_MSG_GETBULK);

		snmp_add_null_var(pdu, ififIndex, OID_LENGTH(ififIndex));
		snmp_add_null_var(pdu, inMib, OID_LENGTH(inMib));
		snmp_add_null_var(pdu, outMIB, OID_LENGTH(outMIB));

		pdu->non_repeaters = 0;
		pdu->max_repetitions = value;

		status = snmp_synch_response(ss, pdu, &response);

		//checks for time.
		do{
			time(&next);

		}while(runs > 0 && difftime(next, previous) < data_rate.sec_per_poll);

		int inswitch = 0;	

		//Data retrieval
		if(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){
			int interface = 0;
			
			for(vars = response->variables; vars; vars = vars->next_variable){
				
				if(vars->type == ASN_INTEGER){
					interface = *(vars->val.integer);
					
					if(runs > 0){
						printf("\nPoll:%d\n", runs);
						printf("Interface %d:\n", interface);

					}
				}

				if(vars->type == ASN_COUNTER){
					//Switches between the two as they occur right after another in variable_list
					if(inswitch == 0){
						in_next[interface] = *(vars->val.integer);

						if(runs > 0){
							unsigned long diff = packet_diff(in_next[interface],in_prev[interface]);
							double bits_per_sec = ((double)(diff*8)/data_rate.sec_per_poll)/1000000;
							printf("In %.2fMb/s\n", bits_per_sec);
						}
						in_prev[interface] = in_next[interface];
						inswitch = 1;

;					}else{
						out_next[interface] = *(vars->val.integer);

						if(runs > 0){
							unsigned long diff = packet_diff(out_next[interface],out_prev[interface]);
							//printf(" Dif: %lu\n", diff);
							double bits_per_sec = ((double)(diff*8)/data_rate.sec_per_poll)/1000000;
							printf("Out: %.2fMb/s\n", bits_per_sec);
						}
						out_prev[interface] = out_next[interface];
						inswitch = 0;
					}
				}
			}

			runs++;

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

		if(response){
			snmp_free_pdu(response);
		}

		

		time(&previous);

	}while(runs < data_rate.num_of_polls);

	snmp_close(ss);
}


/*
	METHOD: get_user_data(struct session_info*)
	PURPOSE: retrieve user input for use. 
*/
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

/*
	METHOD:generate_oid(char *, oid *, size_t)
	PURPOSE: Used to retrieve oid from new_oid and exports to oid array next_ipRouteDest
*/
void generate_oid(char *new_oid, oid *next_ipRouteDest, size_t size){
	int string_index;
	int oid_num = 0;
	int oid_index = 0;
	for(string_index = 1; string_index < size; string_index++){
		if(new_oid[string_index] < ':' && new_oid[string_index] > '/'){
			oid_num = (oid_num * 10) + (new_oid[string_index] - '0');
		}else{
			next_ipRouteDest[oid_index] = oid_num;
			oid_num = 0;
			oid_index++;
		}
		//printf("%d \n", string_index);
	}
}

/*
	METHOD:resolve_ip_string(unsigned char*)
	PURPOSE: Prints out IP and return lendth of ip
*/

int resolve_ip_string(unsigned char *ipaddress){
	int ip_mib_length = 0;

	printf("Address: ");
	int i;
	for(i = 0; i < 4; i++){
		if(ipaddress[i] < 10){
			ip_mib_length += 2;
		}else if(ipaddress[i] < 100){
			ip_mib_length += 3	;
		}else if(ipaddress[i] < 1000){
			ip_mib_length += 4;
		}else if(ipaddress[i] < 10000){
			ip_mib_length += 5;
		}
		if(i < 3)
			printf("%u.",ipaddress[i]);
		else
			printf("%u", ipaddress[i]);
	}
	return ip_mib_length;
}

/*
	METHOD: get_polling_data(struct poll_input*)
	PURPOSE: Uses io_controller to retrieve user input and return poll data
*/
void get_polling_data(struct poll_input *input){

	input->num_of_polls = retrieve_poll_number();
	input->sec_per_poll = retrieve_poll_rate();
}
/*
	METHOD:packet_diff(unsigned long, unsigned long)
	PURPOSE: method to subtract two unsigned longs and cause no overflow. 
*/
unsigned long packet_diff(unsigned long val1, unsigned long val2){
	//printf("VALUE New: %lu, VALUE Old: %lu", val1, val2);
	unsigned long max_counter = 4294967295;
	unsigned long returnval;
	if((val1 - val2) < 0){
		returnval = (max_counter - val2) + val1;
	}else{
		returnval =  val1 - val2;
	}
	//printf(" DIFF: %lu", returnval);
	return returnval;
}