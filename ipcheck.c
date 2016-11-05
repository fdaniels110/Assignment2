/*
	Program to validate IPv4 address strings
	In the case that the IP address is not valid will retrun an array of possible addresses
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ipcheck.h"

/*//Args arg[1] = ipaddress string
 int main(int argc, char *argv[]) {
	
	validateIP(argv[1]);
	//validate_host_name("ala");
	return 0;
}*/


int validateIP(char *ipaddress){
	if( strlen(ipaddress) < 4 || strlen(ipaddress) > 18){
		printf("%s is not a valid IP address and cannot be parsed out. \n", ipaddress);
		return 1;
	}

	int currentIndex = 0;
	int validIp = 0;
	int currentOct = 0;
	do{
		if(ipaddress[currentIndex] > '/' && ipaddress[currentIndex] < ':'){
			if(currentOct > 25){
				printf("%s needs to be formated \n", ipaddress);
				//printf("%d currentOct, %d currentIndex \n",currentOct, currentIndex);
				validIp = 1;
			}else{
				currentOct = (currentOct * 10) + (ipaddress[currentIndex] - '0');
				//printf("%d currentOct, %d ipaddress \n",currentOct, (int) ipaddress[currentIndex] - '0');
				currentIndex++;
			}
		}else if(ipaddress[currentIndex] == '.' ){
			if(currentOct > 255){
				printf("%s needs to be formated \n", ipaddress);
				//printf("%d currentOct, %d currentIndex \n",currentOct, currentIndex);
				validIp = 1;
			}else{
				currentIndex = currentIndex + 2;
				currentOct = 0;
			}
		}else if(ipaddress[currentIndex] == '\n'){
			printf("%s is not a valid IP", ipaddress);
			validIp = 1;
		}else{
			//printf("%d currentOct %d currentIndex %lu size of ipaddress\n", currentOct, currentIndex, strlen(ipaddress));
			//printf("%s is not a valid IP address and cannot be parsed out. \n", ipaddress);
			int result = validate_host_name(ipaddress);
			if(result == 0){
				return 0;
			}
			validIp = 1;
		}
 
		if(strlen(ipaddress) == currentIndex && strlen(ipaddress) == 15){ 
			validIp = 1;	
			printf("%s is a valid IP \n", ipaddress);
			return 0;
		}
	}while(!validIp);

	return 1;

}

int validate_host_name(char *hostname){

	char buff[100];
	FILE *host;

	host = fopen("/etc/hostname", "r");

	if(host == NULL){

		perror("Can't open hostname file. Can't resolve hostnames.\n");
		return -1;

	}else{
		while(fgets(buff, 100, host) != NULL){
			int result = strncmp(buff, hostname, strlen(hostname));
			if(result == 0){
				//printf("Found %s\n", buff);
				return 0;
			}
		};

		printf("Could not find %s. Try IP.\n", hostname);
	}

	fclose(host);

	return 1;

}