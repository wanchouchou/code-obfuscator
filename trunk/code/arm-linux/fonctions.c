#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>

void updateFct (unsigned char *ptr, int offsetInsertion, int addressInsertion, char saut, int nbLignes){
	int i;	
	for(i=0; i<nbLignes; i++){
		if((((int)*ptr>offsetInsertion) && ((int)*ptr<fileLengh)) || ((int)*ptr>addressInsertion)){
			*ptr+=codeLength;
		}
	ptr+=saut;
	}
}

void updateDynsym (unsigned char *ptr, int offsetInsertion, int addressInsertion){
	int size;
	size = shdrPtr[SCT_DYNSYM]->sh_size;
	size = size/16;
	ptr+=4; 
	updateFct (ptr, offsetInsertion, addressInsertion, 16, size);
}

void updateRelPlt (unsigned char *ptr, int offsetInsertion, int addressInsertion){
	int size;
	size = shdrPtr[SCT_RELPLT]->sh_size;
	size = size/8; 
	updateFct (ptr, offsetInsertion, addressInsertion, 8, size);
}

void updateRelPlt (unsigned char *ptr){
	*ptr+=codeLength;
}	

void updateDynamic (unsigned char *ptr, int offsetInsertion, int addressInsertion){
	int size;
	size = shdrPtr[SCT_DYNAMIC]->sh_size;
	size = (size-12)/8;
	ptr+=12; 
	updateFct (ptr, offsetInsertion, addressInsertion, 8, size);
}

void updatePlt (unsigned char *ptr, int offsetInsertion, int addressInsertion){
	int size;
	size = shdrPtr[SCT_PLT]->sh_size;
	size = (size-8)/8;
	ptr+=16; 
	updateFct (ptr, offsetInsertion, addressInsertion, 12, size);
}








