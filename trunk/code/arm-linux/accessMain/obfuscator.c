#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include "obfuscator.h"

FILE *exeFilePtr;             // pointer on the executable file
FILE *tmpFilePtr;             // pointer on the temporary file
FILE *endFilePtr;             // pointer on the modified file                      
unsigned char *tmpBuffer;     // char pointer on the temporary buffer
unsigned long fileLength;     // length of the executable
unsigned char *strPtr;        // char pointer to verify the section names
unsigned int codeLength;      // length of the injected code
Elf32_Shdr *shdrPtr[NB_SHDR]; // array of section header poiters
Elf32_Ehdr elfHdr;            // elf header of the executable

/* injects code into the file at a given offset */
void injectCode(Elf32_Off offset, Elf32_Word *hexcode){

   /* copy content to end file */
   int i;
   fseek(tmpFilePtr, 0, SEEK_SET);
   for(i=0; i<offset/BLOCK_SIZE; i++){ // copy first part of file by chunks of 1024 bytes
      fread(tmpBuffer, BLOCK_SIZE, 1, tmpFilePtr);
      fwrite(tmpBuffer, BLOCK_SIZE, 1, endFilePtr);
   }
   if(offset%BLOCK_SIZE!=0){ // copy the last non 1024 byte long chunk
      fread(tmpBuffer, offset%BLOCK_SIZE, 1, tmpFilePtr);
      fwrite(tmpBuffer, offset%BLOCK_SIZE, 1, endFilePtr);
   }

   for(i=0;i<codeLength/sizeof(Elf32_Word);i++)  // copy code
      fwrite((Elf32_Word*)&(hexcode[i]), sizeof(Elf32_Word), 1, endFilePtr);

   for(i=0; i<(fileLength-offset)/BLOCK_SIZE; i++){   // copy rest of file
      fread(tmpBuffer, BLOCK_SIZE, 1, tmpFilePtr);
      fwrite(tmpBuffer, BLOCK_SIZE, 1, endFilePtr);
   }
   if((fileLength-offset)%BLOCK_SIZE!=0){
      fread(tmpBuffer, (fileLength-offset)%BLOCK_SIZE, 1, tmpFilePtr);
      fwrite(tmpBuffer, (fileLength-offset)%BLOCK_SIZE, 1, endFilePtr);
   }
}

/* updates offsets and pointers */
void updateFct (unsigned int offset, unsigned int insertOff, unsigned int insertAddr, char jump, int nbEntries){
	int i;
	unsigned int *buffer;
   buffer=malloc(sizeof(int));	
	for(i=0; i<nbEntries; i++){
		fseek(tmpFilePtr, offset, SEEK_SET);
		fread(buffer, sizeof(int), 1, tmpFilePtr);
		if(((*buffer>insertOff) && (*buffer<fileLength)) || (*buffer>insertAddr)){
			*buffer+=codeLength;
			fseek(tmpFilePtr, offset, SEEK_SET);
			fwrite(buffer, sizeof(int), 1, tmpFilePtr);
		}
	offset+=jump;
	}
}

/* updates offsets and pointers of the .dynsym section */
void updateDynsym (unsigned int offset, unsigned int insertOff, unsigned int insertAddr){
	int nbEntries; // number of .dynsym entries
	nbEntries = shdrPtr[SCT_DYNSYM]->sh_size/DYNSYM_ENTRY_SIZE;
	offset+=4;  // the first offset to change is 4 bytes into the .dynsym section
	updateFct (offset, insertOff, insertAddr, DYNSYM_ENTRY_SIZE, nbEntries);
}

/* updates offsets and pointers of the .relplt section */
void updateRelPlt (unsigned int offset, unsigned int insertOff, unsigned int insertAddr){
	int nbEntries; // number of .relplt entries
	nbEntries = shdrPtr[SCT_REL_PLT]->sh_size/REL_PLT_ENTRY_SIZE; 
	updateFct (offset, insertOff, insertAddr, REL_PLT_ENTRY_SIZE, nbEntries);
}

/* updates offsets and pointers of the .got section */
void updateGot (unsigned int offset, unsigned int insertOff, unsigned int insertAddr){
	updateFct (offset, insertOff, insertAddr, 1, 1);
}	

/* updates offsets and pointers of the .dynamic section */
void updateDynamic (unsigned int offset, unsigned int insertOff, unsigned int insertAddr){
	int nbEntries; // number of .dynamic entries
	nbEntries = (shdrPtr[SCT_DYNAMIC]->sh_size-12)/DYNAMIC_ENTRY_SIZE;
	offset+=12;  // the first offset to change is 4 bytes into the .dynamic section
	updateFct (offset, insertOff, insertAddr, DYNAMIC_ENTRY_SIZE, nbEntries);
}

/* updates offsets and pointers of the .plt section*/
void updatePlt (unsigned int offset, unsigned int insertOff, unsigned int insertAddr){
	int nbEntries; // number of .plt entries
	int i;
	unsigned int *buffer;
	nbEntries = shdrPtr[SCT_PLT]->sh_size/4; 
	buffer=malloc(4);
	for(i=0; i<nbEntries; i++){
		fseek(tmpFilePtr, offset, SEEK_SET);
      // check if it is an address and if it is after the insertion address
		fread(buffer, sizeof(int), 1, tmpFilePtr);
		if(((*buffer>0x8000) && (*buffer<0x8fff)) ||
		((*buffer>0xe5bcf000) && (*buffer<0xe5bcffff)))
		{
			*buffer+=codeLength; // increment the address
			fseek(tmpFilePtr, offset, SEEK_SET);
			fwrite(buffer, sizeof(int), 1, tmpFilePtr); // write to the file
		}
	offset+=4;
	}
} 

/* updates offsets and pointers of the program header */
void updatePhdr(unsigned int offset, unsigned int insertOff, unsigned int insertAddr){
   int hdrSize, nbEntries;
   hdrSize=shdrPtr[SCT_INTERP]->sh_offset-elfHdr.e_ehsize;
   nbEntries=hdrSize/sizeof(int);
   updateFct (offset, insertOff, insertAddr, sizeof(int), nbEntries);
}

/* updates offsets and pointers of the elf header */
void updateElfHdr(){
   Elf32_Addr newShoff;
   newShoff=elfHdr.e_shoff+codeLength;
   fseek(tmpFilePtr, 0x20, SEEK_SET);
   fwrite(&newShoff, sizeof(Elf32_Addr), 1, tmpFilePtr);
}

/* updates offsets and pointers of the section headers */
void updateShdr(unsigned int insertOff, unsigned int insertAddr){
   int i;
   shdrPtr[SCT_TEXT]->sh_size+=codeLength; // update the size attribute
   fseek(tmpFilePtr, elfHdr.e_shoff+(SCT_TEXT+1)*sizeof(Elf32_Shdr), SEEK_SET);
   fwrite(shdrPtr[SCT_TEXT], sizeof(Elf32_Shdr), 1, tmpFilePtr);
   
   for(i=SCT_FINI; i<sizeof(shdrNames)/sizeof(int); i++){
      fseek(tmpFilePtr, elfHdr.e_shoff+(i+1)*sizeof(Elf32_Shdr), SEEK_SET);
      if(shdrPtr[i]->sh_addr>insertAddr){ // increments the address if it after 
         shdrPtr[i]->sh_addr+=codeLength;
      }
      if(shdrPtr[i]->sh_offset>insertOff){
         shdrPtr[i]->sh_offset+=codeLength;
      }
      fwrite(shdrPtr[i], sizeof(Elf32_Shdr), 1, tmpFilePtr);
   }
}

/* search main method */
unsigned int searchMain (){
	unsigned int location;
	int i;
	unsigned int *buffer;
	int nbEntries;
	unsigned int offset;
	offset = shdrPtr[SCT_TEXT]->sh_offset;
	nbEntries = shdrPtr[SCT_TEXT]->sh_size/4;
   	buffer=malloc(4);	
	for(i=0; i<nbEntries; i++){
		fseek(tmpFilePtr, offset, SEEK_SET);
		fread(buffer, sizeof(int), 1, tmpFilePtr);
		if(*buffer==MAIN_SEQ)
		{
			location=offset;
	      return location;
		}
	offset+=4; 
	}
   return 0;
}

/* updates offsets/pointers/instructions of the .text section */
void updateText (unsigned int offset, unsigned int insertOff, unsigned int insertAddr){
	unsigned int nbEntries;
	unsigned int i;
	unsigned int *buffer;
	unsigned int mainLocation;
	nbEntries = shdrPtr[SCT_TEXT]->sh_size/ARM_INSTRUCTION_SIZE; 
	mainLocation = searchMain();
   buffer=malloc(ARM_INSTRUCTION_SIZE);	
	for(i=0; i<nbEntries; i++){
		fseek(tmpFilePtr, offset, SEEK_SET);
		fread(buffer, sizeof(int), 1, tmpFilePtr);
		if(
		((*buffer>(insertOff+OFFSET_ID)) && (*buffer<(fileLength+OFFSET_ID))) || 
		((*buffer>insertAddr) && (*buffer<insertAddr+fileLength))||
		((*buffer>LDR_START) && (*buffer<LDR_STOP) && (offset>mainLocation))
		)
		{
			*buffer+=codeLength;
			fseek(tmpFilePtr, offset, SEEK_SET);
			fwrite(buffer, sizeof(int), 1, tmpFilePtr);
		}
	offset+=ARM_INSTRUCTION_SIZE;
	}
}


/* create necessary files and allocate memory */
int prepareFiles(unsigned char *exeFilename){

   /* open executable file */
   exeFilePtr = fopen(exeFilename,"rb");
   if(!exeFilePtr){
     fprintf(stderr, "Unable to open file!\n");
     return 0;
   }

   /* create temporary file */
   tmpFilePtr = fopen("tmp","w+b");
   if(!tmpFilePtr){
     fprintf(stderr, "Unable to create file!\n");
     return 0;
   }

   /* create end file */
   remove("obf");
   endFilePtr = fopen("obf","w+b");
   if(!endFilePtr){
     fprintf(stderr, "Unable to create end file!\n");
     return 0;
   }

   /* get the length of executable file */
   fseek(exeFilePtr, 0, SEEK_END);
   fileLength = ftell(exeFilePtr);
   fseek(exeFilePtr, 0, SEEK_SET);
     
   /* allocate memory for temporary buffer */
   tmpBuffer = malloc(BLOCK_SIZE);
   if(!tmpBuffer){
      fprintf(stderr, "Memory error!\n");
      fclose(exeFilePtr);
		return 0;
   }

   /* copy content to temporary file */
   int i;
   for(i=0; i<fileLength/BLOCK_SIZE; i++){
      fread(tmpBuffer, BLOCK_SIZE, 1, exeFilePtr);
      fwrite(tmpBuffer, BLOCK_SIZE, 1, tmpFilePtr);
   }
   if(fileLength%BLOCK_SIZE!=0){
      fread(tmpBuffer, fileLength%BLOCK_SIZE, 1, exeFilePtr);
      fwrite(tmpBuffer, fileLength%BLOCK_SIZE, 1, tmpFilePtr);
   }
   return 1;
}

/* copy all section headers to structures */
void copyShdrs(void){
   
   /* variable declaration */
   Elf32_Shdr strtabShdr, tmpShdr;  // string table section header, temporary section header
   Elf32_Word strtabIndex, strtabStart;   // string table index, string table start offset
   int i,j; // iterators to browse the executable

   /* fill the structures */
   fseek(tmpFilePtr, 0, SEEK_SET);
   fread(&elfHdr, 1, sizeof(Elf32_Ehdr), tmpFilePtr);
   if (elfHdr.e_shoff == 0) {
		fprintf(stderr, "Could not find sections!\n");
		return;
	}
	fseek(tmpFilePtr, elfHdr.e_shoff+(elfHdr.e_shnum-1)*sizeof(Elf32_Shdr), SEEK_SET);  // read the string table header
   fread(&strtabShdr, sizeof(char), sizeof(Elf32_Shdr), tmpFilePtr); // copy the string table header
   strtabStart=strtabShdr.sh_offset;
   j=0;
   for(i=1;i<elfHdr.e_shnum;i++){
      fseek(tmpFilePtr, elfHdr.e_shoff+i*sizeof(Elf32_Shdr), SEEK_SET); // browse every section header
      fread(&tmpShdr, sizeof(char), sizeof(Elf32_Shdr), tmpFilePtr);   // copy it in a temporary section header
      strtabIndex=tmpShdr.sh_name;  // save the index of the string table 
      fseek(tmpFilePtr, strtabStart+strtabIndex, SEEK_SET); // jump to the string table
      strPtr=malloc(15); // allocate space for the string pointer
      fread(strPtr, 1, 15, tmpFilePtr);   // read the string (15 bytes)
      for(j=0;j<sizeof(shdrNames)/sizeof(int);j++){
         if(!strcmp(strPtr, shdrNames[j])){  // compare the string with the array of strings shdrNames
            shdrPtr[j]=(Elf32_Shdr*)malloc(sizeof(Elf32_Shdr));   // allocate memory for each section header
            memcpy((void *)shdrPtr[j], (void *)(&tmpShdr), sizeof(Elf32_Shdr));  // copy each section header
            //printf("%d section %s of size %04x at offset %04x\n", j, shdrNames[j], shdrPtr[j]->sh_size, shdrPtr[j]->sh_offset);
         }
      }
   }  
}

/* close files and delete the temporary file */
void closeFiles(){
   fclose(exeFilePtr);
   fclose(tmpFilePtr);
   fclose(endFilePtr);
   free(tmpBuffer);
   free(strPtr);
   int i;
   for(i=0;i<sizeof(shdrNames)/sizeof(int);i++)
      free(shdrPtr[i]);
   remove("tmp");
}


int main(int argc, char *argv[]){

   /* variable declaration */
   Elf32_Word hexcode[8]={0xe51b3010, 0xe2833001, 0xe50b3010, 0xe51b2010, 0xe1a03002, 0xe1a03083, 0xe0833002, 0xe50b3010};
   codeLength=sizeof(hexcode)/sizeof(Elf32_Word);
   int mainOff=0x418, mainAddr=0x8418;

   if(prepareFiles(argv[1])){
      copyShdrs();
      codeLength=0x20;
      updateDynsym (shdrPtr[SCT_DYNSYM]->sh_offset, mainOff, mainAddr);
      updateRelPlt (shdrPtr[SCT_REL_PLT]->sh_offset, mainOff, mainAddr);
      updatePlt(shdrPtr[SCT_PLT]->sh_offset, mainOff, mainAddr);
      updateDynamic(shdrPtr[SCT_DYNAMIC]->sh_offset, mainOff, mainAddr);
      updateGot(shdrPtr[SCT_GOT]->sh_offset, mainOff, mainAddr);
      updateText(shdrPtr[SCT_TEXT]->sh_offset, mainOff, mainAddr);
      updatePhdr(elfHdr.e_phoff, mainOff, mainAddr);
      updateElfHdr();
      updateShdr(mainOff, mainAddr);
      injectCode(mainOff, hexcode);
      closeFiles();
      return 0;
   }
   else{
      fprintf(stderr, "The program was interrupted!\n");
   }
} 

