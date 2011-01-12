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
FILE *mainFilePtr;            // pointer on the main file         
unsigned char *tmpBuffer;     // char pointer on the temporary buffer
unsigned long fileLength;     // length of the executable in bytes
unsigned char *strPtr;        // char pointer to verify the section names
unsigned int codeLength;      // length of the injected code in bytes
unsigned int mainSize;        // size of the main method in bytes
unsigned int mainOff, mainAddr; // offset and address of the main method
Elf32_Shdr *shdrPtr[NB_SHDR]; // array of section header poiters
Elf32_Ehdr elfHdr;            // elf header of the executable

/* injects code into the file at a given offset */
void writeEndFile(unsigned int mainOff){

   /* copy content to end file */
   int i;
   fseek(tmpFilePtr, 0, SEEK_SET);
   for(i=0; i<mainOff/BLOCK_SIZE; i++){ // copy first part of file by chunks of 1024 bytes
      fread(tmpBuffer, BLOCK_SIZE, 1, tmpFilePtr);
      fwrite(tmpBuffer, BLOCK_SIZE, 1, endFilePtr);
   }
   if(mainOff%BLOCK_SIZE!=0){ // copy the last non 1024 byte long chunk
      fread(tmpBuffer, mainOff%BLOCK_SIZE, 1, tmpFilePtr);
      fwrite(tmpBuffer, mainOff%BLOCK_SIZE, 1, endFilePtr);
   }
   /* copy new main*/
   fseek(mainFilePtr, 0, SEEK_SET);
   for(i=0; i<mainSize/BLOCK_SIZE; i++){ // copy first part of file by chunks of 1024 bytes
      fread(tmpBuffer, BLOCK_SIZE, 1, mainFilePtr);
      fwrite(tmpBuffer, BLOCK_SIZE, 1, endFilePtr);
   }
   if(mainSize%BLOCK_SIZE!=0){ // copy the last non 1024 byte long chunk
      fread(tmpBuffer, mainSize%BLOCK_SIZE, 1, mainFilePtr);
      fwrite(tmpBuffer, mainSize%BLOCK_SIZE, 1, endFilePtr);
   }
   /* copy rest of file */
   fseek(tmpFilePtr, shdrPtr[SCT_FINI]->sh_offset, SEEK_SET);
   for(i=0; i<(fileLength-shdrPtr[SCT_FINI]->sh_offset)/BLOCK_SIZE; i++){
      fread(tmpBuffer, BLOCK_SIZE, 1, tmpFilePtr);
      fwrite(tmpBuffer, BLOCK_SIZE, 1, endFilePtr);
   }
   if((fileLength-shdrPtr[SCT_FINI]->sh_offset)%BLOCK_SIZE!=0){
      fread(tmpBuffer, (fileLength-shdrPtr[SCT_FINI]->sh_offset)%BLOCK_SIZE, 1, tmpFilePtr);
      fwrite(tmpBuffer, (fileLength-shdrPtr[SCT_FINI]->sh_offset)%BLOCK_SIZE, 1, endFilePtr);
   }
}

/* inserts code into a file at a given offset */
void insertInstr(unsigned int *instr, unsigned int offset, unsigned int codeSize){

   int i;
   FILE *tmpMainPtr;
   tmpMainPtr = fopen("tmpMain","w+b");
   if(!tmpMainPtr){
     fprintf(stderr, "Unable to create tmpMain file!\n");
   }
   /* copy content to temporary main file */
   fseek(mainFilePtr, 0, SEEK_SET);
   for(i=0; i<offset/BLOCK_SIZE; i++){
      fread(tmpBuffer, BLOCK_SIZE, 1, mainFilePtr);
      fwrite(tmpBuffer, BLOCK_SIZE, 1, tmpMainPtr);
   }
   if(offset%BLOCK_SIZE!=0){
      fread(tmpBuffer, offset%BLOCK_SIZE, 1, mainFilePtr);
      fwrite(tmpBuffer, offset%BLOCK_SIZE, 1, tmpMainPtr);
   }
   /* copy instruction */
   fwrite(instr, codeSize, 1, tmpMainPtr);

   /* copy rest of file */
   for(i=0; i<(mainSize-offset)/BLOCK_SIZE; i++){  
      fread(tmpBuffer, BLOCK_SIZE, 1, mainFilePtr);
      fwrite(tmpBuffer, BLOCK_SIZE, 1, tmpMainPtr);
   }
   if((mainSize-offset)%BLOCK_SIZE!=0){
      fread(tmpBuffer, (mainSize-offset)%BLOCK_SIZE, 1, mainFilePtr);
      fwrite(tmpBuffer, (mainSize-offset)%BLOCK_SIZE, 1, tmpMainPtr);
   }
   mainSize+=codeSize;

   fseek(tmpMainPtr, 0, SEEK_SET);
   fseek(mainFilePtr, 0, SEEK_SET);
   for(i=0; i<mainSize/BLOCK_SIZE; i++){
      fread(tmpBuffer, BLOCK_SIZE, 1, tmpMainPtr);
      fwrite(tmpBuffer, BLOCK_SIZE, 1, mainFilePtr);
   }
   if(mainSize%BLOCK_SIZE!=0){
      fread(tmpBuffer, mainSize%BLOCK_SIZE, 1, tmpMainPtr);
      fwrite(tmpBuffer, mainSize%BLOCK_SIZE, 1, mainFilePtr);
   }
   fseek(mainFilePtr, offset, SEEK_SET);
   fclose(tmpMainPtr);
   remove("tmpMain");
}

void copyTmp(){
   /* copy content to tmp file */
   int i;
   fseek(tmpFilePtr, 0, SEEK_SET);
   fseek(endFilePtr, 0, SEEK_SET);
   for(i=0; i<(fileLength+codeLength)/BLOCK_SIZE; i++){ // copy first part of file by chunks of 1024 bytes
      fread(tmpBuffer, BLOCK_SIZE, 1, endFilePtr);
      fwrite(tmpBuffer, BLOCK_SIZE, 1, tmpFilePtr);
   }
   if((fileLength+codeLength)%BLOCK_SIZE!=0){ // copy the last non 1024 byte long chunk
      fread(tmpBuffer, (fileLength+codeLength)%BLOCK_SIZE, 1, endFilePtr);
      fwrite(tmpBuffer, (fileLength+codeLength)%BLOCK_SIZE, 1, tmpFilePtr);
   }
}




/* updates offsets and pointers */
void updateFct (unsigned int offset, char jump, int nbEntries){
	int i;
	unsigned int *buffer;
   buffer=malloc(sizeof(int));	
	for(i=0; i<nbEntries; i++){
		fseek(tmpFilePtr, offset, SEEK_SET);
		fread(buffer, sizeof(int), 1, tmpFilePtr);
		if(((*buffer>mainOff) && (*buffer<fileLength)) || (*buffer>mainAddr)){
			*buffer+=codeLength;
			fseek(tmpFilePtr, offset, SEEK_SET);
			fwrite(buffer, sizeof(int), 1, tmpFilePtr);
		}
	offset+=jump;
	}
   free(buffer);
}

/* updates offsets and pointers of the .dynsym section */
void updateDynsym (unsigned int offset){
	int nbEntries; // number of .dynsym entries
	nbEntries = shdrPtr[SCT_DYNSYM]->sh_size/DYNSYM_ENTRY_SIZE;
	offset+=4;  // the first offset to change is 4 bytes into the .dynsym section
	updateFct (offset, DYNSYM_ENTRY_SIZE, nbEntries);
}

/* updates offsets and pointers of the .relplt section */
void updateRelPlt (unsigned int offset){
	int nbEntries; // number of .relplt entries
	nbEntries = shdrPtr[SCT_REL_PLT]->sh_size/REL_PLT_ENTRY_SIZE; 
	updateFct (offset, REL_PLT_ENTRY_SIZE, nbEntries);
}

/* updates offsets and pointers of the .got section */
void updateGot (unsigned int offset){
	updateFct (offset, 1, 1);
}	

/* updates offsets and pointers of the .dynamic section */
void updateDynamic (unsigned int offset){
	int nbEntries; // number of .dynamic entries
	nbEntries = (shdrPtr[SCT_DYNAMIC]->sh_size-12)/DYNAMIC_ENTRY_SIZE;
	offset+=12;  // the first offset to change is 4 bytes into the .dynamic section
	updateFct (offset, DYNAMIC_ENTRY_SIZE, nbEntries);
}

/* updates offsets and pointers of the .plt section*/
void updatePlt (unsigned int offset){
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
   free(buffer);
} 

/* updates offsets and pointers of the program header */
void updatePhdr(unsigned int offset){
   int hdrSize, nbEntries;
   hdrSize=shdrPtr[SCT_INTERP]->sh_offset-elfHdr.e_ehsize;
   nbEntries=hdrSize/sizeof(int);
   updateFct (offset, sizeof(int), nbEntries);
}

/* updates offsets and pointers of the elf header */
void updateElfHdr(){
   Elf32_Addr newShoff;
   newShoff=elfHdr.e_shoff+codeLength;
   fseek(tmpFilePtr, 0x20, SEEK_SET);
   fwrite(&newShoff, sizeof(Elf32_Addr), 1, tmpFilePtr);
}

/* updates offsets and pointers of the section headers */
void updateShdr(){
   int i;
   shdrPtr[SCT_TEXT]->sh_size+=codeLength; // update the size attribute
   fseek(tmpFilePtr, elfHdr.e_shoff+(SCT_TEXT+1)*sizeof(Elf32_Shdr), SEEK_SET);
   fwrite(shdrPtr[SCT_TEXT], sizeof(Elf32_Shdr), 1, tmpFilePtr);
   
   for(i=SCT_FINI; i<sizeof(shdrNames)/sizeof(int); i++){
      fseek(tmpFilePtr, elfHdr.e_shoff+(i+1)*sizeof(Elf32_Shdr), SEEK_SET);
      if(shdrPtr[i]!=0){
         if(shdrPtr[i]->sh_addr>mainAddr){ // increments the address if it is after 
            shdrPtr[i]->sh_addr+=codeLength;
         }
         if(shdrPtr[i]->sh_offset>mainOff){
            shdrPtr[i]->sh_offset+=codeLength;
         }
         fwrite(shdrPtr[i], sizeof(Elf32_Shdr), 1, tmpFilePtr);
      }
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
   free(buffer);
   return 0;
}

/* updates offsets/pointers/instructions of the .text section */
void updateText (unsigned int offset){
	unsigned int nbEntries;
	unsigned int i;
	unsigned int *buffer;
	unsigned int mainLocation;
	mainLocation = searchMain();
	nbEntries = (mainLocation - shdrPtr[SCT_TEXT]->sh_offset)/ARM_INSTRUCTION_SIZE; 
   buffer=malloc(ARM_INSTRUCTION_SIZE);	
	for(i=0; i<nbEntries; i++){
		fseek(tmpFilePtr, offset, SEEK_SET);
		fread(buffer, sizeof(int), 1, tmpFilePtr);
		if(
		((*buffer>(mainOff+OFFSET_ID)) && (*buffer<(fileLength+OFFSET_ID))) || 
		((*buffer>mainAddr) && (*buffer<mainAddr+fileLength))||
		((*buffer>LDR_START) && (*buffer<LDR_STOP) && (offset>mainLocation))
		)
		{
			*buffer+=codeLength;
			fseek(tmpFilePtr, offset, SEEK_SET);
			fwrite(buffer, sizeof(int), 1, tmpFilePtr);
		}
	offset+=ARM_INSTRUCTION_SIZE;
	}
   free(buffer);
}

/* updates offsets/pointers/instructions of the main */
void updateMain (){
	unsigned int nbEntries;
	unsigned int i;
	unsigned int *buffer;
	unsigned int mainLocation;
   unsigned int offset;
   offset = 0;
	nbEntries = (mainSize)/ARM_INSTRUCTION_SIZE; 
   buffer=malloc(ARM_INSTRUCTION_SIZE);	
	for(i=0; i<nbEntries; i++){
		fseek(mainFilePtr, offset, SEEK_SET);
		fread(buffer, sizeof(int), 1, mainFilePtr);
		if(
		((*buffer>(mainOff+OFFSET_ID)) && (*buffer<(fileLength+OFFSET_ID))) || 
		((*buffer>mainAddr) && (*buffer<mainAddr+fileLength))||
		((*buffer>LDR_START) && (*buffer<LDR_STOP) && (offset>mainLocation))
		)
		{
			*buffer+=codeLength;
			fseek(mainFilePtr, offset, SEEK_SET);
			fwrite(buffer, sizeof(int), 1, mainFilePtr);
		}
	offset+=ARM_INSTRUCTION_SIZE;
	}
   free(buffer);
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
   
   /* create main file */
   remove("main");
   mainFilePtr = fopen("main","w+b");
   if(!mainFilePtr){
     fprintf(stderr, "Unable to create main file!\n");
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
   for(i=0;i<NB_SHDR;i++)
      shdrPtr[i]=0;
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

/* updates all of the sections by calling every update function*/
void updateSct(){
      updateDynsym (shdrPtr[SCT_DYNSYM]->sh_offset);
      updateRelPlt (shdrPtr[SCT_REL_PLT]->sh_offset);
      updatePlt(shdrPtr[SCT_PLT]->sh_offset);
      updateDynamic(shdrPtr[SCT_DYNAMIC]->sh_offset);
      updateGot(shdrPtr[SCT_GOT]->sh_offset);
      updateText(shdrPtr[SCT_TEXT]->sh_offset);
      updatePhdr(elfHdr.e_phoff);
      updateElfHdr();
      updateShdr();
}

/* transforms every CMP rx, #0 instruction into an AND */
unsigned int obfuscateCMP(){
	unsigned int nbInstr;
	unsigned int i;
	unsigned int *buffer;
   unsigned int tmp;
	nbInstr = mainSize/ARM_INSTRUCTION_SIZE;
   buffer=malloc(ARM_INSTRUCTION_SIZE);	
   fseek(mainFilePtr, 0, SEEK_SET);
	for(i=0; i<nbInstr; i++){
		fread(buffer, sizeof(int), 1, mainFilePtr);
      if((*buffer & 0xfff0ffff)==0xe3500000){
         tmp=0x000f0000 & *buffer;
         *buffer=0xe0000000+tmp+(tmp>>4)+(tmp>>16);
         fseek(mainFilePtr, -4, SEEK_CUR);
         fwrite(buffer, ARM_INSTRUCTION_SIZE, 1, mainFilePtr);
		}
	}
   return 0;
}

/* replace MOV instructions with PUSH, POP */
unsigned int obfuscateMOV(){
	unsigned int nbInstr;
	unsigned int i;
	unsigned int *buffer1, *buffer2;
   unsigned int param1, param2;
   unsigned int insertedBytes;
   unsigned int position;
   position=0;
   insertedBytes=0;
	nbInstr = mainSize/ARM_INSTRUCTION_SIZE;
   buffer1=malloc(ARM_INSTRUCTION_SIZE);	
   buffer2=malloc(ARM_INSTRUCTION_SIZE);
   fseek(mainFilePtr, 2*ARM_INSTRUCTION_SIZE, SEEK_SET);
	for(i=0; i<(nbInstr+insertedBytes/ARM_INSTRUCTION_SIZE)-2; i++){
		fread(buffer1, ARM_INSTRUCTION_SIZE, 1, mainFilePtr);
      position+=4;
         printf("found instruction to change\n");
      if((*buffer1&0xffff0ff0)==0xe1a00000){
         param1=0x0000f000 & *buffer1;
         param2=0x0000000f & *buffer1;
         *buffer1=0xe52d0000+param1;
         *buffer2=0xe49d0000+(param2<<12);
         fseek(mainFilePtr, -4, SEEK_CUR);
         fwrite(buffer1, ARM_INSTRUCTION_SIZE, 1, mainFilePtr);
         insertInstr(buffer2, position, ARM_INSTRUCTION_SIZE);
         insertedBytes+=4;
		}
	}
   free(buffer1);
   free(buffer2);
   return insertedBytes;
}

/**/
unsigned int obfIncPC(){
	unsigned int nbInstr;
	unsigned int *buffer1, *buffer2;
   unsigned int position1, position2;
	nbInstr = mainSize/ARM_INSTRUCTION_SIZE;
   position1=2*ARM_INSTRUCTION_SIZE;
   position2=mainSize+6-(2*ARM_INSTRUCTION_SIZE);
   printf("pos2: %x\n", position2);
   buffer1=malloc(ARM_INSTRUCTION_SIZE);	
   buffer2=malloc(ARM_INSTRUCTION_SIZE/2);
   *buffer1=0xe28ff002;
   *buffer2=0x0000;
   insertInstr(buffer1, position1, ARM_INSTRUCTION_SIZE);
   insertInstr(buffer2, position1 + ARM_INSTRUCTION_SIZE, ARM_INSTRUCTION_SIZE/2);
   insertInstr(buffer1, position2, ARM_INSTRUCTION_SIZE);
   insertInstr(buffer2, position2 + ARM_INSTRUCTION_SIZE, ARM_INSTRUCTION_SIZE/2); 
   free(buffer1);
   free(buffer2);
   return 3*ARM_INSTRUCTION_SIZE;   
}

void obfuscate(){
   //codeLength += obfuscateCMP();
   codeLength += obfuscateMOV();
   //codeLength += obfIncPC();
   updateMain();
}

/* close files and delete the temporary file */
void closeFiles(){
   fclose(exeFilePtr);
   fclose(tmpFilePtr);
   fclose(endFilePtr);
   fclose(mainFilePtr);
   free(tmpBuffer);
   free(strPtr);
   int i;
   for(i=0;i<sizeof(shdrNames)/sizeof(int);i++)
      free(shdrPtr[i]);
   //remove("obf");
}

void extractMain(){
   int i;
   mainSize=shdrPtr[SCT_FINI]->sh_offset-searchMain();

   /* copy content to temporary file */
   fseek(exeFilePtr, searchMain(), SEEK_SET);
   for(i=0; i<mainSize/BLOCK_SIZE; i++){
      fread(tmpBuffer, BLOCK_SIZE, 1, exeFilePtr);
      fwrite(tmpBuffer, BLOCK_SIZE, 1, mainFilePtr);
   }
   if(mainSize%BLOCK_SIZE!=0){
      fread(tmpBuffer, mainSize%BLOCK_SIZE, 1, exeFilePtr);
      fwrite(tmpBuffer, mainSize%BLOCK_SIZE, 1, mainFilePtr);
   }
}

int main(int argc, char *argv[]){

   /* variable declaration */


   if(prepareFiles(argv[1])){
      copyShdrs(); 
      mainOff=searchMain();
      mainAddr=ADDR_ID+mainOff;
      codeLength=0;
      extractMain();
      obfuscate();
      printf("codeLength: %x\n", codeLength);
      if (codeLength!=0){
         updateSct();
      }   
      writeEndFile(mainOff);
      closeFiles();
      return 0;
   }
   else
      fprintf(stderr, "The program was interrupted!\n");
} 

