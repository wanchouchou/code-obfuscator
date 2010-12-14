#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

#define BLOCK_SIZE   1024
#define SHDR_SIZE    40
#define SHDR_START_OFFSET  0x20
#define TEXT_SHDR_ID 0x00380000
#define SCT_INTERP   0
#define SCT_HASH     1
#define SCT_DYNSYM   2
#define SCT_DYNSTR  3
#define SCT_REL_PLT  4
#define SCT_INIT   5
#define SCT_PLT   6
#define SCT_TEXT  7
#define SCT_FINI  8
#define SCT_RODATA   9
#define SCT_EH_FRAME 10
#define SCT_INIT_FRAME  11
#define SCT_FINI_ARRAY  12
#define SCT_JCR   13
#define SCT_DYNAMIC  14
#define SCT_GOT   15
#define SCT_DATA  16
#define SCT_BSS   17
#define SCT_COMMENT  18
#define SCT_ARM_ATTRIBUTES 19
#define SCT_SHSTRTAB   20
#define NB_SHDR   21

char *shdrNames[] = {".interp", ".hash", ".dynsym", ".dynstr", ".rel.plt", ".init", 
                        ".plt", ".text", ".fini", ".rodata", ".eh_frame", ".init_array", 
                        ".fini_array", ".jcr", ".dynamic", ".got", ".data", ".bss", 
                        ".comment", ".ARM.attributes", ".shstrtab"
                     };
FILE *exeFilePtr;             // pointer on the executable file
FILE *tmpFilePtr;             // pointer on the temporary file                      
unsigned char *tmpBuffer;     // char pointer on the temporary buffer
unsigned long fileLength;     // length of the executable
unsigned char *strPtr;        // char pointer to verify the section names
unsigned int codeLength;      // length of the injected code
Elf32_Shdr *shdrPtr[NB_SHDR]; // array of section header poiters
Elf32_Ehdr elfHdr;            // elf header of the executable

void injectCode(Elf32_Off offset, Elf32_Word *hexcode){
      int i;
      fseek(tmpFilePtr, 20, SEEK_SET);
      for(i=0;i<codeLength;i++)
         fwrite((Elf32_Word*)&(hexcode[i]), sizeof(Elf32_Word), 1, tmpFilePtr);
}

void injectByte(Elf32_Off offset, char *byte){
      int i;
      fseek(tmpFilePtr, offset, SEEK_SET);
      fwrite((byte), sizeof(char), 1, tmpFilePtr);
}

void updateFct (unsigned int offset, unsigned int offsetInsertion, unsigned int addressInsertion, char saut, int nbLignes){
	int i;
	unsigned int *buffer;
   buffer=malloc(4);	
	for(i=0; i<nbLignes; i++){
		fseek(tmpFilePtr, offset, SEEK_SET);
		fread(buffer, sizeof(int), 1, tmpFilePtr);
		if(((*buffer>offsetInsertion) && (*buffer<fileLength)) || (*buffer>addressInsertion)){
			*buffer+=codeLength;
			fseek(tmpFilePtr, offset, SEEK_SET);
			fwrite(buffer, sizeof(int), 1, tmpFilePtr);
		}
	offset+=saut;
	}
}

void updateDynsym (unsigned int offset, unsigned int offsetInsertion, unsigned int addressInsertion){
	int size;
	size = shdrPtr[SCT_DYNSYM]->sh_size;
	size = size/16;
	offset+=4; 
	updateFct (offset, offsetInsertion, addressInsertion, 16, size);
}

void updateRelPlt (unsigned int offset, unsigned int offsetInsertion, unsigned int addressInsertion){
	int size;
	size = shdrPtr[SCT_REL_PLT]->sh_size;
	size = size/8; 
	updateFct (offset, offsetInsertion, addressInsertion, 8, size);
}

void updateGot (unsigned int offset, unsigned int offsetInsertion, unsigned int addressInsertion){
	updateFct (offset, offsetInsertion, addressInsertion, 1, 1);
}	

void updateDynamic (unsigned int offset, unsigned int offsetInsertion, unsigned int addressInsertion){
	int size;
	size = shdrPtr[SCT_DYNAMIC]->sh_size;
	size = (size-12)/8;
	offset+=12; 
	updateFct (offset, offsetInsertion, addressInsertion, 8, size);
}

void updatePlt (unsigned int offset, unsigned int offsetInsertion, unsigned int addressInsertion){
	int size;
	size = shdrPtr[SCT_PLT]->sh_size;
	size = (size-8)/8;
	offset+=16; 
	updateFct (offset, offsetInsertion, addressInsertion, 12, size);
}

void updatePhdr(unsigned int offset, unsigned int offsetInsertion, unsigned int addressInsertion){
   int hdrSize, nbEntries;
   hdrSize=shdrPtr[SCT_INTERP]->sh_offset-52;
   nbEntries=hdrSize/4;
   updateFct (offset, offsetInsertion, addressInsertion, 4, nbEntries);
}

void updateElfHdr(){
   Elf32_Addr newShoff;
   newShoff=elfHdr.e_shoff+codeLength;
   fseek(tmpFilePtr, 0x20, SEEK_SET);
   fwrite(&newShoff, sizeof(Elf32_Addr), 1, tmpFilePtr);
}

void updateShdr(unsigned int offsetInsertion, unsigned int addressInsertion){
   int i;
   shdrPtr[SCT_TEXT]->sh_size+=codeLength;
   printf("%x\n", shdrPtr[SCT_TEXT]->sh_size);
   fseek(tmpFilePtr, elfHdr.e_shoff+(SCT_TEXT+1)*sizeof(Elf32_Shdr), SEEK_SET);
   fwrite(shdrPtr[SCT_TEXT], sizeof(Elf32_Shdr), 1, tmpFilePtr);
   
   for(i=SCT_FINI; i<sizeof(shdrNames)/sizeof(int); i++){
      fseek(tmpFilePtr, elfHdr.e_shoff+(i+1)*sizeof(Elf32_Shdr), SEEK_SET);
      if(shdrPtr[i]->sh_addr>addressInsertion){
         shdrPtr[i]->sh_addr+=codeLength;
      }
      if(shdrPtr[i]->sh_offset>offsetInsertion){
         shdrPtr[i]->sh_offset+=codeLength;
      }
      fwrite(shdrPtr[i], sizeof(Elf32_Shdr), 1, tmpFilePtr);
   }

   
}

int main(int argc, char *argv[]){

   /* variable declaration */
   unsigned char *exeFilename;   // name of the executable file
   int i,j;                      // iterator to browse the executable
   Elf32_Shdr strtabShdr, tmpShdr; // 
   Elf32_Word strtabIndex, strtabStart;
   strPtr=malloc(15);

   /* open executable file */
   exeFilename = argv[1];
   exeFilePtr = fopen(exeFilename,"rb");
   if(!exeFilePtr){
     fprintf(stderr, "Unable to open file!\n");
     return 1;
   }

   /* create temporary file */
   tmpFilePtr = fopen("tmp","w+b");
   if(!tmpFilePtr){
     fprintf(stderr, "Unable to create file!\n");
     return 1;
   }

   /* get the length of executable file  */
   fseek(exeFilePtr, 0, SEEK_END);
   fileLength = ftell(exeFilePtr);
   fseek(exeFilePtr, 0, SEEK_SET);
     
   /* allocate memory for temporary buffer */
   tmpBuffer = malloc(BLOCK_SIZE);
   if(!tmpBuffer){
      fprintf(stderr, "Memory error!\n");
      fclose(exeFilePtr);
		return;
	}
   
   /* copy content to temporary file */
   for(i=0; i<fileLength/BLOCK_SIZE; i++){
      fread(tmpBuffer, BLOCK_SIZE, 1, exeFilePtr);
      fwrite(tmpBuffer, BLOCK_SIZE, 1, tmpFilePtr);
   }
   if(fileLength%BLOCK_SIZE!=0){
      fread(tmpBuffer, fileLength%BLOCK_SIZE, 1, exeFilePtr);
      fwrite(tmpBuffer, fileLength%BLOCK_SIZE, 1, tmpFilePtr);
   }

   /* copy all section headers to structures */
   fseek(tmpFilePtr, 0, SEEK_SET);
   fread(&elfHdr, 1, sizeof(Elf32_Ehdr), tmpFilePtr);
   if (elfHdr.e_shoff == 0) {
		fprintf(stderr, "Could not find sections!\n");
		return 0;
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
      fread(strPtr, 1, 15, tmpFilePtr);   // read the string (15 bytes)
      for(j=0;j<sizeof(shdrNames)/sizeof(int);j++){
         if(!strcmp(strPtr, shdrNames[j])){  // compare the string with the array of strings shdrNames
            shdrPtr[j]=(Elf32_Shdr*)malloc(sizeof(Elf32_Shdr));
            memcpy((void *)shdrPtr[j], (void *)(&tmpShdr), sizeof(Elf32_Shdr));
            printf("%d section %s size %04x offset %04x\n", j, shdrNames[j], shdrPtr[j]->sh_size, shdrPtr[j]->sh_offset);
         }
      }
   }  
   
   /* inject code */
   Elf32_Word hexcode[8]={0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
   char byte;
   byte=0xff;
   //codeLength=sizeof(hexcode)/sizeof(Elf32_Word);
   //injectCode(0x418, hexcode);
   // injectByte(0x418, &byte);
   
   codeLength=0x20;
   updateDynsym (shdrPtr[SCT_DYNSYM]->sh_offset, 0x418, 0x8418);
   updateRelPlt (shdrPtr[SCT_REL_PLT]->sh_offset, 0x418, 0x8418);
   updatePlt(shdrPtr[SCT_PLT]->sh_offset, 0x418, 0x8418);
   updateDynamic(shdrPtr[SCT_DYNAMIC]->sh_offset, 0x418, 0x8418);
   updateGot(shdrPtr[SCT_GOT]->sh_offset, 0x418, 0x8418);
   updatePhdr(elfHdr.e_phoff, 0x418, 0x8418);
   updateElfHdr();
   updateShdr(0x418, 0x8418);

   /* close files and delete the temporary file */
   printf("\n");
   fclose(exeFilePtr);
   fclose(tmpFilePtr);
   free(tmpBuffer);
   free(strPtr);
   for(j=0;j<sizeof(shdrNames)/sizeof(int);j++)
      free(shdrPtr[j]);
   //remove("tmp");
   return 0;
} 
