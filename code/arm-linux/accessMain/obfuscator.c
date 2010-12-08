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
#define SCT_DYNSYM   0
#define SCT_RELPLT  1
#define SCT_PLT   2
#define SCT_TEXT  3
#define SCT_DYNAMIC  4
#define SCT_GOT   5

int main(int argc, char *argv[]){

   /* variable declaration */
   FILE *exeFilePtr;             // pointer on the executable file
   FILE *tmpFilePtr;             // pointer on the temporary file                      
   unsigned char *exeFilename;   // name of the executable file
   unsigned char *strPtr;
   unsigned char *tmpBuffer;     // char pointer on the temporary buffer
   unsigned long fileLength;     // length of the executable file
   int i,j;                      // iterator to browse the executable file
   Elf32_Ehdr elfHdr;            // 
   Elf32_Shdr shdr textShdr, strtabShdr, tmpShdr;
   Elf32_Word strtabIndex, strtabStart;
   char *shdrNames[] = {".dynsym", ".rel.plt", ".plt", ".text", ".dynamic", ".got"};
   unsigned char secTest;  // 

   /* open executable file */
   exeFilename = argv[1];
   exeFilePtr = fopen(exeFilename,"rb");
   if(!exeFilePtr){
     fprintf(stderr, "Unable to open file!\n");
     return 1;
   }

   /* create temporary file */
   tmpFilePtr = fopen("tmp","ar+b");
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

   /* find the .text section header */
   fseek(tmpFilePtr, 0, SEEK_SET);
   fread(&elfHdr, 1, sizeof(Elf32_Ehdr), tmpFilePtr);
   if (elfHdr.e_shoff == 0) {
		fprintf(stderr, "Could not find sections!\n");
		return 0;
	}
	fseek(tmpFilePtr, elfHdr.e_shoff+(elfHdr.e_shnum-1)*sizeof(Elf32_Shdr), SEEK_SET);  // read the string table header
   fread(&strtabShdr, sizeof(char), sizeof(Elf32_Shdr), tmpFilePtr); // copy the string table header
   strtabStart=strtabShdr.sh_offset;
   printf("strtabStart: %x\n", strtabStart);
   for(i=1;i<elfHdr.e_shnum;i++){
      fseek(tmpFilePtr, elfHdr.e_shoff+i*sizeof(Elf32_Shdr), SEEK_SET); // browse every section header
      fread(&tmpShdr, sizeof(char), sizeof(Elf32_Shdr), tmpFilePtr);   // copy it
      strtabIndex=tmpShdr.sh_name;
      fseek(tmpFilePtr, strtabStart+strtabIndex, SEEK_SET); // read the string table
      fread(strPtr, 1, 15, tmpFilePtr);
      for(j=0;j<sizeof(shdrNames);j++){
         if(!strcmp(strPtr, shdrNames[j]))
            secTest=j;
         else
            secTest=-1;
      
      }

      switch(secTest){
         case SCT_DYNSYM:
            
            break;
         case SCT_RELPLT:
            break;
         case SCT_PLT:
            break;
         case SCT_TEXT:
            break;
         case SCT_DYNAMIC:
            break;
         case SCT_GOT:
            break;
      }      
   }  
   
   
   /* close files and delete the temporary file */
   printf("\n");
   fclose(exeFilePtr);
   fclose(tmpFilePtr);
   free(tmpBuffer);
   remove("tmp");
   return 0;
} 
