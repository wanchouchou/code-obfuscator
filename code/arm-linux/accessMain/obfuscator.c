#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

int main(int argc, char *argv[]){

   #define BLOCK_SIZE   1024
   #define SHDR_START   52
   #define SHDR_SIZE    40
   #define TEXT_SHDR_ID 0x00820000

   /*variable declaration  */
   FILE *exeFilePtr;          // pointer on the executable file
   FILE *tmpFilePtr;          // pointer on the temporary file                      
   char *exeFilename;         // name of the executable file
   unsigned char *tmpBuffer;  // char pointer on the temporary buffer
   unsigned int *intTmpBuffer;   // int pointer on the temporary buffer
   unsigned long fileLength;  // length of the executable file
   int i;                     // iterator to browse the executable file
   unsigned int text_shdrOffset;
   Elf32_Shdr text_shdr;

   /*open executable file */
   exeFilename = argv[1];
   exeFilePtr = fopen(exeFilename,"rb");
   if(!exeFilePtr){
     fprintf(stderr, "Unable to open file!\n");
     return 1;
   }

   /*create temporary file */
   tmpFilePtr = fopen("tmp","ar+b");
   if(!tmpFilePtr){
     fprintf(stderr, "Unable to create file!\n");
     return 1;
   }

   /*get the length of the executable file  */
   fseek(exeFilePtr, 0, SEEK_END);
   fileLength = ftell(exeFilePtr);
   fseek(exeFilePtr, 0, SEEK_SET);
     
   /*allocate memory for the temporary buffer */
   tmpBuffer = malloc(BLOCK_SIZE);
   if(!tmpBuffer){
      fprintf(stderr, "Memory error!\n");
      fclose(exeFilePtr);
		return;
	}
   
   /*copy content to temporary file */
   for(i=0; i<fileLength/BLOCK_SIZE; i++){
      fread(tmpBuffer, BLOCK_SIZE, 1, exeFilePtr);
      fwrite(tmpBuffer, BLOCK_SIZE, 1, tmpFilePtr);
   }
   if(fileLength%BLOCK_SIZE!=0){
      fread(tmpBuffer, fileLength%BLOCK_SIZE, 1, exeFilePtr);
      fwrite(tmpBuffer, fileLength%BLOCK_SIZE, 1, tmpFilePtr);
   }

   /*jump to the section headers */
   for(i=0; *intTmpBuffer!=TEXT_SHDR_ID && i<100; i++){
      fseek(tmpFilePtr, SHDR_START+i*SHDR_SIZE, SEEK_SET);
      fread(intTmpBuffer, 4, 1, tmpFilePtr);
      printf("byte is 0x%08x at offset %06x\n", *intTmpBuffer, SHDR_START+i*SHDR_SIZE);
   }
   text_shdrOffset=SHDR_START+(i-1)*SHDR_SIZE;
   printf(".text sct hdr offset: %06x\n", text_shdrOffset);

   /*close files and delete the temporary executable */
   printf("\n");
   fclose(exeFilePtr);
   fclose(tmpFilePtr);
   free(tmpBuffer);
   remove("tmp");
   return 0;
} 
