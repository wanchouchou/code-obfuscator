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
#define SCT_INIT_ARRAY  12
#define SCT_FINI_ARRAY  13
#define SCT_JCR   14
#define SCT_DYNAMIC  15
#define SCT_GOT   16
#define SCT_DATA  17
#define SCT_BSS   18
#define SCT_COMMENT  19
#define SCT_ARM_ATTRIBUTES 20
#define SCT_SHSTRTAB   21


int main(int argc, char *argv[]){

   /* variable declaration */
   FILE *exeFilePtr;             // pointer on the executable file
   FILE *tmpFilePtr;             // pointer on the temporary file                      
   unsigned char *exeFilename;   // name of the executable file
   unsigned char *strPtr;        //
   unsigned char *tmpBuffer;     // char pointer on the temporary buffer
   unsigned long fileLength;     // length of the executable
   int i,j;                      // iterator to browse the executable
   Elf32_Ehdr elfHdr;            // elf header of the executable
   Elf32_Shdr strtabShdr, tmpShdr; // 
   unsigned int shdrOffset[21];
   Elf32_Word strtabIndex, strtabStart;
   unsigned char secTest;  // 
   char *shdrNames[] = {".interp", ".hash", ".dynsym", ".dynstr", ".rel.plt", ".init", 
                        ".plt", ".text", ".fini", ".rodata", ".eh_frame", ".init_array", 
                        ".fini_array", ".jcr", ".dynamic", ".got", ".data", ".bss", 
                        ".comment", ".ARM.attributes", ".shstrtab"};
   strPtr=malloc(15);

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
            shdrOffset[j]=elfHdr.e_shoff+i*sizeof(Elf32_Shdr); // save the offset
            printf("%d The section header %s is at address %04x\n", j, shdrNames[j], shdrOffset[j]);
         }
      }
      
   }  
   fseek(tmpFilePtr, shdrOffset[SCT_DYNSYM], SEEK_SET);
   fread(&tmpShdr, sizeof(char), sizeof(Elf32_Shdr), tmpFilePtr);
   printf("dynsym at 0x%04x\n", tmpShdr.sh_offset);
   
   /* close files and delete the temporary file */
   printf("\n");
   fclose(exeFilePtr);
   fclose(tmpFilePtr);
   free(tmpBuffer);
   free(strPtr);
   remove("tmp");
   return 0;
} 
