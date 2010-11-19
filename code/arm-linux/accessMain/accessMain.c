#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]){

   /*variable declaration  */
   FILE *filePtr;
   int size;
   unsigned int *buffer;
   unsigned long fileLen;
   char *filename;
   char i;

   /*open file */
   filename = argv[1];
   filePtr = fopen(filename,"rb");
   if(!filePtr){
      fprintf(stderr, "Unable to open file!");
      return 1;
   }

   /*get file length */
   fseek(filePtr, 0, SEEK_END);
   fileLen=ftell(filePtr);
   fseek(filePtr, 0, SEEK_SET);

   /*allocate memory */
   buffer=(char *)malloc(fileLen+1);
   if(!buffer){
      fprintf(stderr, "Memory error!");
      fclose(filePtr);
		return;
	}

   /*read file contents into buffer */
   fread(buffer, fileLen, 1, filePtr);

   /*manipulate buffer*/
   for(i=0; i<sizeof(buffer); i++){
      printf("%x", ((char *)buffer)[i]);
   }
   fclose(filePtr);
   free(buffer);
   return 0;
} 
