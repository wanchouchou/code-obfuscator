#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]){

   /*variable declaration  */
   FILE *filePtr;
   int size;
   unsigned char *buffer;
   unsigned long fileLen;
   char *filename;
   int i;

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
   printf("fileLen: %ld\n", fileLen);
   fseek(filePtr, 0, SEEK_SET);

   /*allocate memory */
   buffer=malloc(fileLen+1);

   if(!buffer){
      fprintf(stderr, "Memory error!");
      fclose(filePtr);
		return;
	}


   /*read file content into buffer */
   fread(buffer, fileLen, 1, filePtr);

   /*manipulate buffer (display content)*/
   for(i=1; i<=fileLen; i++){
      printf("%02x", buffer[i-1]);
      if(i%16==0 && i!=0)
         printf("\n",i);
      else if(i%2==0 && i!=0)
         printf(" ");
   }
   printf("\n");
   fclose(filePtr);
   free(buffer);
   return 0;
} 
