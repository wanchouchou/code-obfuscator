#include <stdio.h>

int fct(int a){
 return ++a;
}

int main(int argc, char *argv[]){
   int a;
   a=3;
   a=fct(a);
   return 0;
}
