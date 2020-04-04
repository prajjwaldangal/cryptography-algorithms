#include <stdio.h>
int main(){
	char * line = NULL;
	ssize_t linelen;
	size_t linecap = 0;
	linelen = getline(&line, &linecap, stdin);
	if (linelen > 0) {
		printf("Hello world\n");
	}
	struct auth {
		char name[32];
		int auth;
	}
	if (strncmp(line, "auth ", 5) == 0) {
		auth = malloc(sizeof(auth));
	}
}
