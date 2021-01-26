#include<stdio.h> 
#include<stdlib.h>
#include<unistd.h> 
#include <sys/wait.h>
 int main(int argc, char *argv[]) { 
        int pid; 
        int child_status;
        int pipefd[2];


        printf("Starting program; process has pid %d\n", getpid()); 
        FILE * fp; fp = fopen("fork-output.txt", "w+"); 
        fprintf(fp, "%s", "BEFORE FORK\n");
        fflush(fp);
	
	pipe(pipefd);

        if ((pid = fork()) < 0) {
		fprintf(stderr, "Could not fork()");
		exit(1);
	}

	/* BEGIN SECTION A */
        fprintf(fp, "%s", "SECTION A\n");
        fflush(fp);   

	printf("Section A;  pid %d\n", getpid());

	/* END SECTION A */
	if (pid == 0) {
		/* BEGIN SECTION B */
		printf("Section B; pid %d\n", getpid());

                close(pipefd[0]);
                FILE * fd_one = fdopen(pipefd[1],"w");
                fputs( "hello from Section B\n", fd_one);

                fprintf(fp, "%s", "SECTION B\n");
                fflush(fp);
		printf("Section B done sleeping\n");


                /* exec.c code */
                char *newenviron[] = { NULL };

                printf("Program \"%s\" has pid %d. Sleeping.\n", argv[0], getpid());
                sleep(30);

                if (argc <= 1) {
                        printf("No program to exec.  Exiting...\n");
                        exit(0);
                }

                printf("Running exec of \"%s\"\n", argv[1]);

                int file_descriptor = fileno(fp);
                dup2(fileno(fp), 1);

                execve(argv[1], &argv[1], newenviron);
                printf("End of program \"%s\".\n", argv[0]);
                /* end exec.c code */


		exit(0);

		/* END SECTION B */
	} else {
		/* BEGIN SECTION C */
                fprintf(fp, "%s", "SECTION C\n");
                fflush(fp); 

                close(pipefd[1]);
                FILE * fd;
                fd = fdopen(pipefd[0],"r");
		char buf[100];
                fgets(buf,100,fd);
                fputs(buf,stdout);  

                //read(pipefd[0], buf, 100); 
                // printf("Concatenated string %s\n",buf); 
                wait(&child_status);
		printf("Section C; pid %d\n", getpid());

		printf("Section C done sleeping\n");
		exit(0);
		/* END SECTION C */
	}
	/* BEGIN SECTION D */
        fprintf(fp, "%s", "SECTION D\n");  
        fflush(fp); 
	printf("Section D;pid %d\n", getpid());
	/* END SECTION D */
}

