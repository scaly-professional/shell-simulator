/**
 * @file tsh.c
 * @brief A tiny shell program that supports a simple form of
 * job control and I/O redirection. This handles running
 * background and foreground jobs, and also running built=in
 * commands. The shell program also accomodates signal handlers
 * for SIGCHLD, SIGINT and SIGTSTP.
 *
 * @author Eric Gan <ehgan>
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

/**
 * @brief This function directs all errors to stdout, initializes
 * the job list, installs signal handlers, and reads in the
 * information from the cmdline and outputs the result.
 *
 * @param[in] argc: The number of arguments that is inputted
 * @param[in] argv: The array containing all the arguments from the cmd line
 *
 */
int main(int argc, char **argv) {
    char c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv("MY_ENV=42") < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/**
 * @brief This function outputs an error message that is provided
 *
 * @param[in] msg: The message to be outputted in the error call
 *
 */
void unix_error(char *msg) {
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    exit(0);
}

/**
 * @brief Combines both the fork() call and the error call so that
 * if the fork() failes, then it calls unix_error();
 *
 */
pid_t Fork(void) {
    pid_t pid;

    if ((pid = fork()) < 0) {
        unix_error("Fork error");
    }

    return pid;
}

/**
 * @brief This function resumes job by sending it a SIGCONT signal,
 * and then runs it in the background. The job argument can either be a PID
 * or a JID and is taken from the cmdline tokens.
 *
 * @param[in] token: cmdline_tokens so that the PID or JID can be taken from
 * token.argv.
 *
 */
void run_bg(struct cmdline_tokens token) {
    pid_t pid;
    jid_t jid;
    sigset_t mask, prev;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prev);
    // Only run if there is an argument that follows the bg call
    if (token.argv[1] != NULL) {
        // Check if the argument is a JID by checking for preceding %
        if (token.argv[1][0] == '%') {
            jid = atoi(&token.argv[1][1]);
            if (jid > 0) {
                if (!job_exists(jid)) {
                    printf("%s: No such job\n", token.argv[1]);
                    sigprocmask(SIG_SETMASK, &prev, NULL);
                    return;
                } else {
                    pid = job_get_pid(jid);
                }
            } else {
                printf("bg: argument must be a PID or %s\n", "%jobid");
                sigprocmask(SIG_SETMASK, &prev, NULL);
                return;
            }
        }
        // If not JID, check if argument is PID
        else if (atoi(&token.argv[1][0]) > 0) {
            pid = atoi(&token.argv[1][0]);
            jid = job_from_pid(pid);
            if (!job_exists(jid)) {
                printf("%s: No such job\n", token.argv[1]);
                sigprocmask(SIG_SETMASK, &prev, NULL);
                return;
            }
        }
        // If not JID or PID, print the issue
        else {
            printf("bg: argument must be a PID or %s\n", "%jobid");
            sigprocmask(SIG_SETMASK, &prev, NULL);
            return;
        }
        // Send the SIGCONT signal and run it in the background
        kill(-1 * pid, SIGCONT);
        printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
        job_set_state(jid, BG);
        sigprocmask(SIG_SETMASK, &prev, NULL);
        return;
    } else {
        printf("bg command requires PID or %s argument\n", "%jobid");
        sigprocmask(SIG_SETMASK, &prev, NULL);
        return;
    }
}

/**
 * @brief This function resumes job by sending it a SIGCONT signal,
 * and then runs it in the foreground. The job argument can either be a PID
 * or a JID and is taken from the cmdline tokens.
 *
 * @param[in] token: cmdline_tokens so that the PID or JID can be taken from
 * token.argv.
 *
 */
void run_fg(struct cmdline_tokens token) {
    pid_t pid;
    jid_t jid;
    sigset_t mask, prev;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prev);
    // Only run if there is an argument that follows the fg call
    if (token.argv[1] != NULL) {
        // Check if the argument is a JID by checking for preceding %
        if (token.argv[1][0] == '%') {
            jid = atoi(&token.argv[1][1]);
            if (jid > 0) {
                if (!job_exists(jid)) {
                    printf("%s: No such job\n", token.argv[1]);
                    sigprocmask(SIG_SETMASK, &prev, NULL);
                    return;
                } else {
                    pid = job_get_pid(jid);
                }
            } else {
                printf("fg: argument must be a PID or %s\n", "%jobid");
                sigprocmask(SIG_SETMASK, &prev, NULL);
                return;
            }
        }
        // If not JID, check if argument is PID
        else if (atoi(&token.argv[1][0]) > 0) {
            pid = atoi(&token.argv[1][0]);
            jid = job_from_pid(pid);
            if (!job_exists(jid)) {
                printf("%s: No such job\n", token.argv[1]);
                sigprocmask(SIG_SETMASK, &prev, NULL);
                return;
            }
        }
        // If not JID or PID, print the issue
        else {
            printf("fg: argument must be a PID or %s\n", "%jobid");
            sigprocmask(SIG_SETMASK, &prev, NULL);
            return;
        }
        // Send the SIGCONT signal and run it in the background
        kill(-1 * pid, SIGCONT);
        job_set_state(jid, FG);
        while (job_exists(fg_job())) {
            sigsuspend(&prev);
        }
        sigprocmask(SIG_SETMASK, &prev, NULL);
        return;
    } else {
        printf("fg command requires PID or %s argument\n", "%jobid");
        sigprocmask(SIG_SETMASK, &prev, NULL);
        return;
    }
}

/**
 * @brief checks outfile and infile from cmdline token and if valid files,
 * opens the files and points them to stdin and/or stdout
 *
 * @param[in] token: cmdline_tokens to get outfile and infile
 *
 */
void io_redirect(struct cmdline_tokens token) {
    sigset_t mask, prev;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prev);
    // If infile exists...
    if (token.infile != NULL) {
        int io_infile = open(token.infile, O_RDONLY, DEF_MODE);
        if (io_infile < 0) {
            perror(token.infile);
            sigprocmask(SIG_SETMASK, &prev, NULL);
            exit(1);
        }
        // Set to infile and close file
        dup2(io_infile, STDIN_FILENO);
        close(io_infile);
    }
    // If outfile exists...
    if (token.outfile != NULL) {
        int io_outfile =
            open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC, DEF_MODE);
        if (io_outfile < 0) {
            perror(token.outfile);
            sigprocmask(SIG_SETMASK, &prev, NULL);
            exit(1);
        }
        // Set to outfile and close file
        dup2(io_outfile, STDOUT_FILENO);
        close(io_outfile);
    }
    sigprocmask(SIG_SETMASK, &prev, NULL);
}

/**
 * @brief Main routine that parses, interprets, and executes the command line.
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 *
 * @param[in] cmdline: Contains instructions that the the tiny shell parses,
 * interprets, and executes
 *
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;
    pid_t pid;
    sigset_t mask, prev;
    sigfillset(&mask);
    // Parse command line
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }
    // If not a built-in function...
    if (token.builtin == BUILTIN_NONE) {
        // Blocks all signals
        sigprocmask(SIG_BLOCK, &mask, &prev);
        // Executes program from child
        if ((pid = Fork()) == 0) {
            // Unblocks signals
            sigprocmask(SIG_SETMASK, &prev, NULL);
            io_redirect(token);
            setpgid(0, 0);
            if (execve(token.argv[0], token.argv, environ) < 0) {
                perror(token.argv[0]);
                exit(1);
            }
        }
        // Add job to job list based on foreground or background
        if (parse_result == PARSELINE_FG) {
            add_job(pid, FG, cmdline);
        } else {
            add_job(pid, BG, cmdline);
            printf("[%d] (%d) %s\n", job_from_pid(pid), pid, cmdline);
        }
        // Wait for foreground job to finish running
        if (parse_result == PARSELINE_FG) {
            while (job_exists(fg_job())) {
                // Suspends until signal that invokes handler is delivered
                // If sigchld_handler, reaps children
                sigsuspend(&prev);
            }
        }
        sigprocmask(SIG_SETMASK, &prev, NULL);
    }
    // If built-in quit function is called, exit
    else if (token.builtin == BUILTIN_QUIT) {
        exit(0);
    }
    // If this built-in function is called, list the current jobs
    else if (token.builtin == BUILTIN_JOBS) {
        sigprocmask(SIG_BLOCK, &mask, &prev);
        // If calling list job with a set outfile, just sent jobs to the outfile
        if (token.outfile != NULL) {
            int io_outfile =
                open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC, DEF_MODE);
            if (io_outfile < 0) {
                perror(token.outfile);
            }
            // Set to stdout and close file
            else {
                list_jobs(io_outfile);
                close(io_outfile);
            }
        } else {
            list_jobs(STDOUT_FILENO);
        }
        sigprocmask(SIG_SETMASK, &prev, NULL);
    }
    // Runs job in background
    else if (token.builtin == BUILTIN_BG) {
        run_bg(token);
    }
    // Runs job in foreground
    else if (token.builtin == BUILTIN_FG) {
        run_fg(token);
    }
    return;
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief If SIGCHLD is received, program acts according to the sigchld_handler.
 * Reaps children and if exited or signaled, delete job and print corresponding
 * message. If stopped, set the state of the job to stopped.
 *
 * @param[in] sig: signal that is received by the handler.
 *
 */
void sigchld_handler(int sig) {
    int olderrno = errno;
    int status;
    pid_t pid;
    sigset_t mask, prev;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prev);
    // Reap children with waitpid
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        // If exited, just delete job
        if (WIFEXITED(status)) {
            delete_job(job_from_pid(pid));
        }
        // If terminated by signal, print message and delete job
        else if (WIFSIGNALED(status)) {
            int jid = job_from_pid(pid);
            sio_printf("Job [%d] (%d) terminated by signal %d\n", jid, pid,
                       WTERMSIG(status));
            delete_job(jid);
        }
        // If stopped by signal, set state to stopped and print message
        else if (WIFSTOPPED(status)) {
            int jid = job_from_pid(pid);
            job_set_state(jid, ST);
            sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, pid,
                       WSTOPSIG(status));
        }
    }
    sigprocmask(SIG_SETMASK, &prev, NULL);
    errno = olderrno;
    return;
}

/**
 * @brief If SIGINT is received, program acts according to the sigint_handler.
 * Kills foreground job
 *
 * @param[in] sig: signal that is received by the handler.
 *
 */
void sigint_handler(int sig) {
    int olderrno = errno;
    sigset_t mask, prev;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prev);
    jid_t jid = fg_job();
    if (job_exists(jid)) {
        pid_t pid = job_get_pid(fg_job());
        if (pid != 0) {
            kill(-1 * pid, SIGINT);
        }
    }
    sigprocmask(SIG_SETMASK, &prev, NULL);
    errno = olderrno;
    return;
}

/**
 * @brief If SIGGTSTP is received, program acts according to the
 * sigtstp_handler. Kills foreground job
 *
 * @param[in] sig: signal that is received by the handler.
 *
 */
void sigtstp_handler(int sig) {
    int olderrno = errno;
    sigset_t mask, prev;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prev);
    jid_t jid = fg_job();
    if (job_exists(jid)) {
        pid_t pid = job_get_pid(fg_job());
        if (pid != 0) {
            kill(-1 * pid, SIGTSTP);
        }
    }
    sigprocmask(SIG_SETMASK, &prev, NULL);
    errno = olderrno;
    return;
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}
