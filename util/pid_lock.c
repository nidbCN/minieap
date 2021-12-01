#include <sys/file.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include "minieap_common.h"
#include "logging.h"
#include "config.h"
#include "misc.h"

#define PID_STRING_BUFFER_SIZE 12
#define PID_FILE_NONE "none"

static int pid_lock_fd = 0; // 0 = uninitialized, -1 = disabled

RESULT pid_lock_init(const char* pidfile) {
    if (pidfile == NULL) {
        return FAILURE;
    }

    if (strcmp(pidfile, PID_FILE_NONE) == 0) {
        PR_WARN("PID check has disabled, please make sure only on process each interface")
        pid_lock_fd = -1;
        return SUCCESS;
    }
 
    pid_lock_fd = open(pidfile, O_RDWR | O_CREAT, 0644);
    if (pid_lock_fd < 0) {
        PR_ERRNO("Cannot open PID file");
        return FAILURE;
    }
    return SUCCESS;
}

// Return SUCCESS: We handled the incident and are ready to proceed (i.e. only when user asked)
// Return FAILURE: We could not handle, or we do not want to proceed
static RESULT pid_lock_handle_multiple_instance() {
    char readbuf[PID_STRING_BUFFER_SIZE]; // 12 is big enough to hold PID number

    if (read(pid_lock_fd, readbuf, PID_STRING_BUFFER_SIZE) < 0 || readbuf[0] == '\0') {
        PR_ERRNO("Another MiniEAP process is running but PID is unknow, please kill another MiniEAP process");
        return FAILURE;
    } else {
        int pid = atoi(readbuf);
        switch (get_program_config()->kill_type) {
            case KILL_NONE:
                PR_ERR("Another MiniEAP process is running, PID %d", pid);
                return FAILURE;
            case KILL_ONLY:
                PR_ERR("Another MiniEAP process is running, PID %d, send termination signal and exit...", pid);
                kill(pid, SIGTERM);
                return FAILURE;
            case KILL_AND_START:
                PR_WARN("Another MiniEAP process is running, PID %d, send termination signal and continue...", pid);
                kill(pid, SIGTERM);
                return SUCCESS;
            default:
                PR_ERR("-k unknow parameter");
                return FAILURE;
        }
    }
}

RESULT pid_lock_save_pid() {
    if (pid_lock_fd == 0) {
        PR_WARN("PID file have not be initialized");
        return FAILURE;
    } else if (pid_lock_fd < 0) {
        // User disabled pid lock
        return SUCCESS;
    }

    char writebuf[PID_STRING_BUFFER_SIZE];

    my_itoa(getpid(), writebuf, 10);

    if (write(pid_lock_fd, writebuf, strnlen(writebuf, PID_STRING_BUFFER_SIZE)) < 0) {
        PR_ERRNO("Cannot save PID to PID file");
        return FAILURE;
    }

    return SUCCESS;
}

RESULT pid_lock_lock() {
    if (pid_lock_fd == 0) {
        PR_WARN("PID file have not be initialized");
        return FAILURE;
    } else if (pid_lock_fd < 0) {
        // User disabled pid lock
        return SUCCESS;
    }

    int lock_result = flock(pid_lock_fd, LOCK_EX | LOCK_NB);
    if (lock_result < 0) {
        if (errno == EWOULDBLOCK) {
            if (IS_FAIL(pid_lock_handle_multiple_instance())) {
                close(pid_lock_fd);
                pid_lock_fd = 0;
                return FAILURE;
            } // Continue if handled
        } else {
            PR_ERRNO("Cannot lock PID file");
            return FAILURE;
        }
    }

    return SUCCESS;
}

RESULT pid_lock_destroy() {
    if (pid_lock_fd <= 0) {
        return SUCCESS;
    }

    close(pid_lock_fd); // Unlocks the file simultaneously
    if (unlink(get_program_config()->pidfile) < 0) {
        PR_WARN("Cannot delete PID file");
    }
    return SUCCESS;
}
