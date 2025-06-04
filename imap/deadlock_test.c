/*
 * Copyright (c) 2025 Fastmail Ltd.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include <sys/wait.h>

#include "global.h"
#include "cyr_lock.h"

static int usage(const char *name)
{
    fprintf(stderr, "usage: %s [-C <altconfig>]\n", name);
    exit(EX_USAGE);
}

EXPORTED void fatal(const char* s, int code)
{
    fprintf(stderr, "deadlock_test: %s\n", s);
    cyrus_done();
    exit(code);
}

static char *fname_a = NULL;
static int fd_a = -1;

static char *fname_b = NULL;
static int fd_b = -1;

static int do_child1(void)
{
    int r = lock_setlock(fd_a, 1, 0, fname_a);
    if (r == -1) {
        printf("child1:\tcan not lock %s: %s\n", fname_a, strerror(errno));
        return -1;
    }
    printf("child1:\tlocked %s\n", fname_a);

    printf("child1:\tsleeping 1 second\n");
    sleep(1);

    r = lock_setlock(fd_b, 1, 0, fname_b);
    if (r == -1) {
        printf("child1:\tcan not lock %s: %s\n", fname_b, strerror(errno));
        return -1;
    }
    printf("child1:\tlocked %s\n", fname_b);

    return 0;
}

static int do_child2(void)
{
    int r = lock_setlock(fd_b, 1, 0, fname_b);
    if (r == -1) {
        printf("child2:\tcan not lock %s: %s\n", fname_b, strerror(errno));
        return -1;
    }
    printf("child2:\tlocked %s\n", fname_b);

    printf("child2:\tsleeping 2 seconds\n");
    sleep(2);

    r = lock_setlock(fd_a, 1, 0, fname_a);
    if (r != -1 || errno != EDEADLK) {
        printf("child2:\texpected deadlock on %s, got %s\n", fname_a, strerror(errno));
        return -1;
    }
    printf("child2:\tdeadlock on %s\n", fname_a);

    return 0;
}

int main(int argc, char **argv)
{
    int c;
    const char *alt_config = NULL;
    char *tempdirname = NULL;

    while ((c = getopt(argc, argv, "C:")) != EOF) {
        switch (c) {

        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        default:
            usage(argv[0]);
            break;
        }
    }

    if (optind != argc)
        usage(argv[0]);

    cyrus_init(alt_config, "deadlock_test", 0, 0);

    if (!config_getswitch(IMAPOPT_DEBUG_DEADLOCK)) {
        fprintf(stderr, "main:\tdebug_deadlock is not enabled, aborting.\n");
        goto done;
    }

    tempdirname =
        create_tempdir(config_getstring(IMAPOPT_TEMP_PATH), "deadlock_test");
    if (!tempdirname) {
        fprintf(stderr, "main:\tcreate_tempdir: %s\n", strerror(errno));
        goto done;
    }

    fname_a = strconcat(tempdirname, "/a.lock");
    printf("main:\tcreating lock file %s\n", fname_a);
    fd_a = creat(fname_a, 0644);
    if (fd_a == -1) {
        fprintf(stderr, "main:\tcreat(%s): %s\n", fname_a, strerror(errno));
        goto done;
    }

    fname_b = strconcat(tempdirname, "/b.lock");
    printf("main:\tcreating lock file %s\n", fname_b);
    fd_b = creat(fname_b, 0644);
    if (fd_b == -1) {
        fprintf(stderr, "main:\tcreat(%s): %s\n", fname_b, strerror(errno));
        goto done;
    }

    pid_t pid_child1 = fork();
    if (pid_child1 == -1) {
        fprintf(stderr, "main:\tcan not fork child1: %s", strerror(errno));
        goto done;
    }
    else if (!pid_child1) {
        return do_child1();
    }

    pid_t pid_child2 = fork();
    if (pid_child2 == -1) {
        fprintf(stderr, "main:\tcan not fork child2: %s", strerror(errno));
        goto done;
    }
    else if (!pid_child2) {
        return do_child2();
    }

    while (wait(NULL) != -1) {}

    printf("main:\tdone, check for LOCKERROR in syslog\n");

done:
    if (tempdirname) removedir(tempdirname);
    cyrus_done();
    return 0;
}
