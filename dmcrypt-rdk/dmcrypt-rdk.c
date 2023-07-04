/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 Liberty Global B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author: Piotr Nakraszewicz <piotr.nakraszewicz@redembedded.com>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1 /**/ to get the S_ISVTX visible */
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdbool.h>

#ifndef VERSION
#define VERSION "Unknown"
#endif

// Based on
// https://wiki.sei.cmu.edu/confluence/display/c/FIO15-C.+Ensure+that+file+operations+are+performed+in+a+secure+directory
static int validate_dir(const char *path, bool allow_sticky_bit)
{
    struct stat st;

    if (lstat(path, &st)) {
        fprintf(stderr, "lstat %s failed: %d, %s\n", path, errno, strerror(errno));
        return -1;
    }

    if (S_ISLNK(st.st_mode)) {
        fprintf(stderr, "%s is a symlink\n", path);
        return -1;
    }

    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "%s is not a directory\n", path);
        return -1;
    }

    if (st.st_uid != 0) {
        fprintf(stderr, "%s is not owned by root\n", path);
        return -1;
    }

    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        // If the directory is writable by others, but has sticky bit set,
        // it means that others can't modify files in that directory that
        // don't belong to them. So that's secure.
        if (!(allow_sticky_bit && (st.st_mode & S_ISVTX))) {
            fprintf(stderr, "%s is writable by not only root\n", path);
            return -1;
        }
    }
    return 0;
}

int execute_process(char *name, char **args)
{
    char *execve_env[] = {NULL};
    pid_t pid;
    int child_status;
    int wait_status;

    fprintf(stderr, "executing: ");
    for (size_t i = 0; args[i]; i++) {
        if (i > 0) {
            fprintf(stderr, " ");
        }
        fprintf(stderr, "\"%s\"", args[i]);
    }
    fprintf(stderr, "\n");

    if (!name || !args) {
        fprintf(stderr, "execute_process: invalid arguments\n");
        return -1;
    }

    if (name[0] != '/') {
        fprintf(stderr, "execute_process: full path required for %s\n", name);
        return -1;
    }

    pid = fork();

    // child
    if (pid == 0) {
        execve(name, args, execve_env);
        fprintf(stderr, "execve failed: %d, %s\n", errno, strerror(errno));
        exit(-1);
    }

    // parent error
    if (pid < 0) {
        fprintf(stderr, "fork failed: %d, %s\n", errno, strerror(errno));
        return -1;
    }

    // parent ok
    do {
        wait_status = waitpid(pid, &child_status, WUNTRACED | WCONTINUED);
        if (wait_status == -1) {
            fprintf(stderr, "waitpid failed: %d, %s\n", errno, strerror(errno));
            return -1;
        }

        if (WIFEXITED(child_status)) {
            child_status = WEXITSTATUS(child_status);
            if (child_status != 0) {
                fprintf(stderr, "child didn't exit gracefully: %d\n", child_status);
                return -1;
            }
            // The proper path ends here
            return 0;
        }
        else if (WIFSIGNALED(child_status)) {
            fprintf(stderr, "child killed by signal %d\n", WTERMSIG(child_status));
            return -1;
        }
        else if (WIFSTOPPED(child_status)) {
            printf("stopped by signal %d\n", WSTOPSIG(child_status));
        }
        else if (WIFCONTINUED(child_status)) {
            printf("continued\n");
        }
    } while (!WIFEXITED(child_status) && !WIFSIGNALED(child_status));

    return -1;  // should never reach here
}

int copy_file(char *source, char *dest)
{
    char name[] = "/bin/cp";
    char arg1[] = "-a";

    char *execve_args[] = {name, arg1, source, dest, NULL};

    if (!source || !dest) {
        fprintf(stderr, "copy_file: arguments not provided\n");
        return -1;
    }

    printf("copying %s into %s\n", source, dest);
    return execute_process(name, execve_args);
}

int resize_file(char *file_path, bool reduced)
{
    // luks header is 2050 sectors, we need to make space for it
    char name[] = "/usr/bin/truncate";
    char arg1[] = "-s";
    // OMWHMXRI-1206 reduce device size by as small value as possible
    // cryptsetup does not wipe padding after keyslots area, which may result
    // in a data leak. Reserve minimum allowed space for LUKS header in order
    // to avoid that.
    // 2050 sectors aligned to 4096B (as required by device mapper) = 2056 sectors
    // 2056 sectors * 512B = 1052672B
    char arg2_legacy[] = "+2097152";
    char arg2_reduced[] = "+1052672";
    char *arg2 = reduced ? arg2_reduced : arg2_legacy;

    char *execve_args[] = {name, arg1, arg2, file_path, NULL};

    if (!file_path) {
        fprintf(stderr, "resize_file: arguments not provided\n");
        return -1;
    }

    printf("resizing %s, size: %s\n", file_path, arg2);
    return execute_process(name, execve_args);
}

// returns 1 when supported, 0 otherwise
int luks_type_is_supported()
{
    char name[] = "/sbin/cryptsetup-reencrypt";
    char arg1[] = "--type=luks1";
    char arg2[] = "--help";
    char *execve_args[] = {name, arg1, arg2, NULL};
    int result;

    printf("testing luks_type_support with %s %s\n", arg1, arg2);
    result = execute_process(name, execve_args) == 0 ? 1 : 0;
    printf("luks_type_is_supported: %s\n", result?"YES":"NO");
    return result;
}

// returns 1 when supported, 0 otherwise
int pbkdf_force_iterations_is_supported()
{
    char name[] = "/sbin/cryptsetup-reencrypt";
    char arg1[] = "--pbkdf-force-iterations=1000";
    char arg2[] = "--help";
    char *execve_args[] = {name, arg1, arg2, NULL};
    int result;

    printf("testing pbkdf-force-iterations support with %s %s\n", arg1, arg2);
    result = execute_process(name, execve_args) == 0 ? 1 : 0;
    printf("pbkdf_force_iterations_is_supported: %s\n", result?"YES":"NO");
    return result;
}

static bool is_cryptsetup_reencrypt_exists() {
    struct stat st;

    return lstat("/sbin/cryptsetup-reencrypt", &st) == 0 ? 1 : 0;
}


int encrypt_image(char *image_path, int iter_time_ms, char *cipher, char *hash, bool reduced)
{
    int res;
    const bool use_cryptsetup_reencrypt = is_cryptsetup_reencrypt_exists(); // for cryptsetup older then 2.5 version
    char *name = use_cryptsetup_reencrypt ? "/sbin/cryptsetup-reencrypt" : "/sbin/cryptsetup";
    char *reencrypt_opt = use_cryptsetup_reencrypt ? "" : "reencrypt";
    char new_hdr_opt[] = "--new";
    // OMWHMXRI-1206 reduce device size by ase small value as possible
    // cryptsetup does not wipe padding after keyslots area, which may result
    // in a data leak. Reserve minimum allowed space for LUKS header in order
    // to avoid that
    // 2050 sectors aligned to 4096B (as required by device mapper) = 2056 sectors
    // For backward compatibility, we need to keep old value as a default
    // New padding value will be used only if 'reduced' flag is set to true
    char *device_size_opt = reduced ? "--reduce-device-size=2056S" : "--reduce-device-size=4096S";
    char hash_opt[32] = { 0 };
    char cipher_opt[32] = { 0 };
    char iter_time_opt[32] = { 0 };
    char *luks_type_opt = use_cryptsetup_reencrypt ?
                           (luks_type_is_supported() ? "--type=luks1" : "") :
                           "--type=luks1";
    char *forced_iters_opt = use_cryptsetup_reencrypt ?
                            (pbkdf_force_iterations_is_supported() ? "--pbkdf-force-iterations=1000" : "") :
                             "--pbkdf-force-iterations=1000";

    char* execve_args[] = {name, reencrypt_opt, new_hdr_opt, device_size_opt, hash_opt, cipher_opt, luks_type_opt, forced_iters_opt, image_path, NULL};

    if (use_cryptsetup_reencrypt)
        fprintf(stderr, "WARNING: Using old /sbin/cryptsetup-reencrypt. Please consider upgrading cryptsetup tools.\n");

    if (!image_path) {
        fprintf(stderr, "encrypt_image: arguments not provided\n");
        return -1;
    }

    /* finetune iter-time, cipher and hash per target platform */

    res = snprintf(iter_time_opt, sizeof(iter_time_opt), "--iter-time=%d", iter_time_ms);
    if (res < 0 || (size_t)res >= sizeof(iter_time_opt)) {
        fprintf(stderr, "snprintf failed for --iter-time argument, res = %d.\n", res);
        return -1;
    }

    res = snprintf(cipher_opt, sizeof(cipher_opt), "--cipher=%s", cipher);
    if (res < 0 || (size_t)res >= sizeof(cipher_opt)) {
        fprintf(stderr, "snprintf failed for --cipher argument, res = %d.\n", res);
        return -1;
    }

    res = snprintf(hash_opt, sizeof(hash_opt), "--hash=%s", hash);
    if (res < 0 || (size_t)res >= sizeof(hash_opt)) {
        fprintf(stderr, "snprintf failed for --hash argument, res = %d.\n", res);
        return -1;
    }

    { // Simply remove empty arguments ("") from the list
        int num_args = 0;
        for (; execve_args[num_args] != NULL; num_args++) {};

        for (int i = num_args - 1; i > 0; i--) {
            if (strlen(execve_args[i]) == 0) {
                for (int j = i; j < num_args; j++) {
                    execve_args[j] = execve_args[j + 1];
                }
                num_args--;
            }
        }
    }

    return execute_process(name, execve_args);
}

int move_file(char *source, char *dest)
{
    char name[] = "/bin/mv";

    char *execve_args[] = {name, source, dest, NULL};

    if (!source || !dest) {
        fprintf(stderr, "move_file: arguments not provided\n");
        return -1;
    }

    printf("moving %s into %s\n", source, dest);
    return execute_process(name, execve_args);
}


int main(int argc, char **argv)
{
    char secure_dir_template[] = "/tmp/cryptsetup-workdir.XXXXXX";
    char *secure_dir;
    const char *secure_dir_parent = "/tmp/";
    char *image_path;
    int iter_time_ms;
    char *cipher;
    char *hash;
    bool reduced;
    const char *image_file;
    char enc_file_work_path[1024];
    char enc_file_final_path[1024];
    int res;

    fprintf(stderr, "%s version: %s\n", argv[0], VERSION);

    if (argc < 2 || argc > 6 ) {
        fprintf(stderr, "Usage: %s <image_path> [iter_time_ms] [cipher] [hash] [reduced]\n", argv[0]);
        return -1;
    }

    image_path = argv[1];
    image_file = (image_file = strrchr(image_path, '/')) ? image_file + 1 : image_path;
    printf("image_path: %s, image_file: %s\n", image_path, image_file);

    if (argc >= 3) {
        long val;

        errno = 0;
        val = strtol(argv[2], NULL, 10);
        if (errno) {
            printf("iter_time_ms strtol() conversion error: %s\n", strerror(errno));
            return -1;
        }

        if (val < 1 || val > 10000) {
            printf("iter_time_ms out of range 1..10000\n");
            return -1;
        }

        iter_time_ms = val;
    } else {
        iter_time_ms = 1000;
    }
    printf("iter_time_ms: %d\n", iter_time_ms);

    if (argc >= 4) {
        cipher = argv[3];
    } else {
        cipher = "aes-xts-plain64";
    }
    printf("cipher: %s\n", cipher);

    if (argc >= 5) {
        hash = argv[4];
    } else {
        hash = "sha1";
    }
    printf("hash: %s\n", hash);

    if (argc >= 6) {
        reduced = true;
    } else {
        reduced = false;
    }
    printf("reduced: %d\n", reduced);

    // Program is meant to be called with setuid bit set which elevates effective user id.
    // But to really have the required privileges we need to set real user id too.
    if (setreuid(0, 0)) {
        fprintf(stderr, "setreuid failed: %d:%s\n", errno, strerror(errno));
        return errno;
    }

    // Before creating our secure dir, lets make sure that its parent dir is also secure.
    // For parent dir it is okay if others can write as long as sticky bit is set
    if (validate_dir(secure_dir_parent, true)) {
        return -1;
    }

    // mkdtemp creates the directory with permissions 0700 owned by effective user id -
    // so it's secure from the start.
    secure_dir = mkdtemp(secure_dir_template);
    if (!secure_dir) {
        fprintf(stderr, "mkdtemp %s failed: %d, %s\n", secure_dir_template, errno, strerror(errno));
        return errno;
    }

    // prepare path for the encrypted image in the secure directory
    res = snprintf(enc_file_work_path, sizeof(enc_file_work_path), "%s/%s.enc", secure_dir, image_file);
    if (res < 0 || (size_t)res >= sizeof(enc_file_work_path)) {
        fprintf(stderr, "snprintf failed. res = %d. Most probably file name too long.\n", res);
        return -1;
    }

    // prepare path for the encrypted image in the original directory (same as non enc image)
    res = snprintf(enc_file_final_path, sizeof(enc_file_final_path), "%s.enc", image_path);
    if (res < 0 || (size_t)res >= sizeof(enc_file_final_path)) {
        fprintf(stderr, "snprintf failed. res = %d. Most probably file name too long.\n", res);
        return -1;
    }

    if (copy_file(image_path, enc_file_work_path)) {
        fprintf(stderr, "copy_file %s %s failed.\n", image_path, enc_file_work_path);
        return -1;
    }

    if (resize_file(enc_file_work_path, reduced)) {
        fprintf(stderr, "resize_file %s failed.\n", enc_file_work_path);
        return -1;
    }

    if (encrypt_image(enc_file_work_path, iter_time_ms, cipher, hash, reduced)) {
        fprintf(stderr, "encrypt_image %s failed.\n", enc_file_work_path);
        return -1;
    }

    if (move_file(enc_file_work_path, enc_file_final_path)) {
        fprintf(stderr, "move_file %s %s failed.\n", enc_file_work_path, enc_file_final_path);
        return -1;
    }

    printf("removing %s\n", secure_dir);
    if (rmdir(secure_dir)) {
        fprintf(stderr, "rmdir %s failed: %d, %s\n", secure_dir, errno, strerror(errno));
        return errno;
    }

    return 0;
}
