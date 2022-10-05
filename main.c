#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <pwd.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

//#define DEBUG_PRINT

static uid_t origin_uid = -1;
static uid_t origin_gid = -1;
static int has_suid = 1;

void help()
{
        fprintf(stderr,
                "sanbox -b [MOUNT1] -b [MOUNT2] -t [TARGET] -- [COMMAND] [COMMAND ARGS...]\n"
                "\n"
                "The quick and dirty sandboxing tool.\n"
                "By default / and $HOME are mounted (-u not to mount $HOME).\n"
                "Default command is bash\n"
                "\n"
                "Options:\n"
                "       -t [PATH] : path where to redirect I/Os\n"
                "       -b [MOUNT] : inject given path in chroot\n"
                "       -u : do not mount user's home\n"
                "       -h : show this help\n");
        exit(1);
}

typedef struct dir_entry_s
{
        char path[1024];
        struct dir_entry_s * next;
}dir_entry_t;


static int _push_dir_entry(dir_entry_t ** entry, const char * pathname)
{
        dir_entry_t * new_dir = (dir_entry_t *)malloc(sizeof(dir_entry_t));

        if(!new_dir)
        {
                perror("malloc");
                return 1;
        }


        snprintf(new_dir->path, 1024, "%s", pathname);

        new_dir->next = *entry;
        *entry = new_dir;

        return 0;
}

static int _dir_entry_in_list(dir_entry_t * entry, const char * pathname)
{
        dir_entry_t * tmp = entry;

        while(tmp)
        {
                if(!strcmp(tmp->path, pathname))
                {
                        return 1;
                }

                tmp = tmp->next;
        }

        return 0;
}



static dir_entry_t * __dirs = NULL;


int push_mkdir(const char * pathname)
{
#ifdef DEBUG_PRINT
        fprintf(stderr, "mkdir @ %s\n", pathname);
#endif
        return _push_dir_entry(&__dirs, pathname);
}


int mkdir_tracked(const char *pathname, mode_t mode)
{

        int ret = mkdir(pathname, mode);

        if(ret != 0 )
        {
                fprintf(stderr, "ERROR: could not create directory %s : %s\n", pathname, strerror(errno));
                return ret;
        }

        chown(pathname, origin_uid, origin_gid);

        push_mkdir(pathname);

        return ret;
}

void rmdir_tracked(void)
{
        dir_entry_t *  tmp = __dirs;

        while(tmp)
        {
#ifdef DEBUG_PRINT
                fprintf(stderr, "Rmdir %s\n", tmp->path);
#endif
                if( rmdir(tmp->path) != 0)
                {
                        fprintf(stderr, "ERROR: Failed to delete directory %s : %s\n", tmp->path, strerror(errno));
                }
                dir_entry_t *  to_free = tmp;
                tmp = tmp->next;
                free(to_free);
        }
}


int populate_prefix_with_dir(const char * prefix, const char * dir)
{
        char path[1024];
        snprintf(path, 1024, "%s/%s", prefix, dir);

        if(mkdir_tracked(path, 0700) != 0)
        {
                return 1;
        }

        return 0;
}

typedef dir_entry_t mount_entry_t;

static mount_entry_t * __mounts = NULL;

int mount_tracked(const char *source, const char *target,
                  const char *filesystemtype, unsigned long mountflags,
                  const void *data)
{

        int ret = mount(source, target, filesystemtype, mountflags, data);

        if(ret != 0)
        {
                return ret;
        }
#ifdef DEBUG_PRINT
        fprintf(stderr, "Mounting %s @ %s %s\n", filesystemtype, target, data?(char*)data:NULL);
#endif
        return _push_dir_entry(&__mounts, target);
}

void umount_tracked(void)
{
        mount_entry_t *  tmp = __mounts;

        while(tmp)
        {
#ifdef DEBUG_PRINT
                fprintf(stderr, "Unmounting %s\n", tmp->path);
#endif
                if(has_suid)
                {
                        if( umount2(tmp->path, MNT_DETACH) != 0 )
                        {
                                fprintf(stderr, "ERROR: Failed to unmount %s : %s\n", tmp->path, strerror(errno));
                        }
                }
                else
                {
                        char command[1024];
                        snprintf(command, 1024, "umount -l %s", tmp->path);
                        if( system(command) != 0 )
                        {
                                fprintf(stderr, "ERROR: Failed to unmount %s\n", tmp->path);
                        }
                }

                mount_entry_t *  to_free = tmp;
                tmp = tmp->next;
                free(to_free);
        }
}


int create_overlay(const char * prefix, const char * target, const char * mname, const char * lower_path)
{

        char upper_path[1024];
        snprintf(upper_path, 1024, "%s/%s_upper_XXXXXX", prefix, mname);

        if( mkdtemp(upper_path) == NULL )
        {
                perror("mkdtemp");
                return 1;
        }

        chown(upper_path, origin_uid, origin_gid);

        push_mkdir(upper_path);

        char work_path[1024];
        snprintf(work_path, 1024, "%s/%s_work", prefix, mname);

        if( mkdir_tracked(work_path, 0700) != 0)
        {
                return 1;
        }

        /* Overlay may create a work subdir */
        char work_subpath[1024];
        snprintf(work_subpath, 1024, "%s/%s_%s/work", prefix, mname, "work");
        push_mkdir(work_subpath);

        char opts[4096];

        if(has_suid)
        {
                snprintf(opts, 4096, "lowerdir=%s,upperdir=%s,workdir=%s", lower_path, upper_path, work_path);

                int ret = mount_tracked("overlay", target, "overlay", MS_MGC_VAL | MS_PRIVATE, opts);

                if(ret != 0)
                {
                        fprintf(stderr, "ERROR: failed to mount overlay for %s : %s\n", lower_path, strerror(errno));
                        return 1;
                }

        }
        else
        {
                snprintf(opts, 4096, "lowerdir=%s,upperdir=%s,workdir=%s", lower_path, upper_path, work_path);

                char command[4096];
                snprintf(command, 4096, "fuse-overlayfs -o %s %s", opts, target);
                if( system(command) != 0 )
                {
                        return 1;
                }

                _push_dir_entry(&__mounts, target);
        }

        return 0;
}

int mount_special(const char * special_name, const char * destination)
{
       int ret = mount_tracked("none", destination, special_name, 0, "");

       if(ret != 0)
       {
                perror("mount");
                fprintf(stderr,"Failed to mount %s @ %s\n", special_name, destination);
       }

       return ret;
}

int mount_bind_mirror(const char * target_path, const char * path)
{
        char mount_name[1024];
        snprintf(mount_name, 1024, "%s", path);

        int i;
        int len = strlen(mount_name);

        for(i = 0 ; i < len; i++)
        {
                if(mount_name[i] == '/')
                {
                        mount_name[i] = '_';
                }
        }


        char mount_path[1024];
        snprintf(mount_path, 1024, "%s/root/%s", target_path, path);

        if( create_overlay(target_path, mount_path, mount_name, path) != 0)
        {
                return 1;
        }
}

void driver_cleanup(void)
{
        umount_tracked();
        rmdir_tracked();
}



static mount_entry_t * __bind_mounts = NULL;


int main(int argc, char ** argv)
{

        if(argc < 2)
        {
                help();
                return 1;
        }

        origin_uid = getuid();
        origin_gid = getgid();

        int mount_home = 1;
        int dochroot = 1;

        char target_path[1024];
        target_path[0] = '\0';

        /* Parse options */
        int opt;

        while((opt = getopt(argc, argv, ":b:t:uhc")) != -1)
        {
                switch(opt)
                {
                        case 'c':
                                fprintf(stderr, "INFO: will not chroot in target\n");
                                dochroot=0;
                                break;
                        case 'h':
                                help();
                                break;
                        case 'u':
                                fprintf(stderr, "INFO: user's home not automatically mounted\n");
                                mount_home = 0;
                                break;
                        case 'b':
                                if(_dir_entry_in_list(__bind_mounts, optarg))
                                {
                                        fprintf(stderr, "ERROR: bind mount %s already provided\n", optarg);
                                        return 1;
                                }

                                fprintf(stderr, "INFO: Register bindmount: %s\n", optarg);

                                if( _push_dir_entry(&__bind_mounts, optarg))
                                {
                                        return 1;
                                }
                                break;
                        case 't':
                                if(strlen(target_path))
                                {
                                        fprintf(stderr, "ERROR: Target '-t' already set to : %s", target_path);
                                        return 1;
                                }
                                else
                                {
                                        fprintf(stderr, "INFO: Overlays will be stored in %s\n", optarg);
                                        snprintf(target_path, 1024, optarg);
                                }
                                break;
                        case ':':
                                printf("ERROR: Option -%c needs a value\n", optopt);
                                break;
                        case '?':
                                printf("ERROR: Unknown option: %c\n", optopt);
                                return 1;
                                break;
                }
        }

        if(!strlen(target_path))
        {
                fprintf(stderr, "ERROR: You must at least specify a directory where to store overlays using '-t [DIR]'");
                return 1;
        }

        if(argc - optind)
        {
                fprintf(stderr, "INFO: Command is ");
                int i = optind;
                for(; i < argc; i++)
                {
                        fprintf(stderr, "%s ", argv[i]);
                }
                fprintf(stderr, "\n");
        }


        if( setuid(0) != 0)
        {
                has_suid = 0;
                mount_home = 0;
                dochroot = 0;
                fprintf(stderr, "INFO: No SUID support $HOME mounting and chroot deactivated\n");
                //return 1;
        }

        /* Get temporary directory */

        if(access(target_path, R_OK | W_OK ))
        {
                fprintf(stderr, "Temporary directory %s must be accessible in R/W for your user", target_path);
                return 1;
        }

        /* Create the root overlay */


        char mount_path[1024];
        snprintf(mount_path, 1024, "%s/root", target_path);

        if( mkdir_tracked(mount_path, 0700) != 0)
        {
                return 1;
        }

        if( create_overlay(target_path, mount_path, "root", "/") != 0)
        {
                driver_cleanup();
                return 1;
        }

        /* Insert /proc and /sys */
        char to_path[1024];
        if(dochroot)
        {
                snprintf(to_path, 1024, "%s/root/sys/", target_path);

                if( mount_special("sysfs", to_path) != 0)
                {
                        driver_cleanup();
                        return 1;
                }

                snprintf(to_path, 1024, "%s/root/proc/", target_path);

                if( mount_special("proc", to_path) != 0)
                {
                        driver_cleanup();
                        return 1;
                }
        }

        /* Inject the Home directory in its overlay if not already bind mounted */
        struct passwd *pw = getpwuid(origin_uid);
        const char *homedir = pw->pw_dir;

        if(!_dir_entry_in_list(__bind_mounts, homedir) && mount_home)
        {
                if( mount_bind_mirror(target_path, homedir) != 0)
                {
                        driver_cleanup();
                        return 1;
                }
        }

        /* Not try bindmounts */
        dir_entry_t * tmp = __bind_mounts;

        while(tmp)
        {
                if( mount_bind_mirror(target_path, tmp->path) != 0)
                {
                        driver_cleanup();
                        return 1;
                }

                dir_entry_t * to_free = tmp;
                tmp = tmp->next;
                free(to_free);
        }


        pid_t pid = fork();

        if(pid != 0)
        {
                signal(SIGINT, SIG_IGN);
                wait(NULL);
                driver_cleanup();
                return 0;
        }

        if(dochroot)
        {
                int ret = unshare(CLONE_NEWNS);

                if(ret != 0)
                {
                        driver_cleanup();
                        perror("unshare");
                        return 1;
                }


                char cwd[1024];
                getcwd(cwd, 1024);

                snprintf(to_path, 1024, "%s/root/", target_path);

                //TODO try pivot root
        #if 1
                if( chroot(to_path) != 0)
                {
                        perror("chroot");
                        return 1;
                }

        #else
                /* TODO:
                        - No mount on the target prior to pivot root
                        - The parent directory shall not be MS_SHARED (seems to be last issue)
                */

                char old_root[1024];
                snprintf(old_root, 1024, "%s/root/.old_root", target_path);

                if( mkdir_tracked(old_root, 0700) != 0)
                {
                        driver_cleanup();
                        return 1;
                }

                if( syscall(SYS_pivot_root, to_path, old_root) != 0)
                {
                        perror("pivot_root");
                        driver_cleanup();
                        return 1;
                }
        #endif

                if( chdir(cwd) != 0 )
                {
                        perror("chdir");
                        //return 1;
                }

        }
        else
        {
                snprintf(to_path, 1024, "%s/root/", target_path);
                if( chdir(to_path) != 0 )
                {
                        perror("chdir");
                        //return 1;
                }
        }


        if(has_suid)
        {
                /* Restore original UID */
                setuid(origin_uid);
        }

        char ** cmd;

        if(argc - optind)
        {
                cmd = &argv[optind];
        }
        else
        {
                char *tcmd[] = {"bash", NULL};
                cmd = tcmd;
        }


        if( execvp(cmd[0], cmd) != 0 )
        {
                perror("execvp");
        }

        return 0;
}
