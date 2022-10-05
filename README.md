# Sandbox

An overlay FS sandboxing tool to run modifications on a file-system without modifying it.
It can be seen as a "transparent" container. Note that for now we use chroot for simplicity which is easy to break out of it is then not itended for **secure** isolation but more for FS redirection.

## Install

```
git clone https://github.com/besnardjb/sandbox.git
cd sandbox
make sandbox # Compile
make suid # add suid flag
```

## Usage

```
sanbox -b [MOUNT1] -b [MOUNT2] -t [TARGET] -- [COMMAND] [COMMAND ARGS...]

The quick and dirty sandboxing tool.
By default / and $HOME are mounted (-u not to mount $HOME).
Default command is bash

Options:
       -t [PATH] : path where to redirect I/Os
       -b [MOUNT] : inject given path in chroot
       -u : do not mount user's home
       -h : show this help
```

## Examples

Run a bash in a sandbox, all I/Os are redirected to ./tmpfs/:

```sh
# create storage directory
$ mkdir tmpfs
# Run the sandbox
$ ./sandbox -t tmpfs
# You now run bash in your sandbox
<SANDBOX>$ mount
overlay on / type overlay (rw,relatime,lowerdir=/,upperdir=tmpfs/root_upper_gagLDH,workdir=tmpfs/root_work)
none on /sys type sysfs (rw,relatime)
none on /proc type proc (rw,relatime)
overlay on /home/jbbesnard type overlay (rw,relatime,lowerdir=/home/jbbesnard,upperdir=tmpfs/_home_jbbesnard_upper_c1dp1E,workdir=tmpfs/_home_jbbesnard_work)
# Leave sandbox
<SANDBOX>$ exit
# Here content was added to this layer the directory remains
ERROR: Failed to delete directory tmpfs/_home_jbbesnard_upper_c1dp1E : Directory not empty
# See what was written in the overlay
$ tree -a ./tmpfs/_home_jbbesnard_upper_c1dp1E
./tmpfs/_home_jbbesnard_upper_c1dp1E
└── home
    └── jbbesnard
        └── .bash_history
```
