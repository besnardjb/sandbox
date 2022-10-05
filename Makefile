CC=gcc
CFLAGS=-Wall -Wextra -Werror


all: sandbox


sandbox: main.c
	$(CC) $(FLAGS) $^ -o $@


suid: sandbox
	sudo chown root ./sandbox
	sudo chmod u+s ./sandbox

clean:
	rm -fr ./sandbox