#include <iostream>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>		/* open */
#include <unistd.h>		/* exit */
#include <sys/ioctl.h>		/* ioctl */

#define DEVICE_NAME "/dev/Injector"

typedef struct {
    int pid;
    const char* so_path;
    size_t so_path_size;
} SoInjectionParameters;

int main() {
	const char* so_path = "/root/libhello.so";
	int fd = open(DEVICE_NAME, 0);
	if (fd < 0) {
		printf("Can't open device file: %s\n", DEVICE_NAME);
		return 1;
	}
	SoInjectionParameters parameters;
	std::cout << "Enter the pid: " << std::endl;
	std::cin >> parameters.pid;
	parameters.so_path = so_path;
	parameters.so_path_size = strlen(so_path);
	ioctl(fd, 1337, (void*)&parameters);
	return 0;
}
