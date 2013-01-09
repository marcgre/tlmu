#define TOP_OF_RAM	(0x19000000 + (32 * 1024))
#define MAGIC_PUTC	(0x10500000 + 4)
#define MAGIC_EXIT	(0x10500000 + 8)

void exit(int ec)
{
	*(volatile int *) (MAGIC_EXIT) = ec;
	while (1)
		; /* Wait for the sim to quit.  */
}

int putchar(int c)
{
	*(volatile int *) (MAGIC_PUTC) = c;
    return 0;
}

void putstr(const char *s)
{
	while (*s) {
		putchar(*s);
		s++;
	}
}

void run(void)
{
	putstr("Hello, I am the OPENRISC(or32)\n");
	exit(0);
}
