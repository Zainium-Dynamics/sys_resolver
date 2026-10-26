/* execl, execlp, execle for libsys_resolver.so. They are variadic, which stable Rust cannot
   define, so they live here: each collects its arguments on the stack (no allocation: this can
   run in a vfork() child) and goes through the execv/execvp/execve hooks like every other exec.
   Built with no libc of its own, like the rest of the library (see build-so.sh). */
#include <stdarg.h>
#include <stddef.h>

int execv(const char *path, char *const argv[]);
int execvp(const char *file, char *const argv[]);
int execve(const char *path, char *const argv[], char *const envp[]);

int execl(const char *path, const char *argv0, ...)
{
	int argc, i;
	va_list ap;
	va_start(ap, argv0);
	for (argc = 1; va_arg(ap, const char *); argc++)
		;
	va_end(ap);
	{
		char *argv[argc + 1];
		va_start(ap, argv0);
		argv[0] = (char *)argv0;
		for (i = 1; i < argc; i++)
			argv[i] = va_arg(ap, char *);
		argv[i] = NULL;
		va_end(ap);
		return execv(path, argv);
	}
}

int execlp(const char *file, const char *argv0, ...)
{
	int argc, i;
	va_list ap;
	va_start(ap, argv0);
	for (argc = 1; va_arg(ap, const char *); argc++)
		;
	va_end(ap);
	{
		char *argv[argc + 1];
		va_start(ap, argv0);
		argv[0] = (char *)argv0;
		for (i = 1; i < argc; i++)
			argv[i] = va_arg(ap, char *);
		argv[i] = NULL;
		va_end(ap);
		return execvp(file, argv);
	}
}

int execle(const char *path, const char *argv0, ...)
{
	int argc, i;
	va_list ap;
	va_start(ap, argv0);
	for (argc = 1; va_arg(ap, const char *); argc++)
		;
	va_end(ap);
	{
		char *argv[argc + 1];
		char **envp;
		va_start(ap, argv0);
		argv[0] = (char *)argv0;
		for (i = 1; i <= argc; i++)
			argv[i] = va_arg(ap, char *);
		envp = va_arg(ap, char **);
		va_end(ap);
		return execve(path, argv, envp);
	}
}
