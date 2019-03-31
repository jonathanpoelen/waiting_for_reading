/* The MIT License (MIT)

Copyright (c) 2019 jonathan poelen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/**
* \author    Jonathan Poelen <jonathan.poelen+wfr@gmail.com>
*/

#include <array>
#include <chrono>
#include <thread>
#include <string_view>

#include <cstring>
#include <cerrno>
#include <cstdio>

#include <unistd.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <syscall.h>

#if defined(__GNUC__) || defined(__clang__)
// https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
// #  define JLN_LIKELY_COND(COND) __builtin_expect((COND) ? true : false, 1)
#  define JLN_UNLIKELY_COND(COND) __builtin_expect((COND) ? true : false, 0)
#else
// #  define JLN_LIKELY_COND(COND) (COND)
#  define JLN_UNLIKELY_COND(COND) (COND)
#endif

#define JLN_PP_STRINGIZE(...) JLN_PP_STRINGIZE_I(__VA_ARGS__)
#define JLN_PP_STRINGIZE_I(...) #__VA_ARGS__

namespace
{

using kernel_ulong_t = decltype(user_regs_struct::rdi);

bool vm_read_mem(pid_t pid, void* laddr, kernel_ulong_t raddr, size_t len)
{
  const struct iovec local = {laddr, len};
  const struct iovec remote = {reinterpret_cast<void*>(raddr), len};

  ssize_t rc = process_vm_readv(pid, &local, 1, &remote, 1, 0);

  if (rc < 0 && errno == ENOSYS)
  {
    fprintf(stderr, "%s\n", strerror(errno));
    return false;
  }
  return true;
}


#define CALL_R(expr) do {                        \
  if constexpr (sizeof(expr) == 1) /*is bool*/   \
  {                                              \
    if (JLN_UNLIKELY_COND(!expr))                \
    {                                            \
      fprintf(stderr, JLN_PP_STRINGIZE(__LINE__) \
        ": " #expr ": false\n");                 \
      return false;                              \
    }                                            \
  }                                              \
  else if (JLN_UNLIKELY_COND(-1 == +(expr)))     \
  {                                              \
    fprintf(stderr, JLN_PP_STRINGIZE(__LINE__)   \
      ": " #expr ": %s\n", strerror(errno));     \
    return false;                                \
  }                                              \
} while (0)

class Ptrace
{
  pid_t pid;
  user_regs_struct regs;

public:
  Ptrace(pid_t pid)
  : pid(pid)
  {}

  auto& syscall() { return regs.orig_rax; }
  auto& arg1() { return regs.rdi; }
  auto& arg2() { return regs.rsi; }
  // auto& arg3() { return regs.rdx; }
  // auto& arg4() { return regs.r10; }
  // auto& arg5() { return regs.r8; }
  // auto& arg6() { return regs.r9; }

  bool next()
  {
    CALL_R(trace(PTRACE_SYSCALL));
    CALL_R(wait());
    CALL_R(trace(PTRACE_GETREGS, &regs));
    return true;
  }

  bool wait()
  {
    CALL_R(waitpid(pid, nullptr, 0));
    return true;
  }

  bool trace(enum __ptrace_request request, void* data = nullptr)
  {
    CALL_R(ptrace(request, pid, nullptr, data));
    return true;
  }

  bool exec_current_syscall()
  {
    ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
    waitpid(pid, nullptr, 0);
    return true;
  }

  auto get_result()
  {
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    return regs.rax;
  }

  // bool set_result(long err)
  // {
  //   /* errno = err */
  //   regs.rax = -err;
  //   ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
  //   return true;
  // }

  bool until_end()
  {
    return trace(PTRACE_CONT);
  }

  // bool ignore_current_syscall()
  // {
  //   syscall() = -1; // set to invalid syscall
  //   ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
  //   ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
  //   waitpid(pid, nullptr, 0);
  //   return set_result(-EPERM); // Operation not permitted
  // }
};

std::size_t file_size(char const* filename)
{
  struct stat st;
  stat(filename, &st);
  return std::size_t(st.st_size);
}

bool run_filter(pid_t pid, std::string_view filename_filter)
{
  Ptrace p{pid};
  kernel_ulong_t fd = kernel_ulong_t(-1);
  const auto delay = std::chrono::seconds(10);
  std::size_t fsize = 0;
  std::size_t nb_byte_read = 0;

  p.wait();
  while (p.next())
  {
    switch (p.syscall())
    {
    case SYS_openat: {
      std::array<char, 1024> open_filename;
      open_filename.back() = 0;
      ssize_t len = vm_read_mem(pid, open_filename.data(), p.arg2(), open_filename.size()-1u);
      p.exec_current_syscall();
      if (len != -1 && filename_filter == open_filename.data())
      {
        fd = p.get_result();
      }
      break;
    }

    case SYS_read:
      if (p.arg1() == fd && fd != kernel_ulong_t(-1))
      {
        if (fsize <= nb_byte_read)
        {
          fsize = file_size(filename_filter.data());
          if (fsize <= nb_byte_read)
          {
            fprintf(stderr, "\x1b[33m\nsleep\x1b[0m\n");
            std::this_thread::sleep_for(delay);
            fsize = file_size(filename_filter.data());
            if (fsize <= nb_byte_read)
            {
              return p.until_end();
            }
          }
        }
        p.exec_current_syscall();
        const auto r = p.get_result();
        if (r > 0)
        {
          nb_byte_read += r;
        }
      }
      else
      {
        p.exec_current_syscall();
      }
      break;

    case SYS_close:
      if (p.arg1() == fd && fd != kernel_ulong_t(-1))
      {
        // fd = -1;
        return p.until_end();
      }
      p.exec_current_syscall();
      break;

    default:
      p.exec_current_syscall();
      break;
    }
  }

  return false;
}

}

int main(int ac, char** av)
{
  if (ac < 3)
  {
    fprintf(stderr, "%s filename cmd args...", av[0]);
    return 1;
  }

  const pid_t pid = fork();
  switch (pid)
  {
  case -1: /* error */
    fprintf(stderr, "fork: %s\n", strerror(errno));
    return 2;
  case 0:  /* child */
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execvp(av[2], av + 2);
    fprintf(stderr, "execvp: %s\n", strerror(errno));
    return 3;
  default:
    if (!run_filter(pid, av[1])) {
      return 4;
    }
  }

  return 0;
}
