/*
 * node_dispatch.c —— 单一可执行文件的运行时 ML-DSA 参数集分发器。
 *
 * 协议实现（src/sign/src 目录下的 C 源码）大量使用编译期常量（K、L、数组长度），因此构建时把同一份
 * 源码分别以 MLDSA_MODE=44/65/87 各编译一遍，再各自部分链接成一个只导出
 * node_main_<mode> 的目标文件（其余符号全部本地化，三套实现互不冲突），最后与本文件
 * 链接成**一个** node 二进制。运行时根据参数选择其中一套：
 *
 *   node <config.conf> ...                  读取配置（含 include=）里的 mldsa_mode
 *   node --mldsa-mode 65 <config.conf> ...  显式指定；与配置不一致会被拒绝
 *   node selftest [--mldsa-mode N | --all-modes] [...]
 *   node verify <pk.bin> <sig.bin> <msg.txt> 按公钥长度自动识别参数集
 *   node modes                              列出本二进制支持的参数集
 *
 * 一次配置、一次编译，之后每次运行都可以换参数集，不需要重新编译。
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int node_main_44(int argc, char **argv);
int node_main_65(int argc, char **argv);
int node_main_87(int argc, char **argv);

typedef struct {
    int mode;
    long pk_bytes;
    int (*entry)(int, char **);
} ModeEntry;

static const ModeEntry MODES[] = {
    { 44, 1312, node_main_44 },
    { 65, 1952, node_main_65 },
    { 87, 2592, node_main_87 },
};
#define MODE_COUNT ((int)(sizeof(MODES) / sizeof(MODES[0])))

static const ModeEntry *find_mode(int mode) {
    for (int i = 0; i < MODE_COUNT; i++)
        if (MODES[i].mode == mode) return &MODES[i];
    return NULL;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "用法（同一个二进制支持 ML-DSA-44/65/87，运行时选择）:\n"
            "  %s [--mldsa-mode 44|65|87] <config.conf> [--message <text>] [--out-dir <dir>]\n"
            "  %s selftest [--mldsa-mode 44|65|87 | --all-modes] [--batch K] [--pool L]\n"
            "             [--pool-mode fixed|refill] [--fault-inject]\n"
            "  %s verify [--mldsa-mode 44|65|87] <public_key.bin> <signature.bin> <message.txt>\n"
            "  %s modes\n"
            "未指定 --mldsa-mode 时：签名运行读配置里的 mldsa_mode，verify 按公钥长度识别，\n"
            "selftest 默认 44。\n",
            prog, prog, prog, prog);
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) *--e = '\0';
    return s;
}

/* 与 config.c 相同的语义：顺序解析，include= 相对所在文件目录，后出现的值覆盖先出现的。 */
static int scan_mode(const char *path, int depth, int *mode) {
    if (depth > 4) return -1;
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char line[1024];
    int rc = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        char *s = trim(line);
        char *eq = strchr(s, '=');
        if (!*s || !eq) continue;
        *eq = '\0';
        char *key = trim(s), *val = trim(eq + 1);
        if (strcmp(key, "include") == 0) {
            char inc[PATH_MAX];
            const char *slash = strrchr(path, '/');
            if (val[0] == '/' || !slash) snprintf(inc, sizeof(inc), "%s", val);
            else snprintf(inc, sizeof(inc), "%.*s/%s", (int)(slash - path), path, val);
            if (scan_mode(inc, depth + 1, mode) != 0) { rc = -1; break; }
        } else if (strcmp(key, "mldsa_mode") == 0) {
            *mode = atoi(val);
        }
    }
    fclose(fp);
    return rc;
}

static int parse_mode_value(const char *s) {
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (!s[0] || !end || *end) return -1;
    return find_mode((int)v) ? (int)v : -1;
}

/* 从 argv 中剥离 --mldsa-mode N / --mldsa-mode=N / --all-modes，其余参数原样保留。 */
static int strip_args(int argc, char **argv, char **out, int *out_argc, int *mode, int *all_modes) {
    int n = 0;
    for (int i = 0; i < argc; i++) {
        if (i > 0 && strcmp(argv[i], "--mldsa-mode") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "--mldsa-mode 需要参数 44|65|87\n"); return -1; }
            *mode = parse_mode_value(argv[++i]);
            if (*mode < 0) { fprintf(stderr, "不支持的 --mldsa-mode: %s（可选 44/65/87）\n", argv[i]); return -1; }
        } else if (i > 0 && strncmp(argv[i], "--mldsa-mode=", 13) == 0) {
            *mode = parse_mode_value(argv[i] + 13);
            if (*mode < 0) { fprintf(stderr, "不支持的 %s（可选 44/65/87）\n", argv[i]); return -1; }
        } else if (i > 0 && strcmp(argv[i], "--all-modes") == 0) {
            *all_modes = 1;
        } else {
            out[n++] = argv[i];
        }
    }
    out[n] = NULL;
    *out_argc = n;
    return 0;
}

int main(int argc, char **argv) {
    char **av = calloc((size_t)argc + 1, sizeof(char *));
    if (!av) return 1;
    int ac = 0, mode = -1, all_modes = 0;
    if (strip_args(argc, argv, av, &ac, &mode, &all_modes) != 0) { usage(argv[0]); return 2; }

    if (ac < 2 || strcmp(av[1], "-h") == 0 || strcmp(av[1], "--help") == 0) {
        usage(argv[0]);
        return ac < 2 ? 2 : 0;
    }

    if (strcmp(av[1], "modes") == 0) {
        for (int i = 0; i < MODE_COUNT; i++) printf("%d%s", MODES[i].mode, i + 1 < MODE_COUNT ? " " : "\n");
        return 0;
    }

    if (strcmp(av[1], "selftest") == 0) {
        if (all_modes) {
            int rc = 0;
            for (int i = 0; i < MODE_COUNT; i++) {
                printf("==================== selftest ML-DSA-%d ====================\n", MODES[i].mode);
                fflush(stdout);
                int r = MODES[i].entry(ac, av);
                printf("[dispatch] ML-DSA-%d selftest %s\n", MODES[i].mode, r == 0 ? "OK" : "FAIL");
                if (r != 0) rc = r;
            }
            return rc;
        }
        return find_mode(mode > 0 ? mode : 44)->entry(ac, av);
    }

    if (strcmp(av[1], "verify") == 0) {
        if (mode < 0) {
            struct stat st;
            if (ac < 3 || stat(av[2], &st) != 0) {
                fprintf(stderr, "无法读取公钥文件，无法自动识别参数集；可用 --mldsa-mode 显式指定\n");
                return 1;
            }
            for (int i = 0; i < MODE_COUNT; i++)
                if ((long)st.st_size == MODES[i].pk_bytes) mode = MODES[i].mode;
            if (mode < 0) {
                fprintf(stderr, "公钥长度 %ld 字节不对应任何 ML-DSA 参数集（1312/1952/2592）\n", (long)st.st_size);
                return 1;
            }
        }
        return find_mode(mode)->entry(ac, av);
    }

    /* 签名运行：配置里的 mldsa_mode 是权威值。 */
    int cfg_mode = 44;
    char abs[PATH_MAX];
    const char *conf = realpath(av[1], abs) ? abs : av[1];
    if (scan_mode(conf, 0, &cfg_mode) != 0) {
        fprintf(stderr, "[dispatch] 无法读取配置 %s\n", av[1]);
        return 1;
    }
    if (mode > 0 && mode != cfg_mode) {
        fprintf(stderr, "[dispatch] --mldsa-mode %d 与配置中的 mldsa_mode=%d 不一致\n", mode, cfg_mode);
        return 2;
    }
    const ModeEntry *m = find_mode(cfg_mode);
    if (!m) {
        fprintf(stderr, "[dispatch] 配置中的 mldsa_mode=%d 不受支持（可选 44/65/87）\n", cfg_mode);
        return 2;
    }
    return m->entry(ac, av);
}
