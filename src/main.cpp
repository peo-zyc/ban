#include <csignal>
#include <cstdio>

#include "commands.h"

int main(int argc, char** argv) {
    // 子进程写管道被关闭时不要退出
    std::signal(SIGPIPE, SIG_IGN);
    return cli_main(argc, argv);
}
