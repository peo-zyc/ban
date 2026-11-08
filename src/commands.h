#pragma once

// CLI 入口：解析参数并分发子命令。
// 返回值为进程退出码：
//   0 成功 / 1 一般错误 / 2 用法错误 / 3 权限不足 / 4 依赖缺失 / 5 部分失败
int cli_main(int argc, char** argv);
