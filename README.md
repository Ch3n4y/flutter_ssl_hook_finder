# Flutter SSL Hook Finder

这是一个用于分析Android Flutter应用中libflutter.so库文件的工具，主要用于查找与SSL相关的函数引用，便于进行网络安全分析和调试。

## 功能特点

- 查找SO文件中的特定字符串（默认为"ssl_client"）
- 定位引用这些字符串的函数地址和名称
- 以JSON格式输出分析结果
- 支持自定义搜索字符串
- 跨平台：支持Windows、macOS和Linux

## 前置条件

- 安装 [radare2](https://github.com/radareorg/radare2)（r2），这是一个用于二进制分析的开源工具
  - 在Ubuntu/Debian: `sudo apt install radare2`
  - 在macOS: `brew install radare2`
  - 在Windows: 通过[GitHub发布页](https://github.com/radareorg/radare2/releases)下载安装

## 示例SO文件

仓库中包含的 `libflutter.so` 是一个用于测试的示例SO文件。这是从实际的Flutter应用中提取的共享库文件，您可以用它来测试本工具的功能。

**注意**: 此示例文件仅用于教育和测试目的，请勿用于其他用途。

## 安装使用

### 使用 go get 安装
如果您已经安装了Go环境，可以直接使用以下命令安装：

```bash
go get github.com/ch3n4y/flutter_ssl_hook_finder
```

安装完成后，您可以直接运行：

```bash
flutter_ssl_hook_finder path/to/libflutter.so [可选搜索字符串]
```

### 直接从发布版下载
从[GitHub Releases](https://github.com/ch3n4y/flutter_ssl_hook_finder/releases)下载适合您平台的预编译二进制文件。

### 从源码编译
```bash
# 克隆仓库
git clone https://github.com/ch3n4y/flutter_ssl_hook_finder.git
cd flutter_ssl_hook_finder

# 编译
go build

# 运行
./flutter_ssl_hook_finder path/to/libflutter.so [可选搜索字符串]
```

## 使用示例

```bash
# 使用默认搜索字符串 "ssl_client"
./flutter_ssl_hook_finder path/to/libflutter.so

# 使用自定义搜索字符串
./flutter_ssl_hook_finder path/to/libflutter.so "custom_ssl_string"

# 使用仓库中提供的示例SO文件
./flutter_ssl_hook_finder ./libflutter.so
```

## 输出示例

```json
{
  "file_name": "libflutter.so",
  "search_string": "ssl_client",
  "success": true,
  "functions": [
    {
      "index": 1,
      "address": "0x123456",
      "name": "fcn.123456"
    },
    {
      "index": 2,
      "address": "0x789abc",
      "name": "fcn.789abc"
    }
  ]
}
```

## 输出说明

- `file_name`: 分析的文件名
- `search_string`: 搜索的字符串
- `success`: 是否成功找到引用
- `functions`: 找到的函数列表
  - `index`: 函数索引
  - `address`: 函数地址
  - `name`: 函数名称
- `error`: 如果分析失败，这里会包含错误信息

## 原理说明

1. 使用Go的`debug/elf`库打开并解析ELF文件（Android的SO文件是ELF格式）
2. 在加载段（PT_LOAD）中搜索目标字符串
3. 使用radare2的`axt`命令查找对这些字符串的交叉引用
4. 解析引用结果，提取函数地址和名称

## 许可证

本项目采用 MIT 许可证。

```
MIT License

Copyright (c) 2025 ch3n4y

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
```

## 贡献

欢迎提交问题和PR！ 