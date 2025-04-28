package main

import (
	"bytes"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// 结果结构体
type Result struct {
	FileName     string     `json:"file_name"`
	SearchString string     `json:"search_string"`
	Success      bool       `json:"success"`
	Functions    []Function `json:"functions,omitempty"`
	Error        string     `json:"error,omitempty"`
}

// 函数结构体
type Function struct {
	Index   int    `json:"index"`
	Address string `json:"address"`
	Name    string `json:"name"`
}

// SSLClientFinder 结构体
type SSLClientFinder struct {
	SoPath    string
	SearchStr string
}

// 创建新的SSLClientFinder实例
func NewSSLClientFinder(soPath, searchStr string) *SSLClientFinder {
	if searchStr == "" {
		searchStr = "ssl_client"
	}
	return &SSLClientFinder{
		SoPath:    soPath,
		SearchStr: searchStr,
	}
}

// 检查radare2是否安装
func CheckRadare2() bool {
	cmd := exec.Command("r2", "-v")
	err := cmd.Run()
	return err == nil
}

// 运行radare2命令并返回输出
func RunR2Command(soPath string, commands []string) (string, error) {
	// 构建命令字符串
	cmdStr := strings.Join(commands, "; ")

	// 准备r2命令
	cmd := exec.Command("r2", "-c", cmdStr, "-q", soPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// 执行命令
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("radare2命令执行失败: %s", stderr.String())
	}

	return strings.TrimSpace(stdout.String()), nil
}

// 在二进制数据中查找字符串
func FindStringInData(data []byte, searchStr string) []int {
	results := []int{}
	searchBytes := []byte(searchStr)
	searchLen := len(searchBytes)
	dataLen := len(data)

	// 查找精确匹配
	for i := 0; i < dataLen-searchLen+1; i++ {
		if bytes.Equal(data[i:i+searchLen], searchBytes) {
			// 检查是否是完整字符串(后面是0或者字符串结束)
			if i+searchLen >= dataLen || data[i+searchLen] == 0 {
				results = append(results, i)
			}
		}
	}

	return results
}

// 查找字符串引用及其所在函数
func (f *SSLClientFinder) FindStringReferences() ([]string, error) {
	soPath := f.SoPath
	searchStr := f.SearchStr

	stringAddresses := []int{}
	funcAddresses := []string{} // 用于存储找到的所有函数地址

	// 打开ELF文件
	file, err := os.Open(soPath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	// 检查是否是ELF文件
	header := make([]byte, 4)
	if _, err := file.Read(header); err != nil || !bytes.Equal(header, []byte{0x7F, 'E', 'L', 'F'}) {
		return nil, errors.New("不是有效的ELF文件")
	}

	// 重新打开文件以便使用debug/elf包
	file.Seek(0, 0)
	elfFile, err := elf.NewFile(file)
	if err != nil {
		return nil, fmt.Errorf("解析ELF文件失败: %v", err)
	}

	// 遍历所有段，找到字符串
	for _, prog := range elfFile.Progs {
		if prog.Type == elf.PT_LOAD {
			progData := make([]byte, prog.Filesz)
			if _, err := file.Seek(int64(prog.Off), 0); err != nil {
				continue
			}
			if _, err := io.ReadFull(file, progData); err != nil {
				continue
			}

			res := FindStringInData(progData, searchStr)
			for _, offset := range res {
				// 计算字符串在文件中的虚拟地址
				va := prog.Vaddr + uint64(offset)
				stringAddresses = append(stringAddresses, int(va))
			}
		}
	}

	for _, strAddr := range stringAddresses {
		// 查找对该地址的交叉引用
		axtCmd := []string{fmt.Sprintf("aaa; axt %d", strAddr)}
		xrefs, err := RunR2Command(soPath, axtCmd)
		if err != nil {
			continue
		}

		if xrefs != "" && !strings.Contains(strings.ToLower(xrefs), "invalid") {
			// 从xrefs中直接解析函数名称和地址
			fcnRegex := regexp.MustCompile(`(fcn\.[0-9a-fA-F]+)`)
			fcnMatches := fcnRegex.FindAllString(xrefs, -1)

			if len(fcnMatches) > 0 {
				for _, fcnMatch := range fcnMatches {
					// 去掉'fcn.'前缀
					funcAddr := "0x" + fcnMatch[4:]
					// 添加到函数地址列表中
					funcAddresses = append(funcAddresses, funcAddr)
				}
			}
		}
	}

	// 如果找到了函数地址，返回列表；否则返回nil
	if len(funcAddresses) > 0 {
		return funcAddresses, nil
	}
	return nil, nil
}

// 分析SO文件
func (f *SSLClientFinder) Analyze() *Result {
	soPath := f.SoPath
	searchStr := f.SearchStr
	result := &Result{
		FileName:     filepath.Base(soPath),
		SearchString: searchStr,
		Success:      false,
	}

	// 检查文件是否存在
	if _, err := os.Stat(soPath); os.IsNotExist(err) {
		result.Error = fmt.Sprintf("文件不存在: %s", soPath)
		return result
	}

	// 查找字符串引用
	funcAddresses, err := f.FindStringReferences()
	if err != nil {
		result.Error = fmt.Sprintf("查找字符串引用失败: %v", err)
		return result
	}

	// 总结结果
	if len(funcAddresses) > 0 {
		result.Success = true
		result.Functions = make([]Function, len(funcAddresses))

		for i, funcAddr := range funcAddresses {
			funcName := "fcn." + strings.TrimPrefix(funcAddr, "0x")
			result.Functions[i] = Function{
				Index:   i + 1,
				Address: funcAddr,
				Name:    funcName,
			}
		}
		return result
	}

	result.Error = fmt.Sprintf("未能确定与%s相关的函数入口地址", searchStr)
	return result
}

func main() {
	// 检查命令行参数
	if len(os.Args) < 2 {
		result := &Result{
			Success: false,
			Error:   "参数不足",
		}
		jsonOutput, _ := json.Marshal(result)
		fmt.Println(string(jsonOutput))
		os.Exit(1)
	}

	// 检查radare2是否安装
	if !CheckRadare2() {
		result := &Result{
			Success: false,
			Error:   "未找到radare2，请先安装radare2",
		}
		jsonOutput, _ := json.Marshal(result)
		fmt.Println(string(jsonOutput))
		os.Exit(1)
	}

	soPath := os.Args[1]
	searchStr := "ssl_client"

	if len(os.Args) > 2 {
		searchStr = os.Args[2]
	}

	// 分析SO文件
	finder := NewSSLClientFinder(soPath, searchStr)
	result := finder.Analyze()

	// 输出JSON结果
	jsonOutput, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(jsonOutput))

	if !result.Success {
		os.Exit(1)
	}
	os.Exit(0)
}
