# 🛡️ MassAudit Pro: Intelligent Code Security Audit System

> **Automated Static Analysis & AI-Assisted Verification Tool**
> **基于 CodeQL 与大模型的自动化静态代码审计与验证系统**

![Python](https://img.shields.io/badge/Python-3.9%2B-blue) ![CodeQL](https://img.shields.io/badge/Engine-CodeQL-green) ![DeepSeek](https://img.shields.io/badge/AI-DeepSeek%20%2F%20Local-purple) ![License](https://img.shields.io/badge/License-MIT-grey)

**MassAudit Pro** 是一款面向企业安全建设与 DevSecOps 流程的自动化代码审计工具。它致力于解决传统静态应用程序安全测试 (SAST) 工具误报率高、验证成本大的问题。

系统深度整合了 **CodeQL** 的污点追踪能力与 **LLM (大语言模型)** 的逻辑分析能力，不仅能发现深层逻辑漏洞，还能尝试生成**单元测试级别的验证脚本 (PoC Drafts)**，辅助安全工程师快速验证风险。

---

## 🌟 核心功能 (Core Features)

### 🧠 1. 智能上下文感知 (Context-Aware Analysis)
* **消除幻觉**：当静态分析发现潜在风险但缺乏上下文（如未定义的函数调用）时，系统会自动在项目源码中递归检索相关定义（包括 Go/Python 的函数、变量、常量）。
* **精准研判**：将完整的代码上下文投喂给 AI，大幅降低因“看不见过滤逻辑”导致的误报。

### ⚡ 2. 自动化验证辅助 (Auto-Verification Support)
* **PoC 草稿生成**：针对逻辑型漏洞（如边界溢出、Panic、正则绕过），系统会尝试编写 Go/Python 单元测试脚本。
* **独立归档**：生成的验证脚本会自动归档至 `poc_scripts/` 目录，与源代码隔离，便于后续审计复查。

### 🚀 3. 企业级批量处理 (Batch Processing)
* **断点续传 (Resume Mode)**：自动跳过已审计项目，支持随时中断任务。
* **全量回溯 (Rescan Mode)**：支持强制重新扫描，自动按时间戳归档历史报告。
* **资源优化**：自动管理 CodeQL 数据库生命周期，分析即焚，节省存储空间。

### 🎯 4. 结构化报告 (Structured Reporting)
* **Markdown 报告**：包含漏洞详情、风险等级、代码片段、修复建议及验证指引。
* **本地数据归档**：审计结果自动存入本地 SQLite 数据库，便于长期趋势分析。

---

## ⚠️ 关于自动化 PoC 的重要说明 (Important Note on Auto-PoC)

**AI 生成的验证脚本（PoC）主要作为“逻辑草稿”，通常需要人工微调才能运行。**

由于 Go 等静态语言编译器极其严格，自动生成的代码可能存在以下常见问题：
1.  **依赖缺失**：引入了包但未配置 `go.mod`，或引入了未使用包导致编译错误。
2.  **上下文缺失**：Mock 对象时可能缺少部分结构体字段的初始化。
3.  **运行方式**：建议在目标源码目录下使用 `go test -v .` 运行，以便加载同包下的其他文件（如结构体定义），单文件运行可能会报 `undefined` 错误。

**建议流程**：
> 生成脚本 -> 复制到源码目录 -> **人工修正 (Fix Imports/Structs)** -> 运行验证

---

## 🔄 工作流水线 (Workflow)

1.  **[环境初始化]** 加载项目列表，建立 SQLite 索引。
2.  **[静态扫描]** CodeQL 引擎构建数据库并执行查询，生成 SARIF 原生数据。
3.  **[预处理]** 过滤测试文件与低风险干扰项。
4.  **[智能研判]**
    * 提取漏洞片段。
    * **Context Resolver** 动态补全缺失的函数/变量定义。
    * AI 判定风险等级。
    * **Code Generator** 尝试编写验证脚本 (PoC)。
5.  **[归档输出]** 生成 Markdown 报告，保存 PoC 文件，写入数据库。

---

## 🛠️ 快速开始 (Quick Start)

### 1. 环境准备
* Python 3.8+
* **CodeQL CLI** (需配置到系统 PATH)
* 目标语言的 CodeQL 规则包 (Standard Libraries)

### 2. 安装
```bash
git clone [https://github.com/YourUsername/MassAudit_Pro.git](https://github.com/YourUsername/MassAudit_Pro.git)
cd MassAudit_Pro
pip install -r requirements.txt
3. 配置 (MassAudit_Pro/config.py)
Python

API_KEY = "sk-xxxxxxxxxxxxxxxx"
PROJECTS_ROOT = r"/path/to/source_code"    # 待审计代码目录
4. 运行
Bash

python main.py
程序将交互式询问运行模式：

[1] 重新扫描: 覆盖式审计，保留历史记录。

[2] 断点续传: 仅扫描新项目（推荐）。

📂 结果验证示例
报告中将包含如下验证指引：

💣 自动化 PoC 已生成 脚本位置: /abs/path/to/poc_scripts/project_date/test.go 如何验证:

将脚本复制到漏洞所在目录。

检查并修复脚本中的 import 错误。

执行命令：

Bash

go test -v .
⚖️ 免责声明 (Disclaimer)
本工具旨在辅助安全工程师发现代码缺陷，提升软件质量。

生成的验证脚本仅用于在授权环境（如本地测试环境、CI/CD 流水线）中验证漏洞有效性。

严禁将本工具用于未授权的攻击行为。