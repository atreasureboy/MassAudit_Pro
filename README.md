# 🛡️ MassAudit Pro: Intelligent Code Security Audit System

> **Automated Static Analysis & AI-Assisted Verification Tool**
> **基于 CodeQL 与大模型的自动化静态代码审计与验证系统**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![CodeQL](https://img.shields.io/badge/Engine-CodeQL-green) ![DeepSeek](https://img.shields.io/badge/AI-DeepSeek%20%2F%20LLM-purple) ![License](https://img.shields.io/badge/License-MIT-grey)

**MassAudit Pro** 是一款面向企业安全建设与 DevSecOps 流程的下一代自动化代码审计工具。它致力于解决传统静态应用程序安全测试 (SAST) 工具误报率高、验证成本大、上下文缺失的问题。

系统深度整合了 **CodeQL** 的精准代码检索能力与 **DeepSeek LLM** 的深度逻辑分析能力，不仅能发现深层逻辑漏洞，还能**自动编写、修复并执行单元测试级别的验证脚本 (PoC)**，最终通过 **AI 裁判** 对验证日志进行智能定性，实现从发现到验证的全闭环。

---

## 🌟 核心特性 (Key Features)

### 1. 🧠 智能上下文循环 (Agentic Context Loop)
* **消除幻觉**：当 AI 认为代码片段不足以判断风险时（例如看到未定义的函数调用），会主动要求系统在源码中检索该函数的完整定义。
* **精准研判**：系统会自动递归提取相关变量、结构体和函数定义，大幅降低因“看不见过滤逻辑”导致的误报。

### 2. ⚡ 自动化验证与自愈 (Auto-Verification & Self-Healing)
* **PoC 草稿生成**：针对逻辑型漏洞（如边界溢出、Panic、正则绕过），系统会尝试编写 Go/Python 单元测试脚本。
* **代码自愈**：如果生成的测试脚本因缺包、语法错误导致编译失败，**自愈模块**会将报错信息回传给 AI，自动修正代码并重试（支持多轮自动修复）。

### 3. ⚖️ AI 智能裁判 (AI Judge)
* **智能定性**：AI 会阅读测试日志，区分“程序崩溃”、“被捕获的异常”和“安全防御”。
* **去伪存真**：如果测试脚本运行通过且未触发异常，AI 会将其标记为 **SAFE_PASS**（已防御），有效过滤误报。

---

## ⚠️ 重要说明 (Important Note)

**无法单元测试的漏洞，需手动完成测试。**

AI 虽然强大，但并非万能。对于依赖复杂外部环境（如数据库特定状态、中间件配置、第三方 API）的漏洞，自动化脚本可能无法完美复现。

**建议流程**：
> `python3 main.py` -> 查看生成的 `.md` 报告 -> 针对未验证项进行手动复现

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
5.  **[验证与归档]**
    * 执行 PoC 脚本（含编译错误自愈）。
    * **AI Judge** 分析控制台输出，判定验证结果（崩溃/通过/异常）。
    * 生成 Markdown 报告，保存 PoC 文件，写入数据库。

---

## 🛠️ 快速开始 (Quick Start)

### 1. 环境准备
* Python 3.10+
* **CodeQL CLI** (需配置到系统 PATH)
* **Golang** (用于运行验证脚本)
* 目标语言的 CodeQL 规则包 (Standard Libraries)

### 2. 安装
```bash
git clone [https://github.com/YourUsername/MassAudit_Pro.git](https://github.com/YourUsername/MassAudit_Pro.git)
cd MassAudit_Pro
pip install -r requirements.txt
3. 配置
编辑 MassAudit_Pro/config.py：

Python

API_KEY = "sk-xxxxxxxxxxxxxxxx"
API_BASE = "[https://api.deepseek.com/v1](https://api.deepseek.com/v1)"
PROJECTS_ROOT = r"/path/to/source_code"    # 待审计代码目录
DB_STORAGE = r"/path/to/codeql_dbs"        # 数据库临时目录
4. 运行
Bash

python main.py
程序将交互式询问运行模式：

[1] 重新扫描: 覆盖式审计，生成带时间戳的新报告。

[2] 断点续传: 仅扫描新项目（推荐）。

📊 结果验证示例
报告中将包含详细的自动化验证结果，例如：

🛡️ 自动化验证报告 (Auto-Verify)

脚本位置: /abs/path/to/poc_scripts/project_date/test.go

验证状态: ✅ SAFE_PASS

AI 判定: 测试输出显示 PASS，且未检测到 Panic 日志，代码成功拦截了越界尝试。

⚖️ 免责声明 (Disclaimer)
本工具旨在辅助安全工程师发现代码缺陷，提升软件质量。

生成的验证脚本仅用于在授权环境（如本地测试环境、CI/CD 流水线）中验证漏洞有效性。

严禁将本工具用于未授权的测试或攻击行为。

开发者不对因使用本工具造成的任何直接或间接损失负责。使用本工具即代表您同意遵守当地法律法规。