# 🛡️ MassAudit Pro: Intelligent Code Security Audit System

> **Automated Static Analysis & AI-Assisted Auditing Tool**
> **基于 CodeQL 与大模型的自动化静态代码审计系统**

![Python](https://img.shields.io/badge/Python-3.9%2B-blue) ![CodeQL](https://img.shields.io/badge/Engine-CodeQL-green) ![DeepSeek](https://img.shields.io/badge/AI-DeepSeek%20%2F%20Local-purple) ![License](https://img.shields.io/badge/License-MIT-grey)

**MassAudit Pro** 是一款面向安全工程师和研发团队的下一代代码审计辅助工具。它致力于解决传统静态分析工具（SAST）误报率高、上下文理解能力弱的痛点。

通过将 **CodeQL** 的污点追踪能力与 **LLM (大语言模型)** 的语义理解能力相结合，本系统能够自动识别代码中的逻辑漏洞，并提供高精度的修复建议，助力企业构建安全的软件开发生命周期 (SDLC)。

---

## 🌟 核心功能 (Core Features)

### 🧠 1. 智能上下文感知 (Context-Aware Analysis)
* **深度语义理解**：当静态分析发现潜在风险但缺乏上下文（如未定义的函数调用、复杂的变量传递）时，系统会自动在项目源码中递归检索相关定义（包括 Go/Python 的函数、变量、常量）。
* **消除幻觉**：将完整的代码上下文投喂给 AI，大幅降低因“看不见过滤逻辑”导致的误报（False Positives）。

### ⚡ 2. 企业级批量审计 (Batch Processing)
专为大规模项目库设计，支持高效的并发处理：
* **智能断点续传 (Resume Mode)**：自动识别已完成审计的项目，跳过重复工作，支持随时中断和恢复任务。
* **全量重新审计 (Rescan Mode)**：支持对项目进行强制重新扫描，自动按时间戳归档历史报告，保留完整的审计轨迹。
* **存储自动优化**：自动管理 CodeQL 数据库生命周期，分析完成后即刻清理，大幅节省磁盘空间。

### 🎯 3. 精准降噪 (Smart Filtering)
* **智能分级**：自动解析 SARIF 结果，过滤低风险的代码风格建议（Note），专注于中高危安全漏洞。
* **测试代码排除**：自动识别并排除单元测试文件（如 `_test.go`），聚焦生产环境代码的安全性。

### 📊 4. 结构化归档 (Structured Archiving)
* **独立报告**：为每个项目生成独立的 Markdown 审计报告，包含漏洞位置、风险等级、代码片段及 AI 修复建议。
* **本地数据归档**：将审计结果自动存入本地 SQLite 数据库，便于后续进行数据统计、趋势分析或对接企业内部的漏洞管理平台。

---

## 🔄 工作原理 (Workflow)

系统采用 **“扫描-解析-研判-归档”** 的自动化流水线：

1.  **[源文件加载]** 自动遍历目录下的所有项目源文件。
2.  **[静态分析]** 调用 CodeQL 引擎构建数据库并执行安全查询，生成 SARIF 结果。
3.  **[预处理]** 解析 SARIF，过滤测试文件和低风险干扰项。
4.  **[AI 研判循环]**：
    * 提取漏洞点代码片段。
    * **Context Resolver** 介入：若上下文不足，自动在项目中搜索函数/变量定义。
    * AI 综合判断漏洞有效性及风险等级。
5.  **[输出]** 生成 Markdown 报告并写入本地 SQLite 数据库。

---

## 🛠️ 快速开始 (Quick Start)

### 1. 环境准备
* Python 3.8+
* **CodeQL CLI** (需配置到系统 PATH)
* 对应语言的 CodeQL 规则包 (Standard Libraries)

### 2. 安装
```bash
# 1. 克隆项目
git clone [https://github.com/YourUsername/MassAudit_Pro.git](https://github.com/YourUsername/MassAudit_Pro.git)
cd MassAudit_Pro

# 2. 安装依赖
pip install -r requirements.txt
3. 配置文件 (MassAudit_Pro/config.py)
请根据实际环境修改配置：

Python

# LLM API 设置 (支持兼容 OpenAI 格式的接口)
API_KEY = "sk-xxxxxxxxxxxxxxxx"
API_BASE = "[https://api.deepseek.com/v1](https://api.deepseek.com/v1)"

# 路径设置 (推荐使用绝对路径)
PROJECTS_ROOT = r"/path/to/source_code"    # 待审计的项目代码根目录
DB_STORAGE = r"/path/to/temp_db"           # 临时数据库存储路径
4. 运行
Bash

python main.py
程序启动后提供交互式选项：

[1] 重新扫描 (Rescan): 强制重新审计所有项目，旧报告将保留并重命名（带时间戳）。

[2] 断点续传 (Resume): 仅扫描未产生报告的新项目（推荐日常使用）。

📂 报告示例 (Report Example)
reports/couper_report.md 示例：

Markdown

# Couper 审计报告
**生成时间**: 2026-01-31 10:00:00
**发现风险项**: 2

## 1. go/potential-dos
- **文件**: `server/writer/gzip.go` : `86`
- **风险等级**: **Medium**
- **分析结论**: 代码在处理连接错误时使用了 `panic(err)`，这在生产环境中可能导致服务进程崩溃，引发拒绝服务风险。建议修改为优雅的错误处理或日志记录。

## 2. go/sql-injection
- **文件**: `db/query.go` : `45`
- **风险等级**: **High**
- **分析结论**: 变量 `userInput` 未经参数化处理直接拼接至 SQL 查询语句中。尽管有简单的字符串替换，但无法防御复杂的 SQL 注入攻击。建议使用预编译语句 (Prepared Statements) 进行修复。
⚠️ 免责声明 (Disclaimer)
本工具仅用于代码质量提升、安全合规自查及DevSecOps 流程建设。

使用本工具对代码进行扫描前，请确保您拥有目标代码的合法访问权限或所有权。

开发者不对因使用本工具而产生的任何直接或间接后果负责。
