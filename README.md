# MassAudit Pro - 智能交互式代码审计系统

MassAudit Pro 是一个结合了 **静态应用程序安全测试 (SAST)** 与 **大语言模型 (LLM)** 的自动化代码审计框架。

它不仅仅是简单的“扫描+问答”，而是实现了一个 **Agentic Workflow（智能体工作流）**：利用 CodeQL 的污点追踪能力发现潜在风险，再通过 LLM 进行二次研判。当 LLM 认为上下文不足时，系统会自动在源码中检索相关函数定义并“投喂”给 LLM，形成逻辑闭环。

---

## 核心架构与工作流程

系统的核心逻辑由 `main.py` 调度，主要经历以下阶段：

1.  **CodeQL 静态扫描 (`CodeQLManager`)**
    * 自动识别项目语言（支持 Python, Go, Java, JS 等）。
    * 调用 CodeQL CLI 创建数据库并执行查询（Queries）。
    * 生成 SARIF 格式的中间结果，提取潜在漏洞的元数据（文件、行号、规则ID）。

2.  **智能体漏洞分析 (`VulnerabilityAnalyzer`)**
    * 系统提取漏洞周边的代码片段，构建 Prompt 发送给 LLM（默认为 DeepSeek-V3）。
    * **交互式上下文获取 (Context Loop)**：
        * 如果 LLM 判断现有代码不足以确认漏洞（例如需要查看 `checkAuth` 函数的定义），它会返回 `need_context` 指令。
        * 系统通过 `ContextResolver` 模块利用 AST/正则在项目中检索目标函数的完整代码。
        * 将新上下文追加到对话历史中，再次请求 LLM 进行研判。

3.  **结果聚合与报告 (`Reporter`)**
    * 过滤误报，仅保留 LLM 确认的漏洞。
    * 生成包含完整分析链路（请求->追问->最终裁决）的 Markdown 审计报告。

---

## 🛠 配置指南 (Configuration)

本项目的核心配置文件为 `MassAudit_Pro/config.py`。在使用前，**必须**根据你的环境进行调整。

### 1. API 接口配置 (API Setup)

支持所有兼容 OpenAI 格式的 LLM API（推荐 DeepSeek、GPT-4o）。

打开 `.env` 自行修改。
打开 `MassAudit_Pro/config.py` （必须修改）修改以下字段：

```python
# --- 核心配置 ---

# [必需] 你的 API Key
API_KEY = "sk-xxxxxxxxxxxxxxxxxxxxxxxx" 

# [可选] API 基础地址 (默认为 DeepSeek 官方)
# 如果使用本地模型 (如 Ollama/vLLM)，可改为 "http://localhost:11434/v1"
API_BASE = "[https://api.deepseek.com/v1](https://api.deepseek.com/v1)"

#若是国内必须使用魔法，或自行下载官方检测规则修改文件。
#如下是xray默认端口。
HTTP_PROXY = "http://127.0.0.1:10809"
HTTPS_PROXY = "http://127.0.0.1:10809"
ALL_PROXY = "socks5://127.0.0.1:10808"

# 设置环境变量以确保代理生效
os.environ['HTTP_PROXY'] = HTTP_PROXY
os.environ['HTTPS_PROXY'] = HTTPS_PROXY
os.environ['ALL_PROXY'] = ALL_PROXY

# [必需] 待审计源代码的根目录
# 系统会扫描该目录下的所有子文件夹作为独立项目
# (Linux 示例: "/opt/source_code")

# [必需] CodeQL 数据库存储路径
# 用于临时存放生成的数据库文件，扫描后会自动清理
# (Linux 示例: "/opt/codeql-home/workspace/project_dbs")

#运行该工具 
python3 main.py
