
import os
import logging

API_KEY = "YOUR-APIKEY"

API_BASE = "https://api.deepseek.com/v1"

#可用其它大模型
#配置接口，自己改
#API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
#API_BASE = os.getenv("DEEPSEEK_API_BASE", "https://api.deepseek.com/v1")


# 代理配置 (严格硬编码)，国内请用魔法,如下是xray默认端口，官方规则库调用需要
#HTTP_PROXY = "http://127.0.0.1:10809"
#HTTPS_PROXY = "http://127.0.0.1:10809"
#ALL_PROXY = "socks5://127.0.0.1:10808"

# 设置环境变量以确保代理生效
#os.environ['HTTP_PROXY'] = HTTP_PROXY
#os.environ['HTTPS_PROXY'] = HTTPS_PROXY
#os.environ['ALL_PROXY'] = ALL_PROXY

# 项目路径配置
PROJECTS_ROOT = "/opt/source_code"
DB_STORAGE = "/opt/codeql-home/workspace/project_dbs"

# --- 3. 核心功能模块需求相关配置 ---

# 3.2 熔断与限流机制
MAX_CONTEXT_RETRIES = 3  # 单个漏洞最多允许AI“追问”3次
MAX_CALLS_PER_PROJECT = 100 # 单个项目允许的最大API调用次数
MAX_API_ERROR_COUNT = 5 # 如果连续5个请求发生API连接超时或500错误，立即终止脚本

# 3.3 鲁棒性与错误处理
FILE_SIZE_LIMIT_MB = 1 # 超大文件保护，超过1MB截断

PROJECT_API_CALL_COUNTS = {} # 用于跟踪每个项目的API调用次数

# --- 5. 初始日志设置 ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

print("config.py loaded and initialized.")
