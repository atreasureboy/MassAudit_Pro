import os
import json
import logging
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.text import Text

class Reporter:
    """
    负责实时控制台输出和最终 Markdown 报告的生成。
    """
    def __init__(self):
        """
        初始化 Reporter，设置 rich Console 对象。
        """
        self.console = Console()
        
        # 保存 console 实例，以便传入 Handler
        console_instance = self.console

        # --- 修改内部类以接收外部 console ---
        class RichHandler(logging.Handler):
            def __init__(self, console):
                super().__init__()
                self.console = console  

            def emit(self, record):
                try:
                    log_message = self.format(record)
                    if record.levelno >= logging.ERROR:
                        self.console.print(Text(log_message, style="bold red"))
                    elif record.levelno >= logging.WARNING:
                        self.console.print(Text(log_message, style="bold yellow"))
                    elif record.levelno >= logging.INFO:
                        self.console.print(Text(log_message, style="bold green"))
                    else:
                        self.console.print(Text(log_message))
                except Exception:
                    self.handleError(record)

        # 清除现有的 handlers，防止重复打印
        logging.root.handlers = []
        
        logging.basicConfig(
            level=logging.INFO, 
            handlers=[RichHandler(console_instance)],
            force=True
        )

        logging.info("Reporter initialized with rich Console for enhanced output.")

    def log_info(self, message: str, emoji: str = 'ℹ️') -> None:
        self.console.print(Text(f"{emoji} {message}", style="bold green"))

    def log_warning(self, message: str, emoji: str = '⚠️') -> None:
        self.console.print(Text(f"{emoji} {message}", style="bold yellow"))

    def log_error(self, message: str, emoji: str = '❌') -> None:
        self.console.print(Text(f"{emoji} {message}", style="bold red"))

    def generate_markdown_report(self, results: List[Dict[str, Any]], output_file: str = "audit_report.md") -> None:
        """
        将分析结果格式化为 Markdown 报告并保存。
        """
        self.log_info(f"Generating Markdown report to {output_file}...")

        report_content = []
        report_content.append("# MassAudit Pro 审计报告\n")
        report_content.append(f"**生成时间**: {self.console.get_datetime().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report_content.append(f"**总计发现漏洞**: {len(results)}\n\n")

        for i, result in enumerate(results):
            report_content.append(f"## {i+1}. 漏洞详情\n")
            report_content.append(f"- **文件路径**: `{result.get('file_path', 'N/A')}`\n")
            report_content.append(f"- **行号**: `{result.get('line_number', 'N/A')}`\n")
            
            # 安全处理裁决结果
            verdict = result.get('verdict', 'unknown')
            if verdict:
                verdict = verdict.upper()
            report_content.append(f"- **AI 裁决**: **{verdict}**\n")
            
            report_content.append(f"- **原因**: {result.get('reason', 'N/A')}\n\n")

            analysis_log = result.get('analysis_log')
            if analysis_log:
                report_content.append("### 交互过程\n")
                for round_log in analysis_log:
                    report_content.append(f"#### 回合 {round_log['round'] + 1}\n")
                    
                    req = round_log.get('request', 'N/A')
                    report_content.append(f"- **AI 请求**: \n```markdown\n{req}\n```\n")
                    
                    if round_log.get('requested_context'):
                        report_content.append(f"- **AI 请求上下文**: `{round_log['requested_context']}`\n")
                    
                    if round_log.get('resolved_context'):
                        report_content.append("- **找到的上下文**: \n")
                        for ctx_item in round_log['resolved_context']:
                            report_content.append(f"  - 文件: `{ctx_item.get('file_path', 'N/A')}`\n")
                            report_content.append(f"  - 语言: `{ctx_item.get('language', 'N/A')}`\n")
                            # 防止代码块嵌套破坏 Markdown
                            code = ctx_item.get('code_block', 'N/A')
                            report_content.append(f"  - 代码块: \n```\n{code}\n```\n")
                    
                    if round_log.get('parsed_response'):
                        try:
                            resp_json = json.dumps(round_log['parsed_response'], indent=2, ensure_ascii=False)
                            report_content.append(f"- **AI 响应**: \n```json\n{resp_json}\n```\n")
                        except:
                            report_content.append(f"- **AI 响应**: (无法格式化 JSON) {round_log['parsed_response']}\n")
                    report_content.append("\n")

            report_content.append("--- \n\n")

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("".join(report_content))
            self.log_info(f"✅ Markdown report successfully saved to {output_file}")
        except Exception as e:
            self.log_error(f"❌ Failed to save Markdown report to {output_file}: {e}")
