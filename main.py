import os
import logging
import sqlite3
import json
import time
import subprocess # [新增] 用于执行 shell 命令
import random     # [新增] 用于生成随机文件名
from datetime import datetime
from typing import Dict, Any, List

# Import all necessary modules and constants
from MassAudit_Pro.config import API_KEY, API_BASE, PROJECTS_ROOT, DB_STORAGE, PROJECT_API_CALL_COUNTS, MAX_CALLS_PER_PROJECT
from MassAudit_Pro.core.api_caller import APICaller
from MassAudit_Pro.core.context_resolver import ContextResolver
from MassAudit_Pro.core.codeql_manager import CodeQLManager
from MassAudit_Pro.core.vulnerability_analyzer import VulnerabilityAnalyzer
from MassAudit_Pro.utils.cleanup_utils import cleanup_project_artifacts
from MassAudit_Pro.reporting.reporter import Reporter

class AuditSystem:
    """
    MassAudit Pro 智能交互式代码审计系统的主协调器。
    """
    def __init__(self, rescan_mode: bool = False):
        """
        初始化审计系统。
        """
        self.rescan_mode = rescan_mode
        self.reporter = Reporter()
        self.api_caller = APICaller(API_KEY, API_BASE)
        self.context_resolver = ContextResolver(PROJECTS_ROOT)
        self.codeql_manager = CodeQLManager(DB_STORAGE, PROJECTS_ROOT)
        self.vulnerability_analyzer = VulnerabilityAnalyzer(self.api_caller, self.context_resolver, PROJECT_API_CALL_COUNTS)
        
        self.reports_dir = os.path.join(os.getcwd(), "reports")
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
            
        self._init_c2_database()

        mode_str = "RESCAN (Create new timestamps)" if self.rescan_mode else "RESUME (Skip existing)"
        logging.info(f"AuditSystem initialized. Mode: {mode_str}")

    def _init_c2_database(self):
        """初始化用于 C2 利用的本地数据库"""
        try:
            conn = sqlite3.connect('my_arsenal.db')
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          project_name TEXT,
                          vuln_type TEXT,
                          severity TEXT,
                          file_path TEXT,
                          line_number INTEGER,
                          code_snippet TEXT,
                          ai_verdict TEXT,
                          verification_result TEXT,
                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Failed to init C2 database: {e}")

    def _save_to_sqlite(self, project_name, vuln_data):
        """将高危漏洞存入 SQLite"""
        if vuln_data.get('verdict', '').upper() not in ['HIGH', 'MEDIUM']:
            return 
            
        try:
            conn = sqlite3.connect('my_arsenal.db')
            c = conn.cursor()
            c.execute("INSERT INTO vulnerabilities (project_name, vuln_type, severity, file_path, line_number, code_snippet, ai_verdict, verification_result) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                      (project_name, 
                       vuln_data.get('original_rule_id'), 
                       vuln_data.get('verdict'),
                       vuln_data.get('file_path'), 
                       vuln_data.get('line_number'),
                       vuln_data.get('code_snippet', '')[:500], 
                       vuln_data.get('reason', ''),
                       vuln_data.get('verify_output', 'Not Verified'))) 
            conn.commit()
            conn.close()
            print(f"💾 [C2] 漏洞已入库: {vuln_data.get('original_rule_id')}")
        except Exception as e:
            logging.error(f"DB Error: {e}")

    def _save_project_report(self, project_name, vulnerabilities):
        """
        生成包含验证结果的报告。
        """
        if self.rescan_mode:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{project_name}_{timestamp}.md"
        else:
            filename = f"{project_name}_report.md"

        report_path = os.path.join(self.reports_dir, filename)
        
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(f"# {project_name} 审计报告\n")
                f.write(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**模式**: {'重新扫描 (Rescan)' if self.rescan_mode else '断点续传 (Resume)'}\n")
                f.write(f"**发现漏洞数**: {len(vulnerabilities)}\n\n")
                
                for idx, v in enumerate(vulnerabilities):
                    f.write(f"## {idx+1}. {v.get('original_rule_id', 'Unknown Issue')}\n")
                    f.write(f"- **文件**: `{v.get('file_path')}` : `{v.get('line_number')}`\n")
                    f.write(f"- **AI 裁决**: **{v.get('verdict')}**\n")
                    f.write(f"- **分析结论**: {v.get('reason')}\n")
                    
                    # === [修改] 自动化验证结果展示 (更详细的状态) ===
                    if v.get('has_poc'):
                        f.write(f"\n> 🛡️ **自动化验证报告 (Auto-Verify)**\n")
                        f.write(f"> **PoC 脚本**: `{v.get('poc_path')}`\n")
                        
                        verify_status = v.get('verify_status', 'UNKNOWN')
                        verify_output = v.get('verify_output', '').strip()
                        
                        if verify_status == "EXECUTION_PASS":
                            f.write(f"> **验证状态**: ✅ 测试通过 (PASS) - 脚本运行成功且未崩溃\n")
                            f.write(f"> **说明**: 漏洞可能已被防御，或 PoC 仅验证了连通性。\n")
                            f.write(f"> **控制台输出**: \n```text\n{verify_output}\n```\n")
                        
                        elif verify_status == "EXECUTION_PANIC":
                            f.write(f"> **验证状态**: 🚨 触发 PANIC (漏洞实锤) - 目标代码崩溃\n")
                            f.write(f"> **控制台输出**: \n```text\n{verify_output}\n```\n")

                        elif verify_status == "EXECUTION_FAIL":
                            f.write(f"> **验证状态**: ⚠️ 测试失败 (FAIL) - 脚本运行了但断言未通过\n")
                            f.write(f"> **控制台输出**: \n```text\n{verify_output}\n```\n")

                        elif verify_status == "COMPILATION_FAILED":
                            f.write(f"> **验证状态**: ❌ 编译/环境失败 (AI 尝试修复 {v.get('fix_attempts', 0)} 次后仍失败)\n")
                            f.write(f"> **原因**: 可能是缺包、语法错误或环境缺失\n")
                            f.write(f"> **错误日志**: \n```text\n{verify_output}\n```\n")
                        else:
                            f.write(f"> **验证状态**: ❓ 未知状态 / 运行时异常\n")
                            f.write(f"> **输出**: \n```text\n{verify_output}\n```\n")
                    
                    elif v.get('verdict', '').upper() in ['HIGH', 'MEDIUM']:
                         f.write(f"\n> ⚠️ **验证**: AI 判断无法进行单元测试或无需测试。\n")
                         
                    f.write("---\n")
            self.reporter.log_info(f"✅ Report saved: {filename}")
        except Exception as e:
            self.reporter.log_error(f"Failed to save report for {project_name}: {e}")

    def _check_if_project_scanned(self, project_name):
        """检查该项目是否已经存在任何审计报告"""
        std_report = os.path.join(self.reports_dir, f"{project_name}_report.md")
        if os.path.exists(std_report) and os.path.getsize(std_report) > 50:
            return True
        for f in os.listdir(self.reports_dir):
            if f.startswith(f"{project_name}_") and f.endswith(".md"):
                return True
        return False

    def run_audit(self):
        """执行审计流程"""
        available_projects = []
        if os.path.isdir(PROJECTS_ROOT):
            for item in os.listdir(PROJECTS_ROOT):
                if os.path.isdir(os.path.join(PROJECTS_ROOT, item)):
                    available_projects.append(item)

        if not available_projects:
            self.reporter.log_warning(f"No projects found in {PROJECTS_ROOT}.")
            return

        self.reporter.log_info(f"Found {len(available_projects)} projects. Mode: {'RESCAN ALL' if self.rescan_mode else 'RESUME UNFINISHED'}")

        for i, project_name in enumerate(available_projects):
            project_relative_path = project_name 
            
            if not self.rescan_mode:
                if self._check_if_project_scanned(project_name):
                    self.reporter.log_info(f"⏩ [Skip] {project_name} ({i+1}/{len(available_projects)}): Report exists.")
                    continue

            self.reporter.log_info(f"\n🚀 [{i+1}/{len(available_projects)}] Auditing: {project_name}")

            current_time_str = datetime.now().strftime('%Y%m%d_%H%M%S')
            poc_base_dir = os.path.join(os.getcwd(), "poc_scripts", f"{project_name}_{current_time_str}")

            if APICaller._circuit_breaker_tripped:
                break

            cleanup_project_artifacts(project_relative_path)

            detected_language = self.codeql_manager._detect_language(project_relative_path)
            if not detected_language:
                self.reporter.log_warning(f"Skipping {project_name}: Language not detected.")
                continue

            query_pack_map = {
                'python': 'codeql/python-queries',
                'go': 'codeql/go-queries', 
                'java': 'codeql/java-queries',
                'javascript': 'codeql/javascript-queries',
                'csharp': 'codeql/csharp-queries',
                'cpp': 'codeql/cpp-queries'
            }
            codeql_query_pack = query_pack_map.get(detected_language.lower())
            
            db_path = self.codeql_manager.create_database(project_name, project_relative_path, detected_language)
            if not db_path: continue

            sarif_output_path = os.path.join(db_path, f"{project_name}-results.sarif")
            generated_sarif_path = self.codeql_manager.run_analysis(db_path, codeql_query_pack, sarif_output_path)
            
            if not generated_sarif_path:
                self.codeql_manager.cleanup_database(db_path)
                continue

            sarif_results = self.codeql_manager.parse_sarif_results(generated_sarif_path)
            if not sarif_results:
                self.codeql_manager.cleanup_database(db_path)
                continue
            
            project_vulnerabilities = []
            
            raw_results = []
            if sarif_results.get('runs'):
                for run in sarif_results['runs']:
                    for result in run.get('results', []):
                        location = result.get('locations', [{}])[0].get('physicalLocation', {})
                        file_uri = location.get('artifactLocation', {}).get('uri', 'unknown_file')
                        if "_test.go" in file_uri or "test_" in file_uri or "vendor/" in file_uri:
                            continue 
                        raw_results.append(result)

            self.reporter.log_info(f"🔍 Found {len(raw_results)} issues in {project_name}")
            full_project_source_path = os.path.join(PROJECTS_ROOT, project_relative_path)

            for result in raw_results:
                rule_id = result.get('ruleId', 'unknown')
                location = result.get('locations', [{}])[0].get('physicalLocation', {})
                file_uri = location.get('artifactLocation', {}).get('uri', 'unknown_file')
                start_line = location.get('region', {}).get('startLine', 0)
                full_file_path = os.path.join(full_project_source_path, file_uri)

                code_snippet = ""
                try:
                    if os.path.exists(full_file_path):
                        with open(full_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                            start_idx = max(0, start_line - 21)
                            end_idx = min(len(lines), start_line + 20)
                            code_snippet = "".join(lines[start_idx:end_idx])
                except: pass

                if PROJECT_API_CALL_COUNTS.get(project_name, 0) >= MAX_CALLS_PER_PROJECT: break 
                if APICaller._circuit_breaker_tripped: break

                try:
                    self.reporter.log_info(f"🕵️ Analyzing: {rule_id} @ {file_uri}:{start_line}")
                    analysis_result = self.vulnerability_analyzer.analyze_vulnerability(
                        project_name, code_snippet, project_relative_path, file_uri, start_line
                    )
                    
                    analysis_result['original_rule_id'] = rule_id
                    analysis_result['code_snippet'] = code_snippet
                    analysis_result['file_uri'] = file_uri

                    # === [核心逻辑] 自愈与自动化验证 ===
                    poc_code = analysis_result.get('poc_code', '')
                    is_testable = analysis_result.get('is_testable', False)
                    verdict = analysis_result.get('verdict', '').upper()
                    
                    analysis_result['has_poc'] = False
                    analysis_result['verify_status'] = 'SKIPPED'
                    analysis_result['verify_output'] = ''
                    analysis_result['fix_attempts'] = 0

                    if (verdict in ['HIGH', 'MEDIUM']) and is_testable and poc_code and len(poc_code) > 20:
                        try:
                            if not os.path.exists(poc_base_dir): os.makedirs(poc_base_dir)

                            random_suffix = random.randint(1000, 9999)
                            poc_filename = f"{project_name}_{current_time_str}_{random_suffix}_test.go"
                            poc_save_path = os.path.join(poc_base_dir, poc_filename)
                            
                            with open(poc_save_path, "w", encoding="utf-8") as f:
                                clean_code = poc_code.replace("```go", "").replace("```", "").strip()
                                f.write(clean_code)
                            
                            self.reporter.log_info(f"💣 Draft Generated: {poc_filename}")
                            
                            target_source_dir = os.path.dirname(os.path.join(full_project_source_path, file_uri))
                            
                            MAX_FIX_ATTEMPTS = 5
                            current_attempt_code = clean_code
                            
                            for attempt in range(MAX_FIX_ATTEMPTS + 1):
                                self.reporter.log_info(f"🔧 [Verify] Attempt {attempt+1}/{MAX_FIX_ATTEMPTS + 1}...")

                                copy_cmd = f"cp \"{poc_save_path}\" \"{target_source_dir}/\""
                                os.system(copy_cmd)

                                verify_cmd = f"cd \"{target_source_dir}\" && go test -v {poc_filename}"
                                
                                try:
                                    process = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, timeout=15)
                                    output = process.stdout + "\n" + process.stderr
                                    
                                    # === [修改] 更严格的错误判定逻辑 ===
                                    compile_errors = [
                                        "build failed", 
                                        "undefined:", 
                                        "imported and not used",
                                        "no required module",  # [新增] 缺包
                                        "cannot find package", # [新增] 找不到包
                                        "setup failed"         # [新增] 测试启动失败
                                    ]
                                    
                                    is_compile_error = any(e in output for e in compile_errors)

                                    if is_compile_error:
                                        # === 编译或环境错误，需要修复 ===
                                        if attempt < MAX_FIX_ATTEMPTS:
                                            self.reporter.log_warning(f"❌ Build/Env Failed. Asking AI to fix (Attempt {attempt+1})...")
                                            
                                            fixed_code = self.vulnerability_analyzer.fix_poc_code(current_attempt_code, output)
                                            current_attempt_code = fixed_code
                                            
                                            with open(poc_save_path, "w", encoding="utf-8") as f:
                                                f.write(fixed_code)
                                            
                                            analysis_result['fix_attempts'] = attempt + 1
                                            continue 
                                        else:
                                            analysis_result['verify_status'] = "COMPILATION_FAILED"
                                            analysis_result['verify_output'] = output
                                            analysis_result['fix_attempts'] = attempt
                                    else:
                                        # === 脚本能跑起来了 ===
                                        self.reporter.log_info(f"✅ Execution Finished!")
                                        
                                        if "PASS" in output:
                                            analysis_result['verify_status'] = "EXECUTION_PASS"
                                        elif "panic:" in output:
                                            analysis_result['verify_status'] = "EXECUTION_PANIC"
                                        elif "FAIL" in output:
                                            analysis_result['verify_status'] = "EXECUTION_FAIL"
                                        else:
                                            analysis_result['verify_status'] = "EXECUTION_UNKNOWN"

                                        analysis_result['verify_output'] = output
                                        break 

                                except subprocess.TimeoutExpired:
                                    analysis_result['verify_status'] = "TIMEOUT"
                                    analysis_result['verify_output'] = "Execution timed out."
                                    break
                            
                            analysis_result['has_poc'] = True
                            analysis_result['poc_path'] = poc_save_path
                            
                            try:
                                os.remove(os.path.join(target_source_dir, poc_filename))
                            except: pass

                        except Exception as e:
                            self.reporter.log_error(f"Failed to auto-verify PoC: {e}")

                    project_vulnerabilities.append(analysis_result)
                    self._save_to_sqlite(project_name, analysis_result)
                    if analysis_result.get('status') == 'aborted': break 
                except Exception as e:
                    self.reporter.log_error(f"Analysis error: {e}")

            self._save_project_report(project_name, project_vulnerabilities)
            self.codeql_manager.cleanup_database(db_path)
            if APICaller._circuit_breaker_tripped: break

        self.reporter.log_info("MassAudit Pro: Process completed.")

if __name__ == "__main__":
    print("\n" + "="*50)
    print("   🛡️  MassAudit Pro - 交互式启动")
    print("="*50)
    print("请选择扫描模式：")
    print(" [1] 重新扫描 (Rescan)")
    print("     - 即使项目已有报告，也会重新扫描")
    print("     - 生成带时间戳的新文件 (如: project_20260130.md)")
    print("     - ⚠️ 原 md 文件保留，不会被覆盖")
    print("")
    print(" [2] 断点续传 (Resume) [推荐]")
    print("     - 跳过所有已存在报告的项目")
    print("     - 仅扫描最新的、未处理的项目")
    print("     - 生成标准文件名 (project_report.md)")
    print("="*50)
    
    while True:
        choice = input("请输入选项 (1 或 2): ").strip()
        if choice == '1':
            is_rescan = True
            break
        elif choice == '2':
            is_rescan = False
            break
        else:
            print("❌ 输入无效，请输入 1 或 2")

    print(f"\n✅ 已确认模式: {'重新扫描' if is_rescan else '断点续传'}\n")
    
    # 启动系统
    audit_system = AuditSystem(rescan_mode=is_rescan)
    audit_system.run_audit()