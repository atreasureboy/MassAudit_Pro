
import os
import logging
from typing import Dict, Any, List

from MassAudit_Pro.config import API_KEY, API_BASE, PROJECTS_ROOT, DB_STORAGE, PROJECT_API_CALL_COUNTS,MAX_CALLS_PER_PROJECT
from MassAudit_Pro.core.api_caller import APICaller
from MassAudit_Pro.core.context_resolver import ContextResolver
from MassAudit_Pro.core.codeql_manager import CodeQLManager
from MassAudit_Pro.core.vulnerability_analyzer import VulnerabilityAnalyzer
from MassAudit_Pro.utils.cleanup_utils import cleanup_project_artifacts
from MassAudit_Pro.reporting.reporter import Reporter

class AuditSystem:
    """
    MassAudit Pro 智能交互式代码审计系统的主协调器。
    负责组织和执行整个审计流程，包括项目遍历、CodeQL扫描、SARIF结果解析、
    针对每个漏洞触发智能上下文交互并收集结果。
    """
    def __init__(self):
        """
        初始化审计系统，创建所有必要的组件实例。
        """
        self.reporter = Reporter()
        self.api_caller = APICaller(API_KEY, API_BASE)
        self.context_resolver = ContextResolver(PROJECTS_ROOT)
        self.codeql_manager = CodeQLManager(DB_STORAGE, PROJECTS_ROOT)
        self.vulnerability_analyzer = VulnerabilityAnalyzer(self.api_caller, self.context_resolver, PROJECT_API_CALL_COUNTS)

        logging.info("AuditSystem initialized.")

    def run_audit(self):
        """
        执行整个代码审计流程。
        """
        self.reporter.log_info("MassAudit Pro: Starting code audit process...")
        all_vulnerability_results = []

        available_projects = []
        if os.path.isdir(PROJECTS_ROOT):
            for item in os.listdir(PROJECTS_ROOT):
                item_path = os.path.join(PROJECTS_ROOT, item)
                if os.path.isdir(item_path):
                    available_projects.append(item)

        if not available_projects:
            self.reporter.log_warning(f"No projects found in {PROJECTS_ROOT}. Exiting.")
            return

        self.reporter.log_info(f"Found {len(available_projects)} projects to audit: {', '.join(available_projects)}")

        for project_name in available_projects:
            project_relative_path = project_name 
            full_project_source_path = os.path.join(PROJECTS_ROOT, project_relative_path)
            self.reporter.log_info(f"\n🚀 Starting audit for project: {project_name}")

            if APICaller._circuit_breaker_tripped:
                self.reporter.log_error("Global API circuit breaker tripped. Terminating entire audit process.")
                break

            cleanup_project_artifacts(project_relative_path)

            detected_language = self.codeql_manager._detect_language(project_relative_path)
            if not detected_language:
                self.reporter.log_warning(f"Skipping project {project_name}: Could not detect language.")
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
            if not codeql_query_pack:
                self.reporter.log_warning(f"Skipping project {project_name}: No CodeQL query pack defined for language '{detected_language}'.")
                continue

            # --- 创建CodeQL数据库 ---
            db_path = self.codeql_manager.create_database(project_name, project_relative_path, detected_language)
            if not db_path:
                self.reporter.log_error(f"Failed to create CodeQL database for project {project_name}. Skipping analysis.")
                continue

            # --- 执行CodeQL扫描 ---
            sarif_output_path = os.path.join(db_path, f"{project_name}-results.sarif")
            generated_sarif_path = self.codeql_manager.run_analysis(db_path, codeql_query_pack, sarif_output_path)
            if not generated_sarif_path:
                self.reporter.log_error(f"Failed to run CodeQL analysis for project {project_name}. Skipping SARIF parsing.")
                self.codeql_manager.cleanup_database(db_path)
                continue

            # --- 解析SARIF结果 ---
            sarif_results = self.codeql_manager.parse_sarif_results(generated_sarif_path)
            if not sarif_results or not sarif_results.get('runs'):
                self.reporter.log_warning(f"No valid SARIF results found for project {project_name}. Skipping vulnerability analysis.")
                self.codeql_manager.cleanup_database(db_path)
                continue
            
            project_vulnerabilities = []
            for run in sarif_results['runs']:
                for result in run.get('results', []):
                    rule_id = result.get('ruleId', 'unknown')
                    message = result.get('message', {}).get('text', 'No description')
                    location = result.get('locations', [{}])[0].get('physicalLocation', {})
                    file_uri = location.get('artifactLocation', {}).get('uri', 'unknown_file')
                    start_line = location.get('region', {}).get('startLine', 0)

                    
                    full_file_path = os.path.join(full_project_source_path, file_uri)
                    #可自行修改：重点！！！上下文长度
                    code_snippet = "" 
                    try:
                        with open(full_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                            start_idx = max(0, start_line - 21) 
                            end_idx = min(len(lines), start_line + 20) 
                            code_snippet = "".join(lines[start_idx:end_idx])
                    except Exception as e:
                        self.reporter.log_error(f"Could not read code snippet from {full_file_path}:{start_line}: {e}")
                        code_snippet = f"[ERROR: Could not retrieve code snippet: {e}]\n(File: {full_file_path}, Line: {start_line})\n{message}"

                    # --- 智能上下文交互分析 ---
                    self.reporter.log_info(f"🕵️ Analyzing vulnerability '{rule_id}' in {file_uri}:{start_line}...")
                    
                    if PROJECT_API_CALL_COUNTS.get(project_name, 0) >= MAX_CALLS_PER_PROJECT:
                        self.reporter.log_warning(f"🛑 Project {project_name}: Hit API limit ({PROJECT_API_CALL_COUNTS[project_name]}/{MAX_CALLS_PER_PROJECT}), skipping remaining vulnerabilities in this project.")
                        project_vulnerabilities.append({
                            "status": "skipped",
                            "verdict": "SKIPPED_QUOTA_LIMIT",
                            "reason": "Project API call limit exceeded.",
                            "file_path": file_uri,
                            "line_number": start_line,
                            "original_rule_id": rule_id,
                            "original_message": message
                        })
                        break 

                    if APICaller._circuit_breaker_tripped:
                        self.reporter.log_error("Global API circuit breaker tripped. Terminating current project analysis and entire audit process.")
                        break 
                    try:
                        analysis_result = self.vulnerability_analyzer.analyze_vulnerability(
                            project_name,
                            code_snippet,
                            project_relative_path,
                            file_uri,
                            start_line
                        )
                        project_vulnerabilities.append(analysis_result)
                        if analysis_result.get('status') == 'aborted': 
                            break 
                    except Exception as e:
                        self.reporter.log_error(f"Error analyzing vulnerability '{rule_id}' in {file_uri}:{start_line}: {e}")
                        project_vulnerabilities.append({
                            "status": "failure",
                            "verdict": "error",
                            "reason": f"Error during AI analysis: {e}",
                            "file_path": file_uri,
                            "line_number": start_line,
                            "original_rule_id": rule_id,
                            "original_message": message
                        })

                if APICaller._circuit_breaker_tripped or (
                    project_name in PROJECT_API_CALL_COUNTS and 
                    PROJECT_API_CALL_COUNTS[project_name] >= MAX_CALLS_PER_PROJECT
                ): 
                    break 

            all_vulnerability_results.extend(project_vulnerabilities)
            self.reporter.log_info(f"📊 Finished processing {len(project_vulnerabilities)} vulnerabilities for project {project_name}.")

            # --- 清理CodeQL数据库，也可以自定义重复检测，不清除数据库，注意---
            self.codeql_manager.cleanup_database(db_path)
            
            if APICaller._circuit_breaker_tripped:
                break

        # --- 生成最终审计报告 ---
        self.reporter.generate_markdown_report(all_vulnerability_results)
        self.reporter.log_info("MassAudit Pro: Audit process completed.")

# 主程序入口
if __name__ == "__main__":
    audit_system = AuditSystem()
    audit_system.run_audit()
