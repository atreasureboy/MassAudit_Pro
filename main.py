import os
import logging
import sqlite3
import json
import time
import subprocess # Used for executing shell commands
import random     # Used for generating random filenames
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
    MassAudit Pro: Intelligent Interactive Code Audit System Main Coordinator.
    """
    def __init__(self, rescan_mode: bool = False):
        """
        Initialize the audit system.
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
        """Initialize local database for C2 utilization."""
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
        """Save high-risk vulnerabilities to SQLite."""
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
            print(f"💾 [C2] Vulnerability stored: {vuln_data.get('original_rule_id')}")
        except Exception as e:
            logging.error(f"DB Error: {e}")

    def _save_project_report(self, project_name, vulnerabilities):
        """
        Generate report containing verification results.
        """
        if self.rescan_mode:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{project_name}_{timestamp}.md"
        else:
            filename = f"{project_name}_report.md"

        report_path = os.path.join(self.reports_dir, filename)
        
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(f"# {project_name} Audit Report\n")
                f.write(f"**Generated At**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Mode**: {'Rescan' if self.rescan_mode else 'Resume'}\n")
                f.write(f"**Vulnerabilities Found**: {len(vulnerabilities)}\n\n")
                
                for idx, v in enumerate(vulnerabilities):
                    f.write(f"## {idx+1}. {v.get('original_rule_id', 'Unknown Issue')}\n")
                    f.write(f"- **File**: `{v.get('file_path')}` : `{v.get('line_number')}`\n")
                    f.write(f"- **AI Verdict**: **{v.get('verdict')}**\n")
                    f.write(f"- **Analysis**: {v.get('reason')}\n")
                    
                    # === [Modified] Automated Verification Results (AI Judge Based) ===
                    if v.get('has_poc'):
                        f.write(f"\n> 🛡️ **Automated Verification Report (Auto-Verify)**\n")
                        f.write(f"> **PoC Script**: `{v.get('poc_path')}`\n")
                        
                        verify_status = v.get('verify_status', 'UNKNOWN')
                        verify_output = v.get('verify_output', '').strip()
                        ai_judge_reason = v.get('ai_judge_reason', 'No reasoning provided.')
                        
                        # Icon mapping based on AI verdict
                        icon_map = {
                            "VULN_CRASH": "🚨", 
                            "VULN_RECOVERED": "⚠️", 
                            "SAFE_PASS": "✅", 
                            "TEST_FAIL": "➖", 
                            "ERROR": "❌"
                        }
                        icon = icon_map.get(verify_status, "❓")
                        
                        f.write(f"> **Status**: {icon} **{verify_status}**\n")
                        f.write(f"> **AI Judgment**: {ai_judge_reason}\n")
                        f.write(f"> **Console Output Snippet**: \n```text\n{verify_output[:1000]}...\n```\n")
                    
                    elif v.get('verdict', '').upper() in ['HIGH', 'MEDIUM']:
                         f.write(f"\n> ⚠️ **Verification**: AI determined untestable or skipped.\n")
                         
                    f.write("---\n")
            self.reporter.log_info(f"✅ Report saved: {filename}")
        except Exception as e:
            self.reporter.log_error(f"Failed to save report for {project_name}: {e}")

    def _check_if_project_scanned(self, project_name):
        """Check if report exists."""
        std_report = os.path.join(self.reports_dir, f"{project_name}_report.md")
        if os.path.exists(std_report) and os.path.getsize(std_report) > 50:
            return True
        for f in os.listdir(self.reports_dir):
            if f.startswith(f"{project_name}_") and f.endswith(".md"):
                return True
        return False

    def _analyze_poc_output_with_ai(self, console_output: str) -> Dict[str, str]:
        """
        [New] AI Judge: Analyze PoC console output to determine if vulnerability is confirmed.
        """
        # [关键修改] 使用字符串拼接来构建 Prompt，防止被输出过滤器截断
        p_role = "You are a Security Audit Result Analyst.\n"
        p_task = "I ran a Go language PoC (Proof of Concept exploit), and below is the console output.\nPlease analyze this output and determine the vulnerability status.\n"
        p_content = f"\n【Console Output】\n```text\n{console_output[-2000:]} \n```\n(Showing last 2000 characters)\n"
        
        p_criteria = """
        【Judgment Criteria】
        1. **VULN_CRASH**: A `panic:` occurred and the process crashed (not caught by recover), or a `segmentation fault` occurred. This is High Risk.
        2. **VULN_RECOVERED**: A panic occurred but was caught by `recover()` (script often logs "Panic captured" or similar). This indicates Robustness Issue or DoS risk.
        3. **SAFE_PASS**: Test output `PASS`, and no panic or error messages appeared. Code successfully defended.
        4. **TEST_FAIL**: Test output `FAIL` (assertion error), but no panic. PoC logic failed to trigger expected behavior.
        5. **ERROR**: Compilation failed, missing packages, or setup failed. Script didn't run properly.
        """
        p_format = """
        【Output Format】
        You must return a valid JSON object:
        {
            "status": "VULN_CRASH" | "VULN_RECOVERED" | "SAFE_PASS" | "TEST_FAIL" | "ERROR",
            "reason": "One sentence explaining why."
        }
        """
        # 拼接 Prompt
        final_prompt = p_role + p_task + p_content + p_criteria + p_format
        
        messages = [{"role": "user", "content": final_prompt}]
        try:
            # Reuse api_caller
            response = self.api_caller.call_llm(messages=messages)
            
            # Robust JSON parsing
            try:
                return json.loads(response)
            except:
                # If raw text contains JSON code block, try to extract it
                if "```json" in response:
                    clean = response.split("```json")[1].split("```")[0].strip()
                    return json.loads(clean)
                elif "{" in response:
                    return json.loads(response[response.find("{"):response.rfind("}")+1])
                return {"status": "UNKNOWN", "reason": "Failed to parse AI JSON response."}
                
        except Exception as e:
            logging.error(f"AI Judge Error: {e}")
            return {"status": "UNKNOWN", "reason": f"AI analysis failed: {e}"}

    def run_audit(self):
        """Execute audit flow."""
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

                    # === [Core Logic] Self-Healing & AI-Judged Verification ===
                    poc_code = analysis_result.get('poc_code', '')
                    is_testable = analysis_result.get('is_testable', False)
                    verdict = analysis_result.get('verdict', '').upper()
                    
                    analysis_result['has_poc'] = False
                    analysis_result['verify_status'] = 'SKIPPED'
                    analysis_result['verify_output'] = ''
                    analysis_result['ai_judge_reason'] = '' 
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
                            
                            MAX_FIX_ATTEMPTS = 8
                            current_attempt_code = clean_code
                            
                            for attempt in range(MAX_FIX_ATTEMPTS + 1):
                                self.reporter.log_info(f"🔧 [Verify] Attempt {attempt+1}/{MAX_FIX_ATTEMPTS + 1}...")

                                copy_cmd = f"cp \"{poc_save_path}\" \"{target_source_dir}/\""
                                os.system(copy_cmd)

                                verify_cmd = f"cd \"{target_source_dir}\" && go test -v {poc_filename}"
                                
                                try:
                                    process = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, timeout=15)
                                    output = process.stdout + "\n" + process.stderr
                                    
                                    # 1. Quick check for obvious environmental errors (compile/missing package)
                                    # We handle these with the "Self-Healing" loop before asking the AI Judge.
                                    compile_errors = [
                                        "build failed", "undefined:", "imported and not used",
                                        "no required module", "cannot find package", "setup failed"
                                    ]
                                    is_compile_error = any(e in output for e in compile_errors)

                                    if is_compile_error:
                                        # === Compilation/Env Error: Auto-Fix ===
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
                                        # === Script ran! Send output to AI Judge for verdict ===
                                        self.reporter.log_info(f"✅ Execution Finished! Asking AI Judge...")
                                        
                                        # Call AI Judge
                                        judge_result = self._analyze_poc_output_with_ai(output)
                                        
                                        analysis_result['verify_status'] = judge_result.get("status", "UNKNOWN")
                                        analysis_result['ai_judge_reason'] = judge_result.get("reason", "No reason provided")
                                        analysis_result['verify_output'] = output
                                        
                                        self.reporter.log_info(f"⚖️ AI Verdict: {analysis_result['verify_status']} ({analysis_result['ai_judge_reason']})")
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
    print("   🛡️  MassAudit Pro - Interactive Start")
    print("="*50)
    print("Select Scan Mode:")
    print(" [1] Rescan")
    print("     - Re-scans even if reports exist.")
    print("     - Creates new files with timestamps.")
    print("")
    print(" [2] Resume [Recommended]")
    print("     - Skips already scanned projects.")
    print("="*50)
    
    while True:
        choice = input("Enter choice (1 or 2): ").strip()
        if choice == '1':
            is_rescan = True
            break
        elif choice == '2':
            is_rescan = False
            break
        else:
            print("❌ Invalid input. Enter 1 or 2.")

    print(f"\n✅ Mode: {'Rescan' if is_rescan else 'Resume'}\n")
    
    # Start System
    audit_system = AuditSystem(rescan_mode=is_rescan)
    audit_system.run_audit()