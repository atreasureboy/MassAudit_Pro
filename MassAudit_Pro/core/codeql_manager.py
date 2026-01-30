
import os
import subprocess
import shlex
import json
import logging
import shutil
from typing import Optional, List, Dict, Any

# 从配置中导入常量
from MassAudit_Pro.config import PROJECTS_ROOT, DB_STORAGE

class CodeQLManager:
    """
    负责CodeQL数据库的动态创建、语言识别、扫描执行以及SARIF结果的解析。
    """
    def __init__(self, db_storage_path: str, projects_root: str):
        """
        初始化CodeQLManager。
        :param db_storage_path: CodeQL数据库的存储路径。
        :param projects_root: 所有项目源代码的根目录。
        """
        self.db_storage_path = db_storage_path
        self.projects_root = projects_root
        # 确保数据库存储路径存在
        os.makedirs(self.db_storage_path, exist_ok=True)
        logging.info(f"CodeQLManager initialized. DB storage: {self.db_storage_path}, Projects root: {self.projects_root}")

    def _run_command(self, command_args: List[str], cwd: Optional[str] = None) -> Optional[str]:
        """
        安全地执行Shell命令，并捕获输出和错误。
        :param command_args: 命令及其参数的列表。
        :param cwd: 执行命令的工作目录。
        :return: 命令的标准输出，如果执行失败则返回None。
        """
        try:
            logging.debug(f"Executing command: {' '.join(shlex.quote(arg) for arg in command_args)} in cwd: {cwd}")
            process = subprocess.run(
                command_args,
                cwd=cwd,
                capture_output=True,
                text=True,
                check=True, # Raise an exception for non-zero exit codes
                encoding='utf-8'
            )
            if process.stderr:
                logging.warning(f"Command stderr: {process.stderr.strip()}")
            return process.stdout.strip()
        except subprocess.CalledProcessError as e:
            logging.error(f"Command failed with exit code {e.returncode}: {e.cmd}")
            logging.error(f"Stdout: {e.stdout}")
            logging.error(f"Stderr: {e.stderr}")
            return None
        except FileNotFoundError:
            logging.error(f"Command not found. Is CodeQL CLI installed and in PATH? Command: {command_args[0]}")
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred while running command: {command_args}. Error: {e}")
            return None

    def _detect_language(self, project_path: str) -> Optional[str]:
        """
        动态识别项目的主要编程语言。
        :param project_path: 项目的绝对路径。
        :return: 识别到的语言（如 'python', 'go', 'java', 'javascript'），如果无法识别则返回None。
        """
        language_extensions = {
            'python': ['.py'],
            'go': ['.go'],
            'java': ['.java', '.gradle', '.jar'], # Include build files for Java projects
            'javascript': ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'],
            'csharp': ['.cs'],
            'cpp': ['.c', '.cpp', '.h', '.hpp'],
            'ruby': ['.rb'],
            'php': ['.php'],
            'kotlin': ['.kt', '.kts'],
            'swift': ['.swift'],
            'scala': ['.scala']
        }

        found_languages = {}

        full_project_path = os.path.join(self.projects_root, project_path)
        if not os.path.isdir(full_project_path):
            logging.warning(f"Project path does not exist or is not a directory: {full_project_path}")
            return None

        for root, _, files in os.walk(full_project_path):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                for lang, extensions in language_extensions.items():
                    if ext in extensions:
                        found_languages[lang] = found_languages.get(lang, 0) + 1

        if not found_languages:
            logging.info(f"No primary language detected for project: {project_path}")
            return None

        # 返回文件数量最多的语言作为主语言
        dominant_language = max(found_languages, key=found_languages.get)
        logging.info(f"Detected dominant language for project '{project_path}': {dominant_language} with {found_languages[dominant_language]} files.")
        return dominant_language

    def create_database(self, project_name: str, project_path: str, language: str) -> Optional[str]:
        """
        安全地创建CodeQL数据库。
        :param project_name: 项目的名称，用于数据库命名。
        :param project_path: 源代码的相对路径（相对于self.projects_root）。
        :param language: 项目的编程语言（如 'python', 'go'）。
        :return: 创建的数据库的绝对路径，如果创建失败则返回None。
        """
        full_project_source_path = os.path.join(self.projects_root, project_path)
        db_path = os.path.join(self.db_storage_path, f"{project_name}-db")

        logging.info(f"Attempting to create CodeQL database for project '{project_name}' (language: {language}) at '{db_path}' from source '{full_project_source_path}'")

        # 清理旧的数据库（如果存在）
        if os.path.exists(db_path):
            logging.warning(f"Existing CodeQL database found at '{db_path}'. Deleting it before creation.")
            try:
                shutil.rmtree(db_path)
            except Exception as e:
                logging.error(f"Failed to remove existing database at {db_path}: {e}")
                return None

        command = [
            "codeql", "database", "create", db_path,
            "--language", language,
            "--source-root", full_project_source_path
        ]

        # 根据语言添加特定的构建命令（如果需要）
        # 例如，对于Java，可能需要Maven或Gradle构建命令
        # 对于Go，CodeQL通常可以直接分析，无需显式构建命令
        # 对于Python，CodeQL也会自动找到依赖，无需显式构建命令
        if language == 'java':
            pass # CodeQL can often auto-build simple Java projects
        elif language == 'go':
            pass # Go projects typically don't require an explicit build command for CodeQL
        elif language == 'python':
            pass # Python projects typically don't require an explicit build command for CodeQL

        stdout = self._run_command(command)

        if stdout:
            logging.info(f"Successfully created CodeQL database for '{project_name}': {db_path}")
            return db_path
        else:
            logging.error(f"Failed to create CodeQL database for '{project_name}'.")
            return None

    def run_analysis(self, db_path: str, query_pack: str = 'codeql/java-queries', output_sarif_path: str = None) -> Optional[str]:
        """
        安全地执行CodeQL分析。
        :param db_path: CodeQL数据库的绝对路径。
        :param query_pack: 要运行的CodeQL查询包的名称（例如 'codeql/java-queries'）。
                           也可以是查询文件的路径。
        :param output_sarif_path: SARIF结果的输出路径。如果为None，则默认为数据库目录下的results.sarif。
        :return: 生成的SARIF文件的绝对路径，如果分析失败则返回None。
        """
        if not os.path.isdir(db_path):
            logging.error(f"CodeQL database not found at: {db_path}")
            return None

        if output_sarif_path is None:
            output_sarif_path = os.path.join(db_path, "results.sarif")

        logging.info(f"Running CodeQL analysis on database '{db_path}' with query pack '{query_pack}'. Output will be saved to '{output_sarif_path}'")

        command = [
            "codeql", "database", "analyze", db_path,
            query_pack,
            "--format=sarif-latest",
            f"--output={output_sarif_path}"
        ]

        stdout = self._run_command(command)

        if stdout:
            logging.info(f"Successfully completed CodeQL analysis. SARIF results: {output_sarif_path}")
            return output_sarif_path
        else:
            logging.error(f"Failed to run CodeQL analysis on database '{db_path}'.")
            return None

    def parse_sarif_results(self, sarif_file_path: str) -> Optional[Dict[str, Any]]:
        """
        解析CodeQL生成的SARIF文件。
        :param sarif_file_path: SARIF文件的绝对路径。
        :return: 解析后的SARIF内容（字典），如果文件损坏或JSON格式错误则返回None。
        """
        if not os.path.exists(sarif_file_path):
            logging.error(f"SARIF file not found at: {sarif_file_path}")
            return None

        logging.info(f"Attempting to parse SARIF file: {sarif_file_path}")
        try:
            with open(sarif_file_path, 'r', encoding='utf-8') as f:
                sarif_content = json.load(f)
            logging.info(f"Successfully parsed SARIF file: {sarif_file_path}")
            return sarif_content
        except json.JSONDecodeError as e:
            logging.error(f"SARIF file '{sarif_file_path}' is corrupted or has invalid JSON format: {e}. Skipping this file.")
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred while reading or parsing SARIF file '{sarif_file_path}': {e}. Skipping this file.")
            return None

    def cleanup_database(self, db_path: str) -> bool:
        """
        清理CodeQL数据库。
        :param db_path: CodeQL数据库的绝对路径。
        :return: 清理是否成功。
        """
        if not os.path.isdir(db_path):
            logging.warning(f"CodeQL database directory not found for cleanup: {db_path}. Skipping cleanup.")
            return False
        try:
            logging.info(f"Cleaning up CodeQL database at: {db_path}")
            shutil.rmtree(db_path)
            logging.info(f"Successfully cleaned up CodeQL database: {db_path}")
            return True
        except Exception as e:
            logging.error(f"Failed to clean up CodeQL database at {db_path}: {e}")
            return False
