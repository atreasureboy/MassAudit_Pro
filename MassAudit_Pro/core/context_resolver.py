
import os
import re
import logging
from typing import Optional, Tuple, List, Any

# 从配置中导入常量
from MassAudit_Pro.config import PROJECTS_ROOT, FILE_SIZE_LIMIT_MB

class ContextResolver:
    """
    ContextResolver 类用于在项目中查找AI请求的函数或变量定义，并提取其完整的代码块。
    支持Python和Go语言的函数和变量定义查找。
    """
    def __init__(self, projects_root: str):
        """
        初始化ContextResolver。
        :param projects_root: 所有项目的根目录，用于定位项目。
        """
        self.projects_root = projects_root
        logging.info(f"ContextResolver initialized with projects_root: {self.projects_root}")

    def _read_file_content(self, file_path: str) -> Optional[str]:
        """
        安全地读取文件内容，处理文件大小限制并记录警告。
        :param file_path: 要读取的文件路径。
        :return: 文件内容字符串，如果文件过大则截断，如果读取失败返回None。
        """
        try:
            file_size_bytes = os.path.getsize(file_path)
            file_size_mb = file_size_bytes / (1024 * 1024)

            if file_size_mb > FILE_SIZE_LIMIT_MB: # FILE_SIZE_LIMIT_MB is a global constant
                logging.warning(f"[WARNING] File too large: {file_path} ({file_size_mb:.2f}MB). Truncating to {FILE_SIZE_LIMIT_MB}MB.")
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    # Read up to FILE_SIZE_LIMIT_MB worth of characters, assuming 1 char = 1 byte for simplicity or more robust handling
                    content = f.read(int(FILE_SIZE_LIMIT_MB * 1024 * 1024))
                return content + "\n[WARNING: File too large, truncated]\n"
            else:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return None

    def _extract_python_definition(self, file_content: str, target_name: str) -> Optional[str]:
        """
        使用正则表达式从Python文件中提取函数或变量定义。
        """
        # 查找函数定义 (def function_name(...):)
        # 考虑到async def function_name(...):
        func_pattern = re.compile(r'^(?:async\s+)?def\s+' + re.escape(target_name) + r'\s*\([^)]*\):', re.MULTILINE)
        # 查找变量定义 (variable_name = ...)
        var_pattern = re.compile(r'^\s*' + re.escape(target_name) + r'\s*=\s*(?:[^\n]*)$', re.MULTILINE)

        lines = file_content.splitlines()
        definition_lines = []
        in_definition = False
        target_indent = -1

        for i, line in enumerate(lines):
            if func_pattern.search(line) or var_pattern.search(line):
                definition_lines.append(line)
                target_indent = len(line) - len(line.lstrip())
                in_definition = True
                continue

            if in_definition:
                current_indent = len(line) - len(line.lstrip())
                # 对于多行变量赋值或函数体，只要缩进大于等于目标缩进，就认为是定义的一部分
                # 对于函数，遇到相同或更小缩进的非空行则停止
                if line.strip() == '' or current_indent > target_indent:
                    definition_lines.append(line)
                else:
                    # 遇到相同或更小缩进的有效行，表示定义结束
                    if line.strip() != '': # Only break if it's not just an empty line
                        break
                    else: # Keep empty lines within the same block if indent matches or is greater
                        definition_lines.append(line) # Add empty line that maintains indentation

        return "\n".join(definition_lines).strip() if definition_lines else None

    def _extract_go_definition(self, file_content: str, target_name: str) -> Optional[str]:
        """
        使用正则表达式从Go文件中提取函数或变量定义。
        """
        # 查找函数定义 (func function_name(...) {)
        func_pattern = re.compile(r'^func\s+(?:\(.*\)\s+)?' + re.escape(target_name) + r'\s*\([^)]*\)\s*(?:[^\n]*?)?{', re.MULTILINE)
        # 查找变量定义 (var variable_name type = ... or variable_name := ...)
        var_pattern = re.compile(r'^(?:var\s+' + re.escape(target_name) + r'\s+[^=;\n]+|' + re.escape(target_name) + r'\s*:=\s*[^;\n]+)', re.MULTILINE)

        lines = file_content.splitlines()
        definition_lines = []
        brace_count = 0
        in_definition = False

        for line in lines:
            if func_pattern.search(line) or var_pattern.search(line):
                in_definition = True
                definition_lines.append(line)
                if '{' in line: # 如果函数定义行包含开启大括号
                    brace_count += line.count('{')
                    brace_count -= line.count('}') # Check for closing brace on same line
                continue

            if in_definition:
                definition_lines.append(line)
                brace_count += line.count('{')
                brace_count -= line.count('}')

                if brace_count == 0 and '{' in line: # Go函数或块以'}'结束，当brace_count归零时，表示块结束
                    break
                elif brace_count == 0 and not '{' in line and var_pattern.search(definition_lines[0]): # For variable definitions without braces
                     # Simple variables in Go are typically single line or part of a var block without braces
                    break # Assuming single-line variable definitions or end of var block
        return "\n".join(definition_lines).strip() if definition_lines else None


    def resolve_context(self, project_path: str, target_name: str) -> List[dict]:
        found_contexts = []
        full_project_path = os.path.join(self.projects_root, project_path)
        
        logging.info(f"Searching for '{target_name}' in project: {full_project_path}")

        for root, dirs, files in os.walk(full_project_path):
            # === 过滤 .git 目录 (必须在遍历文件之前做) ===
            if '.git' in dirs:
                dirs.remove('.git')  # 这样修改 dirs 列表，os.walk 下次就不会进入 .git 了
            
            for file_name in files:
                file_path = os.path.join(root, file_name)
                
                # === 过滤非代码文件 (只处理常见源码) ===
                if not file_name.endswith(('.go', '.py', '.js', '.java', '.cpp', '.c')):
                    continue
                
                file_content = self._read_file_content(file_path)
                if file_content is None:
                    continue

                extracted_code = None
                language = None

                if file_name.endswith('.py'):
                    language = 'Python'
                    extracted_code = self._extract_python_definition(file_content, target_name)
                elif file_name.endswith('.go'):
                    language = 'Go'
                    extracted_code = self._extract_go_definition(file_content, target_name)
                # 可以添加更多语言的解析逻辑

                if extracted_code:
                    logging.info(f"Found '{target_name}' definition in {file_path} (Language: {language})")
                    found_contexts.append({
                        'target_name': target_name,
                        'file_path': file_path,
                        'language': language,
                        'code_block': extracted_code
                    })
                    
                    # 通常找到一个定义就够了，直接返回，避免浪费时间和Token
                    if len(found_contexts) >= 1:
                        return found_contexts
        
        if not found_contexts:
            logging.info(f"No definition for '{target_name}' found in project: {full_project_path}")

        return found_contexts