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
                    # Read up to FILE_SIZE_LIMIT_MB worth of characters
                    content = f.read(int(FILE_SIZE_LIMIT_MB * 1024 * 1024))
                return content + "\n[WARNING: File too large, truncated]\n"
            else:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return None

    def _clean_function_name(self, func_name: str) -> str:
        """
        [新增] 清洗函数名，处理调用链。
        例如: 
        'g.writeHeader' -> 'writeHeader'
        'http.ServeContent' -> 'ServeContent'
        'func(a)' -> 'func'
        """
        if "(" in func_name: # 去掉可能的参数
            func_name = func_name.split("(")[0]
        
        if "." in func_name:
            # 取最后一个点后面的部分，解决 g.writeHeader 找不到 writeHeader 的问题
            return func_name.split(".")[-1].strip()
        
        return func_name.strip()

    def _extract_python_definition(self, file_content: str, target_name: str) -> Optional[str]:
        """
        使用正则表达式从Python文件中提取函数或变量定义。
        """
        # 查找函数定义 (def function_name(...):)
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
                if line.strip() == '' or current_indent > target_indent:
                    definition_lines.append(line)
                else:
                    if line.strip() != '': 
                        break
                    else: 
                        definition_lines.append(line) 

        return "\n".join(definition_lines).strip() if definition_lines else None

    def _extract_go_definition(self, file_content: str, target_name: str) -> Optional[str]:
        """
        使用正则表达式从Go文件中提取函数、变量、常量或类型定义。
        [修改] 增强了正则以匹配:
        1. 带接收者的方法 (func (s *Struct) Method)
        2. 常量定义 (const X = ...)
        3. 变量定义 (var X = ...)
        4. 类型定义 (type X struct)
        """
        # 1. 查找函数定义: func Name( | func (r *Receiver) Name(
        func_pattern = re.compile(r'^func\s+(?:\([^)]+\)\s+)?' + re.escape(target_name) + r'\s*\(', re.MULTILINE)
        
        # 2. 查找 常量/变量/类型 定义: const Name = | var Name = | type Name struct
        # 使用 \b 确保 target_name 是完整单词，避免 minCompressBodyLength 匹配到 minCompressBodyLengthSuffix
        def_pattern = re.compile(r'^\s*(?:const|var|type)\s+' + re.escape(target_name) + r'(?:\s|=|:|$)', re.MULTILINE)

        lines = file_content.splitlines()
        definition_lines = []
        brace_count = 0
        in_definition = False

        for line in lines:
            # --- 尚未找到定义，进行搜索 ---
            if not in_definition:
                is_func = func_pattern.search(line)
                is_def = def_pattern.search(line)

                if is_func or is_def:
                    in_definition = True
                    definition_lines.append(line)
                    
                    # 统计大括号，决定是否是块结构
                    if '{' in line:
                        brace_count += line.count('{')
                        brace_count -= line.count('}')
                    
                    # [关键逻辑] 处理单行定义
                    # 如果是 const/var/type 定义，且当前行没有 '{' 也没有 '(' (忽略 var() 块的情况，简化处理)
                    # 那么它通常是单行定义，如: const X = 1
                    if is_def and not '{' in line and not '(' in line:
                        break # 单行定义，直接结束
                    
                    continue

            # --- 已找到定义，提取后续代码 ---
            if in_definition:
                definition_lines.append(line)
                brace_count += line.count('{')
                brace_count -= line.count('}')

                if brace_count <= 0:
                    # 对于函数或结构体，brace_count 归零且曾经有过 brace 表示结束
                    if '{' in "".join(definition_lines): 
                        break
                    # 对于某些特殊情况（如无大括号的），brace_count 始终为0
                    elif brace_count == 0 and not '{' in line:
                        break
                        
        return "\n".join(definition_lines).strip() if definition_lines else None

    def resolve_context(self, project_path: str, target_name: str) -> List[dict]:
        """
        在项目中搜索上下文。
        [修改] 在搜索前先清洗 target_name (例如去掉 g. 前缀)
        """
        found_contexts = []
        full_project_path = os.path.join(self.projects_root, project_path)
        
        # === 1. 关键修改：清洗函数名 ===
        clean_target_name = self._clean_function_name(target_name)
        logging.info(f"Searching for cleaned '{clean_target_name}' (raw: '{target_name}') in project: {full_project_path}")

        for root, dirs, files in os.walk(full_project_path):
            # 过滤 .git 目录
            if '.git' in dirs:
                dirs.remove('.git')
            if 'vendor' in dirs: # Go 项目通常忽略 vendor
                dirs.remove('vendor')
            
            for file_name in files:
                file_path = os.path.join(root, file_name)
                
                # 过滤非代码文件
                if not file_name.endswith(('.go', '.py', '.js', '.java', '.cpp', '.c')):
                    continue
                
                # 忽略测试文件 (可选，根据需要开启或关闭)
                if "_test.go" in file_name or "test_" in file_name:
                    continue

                file_content = self._read_file_content(file_path)
                if file_content is None:
                    continue

                extracted_code = None
                language = None

                # 使用 clean_target_name 进行提取
                if file_name.endswith('.py'):
                    language = 'Python'
                    extracted_code = self._extract_python_definition(file_content, clean_target_name)
                elif file_name.endswith('.go'):
                    language = 'Go'
                    extracted_code = self._extract_go_definition(file_content, clean_target_name)
                # 其他语言可扩展

                if extracted_code:
                    logging.info(f"Found '{clean_target_name}' definition in {file_path} (Language: {language})")
                    found_contexts.append({
                        'target_name': target_name, # 保留原始请求的名字
                        'file_path': file_path,
                        'language': language,
                        'code_block': extracted_code
                    })
                    
                    # 找到一个定义就返回，节省资源
                    if len(found_contexts) >= 1:
                        return found_contexts
        
        if not found_contexts:
            logging.info(f"No definition for '{clean_target_name}' found in project: {full_project_path}")

        return found_contexts