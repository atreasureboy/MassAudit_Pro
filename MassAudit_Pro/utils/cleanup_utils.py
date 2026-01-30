
import os
import shutil
import logging

# 从配置中导入常量
from MassAudit_Pro.config import PROJECTS_ROOT

def cleanup_project_artifacts(project_relative_path: str) -> None:
    """
    在每次扫描前检查并清理上次意外中断留下的锁文件或临时目录。
    :param project_relative_path: 项目相对于 PROJECTS_ROOT 的路径。
    """
    full_project_path = os.path.join(PROJECTS_ROOT, project_relative_path)
    if not os.path.isdir(full_project_path):
        logging.warning(f"Cleanup skipped: Project path does not exist or is not a directory: {full_project_path}")
        return

    logging.info(f"Starting cleanup for project artifacts in: {full_project_path}")

    # 1. 查找并删除锁文件
    lock_file_name = ".scan.lock"
    lock_file_path = os.path.join(full_project_path, lock_file_name)
    if os.path.exists(lock_file_path):
        try:
            os.remove(lock_file_path)
            logging.info(f"Successfully removed lock file: {lock_file_path}")
        except OSError as e:
            logging.error(f"Failed to remove lock file {lock_file_path}: {e}")

    # 2. 查找并删除临时目录
    temp_dir_name = "temp_scan_data"
    temp_dir_path = os.path.join(full_project_path, temp_dir_name)
    if os.path.isdir(temp_dir_path):
        try:
            shutil.rmtree(temp_dir_path)
            logging.info(f"Successfully removed temporary directory: {temp_dir_path}")
        except OSError as e:
            logging.error(f"Failed to remove temporary directory {temp_dir_path}: {e}")
    
    logging.info(f"Cleanup completed for project artifacts in: {full_project_path}")
