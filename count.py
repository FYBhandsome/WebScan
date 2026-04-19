import os
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple


class CodeLineCounter:
    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir)
        self.file_extensions = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.vue': 'Vue',
            '.java': 'Java',
            '.go': 'Go',
            '.rs': 'Rust',
            '.cpp': 'C++',
            '.c': 'C',
            '.h': 'C/C++ Header',
            '.hpp': 'C++ Header',
            '.cs': 'C#',
            '.php': 'PHP',
            '.rb': 'Ruby',
            '.swift': 'Swift',
            '.kt': 'Kotlin',
            '.scala': 'Scala',
            '.sql': 'SQL',
            '.sh': 'Shell',
            '.bat': 'Batch',
            '.ps1': 'PowerShell',
            '.html': 'HTML',
            '.css': 'CSS',
            '.scss': 'SCSS',
            '.sass': 'Sass',
            '.less': 'Less',
            '.json': 'JSON',
            '.xml': 'XML',
            '.yaml': 'YAML',
            '.yml': 'YAML',
            '.md': 'Markdown',
            '.txt': 'Text',
        }
        self.exclude_dirs = {
            '__pycache__',
            'node_modules',
            '.git',
            '.idea',
            '.vscode',
            'venv',
            'env',
            'dist',
            'build',
            '.pytest_cache',
            'coverage',
            '.mypy_cache',
            '.conda',
        }
        self.exclude_files = {
            '.DS_Store',
            'Thumbs.db',
        }

    def is_excluded(self, path: Path) -> bool:
        if path.name in self.exclude_files:
            return True
        for part in path.parts:
            if part in self.exclude_dirs:
                return True
        return False

    def count_lines_in_file(self, file_path: Path) -> Tuple[int, int, int]:
        total_lines = 0
        code_lines = 0
        comment_lines = 0
        blank_lines = 0

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                total_lines = len(lines)

                for line in lines:
                    stripped = line.strip()
                    if not stripped:
                        blank_lines += 1
                    elif stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                        comment_lines += 1
                    else:
                        code_lines += 1
        except Exception as e:
            print(f"Error reading {file_path}: {e}")

        return total_lines, code_lines, comment_lines, blank_lines

    def scan_directory(self) -> Dict[str, Dict]:
        stats = defaultdict(lambda: {
            'total_lines': 0,
            'code_lines': 0,
            'comment_lines': 0,
            'blank_lines': 0,
            'file_count': 0,
            'files': []
        })

        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]

            for file in files:
                file_path = Path(root) / file
                if self.is_excluded(file_path):
                    continue

                ext = file_path.suffix.lower()
                if ext in self.file_extensions:
                    language = self.file_extensions[ext]
                    total, code, comment, blank = self.count_lines_in_file(file_path)

                    stats[language]['total_lines'] += total
                    stats[language]['code_lines'] += code
                    stats[language]['comment_lines'] += comment
                    stats[language]['blank_lines'] += blank
                    stats[language]['file_count'] += 1
                    stats[language]['files'].append(str(file_path.relative_to(self.root_dir)))

        return dict(stats)

    def print_results(self, stats: Dict[str, Dict]):
        print("\n" + "=" * 80)
        print("代码行数统计报告".center(80))
        print("=" * 80)
        print(f"项目路径: {self.root_dir}")
        print("=" * 80)

        total_project_lines = 0
        total_project_code = 0
        total_project_comment = 0
        total_project_blank = 0
        total_project_files = 0

        print(f"\n{'语言':<15} {'文件数':<10} {'总行数':<12} {'代码行':<12} {'注释行':<12} {'空行':<12}")
        print("-" * 80)

        sorted_languages = sorted(stats.items(), key=lambda x: x[1]['total_lines'], reverse=True)

        for language, data in sorted_languages:
            total_project_lines += data['total_lines']
            total_project_code += data['code_lines']
            total_project_comment += data['comment_lines']
            total_project_blank += data['blank_lines']
            total_project_files += data['file_count']

            print(f"{language:<15} {data['file_count']:<10} {data['total_lines']:<12} "
                  f"{data['code_lines']:<12} {data['comment_lines']:<12} {data['blank_lines']:<12}")

        print("-" * 80)
        print(f"{'总计':<15} {total_project_files:<10} {total_project_lines:<12} "
              f"{total_project_code:<12} {total_project_comment:<12} {total_project_blank:<12}")
        print("=" * 80)

        if total_project_lines > 0:
            code_percentage = (total_project_code / total_project_lines) * 100
            comment_percentage = (total_project_comment / total_project_lines) * 100
            blank_percentage = (total_project_blank / total_project_lines) * 100

            print(f"\n代码行占比: {code_percentage:.2f}%")
            print(f"注释行占比: {comment_percentage:.2f}%")
            print(f"空行占比: {blank_percentage:.2f}%")
            print("=" * 80)

        print(f"\n详细文件列表 (按语言分类):")
        print("=" * 80)

        for language, data in sorted_languages:
            print(f"\n【{language}】({data['file_count']} 个文件):")
            for file_path in sorted(data['files']):
                print(f"  - {file_path}")

        print("\n" + "=" * 80)
        print("统计完成!".center(80))
        print("=" * 80 + "\n")


def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    counter = CodeLineCounter(root_dir)
    stats = counter.scan_directory()
    counter.print_results(stats)


if __name__ == "__main__":
    main()
