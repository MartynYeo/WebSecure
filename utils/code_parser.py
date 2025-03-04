# utils/code_parser.py
from pathlib import Path
from typing import Any, Dict, List


class CodeParser:
    def __init__(self):
        """
        Initialize the code parser with language-specific settings
        """

        self.language_extensions = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.cpp': 'C++',
            '.c': 'C',
            '.cs': 'C#',
            '.go': 'Go',
            '.rb': 'Ruby',
            '.php': 'PHP',
            '.rs': 'Rust',
            '.swift': 'Swift',
            '.kt': 'Kotlin',
            '.scala': 'Scala'
        }

    def parse(self, content: str, filename: str) -> Dict[str, Any]:
        """
        Parse code content and extract relevant information

        Args:
            content: The source code content
            filename: Name of the file being parsed

        Returns:
            Dictionary containing parsed information about the code
        """

        file_ext = Path(filename).suffix.lower()
        language = self.language_extensions.get(file_ext, 'Unknown')

        return {
            'language': language,
            'file_type': file_ext,
            'content': content,
            'size': len(content),
            'line_count': content.count('\n') + 1,
            'metadata': self._extract_metadata(content, language),
            'imports': self._extract_imports(content, language),
            'functions': self._extract_functions(content, language),
            'classes': self._extract_classes(content, language)
        }

    def _extract_metadata(self, content: str, language: str) -> Dict[str, Any]:
        """
        Extract metadata like comments, documentation strings

        Args:
            content: The source code content
            language: The programming language of the code

        Returns:
            dictionary: Dictionary containing metadata information
        """

        metadata = {
            'has_documentation': False,
            'comment_lines': 0,
            'todo_count': 0
        }

        # Language-specific comment patterns
        comment_patterns = {
            'Python': ['#', '"""', "'''"],
            'JavaScript': ['//', '/*', '*/'],
            'Java': ['//', '/*', '*/'],
            'C++': ['//', '/*', '*/'],
            'Ruby': ['#'],
            'PHP': ['//', '#', '/*', '*/'],
        }

        patterns = comment_patterns.get(language, [])
        if not patterns:
            return metadata

        lines = content.split('\n')
        in_multiline = False

        for line in lines:
            line = line.strip()

            # Check for multiline comments
            if any(p in line for p in ['"""', "'''", '/*']):
                in_multiline = True
                metadata['has_documentation'] = True
                metadata['comment_lines'] += 1
                continue

            # Count single-line comments
            if any(line.startswith(p) for p in patterns):
                metadata['comment_lines'] += 1
                if 'todo' in line.lower():
                    metadata['todo_count'] += 1

            # Count lines in multiline comments
            elif in_multiline:
                metadata['comment_lines'] += 1

        return metadata

    def _extract_imports(self, content: str, language: str) -> List[str]:
        """
        Extract import statements based on language

        Args:
            content: The source code content
            language: The programming language of the code

        Returns:
            list: List of import statements
        """

        imports = []

        if language == 'Python':
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith(('import ', 'from ')):
                    imports.append(line)

        elif language in ['JavaScript', 'TypeScript']:
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith(('import ', 'require(')):
                    imports.append(line)

        elif language == 'Java':
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('import '):
                    imports.append(line)

        return imports

    def _extract_functions(self, content: str, language: str) -> List[Dict[str, Any]]:
        """
        Extract function definitions based on language

        Args:
            content: The source code content
            language: The programming language of the code

        Returns:
            list: List of function definitions
        """

        functions = []

        if language == 'Python':
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if line.strip().startswith('def '):
                    func_name = line.split('def ')[1].split('(')[0].strip()
                    functions.append({
                        'name': func_name,
                        'line': i + 1,
                        'async': line.strip().startswith('async def')
                    })

        elif language in ['JavaScript', 'TypeScript']:
            lines = content.split('\n')
            for i, line in enumerate(lines):
                line = line.strip()
                if 'function ' in line or '=>' in line:
                    if 'function ' in line:
                        func_name = line.split('function ')[1].split('(')[0].strip()
                    else:
                        parts = line.split('=')
                        if len(parts) > 1:
                            func_name = parts[0].strip()
                    functions.append({
                        'name': func_name,
                        'line': i + 1,
                        'async': 'async ' in line
                    })

        return functions

    def _extract_classes(self, content: str, language: str) -> List[Dict[str, Any]]:
        """
        Extract class definitions based on language

        Args:
            content: The source code content
            language: The programming language of the code

        Returns:
            list: List of class definitions
        """

        classes = []

        if language == 'Python':
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if line.strip().startswith('class '):
                    class_name = line.split('class ')[1].split('(')[0].strip()
                    classes.append({
                        'name': class_name,
                        'line': i + 1
                    })

        elif language in ['JavaScript', 'TypeScript']:
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if line.strip().startswith('class '):
                    class_name = line.split('class ')[1].split('{')[0].split('extends')[0].strip()
                    classes.append({
                        'name': class_name,
                        'line': i + 1
                    })

        return classes