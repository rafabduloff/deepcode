import os
import sys
import argparse
import subprocess
import re
import shlex
import getpass
import tempfile
import logging
import json
import time
import mimetypes
from pathlib import Path
from typing import List, Dict, Optional, Set
from openai import OpenAI
from dotenv import load_dotenv
from datetime import datetime

# Configure logging (default to WARNING level - minimal output)
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

API_KEY = os.getenv("OPENROUTER_API_KEY")
if not API_KEY:
    print("Error: OPENROUTER_API_KEY not found in .env file")
    sys.exit(1)

client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=API_KEY)

SYSTEM_PROMPT = (
    "You are an AI assistant that follows instructions precisely. "
    "You do not argue or contradict. Answer strictly according to the request, without unnecessary explanations or advice. "
    "If you need to write code - write only code, no explanations.\n\n"
    "You are a professional assistant. All your responses must adhere to the following guidelines:\n\n"
    "IMPORTANT:\n"
    "- No emojis: Do not use any emojis, symbols, or decorative characters.\n"
    "- Professional tone: Maintain a formal, respectful, and business-like tone in all replies.\n"
    "- Clarity and precision: Provide clear, concise, and informative responses without unnecessary embellishments.\n"
    "- Consistency: Apply these instructions consistently throughout the entire conversation, regardless of input style.\n"
    "- No assumptions: Do not assume I want expressive or casual language unless explicitly requested.\n"
    "- Focus on content: Prioritize accuracy, relevance, and straightforward explanations.\n\n"
    "Always double-check your responses to ensure they strictly follow these guidelines."
)

# Enhanced security blacklist
BLACKLIST = [
    "rm -rf /",
    "rm -rf --no-preserve-root /",
    ":(){ :|: & };:",
    "mkfs",
    "dd if=",
    ">:(){",
    "shutdown",
    "reboot",
    "init 0",
    "halt",
    "poweroff",
    "sudo rm",
    "chmod 777",
    "chown root",
    "passwd",
    "useradd",
    "userdel",
    "deluser",
    "crontab",
    "systemctl",
    "service",
    "/etc/passwd",
    "/etc/shadow",
    "nc -l",
    "netcat -l",
    "ssh",
    "scp",
    "rsync",
    "mount",
    "umount",
    "fdisk",
    "parted",
    "curl -X POST",
    "wget -O",
    "format",
    "deltree",
]

# Safe file extensions for execution
SAFE_EXTENSIONS = {'.py', '.js', '.sh', '.pl', '.rb', '.go', '.rs', '.cpp', '.c', '.java'}

# Text file extensions for reading
TEXT_EXTENSIONS = {
    '.txt', '.md', '.py', '.js', '.html', '.css', '.json', '.xml', '.yaml', '.yml',
    '.sh', '.bat', '.ps1', '.rb', '.go', '.rs', '.cpp', '.c', '.h', '.hpp',
    '.java', '.php', '.sql', '.csv', '.ini', '.cfg', '.conf', '.log'
}

# Configuration file for persistent settings
CONFIG_FILE = '.ai_agent_config.json'

GUI_KEYWORDS = [
    'import tkinter', 'from tkinter',
    'import PyQt5', 'from PyQt5',
    'import PySide2', 'from PySide2',
    'import wx', 'import wxPython'
]

def load_config() -> Dict:
    """Load configuration from file."""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.debug(f"Error loading config: {e}")
    
    return {
        'auto_execute': False,
        'max_file_size': 100000,  # 100KB
        'ignored_dirs': {'.git', '__pycache__', 'node_modules', '.venv', 'venv'},
        'watch_files': [],
        'aliases': {},
        'max_debug_iterations': 10,
        'auto_install': True,
        'use_venv': True,
    }

def save_config(config: Dict) -> None:
    """Save configuration to file."""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving config: {e}")

def is_command_safe(cmd: str) -> bool:
    """Check if command is safe to execute."""
    lowered = cmd.lower()
    for bad in BLACKLIST:
        if bad in lowered:
            logger.debug(f"Blocked unsafe command pattern: {bad}")
            return False
    return True

def validate_file_path(filepath: str) -> bool:
    """Validate file path to prevent directory traversal attacks."""
    try:
        # Resolve the path and check if it's within current directory
        resolved_path = Path(filepath).resolve()
        current_dir = Path.cwd().resolve()
        return str(resolved_path).startswith(str(current_dir))
    except Exception:
        return False

def get_file_content(filepath: str, max_size: int = 100000) -> Optional[str]:
    """Safely read file content with size limit."""
    try:
        file_path = Path(filepath)
        if not file_path.exists():
            return None
        
        if file_path.stat().st_size > max_size:
            logger.debug(f"File {filepath} too large, skipping")
            return f"[File too large: {file_path.stat().st_size} bytes]"
        
        if file_path.suffix.lower() not in TEXT_EXTENSIONS:
            return f"[Binary file: {filepath}]"
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        logger.debug(f"Error reading file {filepath}: {e}")
        return None

def scan_directory(path: str = ".", ignored_dirs: Set[str] = None) -> Dict[str, str]:
    """Scan directory and return file contents."""
    if ignored_dirs is None:
        ignored_dirs = {'.git', '__pycache__', 'node_modules', '.venv', 'venv'}
    
    files_content = {}
    current_path = Path(path)
    
    try:
        for item in current_path.rglob('*'):
            if item.is_file():
                # Skip if in ignored directory
                if any(ignored_dir in item.parts for ignored_dir in ignored_dirs):
                    continue
                
                relative_path = str(item.relative_to(current_path))
                content = get_file_content(str(item))
                if content is not None:
                    files_content[relative_path] = content
    except Exception as e:
        logger.error(f"Error scanning directory: {e}")
    
    return files_content

def create_context_prompt(files_content: Dict[str, str], specific_files: List[str] = None) -> str:
    """Create context prompt from file contents."""
    if specific_files:
        # Filter to only specified files
        filtered_content = {k: v for k, v in files_content.items() 
                          if any(spec_file in k for spec_file in specific_files)}
        files_content = filtered_content
    
    if not files_content:
        return "No files found in current directory."
    
    context = "Current project files:\n\n"
    for filepath, content in files_content.items():
        context += f"=== {filepath} ===\n{content}\n\n"
    
    return context

def run_shell_command(cmd: str, auto_execute: bool = False) -> Optional[str]:
    """Execute shell command safely with output capture."""
    if not is_command_safe(cmd):
        error_msg = f"REFUSED: Command blocked for security reasons: {cmd}"
        print(error_msg)
        return None

    if not auto_execute:
        try:
            response = input(f"Execute command: {cmd}? (y/N): ").strip().lower()
            if response not in ['y', 'yes']:
                print("Command execution cancelled")
                return None
        except KeyboardInterrupt:
            print("\nCommand execution cancelled")
            return None

    try:
        # Если команда содержит спец-символы shell (&&, ||, ;, |, $, `),
        # выполняем её через zsh — это важно для пользователей zsh.
        use_shell = any(ch in cmd for ch in ['&&', '||', ';', '|', '$', '`'])

        if use_shell:
            result = subprocess.run(cmd, shell=True, executable='/usr/bin/zsh',
                                    capture_output=True, text=True, timeout=60)
            output, err_output = result.stdout, result.stderr
            if err_output:
                print(err_output, file=sys.stderr, end="")
            print(output, end="")
            return output

        # Без спец-символов безопаснее вызывать напрямую
        args = shlex.split(cmd)
        if not args:
            return None

        if args[0] == "sudo":
            password = getpass.getpass("Enter sudo password: ")
            proc = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60
            )
            stdout, stderr = proc.communicate(password + "\n")
            output = stdout
            if stderr:
                print(stderr, file=sys.stderr, end="")
        else:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=True,
                timeout=60
            )
            output = result.stdout
            if result.stderr:
                print(result.stderr, file=sys.stderr, end="")
        
        print(output, end="")
        return output
        
    except subprocess.TimeoutExpired:
        error_msg = f"Command timed out: {cmd}"
        print(error_msg)
    except subprocess.CalledProcessError as e:
        error_msg = f"Command execution error: {e}"
        print(error_msg)
    except FileNotFoundError:
        error_msg = f"Command not found: {args[0] if args else cmd}"
        print(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error executing command: {e}"
        print(error_msg)
    
    return None

def chat_completion(messages: List[Dict], model: str = "deepseek/deepseek-r1:free", max_tokens: int = 1024) -> Optional[str]:
    """Make API call to OpenRouter with error handling."""
    try:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            extra_headers={
                "HTTP-Referer": "https://yourdomain.com",
                "X-Title": "AI Agent"
            }
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"Error communicating with AI: {e}")
        return None

def save_files_from_response(response_text: str) -> List[str]:
    """Extract and save files OR apply diff-patches from AI response.

    Возвращает список файлов, которые были созданы/изменены.
    """

    # 1) Попытка распознать unified diff
    if _looks_like_diff(response_text):
        patched = _apply_unified_diff(response_text)
        if patched:
            return patched

    # 2) Обычный режим создания/перезаписи файлов
    files = {}
    current_file = None
    current_lines = []

    lines = response_text.splitlines()
    for line in lines:
        match = re.match(r"^---\s*(\S+)\s*---$", line)
        if match:
            if current_file:
                files[current_file] = "\n".join(current_lines).strip()
            
            filename = match.group(1)
            if not validate_file_path(filename):
                print(f"Warning: Invalid file path, skipping: {filename}")
                current_file = None
                continue
                
            current_file = filename
            current_lines = []
        else:
            if current_file:
                current_lines.append(line)
    
    if current_file:
        files[current_file] = "\n".join(current_lines).strip()
    elif not files and response_text.strip():
        files["output.py"] = response_text.strip()

    saved_files = []
    for fname, content in files.items():
        try:
            if not validate_file_path(fname):
                print(f"Warning: Skipping invalid file path: {fname}")
                continue
                
            # Create directory if it doesn't exist
            file_path = Path(fname)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(fname, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"Code saved to file: {fname}")
            saved_files.append(fname)
        except Exception as e:
            print(f"Error saving file {fname}: {e}")

    return saved_files

def extract_commands_from_response(response_text: str) -> List[str]:
    """Extract shell commands from AI response."""
    commands = []
    
    # Look for commands in code blocks, including zsh
    code_block_pattern = r"```(?:bash|shell|sh|zsh)?\n(.*?)\n```"
    matches = re.findall(code_block_pattern, response_text, re.DOTALL)
    for match in matches:
        lines = match.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                commands.append(line)
    
    # Look for commands after "Run:" or "Execute:"
    run_pattern = r"(?:Run|Execute):\s*`([^`]+)`"
    matches = re.findall(run_pattern, response_text, re.IGNORECASE)
    commands.extend(matches)
    
    return commands

def init_mode(specific_files: List[str] = None) -> Dict[str, str]:
    """Initialize context with current directory files."""
    config = load_config()
    
    print("Scanning current directory for files...")
    files_content = scan_directory(".", config['ignored_dirs'])
    
    if specific_files:
        print(f"Filtering for specific files: {', '.join(specific_files)}")
        files_content = {k: v for k, v in files_content.items() 
                        if any(spec_file in k for spec_file in specific_files)}
    
    print(f"Found {len(files_content)} files")
    for filepath in files_content.keys():
        print(f"  - {filepath}")
    
    return files_content

def watch_mode(files_to_watch: List[str]) -> None:
    """Watch files for changes and notify."""
    file_times = {}
    
    print(f"Watching files: {', '.join(files_to_watch)}")
    print("Press Ctrl+C to stop watching")
    
    try:
        while True:
            for filepath in files_to_watch:
                if os.path.exists(filepath):
                    mtime = os.path.getmtime(filepath)
                    if filepath not in file_times:
                        file_times[filepath] = mtime
                    elif file_times[filepath] != mtime:
                        print(f"File changed: {filepath}")
                        file_times[filepath] = mtime
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped watching files")

def analyze_code_mode(files_content: Dict[str, str]) -> None:
    """Analyze code for issues and suggestions."""
    if not files_content:
        print("No files to analyze")
        return
    
    context = create_context_prompt(files_content)
    prompt = [
        {"role": "system", "content": SYSTEM_PROMPT + " You are a code reviewer. Analyze the provided code for bugs, security issues, performance problems, and suggest improvements."},
        {"role": "user", "content": f"Analyze this codebase:\n\n{context}"}
    ]
    
    print("Analyzing code...")
    response = chat_completion(prompt, max_tokens=2048)
    if response:
        print("\nCode Analysis:")
        print(response)

def refactor_mode(files_content: Dict[str, str], refactor_request: str) -> None:
    """Refactor code based on request."""
    if not files_content:
        print("No files to refactor")
        return
    
    context = create_context_prompt(files_content)
    prompt = [
        {"role": "system", "content": SYSTEM_PROMPT + " You are a code refactoring assistant. Refactor the provided code according to the user's request. Output refactored files in format:\n--- filename.py ---\n<code>"},
        {"role": "user", "content": f"Refactor this codebase according to: {refactor_request}\n\nCurrent code:\n{context}"}
    ]
    
    print("Refactoring code...")
    response = chat_completion(prompt, max_tokens=4096)
    if response:
        filenames = save_files_from_response(response)
        if filenames:
            print(f"\nRefactored {len(filenames)} file(s)")

def document_mode(files_content: Dict[str, str]) -> None:
    """Generate documentation for the codebase."""
    if not files_content:
        print("No files to document")
        return
    
    context = create_context_prompt(files_content)
    prompt = [
        {"role": "system", "content": SYSTEM_PROMPT + " You are a documentation generator. Create comprehensive documentation for the provided codebase including README.md and inline comments."},
        {"role": "user", "content": f"Generate documentation for this codebase:\n\n{context}"}
    ]
    
    print("Generating documentation...")
    response = chat_completion(prompt, max_tokens=4096)
    if response:
        filenames = save_files_from_response(response)
        if filenames:
            print(f"\nGenerated documentation in {len(filenames)} file(s)")
        else:
            print("\nGenerated Documentation:")
            print(response)

def test_mode(files_content: Dict[str, str]) -> None:
    """Generate tests for the codebase."""
    if not files_content:
        print("No files to test")
        return
    
    context = create_context_prompt(files_content)
    prompt = [
        {"role": "system", "content": SYSTEM_PROMPT + " You are a test generator. Create comprehensive unit tests for the provided code. Use appropriate testing frameworks."},
        {"role": "user", "content": f"Generate tests for this codebase:\n\n{context}"}
    ]
    
    print("Generating tests...")
    response = chat_completion(prompt, max_tokens=4096)
    if response:
        filenames = save_files_from_response(response)
        if filenames:
            print(f"\nGenerated tests in {len(filenames)} file(s)")

def analyze_error_output(error_output: str, code_content: str) -> str:
    """Analyze error output and suggest fixes."""
    return f"""
Error Analysis:
=============
Error Output:
{error_output}

Current Code:
{code_content}

Please analyze this error and provide a fixed version of the code. 
Focus on the specific error and provide a complete working solution.
"""

def generate_test_inputs(code_content: str, file_type: str) -> List[str]:
    """Generate test inputs based on code analysis."""
    prompt = [
        {"role": "system", "content": SYSTEM_PROMPT + " You are a test input generator. Analyze the code and generate various test inputs to test different scenarios including edge cases."},
        {"role": "user", "content": f"Generate test inputs for this {file_type} program. Return only the inputs, one per line:\n\n{code_content}"}
    ]
    
    response = chat_completion(prompt, max_tokens=1024)
    if response:
        # Extract inputs from response
        inputs = []
        for line in response.split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('//'):
                inputs.append(line)
        return inputs
    return []

def run_program_with_input(filename: str, test_input: str = None, timeout: int = 10) -> tuple[bool, str, str]:
    """Run program with optional input and capture output."""
    if not os.path.exists(filename):
        return False, "", f"File {filename} not found"
    
    file_path = Path(filename)
    ext = file_path.suffix.lower()
    
    # Determine run command
    commands = {
        ".py": ["python", filename],
        ".js": ["node", filename],
        ".java": ["java", file_path.stem],
        ".cpp": [f"./{file_path.stem}"],
        ".c": [f"./{file_path.stem}"],
        ".go": ["go", "run", filename],
        ".rs": [f"./{file_path.stem}"]
    }
    
    if ext not in commands:
        return False, "", f"Unsupported file type: {ext}"
    
    try:
        # For compiled languages, compile first
        if ext in [".cpp", ".c"]:
            compiler = "g++" if ext == ".cpp" else "gcc"
            compile_result = subprocess.run(
                [compiler, filename, "-o", file_path.stem],
                capture_output=True, text=True, timeout=timeout
            )
            if compile_result.returncode != 0:
                return False, "", f"Compilation error: {compile_result.stderr}"
        
        elif ext == ".java":
            compile_result = subprocess.run(
                ["javac", filename],
                capture_output=True, text=True, timeout=timeout
            )
            if compile_result.returncode != 0:
                return False, "", f"Compilation error: {compile_result.stderr}"
        
        elif ext == ".rs":
            compile_result = subprocess.run(
                ["rustc", filename, "-o", file_path.stem],
                capture_output=True, text=True, timeout=timeout
            )
            if compile_result.returncode != 0:
                return False, "", f"Compilation error: {compile_result.stderr}"
        
        # Run the program
        proc = subprocess.Popen(
            commands[ext],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        try:
            stdout, stderr = proc.communicate(input=test_input, timeout=timeout)
            success = proc.returncode == 0
            return success, stdout, stderr
        except subprocess.TimeoutExpired:
            proc.kill()
            return False, "", "Program timed out"
            
    except Exception as e:
        return False, "", f"Execution error: {str(e)}"

def auto_debug_mode(filename: str, max_iterations: int = 5) -> None:
    """Auto-debugging mode: run program, analyze errors, fix, repeat."""
    if not os.path.exists(filename):
        print(f"Error: File {filename} not found")
        return
    
    print(f"Starting auto-debug mode for {filename}")
    print(f"Maximum iterations: {max_iterations}")
    print("=" * 50)
    
    iteration = 0
    fixed_versions = []
    
    while iteration < max_iterations:
        iteration += 1
        print(f"\n--- Iteration {iteration} ---")
        
        # Read current code
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                current_code = f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            break
        
        # Generate test inputs based on code analysis
        print("Generating test inputs...")
        file_ext = Path(filename).suffix.lower()
        test_inputs = generate_test_inputs(current_code, file_ext)
        
        if not test_inputs:
            test_inputs = ["", "test", "123", "hello world", "exit", "quit"]
        
        print(f"Generated {len(test_inputs)} test inputs")
        
        # Test with different inputs
        errors_found = []
        successful_runs = 0
        
        for i, test_input in enumerate(test_inputs[:10]):  # Limit to 10 inputs
            print(f"Testing with input {i+1}: '{test_input}'")
            
            success, stdout, stderr = run_program_with_input(filename, test_input)
            
            if success:
                successful_runs += 1
                print(f"  ✓ Success: {stdout[:100]}{'...' if len(stdout) > 100 else ''}")
            else:
                error_info = {
                    'input': test_input,
                    'stdout': stdout,
                    'stderr': stderr
                }
                errors_found.append(error_info)
                print(f"  ✗ Error: {stderr[:100]}{'...' if len(stderr) > 100 else ''}")
        
        print(f"\nResults: {successful_runs}/{len(test_inputs[:10])} tests passed")
        
        # If no errors found, we're done
        if not errors_found:
            print("🎉 No errors found! Program appears to be working correctly.")
            break
        
        # Analyze the most common error
        primary_error = errors_found[0]  # Take first error for analysis
        print(f"\nAnalyzing primary error...")
        print(f"Input that caused error: '{primary_error['input']}'")
        print(f"Error output: {primary_error['stderr']}")
        
        # Generate fix
        error_analysis = analyze_error_output(
            f"STDERR: {primary_error['stderr']}\nSTDOUT: {primary_error['stdout']}\nINPUT: {primary_error['input']}",
            current_code
        )
        
        fix_prompt = [
            {"role": "system", "content": SYSTEM_PROMPT + " You are a debugging expert. Analyze the error and provide a complete fixed version of the code. Output the fixed code in format:\n--- " + filename + " ---\n<fixed_code>"},
            {"role": "user", "content": error_analysis}
        ]
        
        print("Requesting fix from AI...")
        fix_response = chat_completion(fix_prompt, max_tokens=4096)
        
        if not fix_response:
            print("Failed to get fix from AI")
            break
        
        # Save the fixed version
        backup_filename = f"{filename}.backup.{iteration}"
        try:
            # Backup current version
            with open(backup_filename, 'w', encoding='utf-8') as f:
                f.write(current_code)
            print(f"Backed up current version to {backup_filename}")
            
            # Save fixed version
            saved_files = save_files_from_response(fix_response)
            if saved_files:
                print(f"Applied fix to {', '.join(saved_files)}")
                fixed_versions.append({
                    'iteration': iteration,
                    'error': primary_error['stderr'][:200],
                    'files': saved_files
                })
            else:
                print("No files were generated from fix response")
                print("AI response:")
                print(fix_response[:500] + "..." if len(fix_response) > 500 else fix_response)
                break
                
        except Exception as e:
            print(f"Error applying fix: {e}")
            break
    
    # Summary
    print("\n" + "=" * 50)
    print("AUTO-DEBUG SUMMARY")
    print("=" * 50)
    print(f"Total iterations: {iteration}")
    print(f"Fixes applied: {len(fixed_versions)}")
    
    if fixed_versions:
        print("\nFix history:")
        for fix in fixed_versions:
            print(f"  Iteration {fix['iteration']}: Fixed '{fix['error'][:50]}...'")
    
    # Final test
    print("\nRunning final validation...")
    final_success, final_stdout, final_stderr = run_program_with_input(filename, "test")
    
    if final_success:
        print("✅ Final validation: SUCCESS")
        print(f"Output: {final_stdout[:200]}{'...' if len(final_stdout) > 200 else ''}")
    else:
        print("❌ Final validation: FAILED")
        print(f"Error: {final_stderr}")
        
        # Offer to restore backup
        if fixed_versions:
            try:
                response = input("Restore original version? (y/N): ").strip().lower()
                if response in ['y', 'yes']:
                    backup_file = f"{filename}.backup.1"
                    if os.path.exists(backup_file):
                        with open(backup_file, 'r') as f:
                            original_code = f.read()
                        with open(filename, 'w') as f:
                            f.write(original_code)
                        print("Original version restored")
            except KeyboardInterrupt:
                pass

def interactive_debug_mode(filename: str) -> None:
    """Interactive debugging mode with step-by-step control."""
    if not os.path.exists(filename):
        print(f"Error: File {filename} not found")
        return
    
    print(f"Starting interactive debug mode for {filename}")
    print("Commands: run, input <value>, analyze, fix, quit")
    print("=" * 50)
    
    while True:
        try:
            command = input("\ndebug> ").strip().lower()
            
            if command == 'quit' or command == 'q':
                break
            
            elif command == 'run' or command == 'r':
                success, stdout, stderr = run_program_with_input(filename)
                if success:
                    print(f"✓ Success:\n{stdout}")
                else:
                    print(f"✗ Error:\n{stderr}")
            
            elif command.startswith('input '):
                test_input = command[6:]  # Remove 'input '
                success, stdout, stderr = run_program_with_input(filename, test_input)
                if success:
                    print(f"✓ Success with input '{test_input}':\n{stdout}")
                else:
                    print(f"✗ Error with input '{test_input}':\n{stderr}")
            
            elif command == 'analyze' or command == 'a':
                success, stdout, stderr = run_program_with_input(filename, "test")
                if not success:
                    with open(filename, 'r') as f:
                        code = f.read()
                    
                    analysis = analyze_error_output(stderr, code)
                    print("Error Analysis:")
                    print(analysis)
            
            elif command == 'fix' or command == 'f':
                success, stdout, stderr = run_program_with_input(filename)
                if not success:
                    with open(filename, 'r') as f:
                        code = f.read()
                    
                    error_analysis = analyze_error_output(stderr, code)
                    fix_prompt = [
                        {"role": "system", "content": SYSTEM_PROMPT + f" Fix this code and output in format:\n--- {filename} ---\n<fixed_code>"},
                        {"role": "user", "content": error_analysis}
                    ]
                    
                    print("Getting fix from AI...")
                    fix_response = chat_completion(fix_prompt, max_tokens=4096)
                    if fix_response:
                        saved_files = save_files_from_response(fix_response)
                        if saved_files:
                            print(f"Applied fix to {', '.join(saved_files)}")
                        else:
                            print("Fix response:")
                            print(fix_response)
                else:
                    print("No errors found to fix")
            
            elif command == 'help' or command == 'h':
                print("Commands:")
                print("  run/r - Run the program")
                print("  input <value> - Run with specific input")
                print("  analyze/a - Analyze current errors")
                print("  fix/f - Auto-fix current errors")
                print("  quit/q - Exit debug mode")
            
            else:
                print("Unknown command. Type 'help' for available commands.")
                
        except KeyboardInterrupt:
            print("\nExiting debug mode...")
            break
        except Exception as e:
            print(f"Error: {e}")

def run_code_file(filename: str, auto_execute: bool = False) -> bool:
    """Execute code file with safety checks."""
    if not validate_file_path(filename):
        print(f"REFUSED: Invalid file path: {filename}")
        return False
        
    if not os.path.exists(filename):
        print(f"Error: File {filename} does not exist")
        return False
    
    file_path = Path(filename)
    ext = file_path.suffix.lower()
    
    if ext not in SAFE_EXTENSIONS:
        print(f"REFUSED: Unsafe file extension: {ext}")
        return False
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if not is_command_safe(content):
            print(f"REFUSED: File {filename} contains dangerous commands")
            return False
    except Exception as e:
        print(f"Error reading file {filename}: {e}")
        return False
    
    if not auto_execute:
        try:
            response = input(f"Execute {filename}? (y/N): ").strip().lower()
            if response not in ['y', 'yes']:
                print("Execution cancelled")
                return False
        except KeyboardInterrupt:
            print("\nExecution cancelled")
            return False
    
    try:
        commands = {
            ".py": f"python {filename}",
            ".js": f"node {filename}",
            ".sh": f"bash {filename}",
            ".pl": f"perl {filename}",
            ".rb": f"ruby {filename}",
            ".go": f"go run {filename}",
            ".rs": f"rustc {filename} && ./{file_path.stem}",
            ".cpp": f"g++ {filename} -o {file_path.stem} && ./{file_path.stem}",
            ".c": f"gcc {filename} -o {file_path.stem} && ./{file_path.stem}",
            ".java": f"javac {filename} && java {file_path.stem}"
        }
        
        if ext in commands:
            print(f"Running {filename}...")
            run_shell_command(commands[ext], auto_execute=True)
        else:
            print(f"Unknown file type for execution: {filename}")
            return False
        return True
    except Exception as e:
        print(f"Error running {filename}: {e}")
        return False

def coding_mode(user_query: str, context: str = "", auto_execute: bool = False) -> None:
    """Enhanced coding mode with context support."""
    system_content = SYSTEM_PROMPT + " You are in code creation mode. If needed, create multiple files in format:\n--- filename.py ---\n<code>\n--- anotherfile.py ---\n<code>"
    
    if context:
        system_content += f"\n\nProject context:\n{context}"
    
    prompt = [
        {"role": "system", "content": system_content},
        {"role": "user", "content": user_query}
    ]

    print("Generating code based on request...")
    
    code_response = chat_completion(prompt, max_tokens=4096)
    if not code_response:
        print("Failed to get response from AI")
        return

    filenames = save_files_from_response(code_response)
    
    # Extract and execute shell commands
    commands = extract_commands_from_response(code_response)
    if commands:
        print(f"\nFound {len(commands)} command(s) in response:")
        for cmd in commands:
            print(f"  {cmd}")
            run_shell_command(cmd, auto_execute)

    if filenames:
        print(f"\nCreated {len(filenames)} file(s): {', '.join(filenames)}")
        
        for fname in filenames:
            success = run_code_file(fname, auto_execute)
            if not success:
                print(f"Execution failed for {fname}")
    else:
        print("\nAI Response:")
        print(code_response)

def main():
    """Main function with enhanced argument parsing."""
    parser = argparse.ArgumentParser(
        description="Enhanced AI agent console tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ai.py "explain how sorting works"
  python ai.py --coding-only "create a calculator in python"
  python ai.py -c "write a web scraper for news"
  python ai.py --init
  python ai.py --init main.py utils.py
  python ai.py --analyze
  python ai.py --refactor "add error handling"
  python ai.py --document
  python ai.py --test
  python ai.py --auto-debug calculator.py
  python ai.py --interactive-debug main.py
  python ai.py --max-debug-iterations 10 --auto-debug app.py
        """
    )
    parser.add_argument("command", nargs="*", help='Query or files for init mode')
    parser.add_argument("--coding-only", "-c", action="store_true", 
                       help="Agent mode: create and run code")
    parser.add_argument("--init", action="store_true",
                       help="Initialize context with current directory files")
    parser.add_argument("--analyze", action="store_true",
                       help="Analyze code for issues and suggestions")
    parser.add_argument("--refactor", type=str,
                       help="Refactor code based on request")
    parser.add_argument("--document", action="store_true",
                       help="Generate documentation for codebase")
    parser.add_argument("--test", action="store_true",
                       help="Generate tests for codebase")
    parser.add_argument("--auto-debug", type=str,
                       help="Auto-debug mode: automatically fix errors in specified file")
    parser.add_argument("--interactive-debug", type=str,
                       help="Interactive debug mode for specified file")
    parser.add_argument("--max-debug-iterations", type=int, default=5,
                       help="Maximum iterations for auto-debug mode")
    parser.add_argument("--watch", action="store_true",
                       help="Watch files for changes")
    parser.add_argument("--config", nargs=2, metavar=('KEY', 'VALUE'),
                       help="Set configuration option")
    parser.add_argument("--auto-execute", "-a", action="store_true",
                       help="Auto-execute safe commands without confirmation")
    parser.add_argument("--model", "-m", default="deepseek/deepseek-r1:free",
                       help="AI model to use")
    parser.add_argument("--max-tokens", "-t", type=int, default=1024,
                       help="Maximum tokens in response")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose logging")
    parser.add_argument("--debug", "-d", action="store_true",
                       help="Enable debug mode with detailed logging")
    parser.add_argument("--auto-workflow", "-w", action="store_true",
                       help="Run automated coding + debugging workflow")
    parser.add_argument("--workflow-output", type=str, default="workflow_output.json",
                       help="Output file name for workflow report")

    args = parser.parse_args()
    
    # Configure logging
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    config = load_config()
    
    # Handle configuration
    if args.config:
        key, value = args.config
        if value.lower() in ['true', '1']:
            config[key] = True
        elif value.lower() in ['false', '0']:
            config[key] = False
        else:
            try:
                config[key] = int(value)
            except ValueError:
                config[key] = value
        save_config(config)
        print(f"Configuration updated: {key} = {config[key]}")
        return

    auto_execute = args.auto_execute or config.get('auto_execute', False)
    files_content = {}

    # Handle init mode
    if args.init:
        files_content = init_mode(args.command if args.command else None)
        if not args.command:  # If no additional command, just show files
            return

    # Handle special modes
    if args.analyze:
        if not files_content:
            files_content = scan_directory()
        analyze_code_mode(files_content)
        return
    
    if args.refactor:
        if not files_content:
            files_content = scan_directory()
        refactor_mode(files_content, args.refactor)
        return
    
    if args.document:
        if not files_content:
            files_content = scan_directory()
        document_mode(files_content)
        return
    
    if args.test:
        if not files_content:
            files_content = scan_directory()
        test_mode(files_content)
        return
    
    if args.auto_debug:
        auto_debug_mode(args.auto_debug, args.max_debug_iterations)
        return
    
    if args.interactive_debug:
        interactive_debug_mode(args.interactive_debug)
        return
    
    if args.watch:
        files_to_watch = args.command if args.command else ['*.py', '*.js']
        watch_mode(files_to_watch)
        return

    if args.auto_workflow:
        if not args.command:
            print("Error: No query provided for workflow")
            sys.exit(1)
        workflow_query = " ".join(args.command)
        # При запуске workflow автоматически берём весь проект в контекст (кроме игнорируемых папок)
        files_content = scan_directory(".", config.get('ignored_dirs'))
        context = create_context_prompt(files_content) if files_content else ""
        auto_coding_debug_workflow(workflow_query, args.workflow_output, config, context)
        return

    # Handle regular query
    if not args.command:
        print("Error: No command provided")
        sys.exit(1)
    
    user_query = " ".join(args.command)
    
    if not user_query.strip():
        print("Error: Empty query provided")
        sys.exit(1)

    context = ""
    if files_content:
        context = create_context_prompt(files_content)

    if args.coding_only:
        # Если пользователь не делал --init, соберём контекст автоматически
        if not context:
            files_content = scan_directory(".", config.get('ignored_dirs'))
            context = create_context_prompt(files_content)
        coding_mode(user_query, context, auto_execute)
    else:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT + (f"\n\nProject context:\n{context}" if context else "")},
            {"role": "user", "content": user_query}
        ]
        
        print("Sending request to AI...")
        
        answer = chat_completion(messages, model=args.model, max_tokens=args.max_tokens)
        if answer:
            print("\nAI Response:")
            print(answer)
            
            # Auto-execute any shell commands found in response
            commands = extract_commands_from_response(answer)
            if commands:
                print(f"\nFound {len(commands)} command(s) in response:")
                for cmd in commands:
                    print(f"  {cmd}")
                    run_shell_command(cmd, auto_execute)
        else:
            print("Failed to get response from AI")
            sys.exit(1)

# --- Automated Coding & Debugging Workflow ---

def _is_gui_code(code_text: str) -> bool:
    """Rudimentary check: содержит ли код импорты GUI-библиотек."""
    lower = code_text.lower()
    return any(k.lower() in lower for k in GUI_KEYWORDS)

def run_gui_for_test(filename: str, duration: int = 10) -> tuple[bool, str, str]:
    """Запускает GUI-скрипт, наблюдает stdout/stderr в течение `duration` секунд.
    Если за время наблюдения не возникло ошибок (stderr пустой, процесс жив),
    мы завершаем процесс и считаем тест успешным.
    """
    try:
        proc = subprocess.Popen(
            [sys.executable, filename],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=os.environ.copy() | {"QT_QPA_PLATFORM": os.environ.get("QT_QPA_PLATFORM", "offscreen")},
        )
        try:
            stdout, stderr = proc.communicate(timeout=duration)
        except subprocess.TimeoutExpired:
            # Время вышло, процесс ещё жив → GUI работает
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            return True, "", ""

        success = proc.returncode == 0 and not stderr.strip()
        return success, stdout, stderr
    except Exception as e:
        return False, "", str(e)

def auto_debug_file(filename: str, max_iterations: int = 10) -> bool:
    """Lightweight auto-debug helper used by the workflow with progress output."""
    for iteration in range(1, max_iterations + 1):
        print(f"  [DEBUG] Итерация {iteration}/{max_iterations} для {filename} …")
        # Определяем, GUI ли это
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            src = f.read()

        # determine python executable (venv or system)
        python_exec = _ensure_venv() if load_config().get('use_venv', True) else sys.executable

        env_runner = lambda: run_program_with_input(filename, "test")
        if _is_gui_code(src):
            env_runner = lambda: run_gui_for_test(filename, duration=10)

        success, stdout, stderr = env_runner()

        if not success and load_config().get('auto_install', True):
            # Try auto-install missing packages
            _install_missing_modules(stderr or '', python_exec, auto_execute=True)
            # retry once immediately
            success, stdout, stderr = env_runner()

        if success:
            print("  ✅ Успешно: программа работает без ошибок")
            return True
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                current_code = f.read()
        except Exception as e:
            print(f"Failed to read {filename}: {e}")
            return False
        fix_prompt = [
            {"role": "system", "content": SYSTEM_PROMPT + f" Fix the following error(s) and provide a complete corrected version of the file. Output in format:\n--- {filename} ---\n<code>"},
            {"role": "user", "content": f"Error while running {filename}:\n{stderr or stdout}\n\nCurrent code:\n{current_code}"}
        ]
        print("  🔄 Запрос исправления у ИИ …")
        fix_response = chat_completion(fix_prompt, max_tokens=4096)
        if not fix_response:
            break
        # Сначала запустим потенциальные команды (установка пакетов и др.)
        cmds = extract_commands_from_response(fix_response)
        for cmd in cmds:
            print(f"  ⚙  Выполняю команду из ответа: {cmd}")
            run_shell_command(cmd, auto_execute=True)

        saved = save_files_from_response(fix_response)
        if not saved:
            break
    # Final attempt after iterations
    success, _, _ = run_program_with_input(filename, "test")
    return success

def auto_coding_debug_workflow(query: str, output_file: str, config: Dict, context: str = "") -> None:
    """High-level workflow: generate code, auto debug, validate, and save report.
    If context (содержимое текущего проекта) передано, оно добавляется в system-промпт, чтобы ИИ мог учитывать существующие файлы."""
    print(f"[WORKFLOW] Started: {query}")
    print("[WORKFLOW] Шаг 1: генерация кода …")
    steps = []
    # Step 1 – Generate code
    system_header = SYSTEM_PROMPT + " Create complete, functional code. Output files in format:\n--- filename.ext ---\n<code>"
    if context:
        system_header += f"\n\nProject context:\n{context}"

    coding_prompt = [
        {"role": "system", "content": system_header},
        {"role": "user", "content": query}
    ]
    code_response = chat_completion(coding_prompt, max_tokens=config.get('max_tokens', 4096))
    if not code_response:
        print("Failed to get code from AI")
        return
    generated_files = save_files_from_response(code_response)
    print(f"[WORKFLOW] Создано файлов: {len(generated_files)}")
    steps.append({"step": "code_generation", "files": generated_files})
    # Step 2 – Auto-debug each generated file
    print("[WORKFLOW] Шаг 2: авто-дебаг …")
    for fname in generated_files:
        if Path(fname).suffix.lower() not in SAFE_EXTENSIONS:
            continue
        ok = auto_debug_file(fname, config.get('max_debug_iterations', 10))
        steps.append({"step": f"debug_{fname}", "success": ok})
    # Step 3 – Final validation
    print("[WORKFLOW] Шаг 3: финальная валидация …")
    validation = []
    for fname in generated_files:
        if Path(fname).suffix.lower() not in SAFE_EXTENSIONS:
            continue
        success, stdout, stderr = run_program_with_input(fname, "test")
        validation.append({"file": fname, "success": success, "stdout": stdout[:200], "stderr": stderr[:200]})
    # Compose report
    report = {
        "query": query,
        "generated_files": generated_files,
        "steps": steps,
        "validation": validation,
        "timestamp": datetime.now().isoformat()
    }
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[WORKFLOW] Отчёт сохранён в {output_file}")
    except Exception as e:
        print(f"Failed to save workflow report: {e}")

# -----------------------------------------------------------
# Virtualenv helpers & auto-install
# -----------------------------------------------------------

def _ensure_venv(path: Path = Path('.venv')) -> Path:
    """Create venv at `path` if it does not exist and return python executable."""
    if path.exists():
        return path / 'bin' / 'python'
    try:
        print("[ENV] Creating virtual environment …")
        subprocess.run([sys.executable, '-m', 'venv', str(path)], check=True)
        return path / 'bin' / 'python'
    except Exception as e:
        print(f"[ENV] Failed to create venv: {e}")
        return Path(sys.executable)

def _install_missing_modules(stderr_text: str, python_exec: str | Path = sys.executable, auto_execute: bool = True):
    """Detect ModuleNotFoundError/ImportError and run pip install for missing packages."""
    pattern = r"No module named '(.*?)'"
    missing = re.findall(pattern, stderr_text)
    for mod in missing:
        # Skip stdlib like tkinter
        if mod.lower() in {'tkinter'}:
            continue
        print(f"  📦 Отсутствует модуль {mod} — пытаюсь установить…")
        pip_cmd = f"{python_exec} -m pip install --quiet {mod}"
        run_shell_command(pip_cmd, auto_execute=auto_execute)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)