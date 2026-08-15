#!/usr/bin/env python3
"""
Subprocess Utilities

Provides safe subprocess execution utilities.
"""

import subprocess
from typing import Optional, Tuple
from dataclasses import dataclass


@dataclass
class CommandResult:
    """Result of a command execution."""
    returncode: int
    stdout: str
    stderr: str
    success: bool
    
    @classmethod
    def from_completed_process(cls, proc: subprocess.CompletedProcess) -> 'CommandResult':
        return cls(
            returncode=proc.returncode,
            stdout=proc.stdout if isinstance(proc.stdout, str) else proc.stdout.decode('utf-8', errors='replace'),
            stderr=proc.stderr if isinstance(proc.stderr, str) else proc.stderr.decode('utf-8', errors='replace'),
            success=proc.returncode == 0
        )


def run_command(cmd: list, timeout: Optional[int] = None, 
                capture_output: bool = True) -> CommandResult:
    """
    Run a command safely.
    
    Args:
        cmd: Command and arguments as list
        timeout: Timeout in seconds
        capture_output: Whether to capture stdout/stderr
        
    Returns:
        CommandResult with execution details
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            errors='replace'
        )
        return CommandResult.from_completed_process(result)
    except subprocess.TimeoutExpired as e:
        return CommandResult(
            returncode=-1,
            stdout=e.stdout.decode('utf-8', errors='replace') if e.stdout else '',
            stderr=f'Command timed out after {timeout} seconds',
            success=False
        )
    except FileNotFoundError as e:
        return CommandResult(
            returncode=-1,
            stdout='',
            stderr=f'Command not found: {cmd[0]}',
            success=False
        )
    except Exception as e:
        return CommandResult(
            returncode=-1,
            stdout='',
            stderr=str(e),
            success=False
        )
