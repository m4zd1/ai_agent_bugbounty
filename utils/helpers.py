import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

from loguru import logger

def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    log_format = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan> - <level>{message}</level>"
    
    # Remove default logger
    logger.remove()
    
    # Add console logger
    logger.add(
        sys.stdout,
        format=log_format,
        level="DEBUG" if verbose else "INFO",
        colorize=True
    )
    
    # Add file logger
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    logger.add(
        log_dir / f"agent_{datetime.now().strftime('%Y%m%d')}.log",
        format=log_format,
        level="DEBUG",
        rotation="100 MB",
        retention="30 days"
    )

def validate_domain(domain: str) -> bool:
    """Validate domain name format"""
    import re
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def sanitize_url(url: str) -> str:
    """Sanitize URL for safe logging"""
    import re
    # Remove sensitive parameters
    sensitive_params = ['token', 'api_key', 'password', 'secret', 'auth']
    for param in sensitive_params:
        url = re.sub(f'({param}=)[^&]+', r'\1[REDACTED]', url, flags=re.IGNORECASE)
    return url

def load_wordlist(file_path: str) -> List[str]:
    """Load wordlist from file"""
    wordlist = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith('#'):
                    wordlist.append(word)
    except Exception as e:
        logger.error(f"Failed to load wordlist: {e}")
    return wordlist

def calculate_severity_score(severity: str) -> float:
    """Calculate CVSS-like severity score"""
    scores = {
        'critical': 9.0,
        'high': 7.0,
        'medium': 5.0,
        'low': 3.0,
        'info': 1.0
    }
    return scores.get(severity.lower(), 0.0)

def format_report_timestamp() -> str:
    """Format timestamp for reports"""
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")