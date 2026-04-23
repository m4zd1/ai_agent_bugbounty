#!/usr/bin/env python3
"""
Bug Bounty AI Agent - Main Entry Point
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from agent.core import CyberAgent
from agent.utils.helpers import setup_logging

async def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Bug Bounty AI Agent - Automated Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py example.com --scope scope.txt
  python main.py example.com --config custom_config.yaml
  python main.py example.com --report-format pdf
        """
    )
    
    parser.add_argument("domain", help="Target domain to test")
    parser.add_argument("--config", default="config.yaml", help="Configuration file path")
    parser.add_argument("--scope", help="Scope file path (domains/subdomains to include)")
    parser.add_argument("--exclude", help="Exclude file path (domains to skip)")
    parser.add_argument("--report-format", default="html", choices=["html", "markdown", "json", "pdf"],
                       help="Report output format")
    parser.add_argument("--output-dir", default="./reports", help="Output directory for reports")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--quick", action="store_true", help="Quick scan (limited endpoints)")
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(verbose=args.verbose)
    
    # Initialize and run agent
    agent = CyberAgent(args.config)
    
    # Override output directory if specified
    if args.output_dir:
        import yaml
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)
        config['reporting']['output_dir'] = args.output_dir
        with open(args.config, 'w') as f:
            yaml.dump(config, f)
    
    # Run assessment
    await agent.run_full_assessment(args.domain)

if __name__ == "__main__":
    asyncio.run(main())