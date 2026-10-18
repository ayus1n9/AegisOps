"""Parser registry for all supported security scanners."""
from security.policy.parsers.base import BaseParser
from security.policy.parsers.gitleaks import GitleaksParser
from security.policy.parsers.semgrep import SemgrepParser
from security.policy.parsers.bandit import BanditParser
from security.policy.parsers.npm_audit import NpmAuditParser
from security.policy.parsers.pip_audit import PipAuditParser
from security.policy.parsers.trivy import TrivyParser
from security.policy.parsers.checkov import CheckovParser
from security.policy.parsers.zap import ZapParser

PARSER_REGISTRY = {
    "gitleaks": GitleaksParser,
    "semgrep": SemgrepParser,
    "bandit": BanditParser,
    "npm_audit": NpmAuditParser,
    "pip_audit": PipAuditParser,
    "trivy": TrivyParser,
    "checkov": CheckovParser,
    "zap": ZapParser,
}

def get_parser(scanner_name: str) -> BaseParser:
    parser_cls = PARSER_REGISTRY.get(scanner_name)
    if not parser_cls:
        raise ValueError(f"No parser registered for scanner: '{scanner_name}'")
    return parser_cls()
