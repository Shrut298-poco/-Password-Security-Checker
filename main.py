import re
import logging
import argparse
from dataclasses import dataclass
from typing import List

from zxcvbn import zxcvbn
from passlib.context import CryptContext
from rich.console import Console
from rich.table import Table

# ===============================
# Logging
# ===============================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PasswordSecurity")

console = Console()

# ===============================
# Password Hashing Context
# ===============================
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

# ===============================
# Data Model
# ===============================
@dataclass
class PasswordResult:
    password: str
    score: int
    strength: str
    crack_time: str
    valid: bool
    issues: List[str]

# ===============================
# Password Policy
# ===============================
class PasswordPolicy:
    MIN_LENGTH = 8

    @staticmethod
    def validate(password: str) -> List[str]:
        issues = []

        if len(password) < PasswordPolicy.MIN_LENGTH:
            issues.append("Length < 8")

        if not re.search(r"\d", password):
            issues.append("Missing digit")

        if not re.search(r"[A-Z]", password):
            issues.append("Missing uppercase letter")

        if not re.search(r"[a-z]", password):
            issues.append("Missing lowercase letter")

        if not re.search(r"[^\w\s]", password):
            issues.append("Missing special character")

        if re.search(r"(.)\1\1", password):
            issues.append("Repeated character pattern")

        return issues

# ===============================
# Password Evaluator
# ===============================
class PasswordEvaluator:

    @staticmethod
    def evaluate(password: str) -> PasswordResult:
        issues = PasswordPolicy.validate(password)

        zx = zxcvbn(password)
        score = zx["score"] * 25  # Normalize to 100
        crack_time = zx["crack_times_display"]["offline_slow_hashing_1e4_per_second"]

        if score >= 80:
            strength = "VERY STRONG"
        elif score >= 60:
            strength = "STRONG"
        elif score >= 40:
            strength = "MEDIUM"
        else:
            strength = "WEAK"

        valid = len(issues) == 0 and zx["score"] >= 3

        return PasswordResult(
            password=password,
            score=score,
            strength=strength,
            crack_time=crack_time,
            valid=valid,
            issues=issues if issues else ["No policy violations"]
        )

# ===============================
# Hashing Service (Production Ready)
# ===============================
class HashingService:

    @staticmethod
    def hash_password(password: str) -> str:
        return pwd_context.hash(password)

# ===============================
# Security Report
# ===============================
class SecurityReport:

    @staticmethod
    def display(results: List[PasswordResult]):
        table = Table(title="🔐 Password Security Assessment")

        table.add_column("Password", style="cyan")
        table.add_column("Score", justify="center")
        table.add_column("Strength")
        table.add_column("Crack Time")
        table.add_column("Status")
        table.add_column("Issues")

        for r in results:
            table.add_row(
                r.password,
                str(r.score),
                r.strength,
                r.crack_time,
                "PASS ✅" if r.valid else "FAIL ❌",
                ", ".join(r.issues)
            )

        console.print(table)

# ===============================
# CLI ENTRYPOINT
# ===============================
def main():
    passwords = ["abc", "123456", "Pass@123", "Admin","Shrut@298","123@abc","1234@acbd","Shrut,jain.com@298"]

    results = []
    for pwd in passwords:
        logger.info(f"Evaluating password: {pwd}")
        result = PasswordEvaluator.evaluate(pwd)
        hashed_preview = HashingService.hash_password(pwd)
        logger.debug(f"Hashed Preview: {hashed_preview[:20]}")
        results.append(result)

    SecurityReport.display(results)

if __name__ == "__main__":
    main()
