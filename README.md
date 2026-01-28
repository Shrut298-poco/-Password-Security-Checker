# 🔐 Password Security Checker

A **Python-based password security evaluation tool** that analyzes passwords, checks them against common security policies, estimates their strength using [zxcvbn](https://github.com/dropbox/zxcvbn), and provides a hashed preview using bcrypt. It also displays results in a **rich console table** and optionally exports them to JSON.

---

## Features

- ✅ **Password Policy Validation**:
  - Minimum length of 8 characters
  - Must include at least one digit, uppercase letter, lowercase letter, and special character
  - Detects repeated characters (e.g., `aaa`)

- ✅ **Strength Analysis using zxcvbn**:
  - Assigns a score (0–100) and labels strength as WEAK, MEDIUM, STRONG, VERY STRONG
  - Estimates offline crack time

- ✅ **Secure Hashing**:
  - Uses **bcrypt** via `passlib` to generate password hashes

- ✅ **Rich Table Reporting**:
  - Nicely formatted console output with all password details
  - Optional hashed password preview

- ✅ **JSON Export**:
  - Save evaluation results for further analysis

- ✅ **CLI Support**:
  - Evaluate multiple passwords directly from the command line
  - Optional flags for hashing and JSON export

---

## Installation

1. Clone the repository:

git clone https://github.com/<your-username>/password-security-checker.git
cd password-security-checker

2.Create a virtual environment (optional but recommended):

python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

3.Install dependencies:

pip install -r requirements.txt

<img width="987" height="394" alt="image" src="https://github.com/user-attachments/assets/02e8d0e5-7c34-4edf-adca-ea20327e28f4" />



