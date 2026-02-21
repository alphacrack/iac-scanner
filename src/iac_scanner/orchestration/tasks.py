"""LangChain tasks: each task uses a different AI (analysis vs code-gen)."""

import os
from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI


def get_analysis_llm() -> ChatOpenAI | ChatAnthropic:
    """AI for analysis task (findings, security, best practices). Prefer OpenAI for structure."""
    model = os.environ.get("IAC_ANALYSIS_MODEL", "gpt-4o-mini")
    provider = os.environ.get("IAC_ANALYSIS_AI", "openai").lower()
    if provider == "anthropic":
        return ChatAnthropic(
            model=os.environ.get("IAC_ANALYSIS_MODEL", "claude-3-5-haiku-20241022"),
            api_key=os.environ.get("ANTHROPIC_API_KEY"),
        )
    return ChatOpenAI(
        model=model,
        api_key=os.environ.get("OPENAI_API_KEY"),
        temperature=0.2,
    )


def get_fix_llm() -> ChatOpenAI | ChatAnthropic:
    """AI for fix/code-gen task. Prefer Claude for code generation."""
    model = os.environ.get("IAC_FIX_MODEL", "gpt-4o")
    provider = os.environ.get("IAC_FIX_AI", "openai").lower()
    if provider == "anthropic":
        return ChatAnthropic(
            model=os.environ.get("IAC_FIX_MODEL", "claude-3-5-sonnet-20241022"),
            api_key=os.environ.get("ANTHROPIC_API_KEY"),
            temperature=0.1,
        )
    return ChatOpenAI(
        model=model,
        api_key=os.environ.get("OPENAI_API_KEY"),
        temperature=0.1,
    )


ANALYSIS_SYSTEM = """You are an expert IaC security and best-practices analyst.
Analyze the provided Infrastructure-as-Code and output a structured list of findings.
For each finding include: severity (high|medium|low), title, description, and the file/snippet it refers to.
Output ONLY a valid JSON array of objects with keys: severity, title, description, location.
If there are no issues, output: []"""

ANALYSIS_USER = """IaC type: {iac_type}
Entry path: {entry_path}

Code:
---
{raw_content}
---

List all security, compliance, and best-practice findings as a JSON array."""


FIX_SYSTEM = """You are an expert IaC engineer. Given the original code and a list of findings,
produce the FIXED full code only. Preserve structure and style; only change what is needed to address the findings.
Do not add explanations—output only the corrected code, ready to overwrite the original file(s).

IMPORTANT for multi-file projects (e.g. CDK with index.ts and lib/*.ts):
- The original code uses section headers like "// --- index.ts ---" and "// --- lib/demo-stack.ts ---" (CDK) or "# --- main.tf ---" (Terraform).
- You MUST keep these exact section headers and put each file's fixed content under its header, so we can write index.ts, lib/demo-stack.ts, etc. separately.
- Example format:
// --- index.ts ---
<content of index.ts>
// --- lib/demo-stack.ts ---
<content of lib/demo-stack.ts>

Alternatively you may use ---FILE: path/to/file--- before each file's content."""

FIX_USER = """IaC type: {iac_type}

Findings (JSON):
{findings}

Original code (section headers like // --- file --- or # --- file --- must be preserved in your output):
---
{raw_content}
---

Output the complete fixed code. For multiple files, keep the same section headers (// --- filename --- or # --- filename ---) so each file can be written correctly."""


def analysis_chain() -> Any:
    """Chain: raw_content + metadata -> analysis LLM -> findings string (JSON array)."""
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", ANALYSIS_SYSTEM),
            ("human", ANALYSIS_USER),
        ]
    )
    llm = get_analysis_llm()
    return prompt | llm | StrOutputParser()


def fix_chain() -> Any:
    """Chain: raw_content + findings -> fix LLM -> fixed code string."""
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", FIX_SYSTEM),
            ("human", FIX_USER),
        ]
    )
    llm = get_fix_llm()
    return prompt | llm | StrOutputParser()


def run_analysis(iac_type: str, entry_path: str, raw_content: str) -> str:
    """Run analysis task (uses analysis AI)."""
    chain = analysis_chain()
    return chain.invoke(
        {
            "iac_type": iac_type,
            "entry_path": entry_path,
            "raw_content": raw_content,
        }
    )


def run_fix(iac_type: str, raw_content: str, findings: str) -> str:
    """Run fix task (uses fix AI)."""
    chain = fix_chain()
    return chain.invoke(
        {
            "iac_type": iac_type,
            "raw_content": raw_content,
            "findings": findings,
        }
    )
