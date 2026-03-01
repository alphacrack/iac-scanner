"""IaC Scanner - CLI to scan and fix Terraform and CDK with LangChain-orchestrated agents."""


def _get_version() -> str:
    try:
        from importlib.metadata import version

        return version("iac-scanner")
    except Exception:
        return "0.0.0+editable"


__version__ = _get_version()
