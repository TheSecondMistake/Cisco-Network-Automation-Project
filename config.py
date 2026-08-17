"""
Centralized environment loading and configuration validation helpers.
"""

import os
from dotenv import load_dotenv

load_dotenv()


def require_env(required: dict[str, str | None]) -> None:
    """Raise RuntimeError listing any missing required environment variables.

    Args:
        required: mapping of env-var name -> its current value (already
            fetched via os.getenv). Callers build this dict themselves so
            each class only validates the variables it actually needs.
    """
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise RuntimeError(f"Missing required configuration: {', '.join(missing)}")


# Cross-cutting values shared across multiple utils modules —
# not owned by any single class (DNAC, ISE, etc.)
DOMAIN_SUFFIX = os.getenv("domain_suffix", "")
