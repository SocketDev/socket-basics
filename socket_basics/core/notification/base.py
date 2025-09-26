from typing import Any, Dict


class BaseNotifier:
    """Abstract base class for notifier plugins.

    Implementations should override the `notify` method.
    """

    name = "base"

    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        self.config = config or {}

    def notify(self, facts: Dict[str, Any]) -> None:
        """Emit notifications for provided Socket facts.

        facts: full aggregated socket facts structure.
        """
        raise NotImplementedError()
