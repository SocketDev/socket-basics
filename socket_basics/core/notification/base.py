from typing import Any


class BaseNotifier:
    """Abstract base class for notifier plugins.

    Implementations should override the `notify` method.
    """

    name = "base"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    def notify(self, facts: dict[str, Any]) -> None:
        """Emit notifications for provided Socket facts.

        facts: full aggregated socket facts structure.
        """
        raise NotImplementedError
