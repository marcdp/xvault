from abc import abstractmethod

from ..meta import XVaultMeta


class HandlerBase:
    @abstractmethod
    def parse(self, text: str) -> tuple[XVaultMeta, str]:
        pass
