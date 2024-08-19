from abc import ABC, abstractmethod
from importlib import import_module
from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:
    import rcds


class BackendBase(ABC):
    def patch_challenge_schema(self, schema: Dict[str, Any]):
        pass


class BackendScoreboard(BackendBase):
    @abstractmethod
    def commit(self) -> bool:
        raise NotImplementedError()


class BackendContainerRuntime(BackendBase):
    @abstractmethod
    def commit(self) -> bool:
        raise NotImplementedError()


class BackendsInfo:
    HAS_SCOREBOARD: bool = False
    HAS_CONTAINER_RUNTIME: bool = False

    def get_scoreboard(
        self, project: "rcds.Project", options: Dict[str, Any]
    ) -> BackendScoreboard:
        raise NotImplementedError()

    def get_container_runtime(
        self, project: "rcds.Project", options: Dict[str, Any]
    ) -> BackendContainerRuntime:
        raise NotImplementedError()


def load_backend_module(name: str) -> BackendsInfo:
    try:
        module = import_module(f"rcds.backends.{name}")
    except ModuleNotFoundError:
        module = import_module(name)
    return module.get_info()  # type: ignore
