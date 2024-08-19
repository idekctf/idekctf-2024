from pathlib import Path
from typing import Any, Dict, Optional

import docker  # type: ignore
from jinja2 import Environment

from rcds.util import SUPPORTED_EXTENSIONS, find_files

from ..backend import BackendContainerRuntime, BackendScoreboard, load_backend_module
from ..challenge import Challenge, ChallengeLoader
from . import config
from .assets import AssetManager


class Project:
    """
    An rCDS project; the context that all actions are done within
    """

    root: Path
    config: dict
    challenges: Dict[Path, Challenge]
    challenge_loader: ChallengeLoader

    asset_manager: AssetManager

    container_backend: Optional[BackendContainerRuntime] = None
    scoreboard_backend: Optional[BackendScoreboard] = None

    jinja_env: Environment
    docker_client: Any

    def __init__(
        self, root: Path, docker_client: Optional[docker.client.DockerClient] = None
    ):
        """
        Create a project
        """
        root = root.resolve()
        try:
            cfg_file = find_files(
                ["rcds"], SUPPORTED_EXTENSIONS, path=root, recurse=False
            )["rcds"]
        except KeyError:
            raise ValueError(f"No config file found at '{root}'")
        self.root = root
        self.config = config.load_config(cfg_file)
        self.challenge_loader = ChallengeLoader(self)
        self.challenges = dict()
        self.asset_manager = AssetManager(self)
        self.jinja_env = Environment(autoescape=False)
        if docker_client is not None:
            self.docker_client = docker_client
        else:
            self.docker_client = docker.from_env()

    def load_all_challenges(self) -> None:
        for ext in SUPPORTED_EXTENSIONS:
            for chall_file in self.root.rglob(f"challenge.{ext}"):
                path = chall_file.parent
                self.challenges[
                    path.relative_to(self.root)
                ] = self.challenge_loader.load(path)

    def get_challenge(self, relPath: Path) -> Challenge:
        return self.challenges[relPath]

    def load_backends(self) -> None:
        for backend_config in self.config["backends"]:
            backend_info = load_backend_module(backend_config["resolve"])
            if self.scoreboard_backend is None and backend_info.HAS_SCOREBOARD:
                self.scoreboard_backend = backend_info.get_scoreboard(
                    self, backend_config["options"]
                )
            if self.container_backend is None and backend_info.HAS_CONTAINER_RUNTIME:
                self.container_backend = backend_info.get_container_runtime(
                    self, backend_config["options"]
                )
        # TODO: maybe don't reinitialize here?
        self.challenge_loader = ChallengeLoader(self)
