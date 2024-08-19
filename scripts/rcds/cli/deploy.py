from sys import exit

import click

import rcds
import rcds.challenge.docker
from rcds.util import SUPPORTED_EXTENSIONS, find_files


@click.command()
def deploy() -> None:
    try:
        project_config = find_files(["rcds"], SUPPORTED_EXTENSIONS, recurse=True)[
            "rcds"
        ].parent
    except KeyError:
        click.echo("Could not find project root!")
        exit(1)
    click.echo(f"Loading project at {project_config}")
    project = rcds.Project(project_config)
    click.echo("Initializing backends")
    project.load_backends()
    click.echo("Loading challenges")
    project.load_all_challenges()
    for challenge in project.challenges.values():
        cm = rcds.challenge.docker.ContainerManager(challenge)
        for container_name, container in cm.containers.items():
            click.echo(f"{challenge.config['id']}: checking container {container_name}")
            if not container.is_built():
                click.echo(
                    f"{challenge.config['id']}: building container {container_name}"
                    f" ({container.get_full_tag()})"
                )
                container.build()
        challenge.create_transaction().commit()
    if project.container_backend is not None:
        click.echo("Commiting container backend")
        project.container_backend.commit()
    else:
        click.echo("WARN: no container backend, skipping...")
    if project.scoreboard_backend is not None:
        click.echo("Commiting scoreboard backend")
        project.scoreboard_backend.commit()
    else:
        click.echo("WARN: no scoreboard backend, skipping...")
