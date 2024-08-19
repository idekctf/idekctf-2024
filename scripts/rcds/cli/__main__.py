import click

from .deploy import deploy


@click.group()
def cli():
    pass


cli.add_command(deploy)


if __name__ == "__main__":
    cli()
