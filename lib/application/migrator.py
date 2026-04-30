from pathlib import Path

from alembic import command
from alembic.config import Config

from application.config import Settings


class AlembicMigrator:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def upgrade_head(self) -> None:
        ini_path = Path(self._settings.alembic_ini_path).resolve()
        config = Config(str(ini_path))
        config.set_main_option("sqlalchemy.url", self._settings.database_url)
        command.upgrade(config, "head")
