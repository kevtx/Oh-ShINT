import json
import re
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from loguru import logger
from tinydb import Query, TinyDB
from tinydb.storages import JSONStorage
from tinydb.table import Document as TinyDocument
from tinydb.table import Table as TinyTable
from tinydb_serialization import SerializationMiddleware
from tinydb_serialization.serializers import DateTimeSerializer

from .models.ioc import IOC

serialization = SerializationMiddleware(JSONStorage)
serialization.register_serializer(DateTimeSerializer(), "TinyDate")


def dataclass_encoder(obj: Any) -> Any:
    """
    Custom JSON encoder for dataclasses.
    Converts dataclasses to dictionaries for JSON serialization.
    """
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    elif isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


class Cache:
    """
    Class used to interact with cache databases.

    """

    path: Path
    __db: TinyDB

    def __init__(
        self, json_path: str | Path = Path(".history.json"), create: bool = False
    ) -> None:
        if isinstance(json_path, str):
            self.path = Path(json_path)
        elif isinstance(json_path, Path):
            self.path = json_path
        else:
            raise ValueError(f"Invalid json_path type: {type(json_path)}")

        if not self.path.is_absolute():
            self.path = Path(__file__).parent / self.path

        if not self.path.parent.exists():
            if create:
                logger.debug(f"Creating parent directory: {self.path.parent}")
                self.path.parent.mkdir(parents=True, exist_ok=True)
            else:
                raise ValueError(f"Parent directory does not exist: {self.path.parent}")
        elif not self.path.is_file():
            if not create:
                raise ValueError(f"self.path must be a file`: {self.path}")
            else:
                logger.debug(f"Creating database at {self.path}")
                self.path.touch()

        self.__db = TinyDB(self.path, indent=4, sort_keys=True, storage=serialization)
        # logger.debug(f"Database created at {self.path}")

    def __repr__(self) -> str:
        return f"Cache({self.path.absolute()})"

    def __getitem__(self, table_name: str) -> TinyTable:
        return self.__db.table(table_name)

    def __prep_item(self, item: object) -> dict:
        logger.debug(f"Preparing item {item}")
        i_json = json.loads(json.dumps(item, indent=4, default=dataclass_encoder))
        logger.debug(f"Item {item} prepared as {i_json}")
        try:
            ioc_type = i_json["ioc"]["type"]
        except (KeyError, TypeError) as e:
            logger.error(f"Item {item} does not have an IOC type")
            raise e

        allowed = {"ipv4", "ipv6", "md5", "sha1", "sha256", "url", "domain"}
        if ioc_type.lower() not in allowed:
            logger.error(f"Invalid type '{ioc_type}'")
            raise ValueError(f"Invalid type '{ioc_type}'")
        return i_json

    def add(self, item: object) -> None:
        i_json = self.__prep_item(item)
        db = self.__db
        table = db.table(i_json["ioc"]["type"].lower())
        logger.debug(f"Storing item {item} in {table}")
        try:
            table.insert(i_json)
            logger.debug(f"Item {item} stored in {table}")
        except Exception as e:
            logger.error(f"Failed to store item: {item} - {e}")
            raise e

    def get(
        self, ioc: IOC | str, provider_name: Optional[str] = None
    ) -> list[TinyDocument]:
        if isinstance(ioc, str):
            ioc = IOC(ioc)

        db = self.__db
        table = db.table(ioc.__class__.__name__.lower())
        logger.debug(f"Getting '{ioc}' from {ioc.__class__.__name__} table")
        try:
            record = Query()

            if not provider_name:
                result = table.search(
                    record.ioc.value.matches(ioc.value, flags=re.IGNORECASE)
                )
            else:
                result = table.search(
                    record.ioc.value.matches(ioc.value, flags=re.IGNORECASE)
                    & record.provider_name.matches(provider_name, flags=re.IGNORECASE)
                )

            for i in result:
                logger.debug(f"Found {ioc.__class__.__name__} {ioc.value} - {i}")
            return result
        except Exception as e:
            logger.error(f"Failed to get {ioc.__class__.__name__}: {ioc.value} - {e}")
            raise e

    @staticmethod
    def create_table(db: TinyDB, table_name: str) -> None:
        """
        Create a database table.

        :param      db:
            The database to create the table in.

        :param      table_name:
            The name of the table to create.

        :return:    None
        """
        # TODO: I don't really remember what this does
        # if isinstance(db, str):
        # db = self.__db[db]

        db.table(table_name)

    @staticmethod
    def get_table(db: TinyDB, table_name: str) -> TinyTable:
        """
        Get a table from a database.

        :param      db:
            The database to get the table from.

        :param      table_name:
            The name of the table to get.

        :return:    The table.
        """
        # TODO: Again, don't remember what this is for but it doesn't work like this
        # if isinstance(db, str):
        # db = self.__db[db]

        return db.table(table_name)

    @staticmethod
    def drop_table(db: TinyDB, table_name: str) -> None:
        """
        Drop a table from a database.

        :param      db:
            The database to drop the table from.

        :param      table_name:
            The name of the table to drop.

        :return:    None
        """
        # TODO: Again, don't remember what this is for but it doesn't work like this
        # if isinstance(db, str):
        # db = self.__db[db]

        db.drop_table(table_name)

    @staticmethod
    def drop_tables(db: TinyDB) -> None:
        """
        Drop all tables from a database.

        :param      db:
            The database to drop the tables from.

        :return:    None
        """
        # TODO: Again, don't remember what this is for but it doesn't work like this
        # if isinstance(db, str):
        # db = self.__db[db]

        db.drop_tables()
