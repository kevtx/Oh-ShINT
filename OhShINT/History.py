import json
import re
from datetime import datetime
from pathlib import Path

from loguru import logger
from pydantic.json import pydantic_encoder
from tinydb import Query, TinyDB
from tinydb.storages import JSONStorage
from tinydb_serialization import SerializationMiddleware
from tinydb_serialization.serializers import DateTimeSerializer

from .Functions import get_ioc_type

#   from tinydb.storages import JSONStorage
#   from BetterJSONStorage import BetterJSONStorage # Disabled because it makes the JSON files unreadable

serialization = SerializationMiddleware(JSONStorage)
serialization.register_serializer(DateTimeSerializer(), "TinyDate")


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
                self.path.parent.mkdir()
            else:
                e = ValueError(f"self.path.parent does not exist: {self.path.parent}")
        elif not self.path.is_file():
            if not create:
                e = ValueError(f"self.path must be a file`: {self.path}")
            else:
                logger.debug(f"Creating database at {self.path}")
                self.path.touch()

        if "e" in locals():
            logger.error(e)
            raise e

        self.__db = TinyDB(self.path, indent=4, sort_keys=True, storage=serialization)
        # logger.debug(f"Database created at {self.path}")

    def __repr__(self) -> str:
        return f"Cache({self.path.absolute()})"

    def __getitem__(self, table_name: str) -> TinyDB:
        return self.__db[table_name]

    def __prep_item(self, item: object) -> dict:
        logger.debug(f"Preparing item {item}")
        i_json = json.loads(json.dumps(item, indent=4, default=pydantic_encoder))
        logger.debug(f"Item {item} prepared as {i_json}")
        try:
            type = i_json["ioc"]["type"]
        except AttributeError as e:
            logger.error(f"Item {item} does not have an IOC type")
            raise e

        if type.lower() in ("ipv4", "ipv6"):
            type = "ip"
        elif type.lower() in ("md5", "sha1", "sha256", "url", "domain"):
            pass
        else:
            logger.error(f"Invalid type '{type}'")
            raise ValueError(f"Invalid type '{type}'")
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

    def get(self, ioc_value: str, provider_name: str = None) -> list[dict[str, str]]:
        ioc_type = get_ioc_type(ioc_value)
        db = self.__db
        table = db.table(ioc_type.lower())
        logger.debug(
            f"Getting {ioc_type.upper()} {ioc_value} from {table.name.upper()} table"
        )
        try:
            record = Query()

            if not provider_name:
                result = table.search(
                    record.ioc.value.matches(ioc_value, flags=re.IGNORECASE)
                )
            else:
                result = table.search(
                    record.ioc.value.matches(ioc_value, flags=re.IGNORECASE)
                    & record.provider_name.matches(provider_name, flags=re.IGNORECASE)
                )

            if len(result) == 0:
                logger.debug(f"No {ioc_type} {ioc_value} found")
                return None
            elif len(result) > 1:
                logger.warning(f"Multiple {ioc_type} {ioc_value} found")
                return result

            logger.debug(f"Found {ioc_type} {ioc_value} - {result}")
            return result
        except Exception as e:
            logger.error(f"Failed to get {ioc_type}: {ioc_value} - {e}")
            raise e

    def create_table(self, db: str | TinyDB, table_name: str) -> None:
        """
        Create a database table.

        :param      db:
            The database to create the table in.

        :param      table_name:
            The name of the table to create.

        :return:    None
        """
        if isinstance(db, str):
            db = self.__db[db]

        if not hasattr(db, f"{table_name}_table"):
            db.table(table_name)
            logger.info(f"Table '{table_name}' created.")
        else:
            logger.warning(f"Table '{table_name}' already exists.")

    def get_table(self, db: str | TinyDB, table_name: str) -> Query:
        """
        Get a table from a database.

        :param      db:
            The database to get the table from.

        :param      table_name:
            The name of the table to get.

        :return:    The table.
        """
        if isinstance(db, str):
            db = self.__db[db]

        if hasattr(db, f"{table_name}_table"):
            return db.table(table_name)
        else:
            logger.warning(f"Table '{table_name}' does not exist.")
            return None

    @staticmethod
    def drop_table(self, db: str | TinyDB, table_name: str) -> None:
        """
        Drop a table from a database.

        :param      db:
            The database to drop the table from.

        :param      table_name:
            The name of the table to drop.

        :return:    None
        """
        if isinstance(db, str):
            db = self.__db[db]

        if hasattr(db, f"{table_name}_table"):
            db.drop_table(table_name)
            logger.info(f"Table '{table_name}' dropped.")
        else:
            logger.warning(f"Table '{table_name}' does not exist.")

    def drop_tables(self, db: str | TinyDB) -> None:
        """
        Drop all tables from a database.

        :param      db:
            The database to drop the tables from.

        :return:    None
        """
        if isinstance(db, str):
            db = self.__db[db]

        db.drop_tables()
        logger.info("All tables dropped.")
