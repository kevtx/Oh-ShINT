import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from tinydb import TinyDB

from OhShINT.history import Cache
from OhShINT.models.ioc import IOC


@dataclass
class DummyIOC:
    type: str
    value: str


@dataclass
class DummyItem:
    ioc: DummyIOC
    provider_name: str
    data: dict


class TestCacheInit(unittest.TestCase):
    def test_init_with_invalid_path_type(self):
        with self.assertRaises(ValueError):
            Cache(json_path=123)  # type: ignore[arg-type]

    def test_init_creates_missing_parent_when_create_true(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            nested_dir = Path(temp_dir) / "nested" / "deep"
            file_path = nested_dir / "history.json"
            cache = Cache(json_path=file_path, create=True)
            self.assertTrue(file_path.exists())
            self.assertEqual(cache.path, file_path)

    def test_init_requires_existing_file_when_create_false(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "history.json"
            with self.assertRaises(ValueError):
                Cache(json_path=file_path, create=False)

    def test_init_creates_file_when_create_true(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "history.json"
            cache = Cache(json_path=file_path, create=True)
            self.assertTrue(file_path.exists())
            self.assertEqual(cache.path, file_path)

    def test_repr(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "history.json"
            cache = Cache(json_path=file_path, create=True)
            self.assertIn(str(file_path.absolute()), repr(cache))


class TestCacheOperations(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.temp_dir.name) / "history.json"
        self.cache = Cache(json_path=self.file_path, create=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_getitem_returns_table(self):
        table = self.cache["ipv4"]
        self.assertEqual(table.name, "ipv4")

    def test_prep_item_invalid_type(self):
        bad_item = DummyItem(
            ioc=DummyIOC(type="NotAType", value="x"),
            provider_name="Provider",
            data={},
        )
        with self.assertRaises(ValueError):
            prep_item = getattr(self.cache, "_Cache__prep_item")
            prep_item(bad_item)

    def test_add_and_get_by_string(self):
        item = DummyItem(
            ioc=DummyIOC(type="IPv4", value="8.8.8.8"),
            provider_name="TestProvider",
            data={"score": 1},
        )
        self.cache.add(item)

        results = self.cache.get("8.8.8.8")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["provider_name"], "TestProvider")
        self.assertEqual(results[0]["ioc"]["value"], "8.8.8.8")

    def test_get_with_provider_filter(self):
        item = DummyItem(
            ioc=DummyIOC(type="IPv4", value="8.8.8.8"),
            provider_name="TestProvider",
            data={"score": 1},
        )
        self.cache.add(item)

        results = self.cache.get("8.8.8.8", provider_name="TestProvider")
        self.assertEqual(len(results), 1)

        no_results = self.cache.get("8.8.8.8", provider_name="OtherProvider")
        self.assertEqual(no_results, [])

    def test_get_with_ioc_instance(self):
        item = DummyItem(
            ioc=DummyIOC(type="IPv4", value="8.8.8.8"),
            provider_name="TestProvider",
            data={"score": 1},
        )
        self.cache.add(item)

        ioc = IOC("8.8.8.8")
        results = self.cache.get(ioc)
        self.assertEqual(len(results), 1)


class TestCacheStaticMethods(unittest.TestCase):
    def test_create_get_drop_table(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "history.json"
            db = TinyDB(file_path)

            Cache.create_table(db, "test_table")
            table = Cache.get_table(db, "test_table")
            self.assertEqual(table.name, "test_table")

            Cache.drop_table(db, "test_table")
            self.assertNotIn("test_table", db.tables())

    def test_drop_tables(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "history.json"
            db = TinyDB(file_path)

            db.table("one")
            db.table("two")
            Cache.drop_tables(db)
            self.assertEqual(len(db.tables()), 0)


if __name__ == "__main__":
    unittest.main()
