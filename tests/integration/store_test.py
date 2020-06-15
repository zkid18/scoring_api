import os
import unittest
from unittest.mock import MagicMock

from store import Store, RedisStore

@unittest.skipIf(
    not (os.getenv('REDIS_HOST') and os.getenv('REDIS_PORT')),
    'Require "REDIS_HOST" and "REDIS_PORT"' 
)
class TestStore(unittest.TestCase):
    def setUp(self):
        self.redis_storage = RedisStore(host=os.getenv('REDIS_HOST', 'localhost'), port=os.getenv('REDIS_PORT', 6379))
        self.store = Store(self.redis_storage)
        self.store.connect()
        self.key = 'sample_key'
        self.value = 'sample_value'

    def test_connect_to_store(self):
        self.assertTrue(self.store.ping())

    def test_connect_to_redis(self):
        self.assertTrue(self.redis_storage.ping())
        
    def test_redis_set_value(self):
        key = self.key + '_redis'
        self.assertTrue(self.redis_storage.set(key, self.value, 30))
        self.assertEqual(self.store.cache_get(key), self.value)

    def test_redis_connection_error(self):
        self.redis_storage.client.get = MagicMock(side_effect=ConnectionError())
        self.assertRaises(ConnectionError, self.store.cache_get, self.key)

    def test_cache_set_value(self):
        key = self.key + '_cache'
        self.assertTrue(self.store.cache_set(key, self.value, 30))
        self.assertEqual(self.store.cache_get(key), self.value)

    def test_cache_connection_error(self):
        self.redis_storage.get = MagicMock(side_effect=ConnectionError())
        self.redis_storage.set = MagicMock(side_effect=ConnectionError())

        self.assertRaises(ConnectionError, self.store.cache_get ,self.key)
        self.assertRaises(ConnectionError, self.store.cache_set ,self.key, self.value)

    def test_store_set_value(self):
        key = self.key + '_store'
        self.assertTrue(self.store.set(key, self.value, 30))
        self.assertEqual(self.store.get(key), self.value)


if __name__ == "__main__":
    unittest.main()