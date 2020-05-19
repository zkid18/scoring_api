import redis
from datetime import timedelta, datetime

class RedisStore:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connect(self):
        self.client = redis.Redis(host=self.host, port=self.port)

    def ping(self):
        try:
            return self.client.ping()
        except redis.ConnectionError:
            raise ConnectionError

    def get(self, key):
        try:
            value = self.client.get(key)
            return value.decode('utf-8')
        except redis.RedisError:
            raise ConnectionError

    def set(self, key, value, seconds):
        try:
            return self.client.set(key, value, ex=seconds)
        except redis.RedisError:
            raise ConnectionError


class Store:
    def __init__(self, store):
        self.storage = store

    def ping(self):
        return self.storage.ping()

    def connect(self):
        return self.storage.connect()
    
    def get_cache(self, key):
        return self.storage.get(key)

    def cache_set(self, key, score, seconds=60*60):
        try:
            return self.storage.set(key, score, seconds)
        except:
            raise ConnectionError

