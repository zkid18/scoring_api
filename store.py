import redis
import functools
from datetime import timedelta, datetime

def try_connection(attemps):
    def decorator(method):
        @functools.wraps(method)
        def connect(*args, **kwargs):
            for _ in range(N):
                while True:
                    try:
                        return method(*args, **kwargs)
                    except redis.ConnectionError:
                        continue
                    break
        return connect
    return decorator


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
    MAX_ATTEMPS = 10

    def __init__(self, store):
        self.storage = store

    def ping(self):
        return self.storage.ping()

    def connect(self):
        return self.storage.connect()
    
    @try_connection(MAX_ATTEMPS)
    def get_cache(self, key):
        '''
        Communication with client-server cache stoarage (i.e. memcache, tarantool, redis)
        '''
        return self.storage.get(key)
    
    @try_connection(MAX_ATTEMPS)
    def get(self, key):
        '''
        Communication with separate key-value stoarage (i.e nosql)
        '''
        return self.storage.get(key)

    @try_connection(MAX_ATTEMPS)
    def set(self, key):
        '''
        Communication with separate key-value stoarage (i.e nosql)
        '''
        return self.storage.set(key, score, seconds)

    @try_connection(MAX_ATTEMPS)
    def cache_set(self, key, score, seconds=60*60):
        '''
        Communication with client-server cache stoarage (i.e. memcache, tarantool, redis)
        '''
        try:
            return self.storage.set(key, score, seconds)
        except:
            raise ConnectionError

