from redis import Redis
from datetime import timedelta, datetime

class RedisStore(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connect(self):
        self.redis_client = Redis(host=self.host, port=self.port)

    def get(self, key):
        value = self.redis_client.get(key)
        return value.decode('utf-8')

    def set(self, key, value, minutes=10):
        self.redis_client.setex(key, timedelta(minutes=minutes), value)
