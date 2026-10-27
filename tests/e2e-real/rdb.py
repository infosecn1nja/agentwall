"""Tiny Redis helper for the real end-to-end test (uses the same redis-py as the scorer)."""
import os
import sys

import redis

client = redis.Redis(
    host="127.0.0.1",
    port=int(os.environ.get("AGENTWALL_E2E_REDIS_PORT", "6390")),
    password=os.environ.get("AGENTWALL_E2E_REDIS_PASS", "testpass"),
    decode_responses=True,
)

command = sys.argv[1]
if command == "flush":
    client.flushdb()
elif command == "get":
    print(client.get(sys.argv[2]) or "")
elif command == "exists":
    print(client.exists(sys.argv[2]))
elif command == "ttl":
    print(client.ttl(sys.argv[2]))
elif command == "set":
    ttl = int(sys.argv[4]) if len(sys.argv) > 4 else None
    client.set(sys.argv[2], sys.argv[3], ex=ttl)
elif command == "del":
    print(client.delete(*sys.argv[2:]))
else:
    sys.exit("unknown command: {}".format(command))
