import os
import requests
from dotenv import load_dotenv

load_dotenv()

LOKI_URL = os.getenv('LOKI_URL')

# Test health
response = requests.get(f"{LOKI_URL}/ready")
print(f"Loki Health: {response.status_code}")

# Test query
query = '{job="modsecurity"}'
response = requests.get(
    f"{LOKI_URL}/loki/api/v1/query",
    params={"query": query, "limit": 1}
)
print(f"Query Result: {response.json()}")