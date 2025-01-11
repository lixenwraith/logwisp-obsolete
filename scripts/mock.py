import json
import time
import os
from datetime import datetime
import pytz

# Ensure data directory exists
os.makedirs("./data", exist_ok=True)

try:
    while True:
        # Get current time in EST timezone with RFC3339 format
        tz = pytz.timezone('America/Toronto')
        now = datetime.now(tz).isoformat()

        # Create log entry
        log_entry = {
            "time": now,
            "level": "INFO",
            "fields": ["Message", now]
        }

        # Append to file
        with open("./data/sample.log", "a") as f:
            json.dump(log_entry, f)
            f.write("\n")

        time.sleep(0.5)

except KeyboardInterrupt:
    pass