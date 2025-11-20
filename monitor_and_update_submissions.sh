#!/bin/bash
# Monitor Valid8 scan and update submissions when ready

echo "Monitoring Valid8 scan..."
echo ""

while true; do
    if [ -f "top_5_real_valid8.json" ]; then
        echo "✅ Results found!"
        python3 << 'PYEOF'
import json
from pathlib import Path

with open('top_5_real_valid8.json', 'r') as f:
    top_5 = json.load(f)

print(f"Found {len(top_5)} real vulnerabilities")
print("Ready to update HackerOne submissions")
PYEOF
        break
    fi
    
    echo "⏳ Waiting for results..."
    sleep 10
done
