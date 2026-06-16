import os
import json
import datetime

def save_results(indicator, vt_result, otx_result, verdict):
    entry = {
    "timestamp":   datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "indicator":   indicator,
    "vt_result":   vt_result,
    "otx_result":  otx_result,
    "verdict":     verdict
    }
    if os.path.exists("results.json"):
        with open("results.json", "r") as f:
            try:
                result_data = json.load(f)
            except json.JSONDecodeError:
                result_data = []
    else:
        result_data = []
    result_data.append(entry)
    with open("results.json", "w") as f:
        json.dump(result_data, f, indent=4)

    print(f"  Result saved to results.json ({len(result_data)} total)")
