
import json

def diff_json(old_path: str, new_path: str):
    with open(old_path, "r", encoding="utf-8") as f:
        old = json.load(f)
    with open(new_path, "r", encoding="utf-8") as f:
        new = json.load(f)
    old_set = {r["subdomain"] for r in old}
    new_set = {r["subdomain"] for r in new}
    added = sorted(list(new_set - old_set))
    removed = sorted(list(old_set - new_set))
    return {"added": added, "removed": removed}
