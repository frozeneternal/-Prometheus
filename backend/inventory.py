from __future__ import annotations


def config_list_records(config: dict, key: str) -> tuple[list[dict], list[dict]]:
    raw_items = config.get(key, [])
    if raw_items in (None, ""):
        return [], []
    if not isinstance(raw_items, list):
        return [], [{"index": None, "path": key}]

    records: list[dict] = []
    invalid_entries: list[dict] = []
    for index, item in enumerate(raw_items):
        if isinstance(item, dict):
            records.append(item)
        else:
            invalid_entries.append({"index": index, "path": f"{key}[{index}]"})
    return records, invalid_entries
