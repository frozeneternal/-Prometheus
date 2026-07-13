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


def config_dict_field(record: dict, key: str) -> tuple[dict, bool]:
    raw_value = record.get(key) if isinstance(record, dict) else None
    if raw_value in (None, ""):
        return {}, False
    if isinstance(raw_value, dict):
        return raw_value, False
    return {}, True
