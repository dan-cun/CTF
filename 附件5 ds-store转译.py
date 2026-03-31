from ds_store import DSStore
with DSStore.open('DS_Store', 'r') as d:
    for m in d:
        print(m.filename)