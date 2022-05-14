# Cache

The cache functionality will prevent you from causing unnecessary traffic on
suse.com.

```{warning} Use it!
You should use it as often as you can. Otherwise you'll maybe be blocked.
```

## How it works

_scf_ uses the [requests-cache](https://requests-cache.readthedocs.io/en/stable/index.html)
which will cache the raw html response in a **sqlite** database.

Per default the database is saved in `~/.cache/scf.sqlite`, but you can change
it in the [config file](default-config).

## Using the use_cache boolean

Some endpoints or CLI functions have an option to disable the cache. This will
only prevent a cache hit, but the result will still be stored in the cache.
So next time you call the function and don't want to get a fresh data,
you will get the cached data.
