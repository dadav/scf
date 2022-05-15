# cache

```{command-output} scf cache -h
```

## populate

Use **populate** to preload the cve data into a sqlite database.

```{command-output} scf cache populate -h
```

### example

```bash
scf cache populate
```

## clean

Remove expired cache entries from the database.

```{command-output} scf cache clean -h
```

### example

```bash
scf cache clean
```

## clear

Remove all entries from the database.

```{command-output} scf cache clear -h
```

### example

```bash
scf cache clear
```
