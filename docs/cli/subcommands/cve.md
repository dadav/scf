# cve

This subcommand provides CVE related functionality.

```{command-output} scf cve -h
```

## list

Use **list** to get a list of all known _CVE_.

```{command-output} scf cve list -h
```

### example

This will group the found CVE by year:

```{command-output} scf cve list --year
---
ellipsis: 5
---
```

## details

Use **details** to get more information about a specific _CVE_.

```{command-output} scf cve details -h
```

### example

Get the base score for the CVE **CVE-2022-30333**:

```{command-output} scf cve details CVE-2022-30333 --field cvss.score
```

## watch

Use **watch** if you want to get informations about new CVE as they are being published.

```{command-output} scf cve watch -h
```

### example

Start the watcher, run a command (`--command`), exit (`--test`).
This is useful, if you want to test the command before going into watch mode.

```{command-output} scf cve watch --command "echo Does this get executed?" --test
```
