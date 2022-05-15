# config

This subcommand provides functionality related to the config file.

```{command-output} scf config -h
```

## dump

**dump** just prints the config, then exists.

```{command-output} scf config dump -h
```

### example

```{command-output} scf config dump
```

## edit

**edit** opens the config in your editor.

```{command-output} scf config edit -h
```

### example

Set **vim** as editor and open the config:

```bash
export EDITOR=vim
scf config edit
```
