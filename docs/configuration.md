# Configuration

_scf_ can also be configured via a configuration file, which is included in the package.

(default-config)=
## Defaults

```{literalinclude} ../scf/settings.toml
:language: toml
```

## Initialization

To be able to change the configuration, you need the call the `init` command:

```bash
scf config init
```

```{note}
If you want to _reset_ your configuration to the defaults,
run it with the `--overwrite` option.
```

## Viewing the configuration

Sometime you just want to know what the current settings are:

```bash
scf config dump
```

## Autocompletion

To install the autocompletion for your shell, you have to run the following command:

```bash
scf --install-autocompletion $SHELL
```
