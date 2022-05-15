# server

This subcommand contains functionality that is related to the api server.

```{command-output} scf server -h
```

## run

Starts the api server.

```{command-output} scf server run -h
```

### example

Start the server on localhost:5000 with 2 worker processes:

```bash
scf server run --host 127.0.0.1 --port 5000 --workers 2
```
