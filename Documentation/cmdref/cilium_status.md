<!-- This file was autogenerated via cilium cmdref, do not edit manually-->

## cilium status

Display status of daemon

```
cilium status [flags]
```

### Options

```
      --all-addresses      Show all allocated addresses, not just count
      --all-clusters       Show all clusters
      --all-controllers    Show all controllers, not just failing
      --all-health         Show all health status, not just failing
      --all-nodes          Show all nodes, not just localhost
      --all-redirects      Show all redirects
      --brief              Only print a one-line status message
  -h, --help               help for status
  -o, --output string      json| yaml| jsonpath='{}'
      --timeout duration   Sets the timeout to use when querying for health (default 30s)
      --verbose            Equivalent to --all-addresses --all-controllers --all-nodes --all-redirects --all-clusters --all-health
```

### Options inherited from parent commands

```
      --config string   config file (default is $HOME/.cilium.yaml)
  -D, --debug           Enable debug messages
  -H, --host string     URI to server-side API
```

### SEE ALSO

* [cilium](cilium.md)	 - CLI
