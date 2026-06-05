# ShadowSync Assets

Place a static Linux `gocryptfs` binary here when using FUSE mode from a USB drive:

```text
assets/gocryptfs
```

ShadowSync checks this bundled binary first. If it is missing, it falls back to `gocryptfs` from the host system path.
