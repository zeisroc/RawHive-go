This is a Go port of the BOF https://github.com/nmht3t/RawHive, which extracts selected Windows registry hives directly from a raw NTFS volume by parsing NTFS metadata and reading file contents straight from disk.

# Usage

```
# Dump the registry hives
PS > ./rawhive-go.exe c:/

# Unxor the files
python3 unxor.py $DUMP_FILENAME.tmp $OUT_FILENAME $XOR_KEY
```
