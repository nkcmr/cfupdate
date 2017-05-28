.PHONY: binaries

clean:
	rm -rf bin

binaries:
	gox -output="bin/{{.Dir}}_{{.OS}}_{{.Arch}}"
