.PHONY: release

clean:
	rm -rf bin
	rm cfupdate

release: bin/.ok
bin/.ok: main.go
	rm -rf ./bin
	gox \
		-ldflags='-w -s' \
		-output='bin/{{.Dir}}_{{.OS}}_{{.Arch}}'
	touch $@

cfupdate: main.go
	go build \
		-o $@ \
		-ldflags='-w -s'
