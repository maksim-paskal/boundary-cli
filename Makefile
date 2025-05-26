test:
	go mod tidy
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run -v
run:
	go run ./cmd/main.go
build:
	go run github.com/goreleaser/goreleaser@latest build --snapshot --clean --skip=validate
release:
	make build
	mc mirror ./dist/ hcloud-paskal/paskal/boundary-cli --overwrite