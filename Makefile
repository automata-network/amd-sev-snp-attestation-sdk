.PHONY: gen-go-bindings check-go-bindings

gen-go-bindings:
	cd contracts && forge build
	cd go-sdk/packages/gosev/bindings && go generate

check-go-bindings: gen-go-bindings
	git diff --exit-code go-sdk/packages/gosev/bindings/
