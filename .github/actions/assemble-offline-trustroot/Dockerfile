FROM cgr.dev/chainguard/go:latest as builder
WORKDIR /app
COPY go.mod go.sum main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o trustrootassembler

FROM cgr.dev/chainguard/static:latest
WORKDIR /app
COPY --from=builder /app/trustrootassembler .
ENTRYPOINT ["/app/trustrootassembler"]
