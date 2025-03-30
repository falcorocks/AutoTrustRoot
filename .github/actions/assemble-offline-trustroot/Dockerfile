FROM cgr.dev/chainguard/go:latest as builder
WORKDIR /app
COPY go.mod main.go ./
RUN go build -o trustrootassembler

FROM cgr.dev/chainguard/static:latest
WORKDIR /app
COPY --from=builder /app/trustrootassembler .
# Add the template file to the image
COPY trustroot.template.yml /app/trustroot.template.yml
ENTRYPOINT ["/app/trustrootassembler"]
