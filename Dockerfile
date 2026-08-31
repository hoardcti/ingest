# Build
FROM golang:1.25-alpine AS build

WORKDIR /src

# Dependencies first, so a source-only change does not re-download the module
# graph.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO off for a static binary; the migrations are embedded, so the image needs
# nothing from the repository at runtime.
#
# Build info is left in (no -s -w on the symbol table beyond the defaults) so
# `ingest version` can report the commit it was built from — worth the few
# hundred kilobytes when you are trying to work out which build wrote a row.
ENV CGO_ENABLED=0
RUN go build -trimpath -o /out/ingest ./cmd/ingest

# Run
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/ingest /usr/local/bin/ingest

USER nonroot:nonroot
EXPOSE 8080

# No shell in the image, so this must be exec form.
ENTRYPOINT ["/usr/local/bin/ingest"]
CMD ["serve"]
