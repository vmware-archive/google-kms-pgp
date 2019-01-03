FROM golang:1.11 as builder
WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build

FROM alpine:3.8
COPY --from=builder /app/google-kms-pgp /bin
ENTRYPOINT [ "/bin/google-kms-pgp" ]
