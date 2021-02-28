FROM golang:1.16 as builder

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build

# Production image
FROM gcr.io/distroless/static-debian10:latest

COPY --from=builder /app/google-kms-pgp /bin

ENTRYPOINT [ "/bin/google-kms-pgp" ]
