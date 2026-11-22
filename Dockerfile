FROM golang:1.25-alpine AS build
WORKDIR /app
COPY go.mod ./
COPY *.go ./
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -o /server .

FROM scratch
COPY --from=build /server /server
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/server"]
