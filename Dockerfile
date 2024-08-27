FROM golang:1.22.6@sha256:2bd56f00ff47baf33e64eae7996b65846c7cb5e0a46e0a882ef179fd89654afa AS builder
ENV APP_ROOT=/opt/app-root
ENV GOPATH=$APP_ROOT

WORKDIR $APP_ROOT/src/
ADD go.mod go.sum $APP_ROOT/src/
RUN go mod download

# Add source code
ADD ./ $APP_ROOT/src/

RUN go build -o gittuf-app main.go

FROM chainguard/git:latest AS deploy

COPY --from=builder /opt/app-root/src/gittuf-app /usr/local/bin/gittuf-app

ENTRYPOINT ["/usr/local/bin/gittuf-app"]
