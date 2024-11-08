FROM alpine:latest AS builder

RUN apk update --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community && \
    apk add --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community go

ENV APP_ROOT=/opt/app-root
ENV GOPATH=$APP_ROOT

WORKDIR $APP_ROOT/src/

# Add source code
ADD ./ $APP_ROOT/src/

RUN go build -o gittuf-app main.go

FROM alpine:latest AS deploy

RUN apk update && apk add git openssh

COPY --from=builder /opt/app-root/src/gittuf-app /usr/local/bin/gittuf-app

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

ENTRYPOINT ["/usr/local/bin/gittuf-app"]
