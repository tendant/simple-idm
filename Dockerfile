ARG GIT_COMMIT=noversion
ARG GIT_COMMIT_SHORT=noversion

FROM public.ecr.aws/docker/library/golang:1.23-alpine AS build

RUN apk update && \
  apk add --update openntpd && \
  ntpd && \
  apk upgrade && \
  apk add --no-cache alpine-sdk git make openssh

WORKDIR /app

# Cache go mod dependencies
COPY go.mod ./

RUN go mod download

COPY . .

# Build the login binary directly in the app directory
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 make all

FROM public.ecr.aws/docker/library/golang:1.23-alpine

WORKDIR /app

COPY --from=build --chmod=0755 /app/dist/ /app/

# Set the default command
CMD ["/app/cmd/login"]