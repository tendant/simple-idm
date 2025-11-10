ARG GIT_COMMIT=noversion
ARG GIT_COMMIT_SHORT=noversion

FROM public.ecr.aws/docker/library/golang:1.24-alpine AS build

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

# Build the login binary directly with explicit architecture settings
RUN make all

FROM public.ecr.aws/docker/library/golang:1.24-alpine

WORKDIR /app

# Copy only the binary with executable permissions
COPY --from=build --chmod=0755 /app/dist/ /app/

# Set the default command
CMD ["/app/cmd/login"]