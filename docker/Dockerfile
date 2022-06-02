FROM golang:1.17.10-alpine

# LABEL maintainer="jesus.ramos.external@atos.net"

RUN mkdir /app
WORKDIR /app

# Install git
RUN apk add --update --no-cache git

ARG VERSION
# Get HPC exporter
RUN git clone https://github.com/SODALITE-EU/hpc-exporter.git --depth 1 --branch $VERSION
# Build the code
RUN cd hpc-exporter && go build

EXPOSE ${EXPORTER_PORT}

CMD [ "sh", "-c", "./hpc-exporter/hpc_exporter "]
