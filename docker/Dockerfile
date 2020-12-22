FROM golang:1.13.8-alpine

# LABEL maintainer="fabeirojorge.secondwindow@gmail.com"

RUN mkdir /app
WORKDIR /app

# Install git
RUN apk add --update --no-cache git

# Get HPC exporter
RUN git clone -b ignore-host-key https://github.com/SODALITE-EU/hpc-exporter.git

# Build the code
RUN cd hpc-exporter && go build

EXPOSE ${EXPORTER_PORT}

CMD [ "sh", "-c", "./hpc-exporter/hpc_exporter -host=${HPC_FRONTEND} -listen-address=:${EXPORTER_PORT} -scheduler=${SCHEDULER} -ssh-user=${SSH_USER} -ssh-private-key=/app/ssh_key -log-level=${LOG_LEVEL} -target-job-ids=${JOBLIST}"]