# Prometheus with the ingest scrape config and rules baked in.
#
# An image rather than a bind-mounted config file: bind mounts fail on any
# machine whose project drive is not shared with the container runtime, and the
# development stack should work on everyone's laptop. The build is a two-line
# COPY, so it costs nothing.
FROM prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0

COPY prometheus.yml /etc/prometheus/prometheus.yml
COPY rules.yml /etc/prometheus/rules.yml
