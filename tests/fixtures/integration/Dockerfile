# Integration-test fixture for Trivy Dockerfile (misconfiguration) scanning.
# Deliberately minimal and imperfect (no USER, broad COPY) so trivy has
# something to look at; the test asserts the scan runs, not specific findings.
FROM alpine:3.20
COPY . /app
CMD ["sh"]
