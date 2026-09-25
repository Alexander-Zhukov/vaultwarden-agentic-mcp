# The official Bitwarden CLI, used by the integration suite to check that what
# this service writes is readable by first-party clients, and the reverse.
FROM node:22.19-alpine
RUN npm install -g @bitwarden/cli@2026.6.0 && npm cache clean --force
ENTRYPOINT ["bw"]
