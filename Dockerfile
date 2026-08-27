# ============================================================
# Stage 1: Go binary builder
# ============================================================
FROM golang:alpine AS go-builder

WORKDIR /build
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /armur-server ./cmd/server/main.go

# ============================================================
# Stage 2: Go security tools
# ============================================================
FROM golang:alpine AS go-tools

RUN apk add --no-cache git
ENV GOBIN=/go-tools
RUN mkdir -p /go-tools

RUN go install golang.org/x/vuln/cmd/govulncheck@latest && \
    go install honnef.co/go/tools/cmd/staticcheck@latest && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    go install github.com/fzipp/gocyclo/cmd/gocyclo@latest && \
    go install golang.org/x/tools/cmd/deadcode@latest && \
    go install golang.org/x/lint/golint@latest && \
    go install github.com/google/osv-scanner/cmd/osv-scanner@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/zricethezav/gitleaks/v8@latest && \
    go clean -cache -modcache

# ============================================================
# Stage 3: Python security tools
# ============================================================
FROM python:3.12-slim AS python-tools

RUN pip install --no-cache-dir \
    semgrep==1.174.0 bandit==1.9.4 pydocstyle==6.3.0 radon==6.0.1 pylint==4.0.7 checkov==3.3.13 vulture==2.16 && \
    python -m venv /usr/local/venv-truffle && \
    /usr/local/venv-truffle/bin/pip install trufflehog3==3.0.10 && \
    ln -s /usr/local/venv-truffle/bin/trufflehog3 /usr/local/bin/trufflehog3

# ============================================================
# Runtime target: armur:go  (Go tools only)
# docker build --target armur-go -t armur:go .
# ============================================================
FROM debian:bookworm-slim AS armur-go

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=go-builder /armur-server  /usr/local/bin/armur-server
COPY --from=go-tools   /go-tools      /usr/local/bin/
COPY . /armur
WORKDIR /armur
ENV ARMUR_REPOS_DIR=/armur/repos
RUN mkdir -p /armur/repos
EXPOSE 4500
CMD ["/usr/local/bin/armur-server"]

# ============================================================
# Runtime target: armur:python  (Python tools only)
# docker build --target armur-py -t armur:python .
# ============================================================
FROM python:3.12-slim AS armur-py

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=go-builder   /armur-server /usr/local/bin/armur-server
COPY --from=python-tools /usr/local    /usr/local
COPY . /armur
WORKDIR /armur
ENV ARMUR_REPOS_DIR=/armur/repos
RUN mkdir -p /armur/repos
EXPOSE 4500
CMD ["/usr/local/bin/armur-server"]

# ============================================================
# Runtime target: armur:js  (JavaScript/TypeScript tools only)
# docker build --target armur-js -t armur:js .
# ============================================================
FROM node:22-slim AS armur-js

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=go-builder /armur-server /usr/local/bin/armur-server
RUN npm install -g eslint@10.9.0 jscpd@5.0.16
COPY . /armur
WORKDIR /armur
RUN npm install @eslint/js@10.0.1 eslint-plugin-jsdoc@64.2.1 eslint-plugin-security@4.0.1
COPY rule_config/eslint/eslint.config.js           /armur/eslint.config.js
COPY rule_config/eslint/eslint_jsdoc.config.js     /armur/eslint_jsdoc.config.js
COPY rule_config/eslint/eslint_security.config.js  /armur/eslint_security.config.js
COPY rule_config/eslint/eslint_deadcode.config.js  /armur/eslint_deadcode.config.js
ENV ARMUR_REPOS_DIR=/armur/repos
RUN mkdir -p /armur/repos
EXPOSE 4500
CMD ["/usr/local/bin/armur-server"]

# ============================================================
# Runtime target: armur:full  (all tools — DEFAULT)
# docker build -t armur:full .
# ============================================================
FROM python:3.12-slim AS armur-full

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates curl build-essential gcc wget unzip jq \
    default-jre ruby php-cli php-xml composer cppcheck flawfinder golang-go \
    shellcheck checksec libssl-dev pkg-config python3-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Go binary + Go tools
COPY --from=go-builder /armur-server /usr/local/bin/armur-server
COPY --from=go-tools   /go-tools     /usr/local/bin/

# Python tools & Missing security tools
COPY --from=python-tools /usr/local /usr/local
RUN pip install --no-cache-dir --break-system-packages slither-analyzer || true
RUN pip install --no-cache-dir --break-system-packages mythril || true
RUN pip install --no-cache-dir --break-system-packages pip-audit || true

# Trivy & Grype & IaC tools
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin v0.74.0 && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sLo /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64 && \
    chmod +x /usr/local/bin/hadolint && \
    curl -sLo /usr/local/bin/tfsec https://github.com/aquasecurity/tfsec/releases/download/v1.28.1/tfsec-linux-amd64 && \
    chmod +x /usr/local/bin/tfsec

# Install Ruby tools
RUN gem install bundler brakeman bundler-audit || true

# Install PHP tools
RUN composer global require "squizlabs/php_codesniffer=*" "vimeo/psalm" || true
ENV PATH="/root/.composer/vendor/bin:${PATH}"

# Install Rust and Rust tools
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup component add clippy && \
    cargo install cargo-audit cargo-geiger || true && \
    rm -rf /root/.cargo/registry /root/.cargo/git

# Node tools
RUN npm install -g eslint@10.9.0 jscpd@5.0.16 @cyclonedx/cdxgen

COPY . /armur
WORKDIR /armur
RUN npm install @eslint/js@10.0.1 eslint-plugin-jsdoc@64.2.1 eslint-plugin-security@4.0.1

COPY rule_config/eslint/eslint.config.js           /armur/eslint.config.js
COPY rule_config/eslint/eslint_jsdoc.config.js     /armur/eslint_jsdoc.config.js
COPY rule_config/eslint/eslint_security.config.js  /armur/eslint_security.config.js
COPY rule_config/eslint/eslint_deadcode.config.js  /armur/eslint_deadcode.config.js

ENV ARMUR_REPOS_DIR=/armur/repos
RUN mkdir -p /armur/repos
EXPOSE 4500
CMD ["/usr/local/bin/armur-server"]
