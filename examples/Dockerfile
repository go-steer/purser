# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Image for the purser examples. It is not a purser image: purser is a
# library and publishes none. This exists so the Kubernetes and GKE
# cells have something to run, and it is built from this repository
# rather than pulled from anywhere.
#
# Build from the repository root:
#   docker build -f examples/Dockerfile -t purser-examples:latest .
#
# Both binaries live in one image; the manifests pick between them with
# `command`.

FROM golang:1.26 AS build

WORKDIR /src

# Dependencies first, so an edit to the source does not re-download the
# module graph.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO off and a static link, because the runtime stage has no libc.
# -trimpath keeps the build directory out of the binary.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ \
    ./examples/cmd/hello-server \
    ./examples/cmd/hello-client

# static, not base: no shell, no package manager, nothing to exec into.
# A service holding a private key should not also carry a debugger.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/hello-server /out/hello-client /

# 65532 is distroless's nonroot user. The manifests repeat it in their
# securityContext so the constraint is visible where it is enforced.
USER 65532:65532

ENTRYPOINT ["/hello-server"]
