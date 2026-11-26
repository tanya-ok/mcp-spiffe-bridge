FROM node:26-bookworm-slim@sha256:0042e17d232a87a2cd485be1da7900fca4d10a4ad11b29e9285da1d2e54798c9
# uid 1000 (node) runs the bridge or the allowed caller; 1001 is a second identity.
RUN useradd --uid 1001 --create-home second
WORKDIR /bench
COPY package.tgz ./
RUN printf '{"private":true,"type":"module"}\n' > package.json \
  && npm install --no-audit --no-fund --ignore-scripts ./package.tgz
COPY *.mjs ./
