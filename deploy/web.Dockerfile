# Next.js UI image.
FROM node:20-slim
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
# NEXT_PUBLIC_* vars are inlined into the client bundle at build time, so the API base the
# browser calls must be set here (not just at runtime). Defaults to localhost for local use.
ARG NEXT_PUBLIC_API_BASE=http://localhost:9000
ENV NEXT_PUBLIC_API_BASE=$NEXT_PUBLIC_API_BASE
RUN npm run build
EXPOSE 3000
CMD ["npm", "run", "start"]
