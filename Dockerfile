# Use high-performance Node LTS Alpine image
FROM node:22-alpine

# Establish isolated workspace
WORKDIR /app

# Copy package descriptors first to make cache layer highly repeatable
COPY package.json ./

# Install packages
RUN npm install

# Sync other application components
COPY . .

# Expose production environment parameters
# NOTE: DB_ENCRYPTION_KEY is intentionally NOT baked into the image.
# Provide it at runtime (docker-compose .env / secrets), or the server will
# generate and persist a random key in the data volume.
ENV NODE_ENV=production

# Build static assets & compile TypeScript express handler bundle
RUN npm run build

# Restructure permissions securely
RUN chmod -R 755 /app

# Expose the essential service ingress port
EXPOSE 3000

# Execute server entry points
CMD ["npm", "start"]
