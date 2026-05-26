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
ENV NODE_ENV=production
ENV DB_ENCRYPTION_KEY="production_default_secured_salt_change_this"

# Build static assets & compile TypeScript express handler bundle
RUN npm run build

# Restructure permissions securely
RUN chmod -R 755 /app

# Expose the essential service ingress port
EXPOSE 3000

# Execute server entry points
CMD ["npm", "start"]
