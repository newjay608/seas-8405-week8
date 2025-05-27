FROM node:18-alpine

# Create a non-root user and group to run the app
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY . .

# Change ownership to the non-root user
RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 3000

# Use NODE_ENV=production for security and performance
ENV NODE_ENV=production

CMD ["node", "server.js"]