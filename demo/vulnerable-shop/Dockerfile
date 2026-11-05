FROM node:latest
WORKDIR /app
ENV API_TOKEN=shop-internal-token-7f3k9q
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["node", "src/server.js"]
