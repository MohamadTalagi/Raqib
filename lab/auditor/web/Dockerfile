FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# Leave VITE_API_URL unset by default so the app derives the API host from
# window.location at runtime (works from localhost, LAN, or Tailscale).
# Pass --build-arg VITE_API_URL=... only if the API truly lives elsewhere.
ARG VITE_API_URL
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
