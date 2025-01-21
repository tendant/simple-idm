FROM node:22-alpine AS build

WORKDIR /app

COPY ./ /app/

RUN npm install

RUN npm run build

FROM nginx:latest

# Copy the build output to replace the default nginx contents.
COPY --from=build /app/dist/ /usr/share/nginx/html
# COPY nginx-default.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80