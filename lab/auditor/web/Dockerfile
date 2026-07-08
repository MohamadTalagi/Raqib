FROM ghcr.io/cirruslabs/flutter:stable AS build
WORKDIR /app
COPY pubspec.yaml .
RUN flutter pub get
COPY . .
RUN flutter build web --release --dart-define=AUDITOR_API_URL=http://localhost:8000

FROM nginx:alpine
COPY --from=build /app/build/web /usr/share/nginx/html
EXPOSE 80
