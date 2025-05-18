# 1. Build frontend
FROM node:18 AS frontend-build
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
RUN npm run build

# 2. Build backend + chèn frontend vào Spring Boot static
FROM maven:3.8-openjdk-17 AS backend-build
WORKDIR /app
COPY backend/pom.xml backend/
COPY backend/src backend/src
COPY --from=frontend-build /app/frontend/build/. backend/src/main/resources/static/
RUN mvn -f backend/pom.xml clean package -DskipTests

# 3. Runtime
FROM openjdk:17-jdk-slim
WORKDIR /app
COPY --from=backend-build /app/backend/target/*.jar app.jar
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "app.jar"]
