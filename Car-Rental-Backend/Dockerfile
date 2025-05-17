FROM openjdk:17-jdk-slim
WORKDIR /app
COPY target/*.jar CarRentalApplication.jar
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "CarRentalApplication.jar"]
