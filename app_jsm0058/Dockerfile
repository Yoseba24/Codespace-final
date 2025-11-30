FROM eclipse-temurin:17-alpine
WORKDIR /app
COPY HelloWorldServer.java .
RUN javac HelloWorldServer.java
EXPOSE 8000
CMD ["java", "HelloWorldServer"]
