FROM python:3.10-slim
WORKDIR /app
RUN pip install flask
COPY Hello_Email.py .
EXPOSE 8000
CMD ["python", "Hello_Email.py"]
