FROM python:3.11-slim

RUN useradd -r -m -d /home/user -s /usr/sbin/nologin user

WORKDIR /app
COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app

RUN mkdir -p /home/user/data && chown -R user:user /home/user
USER user

ENV DB_PATH=/home/user/data/app.db
EXPOSE 8080

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
