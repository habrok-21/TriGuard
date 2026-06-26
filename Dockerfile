FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py models.py proxy.py ad_auth.py admin.html employee.html login.html email-verification.html manage_users.py ./

EXPOSE 8443

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8443"]
