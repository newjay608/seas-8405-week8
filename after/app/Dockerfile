FROM python:3.13-alpine

WORKDIR /app

RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
COPY --chown=appuser:appgroup requirements.txt requirements.txt
COPY --chown=appuser:appgroup app.py app.py

# Ensure requirements.txt exists in your build context before building
RUN pip install --no-cache-dir -r requirements.txt
USER appuser

CMD ["python3", "app.py"]

# Ensure requirements.txt exists in your build context before building


