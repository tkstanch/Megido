FROM python:3.12-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy project files
COPY . .

# Create media directory for file uploads
RUN mkdir -p /app/media/malware_analyser_uploads && \
    chmod 755 /app/media

# Run migrations and collect static files on container start
# Note: In production, these should be run separately
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Expose port
EXPOSE 8000

# Set entrypoint
ENTRYPOINT ["/docker-entrypoint.sh"]

# Default command: Use Gunicorn with extended timeout for production
# For development, override with: docker run ... python manage.py runserver 0.0.0.0:8000
CMD ["gunicorn", "--config", "gunicorn.conf.py", "megido_security.wsgi:application"]
